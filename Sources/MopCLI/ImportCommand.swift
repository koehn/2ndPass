import ArgumentParser
import Foundation
import Darwin
import MopCore
import MopAppSupport

extension ImportFormat: ExpressibleByArgument {}

extension Item {
    struct Import: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Import password-manager exports without replacing existing items.")
        @OptionGroup var storage: VaultOptions
        @Argument(help: "Unencrypted CSV, Bitwarden JSON, or 1Password 1PUX export.", completion: .file()) var file: String
        @Option var format: ImportFormat = .auto
        @Flag(help: "Preview without changing the vault.") var dryRun = false
        @Flag(help: "Accept the preview, including reported preservation warnings.") var yes = false
        @Flag(help: "Emit a JSON report without field values.") var json = false
        func validate() throws {
            guard storage.vault != nil else { throw ValidationError("Choose a destination with --vault.") }
            try storage.requireOnline()
        }
        func run() async throws {
            do { try await importFile() }
            catch let code as ExitCode { throw code }
            catch {
                let message = (error as? ImportFailure)?.errorDescription ?? (error as? MopError)?.errorDescription ?? "Import could not be completed."
                IO.diagnostic("mop: " + message + "\n")
                throw ExitCode(1)
            }
        }
        private func importFile() async throws {
            let service = storage.native(); defer { service.lock() }
            let document = try PasswordImport.read(URL(fileURLWithPath: file), format: format)
            let result = try await service.execute(.previewImport(document, selected: nil), vault: storage.vault, offline: false)
            guard let preview = result.importPreview else { throw MopError.invalidVault }
            if dryRun {
                try emit(preview.report)
                if preview.report.needsAttention { throw ExitCode(2) }
                return
            }
            if !yes {
                guard isatty(STDIN_FILENO) != 0, !json else { throw MopError.confirmationRequired }
                try emit(preview.report)
                try IO.output("Affected vaults require updated Mop clients. Import these items? [y/N] ")
                guard ["y", "yes"].contains(readLine()?.lowercased() ?? "") else { return }
            }
            let selected = Set(document.records.map(\.id))
            let committed = try await service.execute(.commitImport(document, selected: selected, vault: preview.vault, revision: preview.revision), vault: storage.vault, offline: false)
            guard let report = committed.importReport else { throw MopError.invalidVault }
            try emit(report)
            if !json { try IO.output("Check the results, then delete the unencrypted source export manually.\n") }
            if report.needsAttention { throw ExitCode(2) }
        }
        private func emit(_ report: ImportReport) throws {
            if json {
                let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
                try IO.output(String(decoding: encoder.encode(report), as: UTF8.self) + "\n")
            } else {
                try IO.output(report.summary + "\n")
                for row in report.rows {
                    // JSON-escape user-controlled titles to prevent terminal control sequences.
                    let title = String(decoding: try JSONEncoder().encode(row.name), as: UTF8.self)
                    try IO.output("\(row.id): \(title) — \(row.disposition.rawValue)\(row.warnings.isEmpty ? "" : "; " + row.warnings.joined(separator: " "))\n")
                }
            }
        }
    }
}
