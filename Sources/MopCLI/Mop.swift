import ArgumentParser
import Foundation
import MopCore

@main
struct Mop: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "2ndpass",
        abstract: "Read and manage an encrypted vault using your Mac's Secure Enclave.",
        version: "0.7.0",
        subcommands: [Item.self, Read.self, Write.self, List.self, Delete.self, Run.self, Inject.self, Vault.self, Completion.self, Device.self]
    )

    /// ArgumentParser wraps errors thrown by option-group validation. Match only
    /// our fixed diagnostics; never print parser text containing user arguments.
    static func knownValidationError(_ error: Error) -> MopError? {
        let message = message(for: error)
        return [MopError.invalidVaultName, .confirmationRequired, .invalidProcess]
            .first { $0.errorDescription == message }
    }

    static func main() async {
        do {
            var command = try parseAsRoot()
            if var asyncCommand = command as? any AsyncParsableCommand { try await asyncCommand.run() }
            else { try command.run() }
        } catch let code as ExitCode {
            exit(withError: code)
        } catch let error as CompoundFieldFailure {
            IO.diagnostic("2ndpass: \(error.errorDescription ?? "Invalid structured field.")\n")
            exit(withError: ExitCode(1))
        } catch let error as AttachmentFailure {
            IO.diagnostic("2ndpass: \(error.errorDescription ?? "Attachment operation failed.")\n")
            exit(withError: ExitCode(1))
        } catch let error as ImportFailure {
            IO.diagnostic("2ndpass: \(error.errorDescription ?? "Import failed.")\n")
            exit(withError: ExitCode(1))
        } catch let error as MopError {
            IO.diagnostic("2ndpass: \(error.errorDescription ?? "Operation failed.")\n")
            exit(withError: ExitCode(error.exitCode))
        } catch {
            if exitCode(for: error) == .success { exit(withError: error) }
            if let known = knownValidationError(error) {
                IO.diagnostic("2ndpass: \(known.errorDescription!)\n")
                exit(withError: ExitCode(known.exitCode))
            }
            // Parser diagnostics can echo unexpected arguments. Do not accidentally
            // reveal a secret supplied as an unsupported positional argument.
            IO.diagnostic("2ndpass: Invalid command arguments. Use '2ndpass --help' or '2ndpass <command> --help'.\n")
            exit(withError: ExitCode(2))
        }
    }

}

struct Read: AsyncParsableCommand {
    @OptionGroup var storage: VaultOptions
    static let configuration = CommandConfiguration(abstract: "Read one secret field.")
    @Argument(help: "A secondpass://vault/item/[section/]field reference.") var reference: String
    @OptionGroup var output: OutputOptions
    @Flag(name: [.short, .long], help: "Do not append a newline.") var noNewline = false

    func run() async throws {
        let destination = try output.destination(storage: storage)
        let value = try await storage.service.read(SecretReference(reference))
        try output.emit(value + (noNewline ? SecretBytes(utf8: "") : SecretBytes(utf8: "\n")), to: destination)
    }
}

struct Write: AsyncParsableCommand {
    @OptionGroup var storage: VaultOptions
    static let configuration = CommandConfiguration(abstract: "Create a field from a hidden prompt or UTF-8 stdin.")
    @Argument var reference: String
    @Flag(help: "Replace an existing field; fails if it does not exist.") var replace = false

    func run() async throws {
        try storage.requireOnline()
        let reference = try SecretReference(reference)
        let value = try IO.secret()
        try await storage.service.write(reference, value: value, replace: replace)
    }
}

struct List: AsyncParsableCommand {
    @OptionGroup var storage: VaultOptions
    static let configuration = CommandConfiguration(abstract: "List references without secret values.")
    @Flag(help: "Output a JSON array of reference strings.") var json = false

    func run() async throws {
        let references = try await storage.service.list(vault: storage.selection).map(\.description)
        if json {
            let data = try JSONEncoder().encode(references)
            try IO.output(String(decoding: data, as: UTF8.self) + "\n")
        } else {
            try IO.output(references.isEmpty ? "" : references.joined(separator: "\n") + "\n")
        }
    }
}

struct Delete: AsyncParsableCommand {
    @OptionGroup var storage: VaultOptions
    static let configuration = CommandConfiguration(abstract: "Delete exactly one field after authentication.")
    @Argument var reference: String

    func run() async throws { try storage.requireOnline(); try await storage.service.delete(SecretReference(reference)) }
}

struct Run: AsyncParsableCommand {
    @OptionGroup var storage: VaultOptions
    static let configuration = CommandConfiguration(
        abstract: "Resolve environment references and execute a command. Resolved secrets are masked on stdout and stderr by default.",
        discussion: "Usage: 2ndpass run [--env-file FILE] -- COMMAND [ARGS...]. Later dotenv files override earlier files and inherited variables."
    )
    @Option(help: "Literal dotenv file. May be repeated.", completion: .file()) var envFile: [String] = []
    @Flag(help: "Disable output masking and preserve direct execution and terminal behavior.") var noMasking = false
    @Argument(parsing: .postTerminator, help: "Command and arguments after --; no implicit shell.") var command: [String] = []

    func run() async throws {
        try Execute.validate(command)
        func executeResolved() async throws -> Int32 {
            let files = try envFile.map { try IO.input(file: $0) }
            let environment = try await storage.service.resolvedEnvironment(inherited: ProcessInfo.processInfo.environment, files: files)
            if noMasking { try Execute.run(command, environment: environment.variables) }
            return try MaskedExecute.execute(command, environment: environment.variables, secrets: environment.secrets)
        }
        // Release owned plaintext before exit(), which does not unwind Swift scopes.
        let status = try await executeResolved()
        MaskedExecute.exitWithStatus(status)
    }
}

struct Inject: AsyncParsableCommand {
    @OptionGroup var storage: VaultOptions
    static let configuration = CommandConfiguration(abstract: "Resolve {{ secondpass://vault/item/[section/]field }} placeholders.")
    @OptionGroup var output: OutputOptions
    @Option(name: [.short, .long], help: "Read a UTF-8 template file instead of stdin.", completion: .file()) var inFile: String?

    func run() async throws {
        let destination = try output.destination(storage: storage)
        let result = try await storage.service.inject(IO.input(file: inFile), variables: ProcessInfo.processInfo.environment)
        try output.emit(result, to: destination)
    }
}

struct Item: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "List typed items or atomically save an item from JSON stdin.", subcommands: [Catalog.self, Save.self, Import.self, Attachments.self])
    struct Catalog: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        func run() async throws {
            let store = try await storage.open(); defer { store.close() }
            try IO.output(String(decoding: JSONEncoder().encode(await store.catalog()), as: UTF8.self) + "\n")
        }
    }
    struct Save: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        func run() async throws {
            try storage.requireOnline()
            let input = try IO.secret()
            let edit = try input.withFoundationData { try JSONDecoder().decode(ItemEdit.self, from: $0) }
            let store = try await storage.open(); defer { store.close() }
            try await store.saveItem(edit)
            try IO.output(String(decoding: JSONEncoder().encode(await store.catalog()), as: UTF8.self) + "\n")
        }
    }
}
