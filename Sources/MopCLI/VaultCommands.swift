import MopLocalIdentity
import ArgumentParser
import Foundation
import MopCore
import MopVaultNext
import MopAppSupport

enum PortableBackupInputFailure: Error, Equatable {
    case archiveMissing, keyMissing
    var message: String {
        switch self {
        case .archiveMissing: "Portable archive file not found. Supply the path to the exported .moparchive file."
        case .keyMissing: "Backup key file not found. Supply its saved path with --key-file."
        }
    }
}

private func readPortableBackupInput(_ path: String, key: Bool = false) throws -> Data {
    do { return try LocalFile.read(URL(fileURLWithPath: path), limit: key ? 4096 : PortableArchive.maximumSize) }
    catch MopError.vaultMissing {
        throw key ? PortableBackupInputFailure.keyMissing : PortableBackupInputFailure.archiveMissing
    }
}

struct CloudConfirmationPending: Error {
    let mutationIDs: [UUID]
    var message: String {
        "Saved locally; iCloud confirmation is pending. Do not repeat the write. Run sp vault sync to retry delivery."
        + (mutationIDs.isEmpty ? "" : " Mutation receipts: " + mutationIDs.map(\.uuidString).joined(separator: ", "))
    }
}
private func requireCloudConfirmation(_ result: VaultResult) throws -> VaultResult {
    if result.saveStatus == .pending { throw CloudConfirmationPending(mutationIDs: result.mutationIDs) }
    return result
}

struct VaultOptions: ParsableArguments {
    @Option(help: "Vault name or UUID.") var vault: String?
    @Flag(help: "Read or edit the previously authenticated local vault inventory without network access.") var offline = false
    @Flag(help: "Return after the durable local save; do not wait for iCloud confirmation.") var localSave = false
    var stateURL: URL { AppStorageLocation.defaultState }
    var selection: String? { vault }
    func validate() throws { if let vault, UUID(uuidString: vault) == nil { try VaultName.validate(vault) } }
    func requireOnline() throws { try CloudVaultBoundary.requireCloud(vault); guard !offline else { throw MopError.offlineWrite } }
    func native() -> ItemVaultService {
        ItemVaultService(delivery: (localSave || offline) ? .local : .cloudConfirmed(timeout: .seconds(20)))
    }
    func execute(_ operation: VaultOperation, selection: String? = nil) async throws -> VaultResult {
        let service = native(); defer { service.lock() }
        return try requireCloudConfirmation(await service.execute(operation, vault: selection ?? vault, offline: offline))
    }
    func open() async throws -> CommandStore { CommandStore(options: self) }
    var service: AsyncSecretService { AsyncSecretService { CommandStore(options: self) } }
}

final class CommandStore: AsyncSecretStore {
    let options: VaultOptions
    let service: any VaultService
    private let usageStore: any ItemUsageStoring
    private var used: Set<ItemUsageIdentity> = []
    init(options: VaultOptions, service: (any VaultService)? = nil, usageStore: (any ItemUsageStoring)? = nil) {
        self.options = options; self.service = service ?? options.native()
        self.usageStore = usageStore ?? ItemUsageStore(state: options.stateURL)
    }
    func close() { service.lock() }
    func perform(_ operation: VaultOperation, reference: SecretReference? = nil) async throws -> VaultResult {
        try CloudVaultBoundary.requireCloud(options.vault)
        try CloudVaultBoundary.requireCloud(reference?.vault)
        return try requireCloudConfirmation(await service.execute(operation, vault: options.vault ?? reference?.vault, offline: options.offline))
    }
    func read(_ reference: SecretReference) async throws -> SecretBytes {
        let result = try await perform(.read(reference), reference: reference)
        guard let value = result.value else { throw MopError.notFound }
        if let identity = result.usageIdentity, used.insert(identity).inserted {
            await ItemUsageLogging.record([identity], store: usageStore)
        }
        return value
    }
    func write(_ reference: SecretReference, value: SecretBytes, replace: Bool) async throws { _ = try await perform(.write(reference, value, replace: replace), reference: reference) }
    func delete(_ reference: SecretReference) async throws { _ = try await perform(.delete(reference), reference: reference) }
    func catalog() async throws -> ItemCatalog { try await perform(.catalog).requireCatalog() }
    func saveItem(_ edit: ItemEdit) async throws { _ = try await perform(.save(edit)) }
    func list(vault: String?) async throws -> [SecretReference] {
        let result = try await service.execute(.discover, vault: nil, offline: options.offline)
        var references: [SecretReference] = []
        for row in result.vaults where vault == nil || row.name == vault || row.id == vault {
            let catalog = try await service.execute(.catalog, vault: row.id, offline: options.offline).requireCatalog()
            for item in catalog.items { for field in item.fields {
                references.append(try SecretReference(vault: catalog.vault, relativePath: SecretReference.encode(item.name) + "/" + field.path))
            } }
        }
        return references
    }
}
private func emit(_ result: VaultResult) throws {
    if let bytes = result.document { try IO.output(String(decoding: bytes, as: UTF8.self) + "\n"); IO.diagnostic(result.message + "\n") }
    else { try IO.output(result.message + "\n") }
}
private func readFile(_ path: String) throws -> Data { try LocalFile.read(URL(fileURLWithPath: path), limit: 24 * 1024 * 1024) }

struct Vault: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Manage hardware-protected personal and shared vaults.", subcommands: [Devices.self, Enrollment.self, Initialize.self, ListVaults.self, Sync.self, Rename.self, Export.self, Backup.self, RestoreBackup.self, Fingerprint.self, Members.self, Invite.self, Accept.self, Approve.self, RemoveMember.self, RemoveDevice.self, Role.self, Recovery.self, ReconcileShare.self, Import.self, DeleteVault.self])
    struct Devices: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List or remove devices across enrolled personal vaults.")
        @OptionGroup var storage: VaultOptions
        @Option(help: "Remove this device UUID. Omit to list devices.") var remove: String?
        func validate() throws {
            if let remove, UUID(uuidString: remove) == nil { throw MopError.invalidProcess }
        }
        func run() async throws { throw ItemVaultServiceFailure.unavailable }
    }

    struct Enrollment: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Manage own-device iCloud enrollment and explicit reconnection.")
        @OptionGroup var storage: VaultOptions
        @Argument(help: "request, restart, reconnect, cancel, status, confirm, inbox, approve, or decline") var action: String
        @Option var name = "New device"
        @Option var requestID: String?
        @Option var code: String?
        func validate() throws {
            guard ["request", "restart", "reconnect", "cancel", "status", "confirm", "inbox", "approve", "decline"].contains(action),
                  !["approve", "decline"].contains(action) || requestID.flatMap(UUID.init(uuidString:)) != nil,
                  !["approve", "confirm"].contains(action) || code != nil else { throw MopError.invalidProcess }
        }
        func run() async throws { throw ItemVaultServiceFailure.unavailable }
    }

    struct Initialize: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "init", abstract: "Create a vault on this device. Offline recovery is optional.")
        @OptionGroup var storage: VaultOptions
        @Argument var name: String
        func validate() throws { try VaultName.validate(name) }
        func run() async throws {
            try storage.requireOnline()
            let id = storage.vault ?? UUID().uuidString
            IO.diagnostic("sp: creation UUID \(id); retain it to reconcile an interrupted submission.\n")
            try emit(await storage.execute(.create(name: name), selection: id))
        }
    }
    struct ListVaults: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "list", abstract: "List trusted vaults and iCloud vaults needing device enrollment.")
        @OptionGroup var storage: VaultOptions
        @Flag var json = false
        func run() async throws {
            struct Row: Encodable { let id: String; let name: String?; let format: String; let kind: String }
            var rows = [Row(id: LocalVault.id, name: LocalVault.name, format: "device-local", kind: "local")]
            if storage.vault.map(LocalVault.isLocal) != true {
                do {
                    let result = try await storage.execute(.discover)
                    rows += result.vaults.map { Row(id: $0.id, name: $0.name, format: $0.format, kind: "cloud") }
                } catch { IO.diagnostic("Cloud vault discovery failed; local remains available: \(error)\n") }
            }
            if json { try IO.output(String(decoding: JSONEncoder().encode(rows), as: UTF8.self) + "\n") }
            else { for row in rows { try IO.output("\(row.name ?? "")\t\(row.id)\t\(row.format)\n") } }
        }
    }
    struct Sync: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Verify new revisions and reconcile uncertain writes; never replay a secret mutation.")
        @OptionGroup var storage: VaultOptions
        func run() async throws { try emit(await storage.execute(.sync)) }
    }
    struct Rename: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        @Argument var name: String
        func validate() throws { try VaultName.validate(name) }
        func run() async throws { try emit(await storage.execute(.rename(name))) }
    }
    struct Export: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        @Argument(completion: .file()) var file: String
        func run() async throws { try emit(await storage.execute(.export(URL(fileURLWithPath: file)))) }
    }
    struct Backup: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Export a portable encrypted archive and a separate generated key. Neither output is overwritten.")
        @OptionGroup var storage: VaultOptions
        @Argument(completion: .file()) var file: String
        @Option(help: "Separate destination for the generated backup key; protect this file like a password.", completion: .file()) var keyFile: String
        func run() async throws {
            let output = URL(fileURLWithPath: file).standardizedFileURL
            let keyURL = URL(fileURLWithPath: keyFile).standardizedFileURL
            guard output != keyURL, !FileManager.default.fileExists(atPath: output.path),
                  !FileManager.default.fileExists(atPath: keyURL.path) else { throw MopError.duplicate }
            let result = try await storage.execute(.exportPortable(output))
            guard let key = result.value else { throw MopError.invalidVault }
            do {
                try OutputFile(url: keyURL, force: false, mode: 0o600, protectedFiles: [output], protectedDirectories: [storage.stateURL]).write(key)
            } catch {
                IO.diagnostic("The archive was written, but its key could not be saved. It is not a usable backup. Keep the source vault and repeat with new output paths.\n")
                throw error
            }
            try IO.output(result.message + "\nKey saved separately to " + keyURL.path + "\n")
        }
    }
    struct RestoreBackup: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "restore-backup", abstract: "Restore a portable backup into a new owner-only vault. Reuse --restore-id to resume after an interruption.")
        @OptionGroup var storage: VaultOptions
        @Argument(completion: .file()) var file: String
        @Option(completion: .file()) var keyFile: String
        @Option(help: "Name for the new restored vault.") var name: String
        @Option(help: "Fresh destination UUID, retained for resumable restore.") var restoreID: String
        @Flag(help: "Validate the archive without creating a vault.") var dryRun = false
        func validate() throws {
            try VaultName.validate(name)
            guard UUID(uuidString: restoreID) != nil, storage.vault == nil else { throw MopError.invalidProcess }
        }
        func run() async throws {
            let data = try readPortableBackupInput(file)
            var keyData = try readPortableBackupInput(keyFile, key: true)
            defer { SecretBytes.wipe(&keyData) }
            let key = SecretBytes(copying: keyData)
            let archive = try PortableArchive.open(data, recoveryKey: key)
            if dryRun {
                try IO.output("Archive verified: \(archive.items.count) items, \(archive.records.count) current/history records. Destination: \(restoreID).\n")
                for exclusion in archive.exclusions { IO.diagnostic(exclusion + "\n") }
                return
            }
            try storage.requireOnline()
            IO.diagnostic("Restore destination: \(restoreID). Retain this UUID to resume an interrupted restore.\n")
            try emit(await storage.execute(.restorePortable(document: data, key: key, name: name), selection: restoreID))
        }
    }
    struct Fingerprint: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        func run() async throws { try emit(await storage.execute(.manage(.fingerprint))) }
    }
    struct Members: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        func run() async throws {
            for member in try await storage.execute(.members).members { try IO.output("\(member.id)\t\(member.role)\n") }
        }
    }
    struct Invite: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Verify a public device request and issue a one-day invitation. JSON on stdout; share URL/checkpoint on stderr.")
        @OptionGroup var storage: VaultOptions
        @Argument(completion: .file()) var request: String
        @Option var fingerprint: String
        @Option var role: String = "editor"
        func run() async throws {
            guard let role = MemberRole(rawValue: role) else { throw MopError.invalidProcess }
            try emit(await storage.execute(.manage(.invite(request: readFile(request), fingerprint: fingerprint, role: role))))
        }
    }
    struct Accept: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Accept an independently verified invitation; return acceptance JSON to the owner.")
        @OptionGroup var storage: VaultOptions
        @Argument(completion: .file()) var invitation: String
        @Option var checkpoint: String
        @Option var shareURL: String?
        func run() async throws { try emit(await storage.execute(.manage(.accept(packet: readFile(invitation), checkpoint: checkpoint, shareURL: shareURL.flatMap(URL.init(string:)))))) }
    }
    struct Approve: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Approve the exact accepted device and grant current secrets. Stale invitations must be reissued.")
        @OptionGroup var storage: VaultOptions
        @Argument(completion: .file()) var acceptance: String
        @Option var fingerprint: String
        func run() async throws { try emit(await storage.execute(.manage(.approve(packet: readFile(acceptance), fingerprint: fingerprint)))) }
    }
    struct RemoveMember: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        @Argument var member: String
        func run() async throws {
            guard let id = UUID(uuidString: member) else { throw MopError.invalidProcess }
            try emit(await storage.execute(.manage(.removeMember(id))))
        }
    }
    struct RemoveDevice: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        @Argument var device: String
        func run() async throws {
            guard let id = UUID(uuidString: device) else { throw MopError.invalidProcess }
            try emit(await storage.execute(.manage(.removeDevice(id))))
        }
    }
    struct Role: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        @Argument var member: String
        @Argument var role: String
        func run() async throws {
            guard let id = UUID(uuidString: member), let role = MemberRole(rawValue: role) else { throw MopError.invalidProcess }
            try emit(await storage.execute(.manage(.role(id, role))))
        }
    }
    struct Recovery: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "recovery", abstract: "Manage the account's offline recovery key or recover after device loss.", subcommands: [Generate.self, Activate.self, Status.self, Resume.self, Revoke.self, Open.self])
        struct Generate: AsyncParsableCommand {
            @OptionGroup var storage: VaultOptions
            @Option(help: "New recovery file path. Store offline; existing files are never replaced.", completion: .file()) var output: String
            func run() async throws {
                try storage.requireOnline()
                let result = try await storage.execute(.manage(.recoveryGenerate))
                guard let file = result.recoveryFile else { throw MopError.invalidRecovery }
                try file.withFoundationData { try LocalFile.write($0, to: URL(fileURLWithPath: output)) }
                try IO.output("Saved recovery copy. Public fingerprint: " + (result.recoveryFingerprint ?? "") + "\nRe-import with recovery activate before relying on it.\n")
            }
        }
        struct Activate: AsyncParsableCommand {
            @OptionGroup var storage: VaultOptions
            @Option(completion: .file()) var file: String
            @Option(help: "Public fingerprint displayed when the copy was generated.") var fingerprint: String
            func run() async throws {
                try storage.requireOnline()
                try emit(await storage.execute(.manage(.recoveryActivate(copy: Recovery.read(file), fingerprint: fingerprint))))
            }
        }
        struct Status: AsyncParsableCommand {
            @OptionGroup var storage: VaultOptions
            func run() async throws {
                try storage.requireOnline()
                let result = try await storage.execute(.manage(.recoveryStatus))
                if let configuration = result.recoveryConfiguration { try IO.output(String(decoding: JSONEncoder().encode(configuration), as: UTF8.self) + "\n") }
            }
        }
        struct Resume: AsyncParsableCommand {
            @OptionGroup var storage: VaultOptions
            func run() async throws { try storage.requireOnline(); try emit(await storage.execute(.manage(.recoveryResume))) }
        }
        struct Revoke: AsyncParsableCommand {
            @OptionGroup var storage: VaultOptions
            func run() async throws { try storage.requireOnline(); try emit(await storage.execute(.manage(.recoveryRevoke))) }
        }
        struct Open: AsyncParsableCommand {
            @OptionGroup var storage: VaultOptions
            @Option(help: "Offline recovery file or paper-code file.", completion: .file()) var file: String
            @Option(help: "Read a relative field path without completing recovery.") var read: String?
            @Option(help: "Write a recovered field or attachment to a new file.", completion: .file()) var output: String?
            @Flag(help: "Complete recovery and rotate access for selected or all matching vaults.") var complete = false
            func validate() throws { guard !(complete && read != nil), output == nil || read != nil else { throw MopError.invalidProcess } }
            func run() async throws {
                try storage.requireOnline()
                let service = storage.native(); defer { service.lock() }
                let opened = try await service.execute(.manage(.recoveryOpen(copy: Recovery.read(file))), vault: nil)
                let selected = opened.vaults.filter { storage.vault == nil || $0.id == storage.vault || $0.name == storage.vault }
                guard !selected.isEmpty, read == nil || selected.count == 1 else { throw MopError.ambiguousVault }
                for vault in selected {
                    guard let id = UUID(uuidString: vault.id) else { throw MopError.invalidVault }
                    if let read {
                        let result = try await service.execute(.manage(.recoveryRead(id, read)), vault: nil)
                        let value = result.value ?? result.recoveredAttachment.map { SecretBytes(copying: $0.data) }
                        guard let value else { throw MopError.notFound }
                        if let output { try value.withFoundationData { try LocalFile.write($0, to: URL(fileURLWithPath: output)) } }
                        else { try value.write(descriptor: STDOUT_FILENO) }
                    } else if complete {
                        try emit(await service.execute(.manage(.recoveryComplete(id)), vault: nil))
                    } else {
                        try IO.output(vault.id + " " + (vault.name ?? vault.id) + " (read-only; existing devices and accounts keep access)\n")
                        let result = try await service.execute(.manage(.recoveryCatalog(id)), vault: nil)
                        for item in result.catalog?.items ?? [] { for field in item.fields { try IO.output(SecretReference.encode(item.name) + "/" + field.path + "\n") } }
                    }
                }
                for status in opened.recoveryVaults where status.issue != nil { IO.diagnostic(status.id.uuidString + ": " + status.issue! + "\n") }
            }
        }
        private static func read(_ path: String) throws -> SecretBytes {
            var bytes = try LocalFile.read(URL(fileURLWithPath: path), limit: 8192)
            defer { SecretBytes.wipe(&bytes) }
            return SecretBytes(copying: bytes)
        }
    }
    struct ReconcileShare: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Retry cloud participant permissions after a committed roster change.")
        @OptionGroup var storage: VaultOptions
        func run() async throws { try emit(await storage.execute(.manage(.reconcileShare))) }
    }
    struct Import: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Trust an independently verified v7 checkpoint for an already enrolled device; never converts old formats.")
        @OptionGroup var storage: VaultOptions
        @Argument(completion: .file()) var file: String
        @Option var checkpoint: String
        @Option(help: "Actual zone owner record name for a shared database vault; omit for your own private vault.") var sharedOwner: String?
        func run() async throws { throw ItemVaultServiceFailure.unavailable }
    }
    struct DeleteVault: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "delete", abstract: "Delete the selected cloud vault. Backups and local ciphertext remain.")
        @OptionGroup var storage: VaultOptions
        @Option(help: "Repeat the exact vault UUID to confirm deletion.") var confirm: String
        func run() async throws {
            guard let selected = storage.vault, UUID(uuidString: selected) != nil, confirm == selected else { throw MopError.confirmationRequired }
            try emit(await storage.execute(.deleteVault))
        }
    }
}
