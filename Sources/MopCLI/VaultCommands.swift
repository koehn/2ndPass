import ArgumentParser
import Foundation
import MopCore
import MopVault
import MopKeychain
import MopCloudKit

struct VaultOptions: ParsableArguments {
    @Option(help: "Independent CloudKit vault UUID; defaults to MOP_CLOUD_VAULT or the saved account default.") var cloudVault: String?
    @Option(help: "Local state directory; defaults to MOP_STATE_DIRECTORY or ~/.mop. Never synchronize this directory.", completion: .directory) var stateDirectory: String?
    @Flag(help: "Explicitly use a previously verified encrypted cache for read-only commands.") var offline = false
    @Option(help: .hidden) var vaultFile: String?

    var stateURL: URL {
        URL(fileURLWithPath: stateDirectory ?? ProcessInfo.processInfo.environment["MOP_STATE_DIRECTORY"] ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".mop").path, isDirectory: true).standardizedFileURL
    }
    var selection: String? { cloudVault ?? ProcessInfo.processInfo.environment["MOP_CLOUD_VAULT"] }
    func validate() throws {
        guard vaultFile == nil, ProcessInfo.processInfo.environment["MOP_VAULT_FILE"] == nil else { throw MopError.fileMigration }
        if let selection { guard UUID(uuidString: selection) != nil else { throw MopError.invalidProcess } }
    }
    func requireOnline() throws { guard !offline else { throw MopError.offlineWrite } }
    func repository() async throws -> CloudRepository {
        try validate()
        let config = try SigningIdentity.cloudConfiguration()
        return try await CloudRepository.open(transport: AppleCloudTransport(container: config.container, environment: config.environment), state: stateURL, offline: offline)
    }
    func selected() async throws -> (CloudRepository, CloudVault) {
        let repository = try await repository()
        return (repository, try repository.selected(selection))
    }
    func snapshot(_ vault: CloudVault) async throws -> Data {
        if offline {
            let (bytes, date) = try vault.cached()
            IO.diagnostic("mop: offline cache from \(ISO8601DateFormatter().string(from: date)); remote revocation cannot be checked.\n")
            return bytes
        }
        return try await vault.sync()
    }
    func open() async throws -> CloudSecretStore {
        let (_, vault) = try await selected()
        let bytes = try await snapshot(vault)
        let device = try LocalDevice.open(directory: stateURL)
        do { return try CloudSecretStore(vault: vault, snapshot: bytes, opener: device, offline: offline, onClose: { device.close() }) }
        catch { device.close(); throw error }
    }
    var service: AsyncSecretService { AsyncSecretService { try await self.open() } }
}

private func validateEvidence(_ fingerprint: String?, _ revision: String?, required: Bool = false) throws {
    if required || fingerprint != nil || revision != nil {
        guard (fingerprint == nil) != (revision == nil), VaultTrust.validFingerprint(fingerprint ?? revision ?? "") else { throw MopError.invalidProcess }
    }
}

private func outputJSON<T: Encodable>(_ value: T) throws { try IO.output(String(decoding: VaultCoding.encode(value), as: UTF8.self) + "\n") }

struct Vault: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Manage encrypted CloudKit vaults and backups.", subcommands: [Initialize.self, ListVaults.self, Use.self, Sync.self, Status.self, Import.self, Export.self, Recover.self, Conflicts.self, Resolve.self, Trust.self, Fingerprint.self])

    struct Initialize: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "init", abstract: "Create a CloudKit vault and an offline recovery credential.")
        @OptionGroup var storage: VaultOptions
        @Option(completion: .file()) var recoveryFile: String
        @Option var name: String = "Mac"
        @Flag var strictBiometrics = false
        func run() async throws {
            try storage.requireOnline()
            let repo = try await storage.repository()
            let recoveryURL = URL(fileURLWithPath: recoveryFile).standardizedFileURL
            _ = try OutputFile(url: recoveryURL, force: false, mode: 0o600, protectedFiles: [], protectedDirectories: [storage.stateURL])
            let device = try LocalDevice.open(directory: storage.stateURL, create: true, name: name, strictBiometrics: strictBiometrics ? true : nil)
            defer { device.close() }
            let recovery = RecoveryKey()
            try recovery.save(to: recoveryURL)
            let id = storage.selection.flatMap(UUID.init(uuidString:)) ?? UUID()
            let bytes = try FileSecretStore.createSnapshot(id: id, device: device.request, recovery: recovery)
            let doc = try VaultDocument.decode(bytes)
            let slot = doc.header.recipients.first { $0.publicKey == device.publicKey }!
            let fingerprint = try VaultTrust.fingerprint(document: doc, key: device.unwrap(slot, vaultID: id))
            // Recovery was written first and is retained on every later failure.
            IO.diagnostic("mop: initializing cloud vault \(id.uuidString); use this UUID to reconcile an interrupted creation.\n")
            let vault = try await repo.create(bytes, fingerprint: fingerprint)
            let store = try CloudSecretStore(vault: vault, snapshot: bytes, opener: device)
            defer { store.close() }
            try IO.output("Vault created: \(id.uuidString)\nMove the recovery credential offline.\nDevice fingerprint: \(device.request.fingerprint)\nVault fingerprint: \(fingerprint)\n")
        }
    }
    struct ListVaults: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "list", abstract: "List independent CloudKit vault UUIDs.")
        @OptionGroup var storage: VaultOptions
        func run() async throws { try storage.requireOnline(); let repo = try await storage.repository(); try outputJSON(try await repo.list().map(\.uuidString)) }
    }
    struct Use: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Save the default vault for this iCloud account.")
        @OptionGroup var storage: VaultOptions
        @Argument var uuid: String
        func run() async throws {
            try storage.requireOnline()
            guard let id = UUID(uuidString: uuid) else { throw MopError.invalidProcess }
            let repo = try await storage.repository()
            let vault = try repo.vault(id)
            _ = try await vault.sync()
            try repo.use(id)
            try IO.output("Default vault: \(id.uuidString)\n")
        }
    }
    struct Sync: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Fetch ciphertext and reconcile interrupted commits without unlocking secrets.")
        @OptionGroup var storage: VaultOptions
        func run() async throws {
            try storage.requireOnline()
            let (_, vault) = try await storage.selected()
            _ = try await vault.sync()
            try outputJSON(vault.status())
        }
    }
    struct Status: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Report cached state and incomplete operations without unlocking secrets.")
        @OptionGroup var storage: VaultOptions
        func run() async throws {
            try storage.requireOnline()
            let (_, vault) = try await storage.selected()
            try outputJSON(vault.status())
        }
    }
    struct Import: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "import", abstract: "Verify and import a v3 encrypted file into an absent CloudKit vault.")
        @OptionGroup var storage: VaultOptions
        @Option(completion: .file()) var file: String
        @Option(completion: .file()) var recoveryFile: String?
        @Option var name: String = "Recovered Mac"
        @Flag var strictBiometrics = false
        @Option var fingerprint: String?
        @Option var revision: String?
        func validate() throws { try validateEvidence(fingerprint, revision) }
        func run() async throws {
            try storage.requireOnline()
            let repo = try await storage.repository()
            let source = URL(fileURLWithPath: file)
            let bytes = try SafeFile.read(source)
            let doc = try VaultDocument.decode(bytes)
            if let selection = storage.selection { guard UUID(uuidString: selection) == doc.header.vaultID else { throw MopError.invalidVault } }
            let device = try LocalDevice.open(directory: storage.stateURL, create: recoveryFile != nil, name: name, strictBiometrics: strictBiometrics ? true : nil)
            defer { device.close() }
            let recovery = try recoveryFile.map { try RecoveryKey(file: URL(fileURLWithPath: $0)) }
            let opener: any VaultKeyOpener = recovery.map { $0 as any VaultKeyOpener } ?? device
            // Use the existing path's local trust; independent evidence may establish it.
            let disk = VaultDisk(url: source, trustDirectory: storage.stateURL.appendingPathComponent("trust"))
            if fingerprint != nil || revision != nil { try FileSecretStore.trustSnapshot(bytes, trust: disk.trust, opener: opener, fingerprint: fingerprint, revision: revision) }
            let original = try FileSecretStore(snapshot: bytes, trust: disk.trust, opener: opener)
            defer { original.close() }
            // Canonicalize legacy serialization so content addressing is deterministic.
            if recovery != nil && !doc.header.recipients.contains(where: { $0.publicKey == device.publicKey }) {
                try original.enroll(device.request, expectedFingerprint: device.request.fingerprint)
            }
            let canonical = try VaultCoding.encode(VaultDocument.decode(original.snapshot))
            IO.diagnostic("mop: importing cloud vault \(doc.header.vaultID.uuidString).\n")
            let vault = try await repo.create(canonical, fingerprint: original.fingerprint())
            let imported = try CloudSecretStore(vault: vault, snapshot: canonical, opener: device)
            defer { imported.close() }
            try IO.output("Imported vault: \(vault.id.uuidString). Source file retained.\n")
        }
    }
    struct Export: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "export", abstract: "Export a verified encrypted v3 backup.")
        @OptionGroup var storage: VaultOptions
        @Option(completion: .file()) var outFile: String
        @Flag var force = false
        func run() async throws {
            let out = try OutputFile(url: URL(fileURLWithPath: outFile), force: force, mode: 0o600, protectedFiles: [], protectedDirectories: [storage.stateURL])
            let store = try await storage.open()
            defer { store.close() }
            try out.write(store.snapshot)
        }
    }
    struct Trust: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Trust a vault using independently obtained fingerprint or backup revision evidence.")
        @OptionGroup var storage: VaultOptions
        @Option var fingerprint: String?
        @Option var revision: String?
        func validate() throws { try validateEvidence(fingerprint, revision, required: true) }
        func run() async throws {
            try storage.requireOnline()
            let (_, vault) = try await storage.selected()
            let bytes = try await vault.sync()
            let device = try LocalDevice.open(directory: storage.stateURL)
            defer { device.close() }
            try vault.establishTrust(bytes, opener: device, fingerprint: fingerprint, revision: revision)
            try IO.output("Vault key trusted for this account and vault.\n")
        }
    }
    struct Fingerprint: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show the authenticated vault fingerprint.")
        @OptionGroup var storage: VaultOptions
        func run() async throws { try storage.requireOnline(); let store = try await storage.open(); defer { store.close() }; try IO.output(store.fingerprint() + "\n") }
    }
    struct Recover: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Enroll this Mac using an offline recovery credential and independent trust evidence.")
        @OptionGroup var storage: VaultOptions
        @Option(completion: .file()) var recoveryFile: String
        @Option var name: String = "Mac"
        @Flag var strictBiometrics = false
        @Option var fingerprint: String?
        @Option var revision: String?
        func validate() throws { try validateEvidence(fingerprint, revision) }
        func run() async throws {
            try storage.requireOnline()
            let (_, vault) = try await storage.selected()
            let bytes = try await vault.sync()
            let recovery = try RecoveryKey(file: URL(fileURLWithPath: recoveryFile))
            let device = try LocalDevice.open(directory: storage.stateURL, create: true, name: name, strictBiometrics: strictBiometrics ? true : nil)
            defer { device.close() }
            if fingerprint != nil || revision != nil { try vault.establishTrust(bytes, opener: recovery, fingerprint: fingerprint, revision: revision) }
            let store = try CloudSecretStore(vault: vault, snapshot: bytes, opener: recovery)
            defer { store.close() }
            try await store.enroll(device.request, fingerprint: device.request.fingerprint)
            try IO.output("This Mac is enrolled. Return the recovery credential offline.\n")
        }
    }
    struct Conflicts: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List committed encrypted revision hashes, newest first.")
        @OptionGroup var storage: VaultOptions
        func run() async throws { try storage.requireOnline(); let (_, vault) = try await storage.selected(); try IO.output(try await vault.revisions().joined(separator: "\n") + "\n") }
    }
    struct Resolve: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Restore historical contents under current device authorization.")
        @OptionGroup var storage: VaultOptions
        @Option var revision: String
        func run() async throws {
            try storage.requireOnline()
            let store = try await storage.open(); defer { store.close() }
            try await store.restore(revision)
            try IO.output("Historical contents restored under current authorization.\n")
        }
    }
}

struct Device: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Enroll and revoke Secure Enclave devices through CloudKit.", subcommands: [Identity.self, Request.self, Requests.self, Add.self, Devices.self, Remove.self])
    struct Identity: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Verify application signing and the private Keychain group.")
        func run() throws { try IO.output(SigningIdentity.accessGroup() + "\n") }
    }
    struct Request: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Publish this Mac's public enrollment request.")
        @OptionGroup var storage: VaultOptions
        @Option var name: String = "Mac"
        @Flag var strictBiometrics = false
        func run() async throws {
            try storage.requireOnline()
            let (repo, vault) = try await storage.selected()
            let device = try LocalDevice.open(directory: storage.stateURL, create: true, name: name, strictBiometrics: strictBiometrics ? true : nil)
            defer { device.close() }
            let id = try await repo.request(device.request, vault: vault)
            try IO.output("Request: \(id)\nCompare on the authorizing Mac: \(device.request.fingerprint)\n")
        }
    }
    struct Requests: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List public enrollment requests; these are not trust evidence.")
        @OptionGroup var storage: VaultOptions
        func run() async throws {
            try storage.requireOnline()
            let (repo, vault) = try await storage.selected()
            var rows: [[String: String]] = []
            for id in try await repo.transport.requests(vault: vault.id) {
                let request = try await repo.request(id, vault: vault)
                rows.append(["request": id, "name": request.name, "fingerprint": request.fingerprint])
            }
            try outputJSON(rows)
        }
    }
    struct Add: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Approve a request after independently comparing its fingerprint.")
        @OptionGroup var storage: VaultOptions
        @Argument var requestID: String
        @Option var fingerprint: String
        func run() async throws {
            try storage.requireOnline()
            let (repo, vault) = try await storage.selected()
            let request = try await repo.request(requestID, vault: vault)
            guard request.fingerprint == fingerprint else { throw MopError.invalidDevice }
            let store = try await storage.open(); defer { store.close() }
            try await store.enroll(request, fingerprint: fingerprint)
            try IO.output("Device enrolled. Independently verify this vault fingerprint on the new Mac:\n\(try store.fingerprint())\n")
        }
    }
    struct Devices: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "list", abstract: "List authorized devices after authentication.")
        @OptionGroup var storage: VaultOptions
        func run() async throws {
            try storage.requireOnline(); let store = try await storage.open(); defer { store.close() }
            try outputJSON(store.recipients().map { ["name": $0.name, "fingerprint": $0.fingerprint] })
        }
    }
    struct Remove: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Remove another device and rotate all encryption keys.")
        @OptionGroup var storage: VaultOptions
        @Argument var fingerprint: String
        func run() async throws {
            try storage.requireOnline()
            let (_, vault) = try await storage.selected()
            let bytes = try await vault.sync()
            let device = try LocalDevice.open(directory: storage.stateURL); defer { device.close() }
            let store = try CloudSecretStore(vault: vault, snapshot: bytes, opener: device); defer { store.close() }
            try await store.revoke(fingerprint, currentDevice: device.publicKey)
            try IO.output("Device removed; historical copies remain decryptable. Independently verify the new fingerprint on remaining Macs:\n\(try store.fingerprint())\n")
        }
    }
}
