import ArgumentParser
import Foundation
import MopCore
import MopVault

struct VaultOptions: ParsableArguments {
    @Option(help: "Encrypted vault path; defaults to MOP_VAULT_FILE or ~/.mop/.mopfile.", completion: .file()) var vaultFile: String?
    @Option(help: "Local device-key directory; defaults to MOP_STATE_DIRECTORY or ~/.mop. Never sync this directory.", completion: .directory) var stateDirectory: String?

    var stateURL: URL {
        if let path = stateDirectory ?? ProcessInfo.processInfo.environment["MOP_STATE_DIRECTORY"] {
            return URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL
        }
        return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".mop", isDirectory: true)
    }
    var fileURL: URL {
        if let path = vaultFile ?? ProcessInfo.processInfo.environment["MOP_VAULT_FILE"] {
            return URL(fileURLWithPath: path).standardizedFileURL
        }
        return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".mop/.mopfile")
    }
    var disk: VaultDisk { VaultDisk(url: fileURL, trustDirectory: stateURL.appendingPathComponent("trust")) }
    var service: SecretService { SecretService { try self.open() } }

    func open() throws -> FileSecretStore { try FileSecretStore.open(file: fileURL, stateDirectory: stateURL) }
}

struct Vault: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Initialize, recover, or resolve vault revisions.",
                                                     subcommands: [Initialize.self, Recover.self, Conflicts.self, Resolve.self, Trust.self, Fingerprint.self])

    struct Initialize: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "init", abstract: "Create an encrypted vault and an exclusive, owner-only recovery file.")
        @OptionGroup var storage: VaultOptions
        @Option(help: "New recovery file path. Move it to offline storage; never sync it alongside the vault.", completion: .file()) var recoveryFile: String
        @Option(help: "Name for this device when first created.") var name: String = "Mac"

        func run() throws {
            let recoveryURL = URL(fileURLWithPath: recoveryFile).standardizedFileURL
            guard recoveryURL != storage.fileURL,
                  recoveryURL != storage.stateURL.appendingPathComponent("device.json") else { throw MopError.invalidRecovery }
            guard !FileManager.default.fileExists(atPath: storage.fileURL.path),
                  !FileManager.default.fileExists(atPath: recoveryURL.path) else { throw MopError.duplicate }
            do {
                try FileManager.default.createDirectory(at: storage.fileURL.deletingLastPathComponent(), withIntermediateDirectories: true,
                                                         attributes: [.posixPermissions: 0o700])
            } catch { throw MopError.inputOutput }
            let device = try LocalDevice.open(directory: storage.stateURL, create: true, name: name)
            defer { device.close() }
            let recovery = RecoveryKey()
            // Save recovery first. On a later failure keep it; never leave a vault
            // whose only recovery copy was discarded during an ambiguous write.
            try recovery.save(to: recoveryURL)
            let fingerprint = try FileSecretStore.initialize(disk: storage.disk, device: device.request, recovery: recovery)
            try IO.output("Vault created. Move the recovery file to offline storage.\nDevice fingerprint: \(device.request.fingerprint)\nVault fingerprint: \(fingerprint)\n")
        }
    }

    struct Recover: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Use the offline recovery key to enroll this Mac. Requires local authentication.")
        @OptionGroup var storage: VaultOptions
        @Option(completion: .file()) var recoveryFile: String
        @Option var name: String = "Mac"
        @Option(help: "Vault fingerprint obtained from a trusted Mac.") var fingerprint: String?
        @Option(help: "SHA-256 of a known-good vault backup, obtained independently.") var revision: String?

        func validate() throws {
            if fingerprint != nil || revision != nil {
                guard (fingerprint == nil) != (revision == nil),
                      VaultTrust.validFingerprint(fingerprint ?? revision ?? "") else { throw MopError.invalidProcess }
            }
        }

        func run() throws {
            let disk = storage.disk
            let bytes = try disk.read()
            let recovery = try RecoveryKey(file: URL(fileURLWithPath: recoveryFile))
            let device = try LocalDevice.open(directory: storage.stateURL, create: true, name: name)
            defer { device.close() }
            if fingerprint != nil || revision != nil {
                try FileSecretStore.establishTrust(disk: disk, opener: recovery, fingerprint: fingerprint, revision: revision)
            }
            let store: FileSecretStore
            do { store = try FileSecretStore(disk: disk, snapshot: bytes, opener: recovery) }
            catch MopError.deviceNotEnrolled { throw MopError.invalidRecovery }
            defer { store.close() }
            try store.enroll(device.request, expectedFingerprint: device.request.fingerprint)
            try IO.output("This device is enrolled. Return the recovery file to offline storage.\n")
        }
    }

    struct Trust: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Trust a vault key using independently verified evidence.",
            discussion: "Use a vault fingerprint from an already trusted Mac. For migration, use the SHA-256 of a known-good backup. Never obtain the evidence solely from the file you are trying to verify.")
        @OptionGroup var storage: VaultOptions
        @Option(help: "Vault fingerprint obtained from a trusted Mac.") var fingerprint: String?
        @Option(help: "SHA-256 of a known-good vault backup, obtained independently.") var revision: String?

        func validate() throws {
            guard (fingerprint == nil) != (revision == nil),
                  VaultTrust.validFingerprint(fingerprint ?? revision ?? "") else { throw MopError.invalidProcess }
        }

        func run() throws {
            let device = try LocalDevice.open(directory: storage.stateURL)
            defer { device.close() }
            try FileSecretStore.establishTrust(disk: storage.disk, opener: device, fingerprint: fingerprint, revision: revision)
            try IO.output("Vault key trusted for this local path.\n")
        }
    }

    struct Fingerprint: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show the vault fingerprint after verifying local trust and authenticating.")
        @OptionGroup var storage: VaultOptions

        func run() throws {
            let store = try storage.open()
            defer { store.close() }
            try IO.output(store.fingerprint() + "\n")
        }
    }

    struct Conflicts: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Preserve known conflicting file versions and list encrypted revision hashes.")
        @OptionGroup var storage: VaultOptions

        func run() throws {
            let revisions = try storage.disk.revisions()
            try IO.output(revisions.joined(separator: "\n") + "\n")
        }
    }

    struct Resolve: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Restore selected revision contents while retaining the current device authorization list.")
        @OptionGroup var storage: VaultOptions
        @Option(help: "Full encrypted revision hash from 'mop vault conflicts'.") var revision: String

        func run() throws {
            let disk = storage.disk
            _ = try disk.revision(revision)
            let device = try LocalDevice.open(directory: storage.stateURL)
            defer { device.close() }
            try FileSecretStore.resolve(disk: disk, revision: revision, opener: device)
            try IO.output("Selected contents restored. Prior encrypted revisions are preserved.\n")
        }
    }
}

struct Device: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Enroll or revoke Secure Enclave devices.",
                                                     subcommands: [Request.self, Add.self, Devices.self, Remove.self])

    struct Request: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Create or unlock this Mac's key and export a public enrollment request.")
        @OptionGroup var storage: VaultOptions
        @Option(help: "New public request file path.", completion: .file()) var out: String
        @Option var name: String = "Mac"

        func run() throws {
            let device = try LocalDevice.open(directory: storage.stateURL, create: true, name: name)
            defer { device.close() }
            try SafeFile.write(VaultCoding.encode(device.request), to: URL(fileURLWithPath: out))
            try IO.output("Compare this fingerprint on the authorizing Mac:\n\(device.request.fingerprint)\n")
        }
    }

    struct Add: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Authorize a device after comparing its fingerprint through a trusted channel.")
        @OptionGroup var storage: VaultOptions
        @Option(completion: .file()) var request: String
        @Option(help: "Full SHA-256 fingerprint displayed by the new Mac; compare outside the request file.") var fingerprint: String

        func run() throws {
            let value: DeviceRequest
            do { value = try JSONDecoder().decode(DeviceRequest.self, from: SafeFile.read(URL(fileURLWithPath: request), limit: 4096)) }
            catch { throw MopError.invalidDevice }
            try value.validate()
            guard value.fingerprint == fingerprint else { throw MopError.invalidDevice }
            let store = try storage.open()
            defer { store.close() }
            try store.enroll(value, expectedFingerprint: fingerprint)
            try IO.output("Device enrolled. Wait for the updated vault file to sync on the other Mac.\n")
        }
    }

    struct Devices: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "list", abstract: "List authorized device names and fingerprints as JSON.")
        @OptionGroup var storage: VaultOptions

        func run() throws {
            let store = try storage.open()
            defer { store.close() }
            let devices = try store.recipients().map { ["name": $0.name, "fingerprint": $0.fingerprint] }
            try IO.output(String(decoding: VaultCoding.encode(devices), as: UTF8.self) + "\n")
        }
    }

    struct Remove: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Revoke another device and rotate the vault key. Old copies remain decryptable by their former recipients.")
        @OptionGroup var storage: VaultOptions
        @Argument var fingerprint: String

        func run() throws {
            let disk = storage.disk
            let bytes = try disk.read()
            let device = try LocalDevice.open(directory: storage.stateURL)
            defer { device.close() }
            let store = try FileSecretStore(disk: disk, snapshot: bytes, opener: device)
            defer { store.close() }
            try store.revoke(fingerprint, currentDevice: device.publicKey)
            try IO.output("Device removed and vault key rotated. Historical copies are unaffected.\nVerify this new vault fingerprint on every remaining Mac:\n\(try store.fingerprint())\n")
        }
    }
}
