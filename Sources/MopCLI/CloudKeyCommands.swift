import ArgumentParser
import Foundation
import Darwin
import MopCore
import MopAppSupport

extension Item {
    struct ImportSSH: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "import-ssh", abstract: "Import a usable OpenSSH private key into a cloud vault.")
        @OptionGroup var storage: VaultOptions
        @Option var name: String
        @Option(help: "ssh or git-signing") var purpose = "ssh"
        @Flag(help: "Explicitly replace an existing untyped SSH item with this credential.") var convert = false
        @Argument var file: String
        func run() async throws {
            guard let vault = storage.vault else { throw ValidationError("Specify --vault explicitly.") }
            guard !LocalVault.isLocal(vault) else { throw CredentialFailure.localImport }
            try storage.requireOnline()
            guard let purpose = CredentialPurpose(rawValue: purpose), purpose != .passkey else { throw CredentialFailure.invalid }
            let bytes = SecretBytes(copying: try LocalFile.read(URL(fileURLWithPath: file), limit: 1024 * 1024))
            let service = storage.native(); defer { service.lock() }
            let keys = CloudCredentialService(service)
            let record: CloudCredentialRecord
            do { record = try await keys.importSSH(vault: vault, name: name, bytes: bytes, purposes: [purpose], converting: convert) }
            catch CredentialFailure.passphraseRequired {
                guard isatty(STDIN_FILENO) != 0, let ptr = getpass("Private-key passphrase: ") else { throw CredentialFailure.passphraseRequired }
                let count = strlen(ptr); let passphrase = SecretBytes(copying: UnsafeRawBufferPointer(start: ptr, count: count))
                _ = memset_s(ptr, count, 0, count)
                record = try await keys.importSSH(vault: vault, name: name, bytes: bytes, passphrase: passphrase, purposes: [purpose], converting: convert)
            }
            try IO.output(record.publicKeyText + "\n")
        }
    }
}
