import ArgumentParser
import Darwin
import Foundation
import MopCore
import MopLocalIdentity

extension Item {
    struct Create: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        @Option var type: String
        @Option var name: String
        @Flag(help: "Acknowledge permanent identity loss if this device is lost or erased") var acknowledgeDeviceLoss = false
        func validate() throws {
            _ = try LocalIdentity.validateName(name)
            guard let purpose = LocalIdentityProtocol(rawValue: type), LocalIdentityProtocol.creatable.contains(purpose) else { throw MopError.localIdentityCapability }
        }
        func run() async throws {
            guard let vault = storage.vault else { throw ValidationError("Specify --vault for identity creation.") }
            try IdentitySelection.requireSupportedBackend(vault)
            guard !storage.offline,
                  let purpose = LocalIdentityProtocol(rawValue: type), LocalIdentityProtocol.creatable.contains(purpose) else { throw MopError.localOperationForbidden }
            IO.diagnostic(LocalIdentityWarning.loss + "\n" + LocalIdentityWarning.redundancy(purpose) + "\n")
            if !acknowledgeDeviceLoss {
                guard isatty(STDIN_FILENO) != 0 else { throw MopError.confirmationRequired }
                IO.diagnostic("Type 'local' to acknowledge permanent device-loss consequences: ")
                guard readLine() == "local" else { throw MopError.operationCancelled }
            }
            let authorization = try LocalAuthorization.authorize(reason: "create identity in local", ids: [], purposes: [purpose], operations: [.create])
            defer { authorization.revoke() }
            let identity = try LocalIdentityStore.open().create(name: name, protocolType: purpose, authorization: authorization)
            try IO.output(String(decoding: JSONEncoder().encode(identity), as: UTF8.self) + "\n")
        }
    }
    struct PublicKey: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        @Argument var identity: String
        func run() async throws {
            let selection = try IdentitySelection(identity, vault: storage.vault)
            let store = try selection.openStore()
            try IO.output(store.read(id: localIdentityID(store, selection.reference.name)).publicKeyText + "\n")
        }
    }
    struct DeleteIdentity: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "delete")
        @OptionGroup var storage: VaultOptions
        @Argument var identity: String
        @Flag var yes = false
        func run() async throws {
            let selection = try IdentitySelection(identity, vault: storage.vault)
            let store = try selection.openStore(), id = try localIdentityID(store, selection.reference.name), row = try store.read(id: id)
            IO.diagnostic(LocalIdentityWarning.deletion + "\n")
            if !yes {
                guard isatty(STDIN_FILENO) != 0 else { throw MopError.confirmationRequired }
                IO.diagnostic("Type \(row.name) to delete: ")
                guard readLine() == row.name else { throw MopError.operationCancelled }
            }
            let authorization = try LocalAuthorization.authorize(reason: "delete identity from local", ids: [id], purposes: [row.protocolType], operations: [.delete])
            defer { authorization.revoke() }
            try store.delete(id: id, authorization: authorization)
        }
    }
}

extension Item {
    struct CSR: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "csr")
        @OptionGroup var storage: VaultOptions
        @Argument var identity: String
        @Option var commonName: String
        @Option var organization: String?
        @Option var organizationalUnit: String?
        @Option var country: String?
        @Option var dns: [String] = []
        @Option var email: [String] = []
        @Option var uri: [String] = []
        @Option var ip: [String] = []
        func run() async throws {
            let selection = try IdentitySelection(identity, vault: storage.vault)
            let store = try selection.openStore(), id = try localIdentityID(store, selection.reference.name)
            let auth = try LocalAuthorization.authorize(reason: "create certificate request", ids: [id], purposes: [.x509], operations: [.csr])
            defer { auth.revoke() }
            let names = dns.map(CertificateAlternativeName.dns) + email.map(CertificateAlternativeName.email) + uri.map(CertificateAlternativeName.uri) + ip.map(CertificateAlternativeName.ip)
            try IO.output(store.csr(id: id, subject: CertificateSubject(commonName: commonName, organization: organization, organizationalUnit: organizationalUnit, country: country), names: names, authorization: auth) + "\n")
        }
    }
    struct Certificate: AsyncParsableCommand {
        static let configuration = CommandConfiguration(subcommands: [Attach.self, Show.self, Export.self])
        struct Attach: AsyncParsableCommand {
            @OptionGroup var storage: VaultOptions
            @Argument var identity: String
            @Argument var file: String
            func run() async throws {
                let selection = try IdentitySelection(identity, vault: storage.vault)
                let store = try selection.openStore(), id = try localIdentityID(store, selection.reference.name)
                let data = try LocalFile.read(URL(fileURLWithPath: file), privateFile: false)
                let auth = try LocalAuthorization.authorize(reason: "attach public certificate", ids: [id], purposes: [.x509], operations: [.certificate])
                defer { auth.revoke() }
                try store.attachCertificates(id: id, data: data, authorization: auth)
                IO.diagnostic("Certificate attached. Public key matches; trust chain was not validated.\n")
            }
        }
        struct Show: AsyncParsableCommand {
            @OptionGroup var storage: VaultOptions
            @Argument var identity: String
            func run() async throws {
                let selection = try IdentitySelection(identity, vault: storage.vault)
                let store = try selection.openStore(), row = try store.read(id: localIdentityID(store, selection.reference.name))
                try IO.output(String(decoding: JSONEncoder().encode(row.certificateInfo), as: UTF8.self) + "\n")
            }
        }
        struct Export: AsyncParsableCommand {
            @OptionGroup var storage: VaultOptions
            @Argument var identity: String
            func run() async throws {
                let selection = try IdentitySelection(identity, vault: storage.vault)
                let store = try selection.openStore()
                try IO.output(store.read(id: localIdentityID(store, selection.reference.name)).certificatePEM + "\n")
            }
        }
    }
}
