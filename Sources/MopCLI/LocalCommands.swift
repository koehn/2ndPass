import ArgumentParser
import Darwin
import Foundation
import MopAuth
import MopCore
import MopKeychain

private func localIdentityID(_ store: LocalIdentityStore, _ reference: String) throws -> UUID {
    if let uuid = UUID(uuidString: reference) { return uuid }
    guard let identity = try store.list().first(where: { $0.name == reference }) else { throw MopError.notFound }
    return identity.id
}

struct Local: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "local",
        abstract: "Manage the device-local vault. Identities never leave the Secure Enclave and never synchronize.",
        discussion: "The vault is always named \"local\". It cannot be renamed, shared, exported, or backed up.",
        subcommands: [List.self, Create.self, PublicKey.self, Sign.self, Delete.self]
    )

    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List device-local identities.")
        @Flag(help: "Output a JSON array.") var json = false
        func run() async throws {
            let rows = try LocalIdentityStore.open().list()
            if json {
                struct Row: Encodable { let id: UUID; let name: String; let `protocol`: String; let algorithm: String }
                let out = rows.map { Row(id: $0.id, name: $0.name, protocol: $0.protocolType.rawValue, algorithm: $0.algorithm.rawValue) }
                try IO.output(String(decoding: JSONEncoder().encode(out), as: UTF8.self) + "\n")
            } else {
                for row in rows { try IO.output("\(row.name)\t\(row.id)\t\(row.protocolType.rawValue)\t\(row.algorithm.rawValue)\n") }
            }
        }
    }

    struct Create: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Create a new non-exportable device-local identity.")
        @Argument(help: "Identity name (1-64 characters).") var name: String
        @Option(help: "Protocol: ssh (default), git-signing, tls-client, x509, generic-ecdh, and more.") var `protocol`: String = "ssh"
        func validate() throws {
            _ = try LocalIdentity.validateName(name)
            guard LocalIdentityProtocol(rawValue: `protocol`) != nil else { throw MopError.invalidProcess }
        }
        func run() async throws {
            let context = try Authentication.authorize(reason: "create a device-local identity in the Secure Enclave")
            let store = try LocalIdentityStore.open()
            let identity = try store.create(name: name, protocolType: LocalIdentityProtocol(rawValue: `protocol`)!, context: context)
            struct Row: Encodable { let id: UUID; let name: String; let `protocol`: String; let algorithm: String; let publicSSH: String? }
            let publicSSH: String?
            if identity.algorithm == .p256Signing {
                publicSSH = try SSHPublicKey.openSSH(x963: identity.publicKey, comment: identity.sshComment)
            } else {
                publicSSH = nil
            }
            try IO.output(String(decoding: JSONEncoder().encode(Row(id: identity.id, name: identity.name, protocol: identity.protocolType.rawValue, algorithm: identity.algorithm.rawValue, publicSSH: publicSSH)), as: UTF8.self) + "\n")
        }
    }

    struct PublicKey: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show the OpenSSH public key line for a device-local identity.")
        @Argument(help: "Identity name or UUID.") var identity: String
        func run() async throws {
            let store = try LocalIdentityStore.open()
            let row = try store.read(id: try localIdentityID(store, identity))
            guard row.algorithm == .p256Signing else { throw MopError.invalidLocalIdentity }
            let line = try SSHPublicKey.openSSH(x963: row.publicKey, comment: row.sshComment)
            try IO.output(line + "\n")
        }
    }

    struct Sign: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Sign data (default stdin) with a device-local identity; prints the DER signature.")
        @Argument(help: "Identity name or UUID.") var identity: String
        @Option(help: "Read the data to sign from this file instead of stdin.", completion: .file()) var file: String?
        @Flag(help: "Print the signature as base64 instead of hex.") var base64 = false
        func run() async throws {
            let context = try Authentication.authorize(reason: "sign data with a device-local identity")
            let store = try LocalIdentityStore.open()
            let data = try IO.input(file: file)
            let id = try localIdentityID(store, identity)
            let signature = try data.withFoundationData { try store.sign(id: id, data: $0, context: context) }
            let encoded = base64 ? signature.base64EncodedString() : signature.map { String(format: "%02x", $0) }.joined()
            try IO.output(encoded + "\n")
        }
    }

    struct Delete: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Delete a device-local identity; its private key is destroyed and cannot be recovered.")
        @Argument(help: "Identity name or UUID.") var identity: String
        @Flag(name: [.short, .long], help: "Do not prompt for confirmation.") var yes = false
        func run() async throws {
            let store = try LocalIdentityStore.open()
            let id = try localIdentityID(store, identity)
            let row = try store.read(id: id)
            if !yes {
                IO.diagnostic("Delete identity \(row.name) [\(row.id)]? This cannot be undone.\n")
                guard isatty(STDIN_FILENO) != 0 else { throw MopError.confirmationRequired }
                IO.diagnostic("Type \(row.name) to delete: ")
                guard readLine() == row.name else { throw MopError.operationCancelled }
            }
            _ = try Authentication.authorize(reason: "delete a device-local identity")
            try store.delete(id: id)
        }
    }
}

struct SSHAgent: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ssh-agent",
        abstract: "Run a Secure Enclave-backed SSH agent; run a command after -- with SSH_AUTH_SOCK set.",
        discussion: "Example: 2ndpass ssh-agent -- ssh user@example.com. With no command, serves in the foreground and prints the socket path."
    )
    @Argument(parsing: .postTerminator, help: "Command and arguments after --.") var command: [String] = []

    func run() throws {
        let context = try Authentication.authorize(reason: "authenticate the Secure Enclave SSH agent session")
        let store = try LocalIdentityStore.open()
        let backend = StoreSSHAgentBackend(store: store, context: context)
        let agent = MopKeychain.SSHAgent(backend: backend)
        let socketPath = Self.socketPath()

        guard command.isEmpty else {
            try Execute.validate(command)
            let group = DispatchGroup()
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                try? agent.serve(socketPath: socketPath)
                group.leave()
            }
            var attempts = 0
            while !FileManager.default.fileExists(atPath: socketPath) && attempts < 200 { usleep(5_000); attempts += 1 }
            IO.diagnostic("SSH_AUTH_SOCK=\(socketPath)\n")
            defer {
                agent.stop()
                group.wait()
                IO.diagnostic("agent socket removed.\n")
            }
            let status = try Self.runChild(command, environment: Self.childEnvironment(sshAgentSocket: socketPath))
            throw ExitCode(status)
        }

        IO.diagnostic("SSH_AUTH_SOCK=\(socketPath)\n")
        try agent.serve(socketPath: socketPath)
    }

    private static func socketPath() -> String {
        let base = ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory()
        let directory = base.hasSuffix("/") ? base : base + "/"
        return directory + "2ndpass-ssh-agent-\(ProcessInfo.processInfo.processIdentifier).sock"
    }

    private static func childEnvironment(sshAgentSocket: String) -> [String: String] {
        var environment = ProcessInfo.processInfo.environment
        environment["SSH_AUTH_SOCK"] = sshAgentSocket
        return environment
    }

    static func runChild(_ command: [String], environment: [String: String]) throws -> Int32 {
        try TerminalExecute.run(command, environment: environment.mapValues { SecretBytes(utf8: $0) })
    }
}
