import MopLocalIdentity
import ArgumentParser
import Darwin
import Foundation
import MopAuth
import MopCore
import MopKeychain
import Synchronization

func localIdentityID(_ store: LocalIdentityStore, _ reference: String) throws -> UUID {
    if let uuid = UUID(uuidString: reference) { return uuid }
    guard let identity = try store.list().first(where: { $0.name == reference }) else { throw MopError.notFound }
    return identity.id
}

struct SSHAgent: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ssh-agent",
        abstract: "Run an SSH signing agent; run a command after -- with SSH_AUTH_SOCK set.",
        discussion: "Example: sp ssh-agent --vault local -- ssh user@example.com. With no command, serves in the foreground and prints the socket path."
    )
    @Argument(parsing: .postTerminator, help: "Command and arguments after --.") var command: [String] = []

    @Option(help: "Vault name or UUID for identity names or enumeration.") var vault: String?
    @Option(help: "ssh or git-signing") var purpose: String = "ssh"
    @Option(name: .customLong("identity"), help: "Identity name, UUID, or sp://VAULT/NAME; may be repeated") var identities: [String] = []

    @Option(help: "Standalone approval lifetime in seconds, scoped to the requesting process and key (1–43200).")
    var approvalSeconds: Int = 300

    func validate() throws {
        guard (1...43200).contains(approvalSeconds) else { throw ValidationError("--approval-seconds must be between 1 and 43200.") }
    }

    func run() throws {
        guard let purpose = LocalIdentityProtocol(rawValue: purpose), [.ssh, .gitSigning].contains(purpose) else { throw MopError.localIdentityCapability }
        let selections = try identities.map { try IdentitySelection($0, vault: vault) }
        if selections.isEmpty {
            guard let vault else { throw ValidationError("Specify --vault, or select identities using --identity sp://VAULT/NAME.") }
            try IdentitySelection.requireSupportedBackend(vault)
        }
        for selection in selections { try IdentitySelection.requireSupportedBackend(selection.reference.vault) }
        let store = try LocalIdentityStore.open()
        let selected = Set(try selections.map { try localIdentityID(store, $0.reference.name) })
        let available = try store.list()
        for row in available where selected.contains(row.id) {
            try Self.validatePurpose(row.protocolType, requested: purpose, reference: row.reference.description)
        }
        let rows = available.filter { $0.protocolType == purpose && (selected.isEmpty || selected.contains($0.id)) }
        let ids = Set(rows.map(\.id))
        guard selected.isSubset(of: ids) else { throw MopError.notFound }
        guard !ids.isEmpty else { throw ValidationError("No \(purpose.rawValue) identities were found in the selected vault.") }
        let session = try SSHAgentSession(store: store, purpose: purpose, ids: ids, wrapped: !command.isEmpty, approvalLifetime: TimeInterval(approvalSeconds))
        defer { session.stop() }
        let agent = MopLocalIdentity.SSHAgent(connectionBackend: { try session.backend(socket: $0) }, onStop: { session.stop() })
        var template = Array("/tmp/sp-agent-XXXXXX".utf8CString)
        guard let directory = mkdtemp(&template) else { throw MopError.inputOutput }
        let directoryPath = String(cString: directory)
        defer { try? FileManager.default.removeItem(atPath: directoryPath) }
        let socketPath = directoryPath + "/agent.sock"

        guard command.isEmpty else {
            try Execute.validate(command)
            let group = DispatchGroup()
            group.enter()
            let ready = DispatchSemaphore(value: 0)
            let startup = Mutex<Result<Void, any Error>?>(nil)
            DispatchQueue.global(qos: .userInitiated).async {
                defer { group.leave() }
                do {
                    try agent.serve(socketPath: socketPath, whileActive: { session.isActive }, onReady: {
                        startup.withLock { $0 = .success(()) }; ready.signal()
                    })
                } catch { startup.withLock { $0 = .failure(error) }; ready.signal() }
            }
            ready.wait()
            try startup.withLock { try $0?.get() }
            IO.diagnostic("SSH_AUTH_SOCK=\(socketPath)\n")
            defer {
                agent.stop()
                group.wait()
                IO.diagnostic("agent socket removed.\n")
            }
            let status = try TerminalExecute.run(command, environment: Self.childEnvironment(sshAgentSocket: socketPath).mapValues { SecretBytes(utf8: $0) }, onSpawn: { try session.setCommand($0) }, onExit: { agent.stop() })
            throw ExitCode(status)
        }

        let signals: [Int32] = [SIGINT, SIGTERM, SIGHUP, SIGQUIT]
        let handlers = signals.map { signal($0, SIG_IGN) }
        let sources = signals.map { number in
            let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
            source.setEventHandler { session.stop(); agent.stop() }
            source.resume(); return source
        }
        defer {
            sources.forEach { $0.cancel() }
            for (number, handler) in zip(signals, handlers) { signal(number, handler) }
        }
        IO.diagnostic("SSH_AUTH_SOCK=\(socketPath)\n")
        try agent.serve(socketPath: socketPath, whileActive: { session.isActive })
    }

    static func validatePurpose(_ actual: LocalIdentityProtocol, requested: LocalIdentityProtocol, reference: String) throws {
        guard actual != requested else { return }
        let guidance: String
        if actual == .gitSigning {
            guidance = "Use --purpose git-signing with a Git signing command. For SSH login (including Git over SSH), select an SSH identity; Git signing identities cannot authenticate SSH connections."
        } else {
            guidance = "Select an identity matching --purpose \(requested.rawValue)."
        }
        throw ValidationError("Identity '\(reference)' has purpose '\(actual.rawValue)', but this agent session requires '\(requested.rawValue)'. " + guidance)
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
