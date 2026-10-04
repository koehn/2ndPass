import MopLocalIdentity
import ArgumentParser
import Darwin
import Foundation
import MopAuth
import MopCore
import MopKeychain
import MopAppSupport
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
        let cloudVault = vault.flatMap { LocalVault.isLocal($0) ? nil : $0 } ?? selections.first.flatMap { LocalVault.isLocal($0.reference.vault) ? nil : $0.reference.vault }
        let cloudService = ItemVaultService()
        defer { cloudService.lock() }
        let session: SSHAgentSession
        if let cloudVault {
            guard selections.allSatisfy({ $0.reference.vault == cloudVault }) else { throw ValidationError("Select keys from one vault per agent session.") }
            let provider = CloudCredentialService(cloudService)
            let rows = try waitForCloud { try await provider.records(vault: cloudVault) }
            let requested = Set(selections.map { $0.reference.name })
            let chosen = rows.filter { $0.credential.purposes.contains(purpose == .ssh ? .ssh : .gitSigning) && (requested.isEmpty || requested.contains($0.item.name) || requested.contains($0.item.storageID ?? "")) }
            guard !chosen.isEmpty, requested.allSatisfy({ name in chosen.contains { $0.item.name == name || $0.item.storageID == name } }) else { throw MopError.notFound }
            let ids = Set(chosen.compactMap { UUID(uuidString: $0.item.storageID ?? "") })
            guard ids.count == chosen.count else { throw CredentialFailure.invalid }
            session = try SSHAgentSession(purpose: purpose, ids: ids, wrapped: !command.isEmpty, approvalLifetime: TimeInterval(approvalSeconds), listCredentials: {
                try waitForCloud { try await provider.records(vault: cloudVault) }.filter { ids.contains(UUID(uuidString: $0.item.storageID ?? "") ?? UUID()) && $0.credential.purposes.contains(purpose == .ssh ? .ssh : .gitSigning) }.map { row in
                    SSHSessionIdentity(id: UUID(uuidString: row.item.storageID!)!, name: row.item.name, purpose: purpose, blob: row.sshBlob, algorithm: row.credential.algorithm == .rsa ? "ssh-rsa" : row.credential.algorithm == .p256 ? "ecdsa-sha2-nistp256" : "ssh-ed25519")
                }
            }, sign: { id, data, flags, approval in
                guard approval.isActive, let row = chosen.first(where: { $0.item.storageID == id.uuidString }) else { throw MopError.authentication }
                let key = try waitForCloud { try await provider.key(row) }
                guard approval.isActive else { throw MopError.authentication }
                let signature = try key.sign(data, flags: flags)
                guard approval.isActive, cloudService.isAuthenticated else { throw MopError.authentication }
                return signature
            })
        } else {
            guard vault.map(LocalVault.isLocal) == true || !selections.isEmpty else { throw ValidationError("Specify --vault or an identity reference.") }
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
            session = try SSHAgentSession(store: store, purpose: purpose, ids: ids, wrapped: !command.isEmpty, approvalLifetime: TimeInterval(approvalSeconds))
        }
        defer { session.stop() }
        let agent = MopLocalIdentity.SSHAgent(connectionBackend: { try session.backend(socket: $0) }, onStop: { session.stop(); cloudService.lock() })
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

// The socket server is synchronous; vault I/O runs on Swift's cooperative pool.
private func waitForCloud<T: Sendable>(_ work: @escaping @Sendable () async throws -> T) throws -> T {
    let result = Mutex<Result<T, any Error>?>(nil), done = DispatchSemaphore(value: 0)
    Task.detached { do { let value = try await work(); result.withLock { $0 = .success(value) } } catch { result.withLock { $0 = .failure(error) } }; done.signal() }
    done.wait()
    return try result.withLock { try $0!.get() }
}
