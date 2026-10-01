#if os(macOS)
import Foundation
import LocalAuthentication
import MopCore

/// Requests are serialized by SSHAgent. The state lock also allows stop/lock to
/// invalidate a pending system prompt without waiting for that request to finish.
public struct SSHSessionIdentity {
    public let id: UUID
    public let name: String
    public let purpose: LocalIdentityProtocol
    public let blob: Data
    public let algorithm: String
    public init(id: UUID, name: String, purpose: LocalIdentityProtocol, blob: Data, algorithm: String) {
        self.id = id; self.name = name; self.purpose = purpose; self.blob = blob; self.algorithm = algorithm
    }
    init(_ local: LocalIdentity) throws {
        self.init(id: local.id, name: local.name, purpose: local.protocolType, blob: try SSHPublicKey.wireBlob(x963: local.publicKey), algorithm: SSHPublicKey.algorithm)
    }
}
public final class SSHAgentSession: @unchecked Sendable {
    typealias Authorizer = (String, LocalIdentity, TimeInterval, (LAContext) throws -> Void) throws -> LocalAuthorization
    private let list: () throws -> [SSHSessionIdentity]
    private let signData: (UUID, Data, UInt32, LocalAuthorization) throws -> Data
    private let authorize: (String, SSHSessionIdentity, TimeInterval, (LAContext) throws -> Void) throws -> LocalAuthorization
    private let wireSignatures: Bool
    private let purpose: LocalIdentityProtocol
    private let ids: Set<UUID>
    private let wrapped: Bool
    private let lifetime: TimeInterval
    private let state = NSLock()
    private var root: SSHAgentProcess?
    private var stopped = false
    private var pending: LAContext?
    private var approvals: [String: LocalAuthorization] = [:]
    private let gate: LocalAuthorization

    public convenience init(store: LocalIdentityStore, purpose: LocalIdentityProtocol, ids: Set<UUID>, wrapped: Bool, approvalLifetime: TimeInterval) throws {
        try self.init(purpose: purpose, ids: ids, wrapped: wrapped, approvalLifetime: approvalLifetime,
            list: { try store.list() }, sign: { try store.sign(id: $0, data: $1, authorization: $2) },
            authorize: { reason, identity, lifetime, created in
                try LocalAuthorization.authorize(reason: reason, ids: [identity.id], purposes: [identity.protocolType], operations: [.sign], oneShot: false, lifetime: lifetime, contextCreated: created)
            })
    }

    convenience init(purpose: LocalIdentityProtocol, ids: Set<UUID>, wrapped: Bool, approvalLifetime: TimeInterval,
         list: @escaping () throws -> [LocalIdentity], sign: @escaping (UUID, Data, LocalAuthorization) throws -> Data,
         authorize: @escaping Authorizer, watchDevice: Bool = true) throws {
        try self.init(purpose: purpose, ids: ids, wrapped: wrapped, approvalLifetime: approvalLifetime,
            listCredentials: { try list().map(SSHSessionIdentity.init) }, sign: { id, data, flags, auth in
                guard flags == 0 else { throw MopError.localIdentityCapability }
                return try sign(id, data, auth)
            }, authorizeCredential: { reason, row, lifetime, created in
                guard let local = try list().first(where: { $0.id == row.id }) else { throw MopError.notFound }
                return try authorize(reason, local, lifetime, created)
            }, wireSignatures: false, watchDevice: watchDevice)
    }
    public convenience init(purpose: LocalIdentityProtocol, ids: Set<UUID>, wrapped: Bool, approvalLifetime: TimeInterval,
        listCredentials: @escaping () throws -> [SSHSessionIdentity],
        sign: @escaping (UUID, Data, UInt32, LocalAuthorization) throws -> Data) throws {
        try self.init(purpose: purpose, ids: ids, wrapped: wrapped, approvalLifetime: approvalLifetime, listCredentials: listCredentials, sign: sign,
            authorizeCredential: { reason, row, lifetime, created in
                try LocalAuthorization.authorize(reason: reason, ids: [row.id], purposes: [row.purpose], operations: [.sign], oneShot: false, lifetime: lifetime, contextCreated: created)
            })
    }
    private init(purpose: LocalIdentityProtocol, ids: Set<UUID>, wrapped: Bool, approvalLifetime: TimeInterval,
        listCredentials: @escaping () throws -> [SSHSessionIdentity],
        sign: @escaping (UUID, Data, UInt32, LocalAuthorization) throws -> Data,
        authorizeCredential: @escaping (String, SSHSessionIdentity, TimeInterval, (LAContext) throws -> Void) throws -> LocalAuthorization,
        wireSignatures: Bool = true, watchDevice: Bool = true) throws {
        guard [.ssh, .gitSigning].contains(purpose), !ids.isEmpty,
              approvalLifetime > 0, approvalLifetime <= 43200 else { throw MopError.localIdentityCapability }
        self.wireSignatures = wireSignatures
        self.list = listCredentials; self.signData = sign; self.authorize = authorizeCredential
        self.purpose = purpose; self.ids = ids
        self.wrapped = wrapped; self.lifetime = approvalLifetime
        // Monitors device lock/sleep without authenticating the user at startup.
        gate = LocalAuthorization(context: LAContext(), ids: [], purposes: [], operations: [], expires: Date().addingTimeInterval(43200))
        if watchDevice { gate.watchDeviceState() }
    }

    public var isActive: Bool { state.withLock { !stopped && gate.isActive } }

    public func setCommand(_ pid: Int32) throws {
        let process = try SSHAgentProcess.read(pid)
        try state.withLock {
            guard !stopped, wrapped, root == nil, gate.isActive else { throw MopError.authentication }
            root = process
        }
    }

    public func stop() {
        state.withLock {
            stopped = true
            gate.revoke()
            pending?.invalidate(); pending = nil
            approvals.values.forEach { $0.revoke() }; approvals.removeAll()
        }
    }

    public func backend(socket: Int32) throws -> any SSHAgentBackend {
        let peer = try SSHAgentPeer(socket: socket)
        try validate(peer)
        return PeerBackend(session: self, peer: peer)
    }

    private func validate(_ peer: SSHAgentPeer) throws {
        let command = try state.withLock {
            guard !stopped, gate.isActive, !wrapped || root != nil else { throw MopError.authentication }
            return root
        }
        try peer.validate(root: command)
    }

    private func identities(_ peer: SSHAgentPeer) throws -> [SSHSessionIdentity] {
        try validate(peer)
        let rows = try list().filter { ids.contains($0.id) && $0.purpose == purpose }
        guard Set(rows.map(\.id)) == ids else { stop(); throw MopError.authentication }
        try validate(peer)
        return rows
    }

    private func sign(_ peer: SSHAgentPeer, blob: Data, data: Data, flags: UInt32) throws -> Data {
        guard let identity = try identities(peer).first(where: { $0.blob == blob }) else { throw MopError.notFound }
        guard identity.algorithm == "ssh-rsa" ? (flags == 2 || flags == 4 || flags == 6) : flags == 0 else { throw MopError.localIdentityCapability }
        try SSHSigningPolicy.validate(data: data, key: blob, purpose: purpose, algorithm: identity.algorithm == "ssh-rsa" ? (flags & 4 != 0 ? "rsa-sha2-512" : "rsa-sha2-256") : identity.algorithm)
        // Wrapped mode approves this key for the command tree. Standalone mode
        // approves only this exact connecting process instance (including exec version).
        let scope = (wrapped ? "command" : peer.cacheKey) + ":" + identity.id.uuidString
        var auth = state.withLock { approvals[scope] }
        if auth?.isActive != true {
            let duration = wrapped ? "this command (at most 12 hours)" : "this process for \(Int(lifetime)) seconds"
            let reason = "allow \(peer.path) (PID \(peer.process.pid)) to use \(identity.name) for \(purpose.rawValue) signing; approval lasts for \(duration)"
            defer { state.withLock { pending = nil } }
            auth = try authorize(reason, identity, wrapped ? 43200 : lifetime, { context in
                try self.state.withLock {
                    guard !self.stopped, self.gate.isActive else { throw MopError.authentication }
                    self.pending = context
                }
            })
            do {
                try validate(peer)
                try state.withLock {
                    guard !stopped, gate.isActive, let auth, auth.isActive else { throw MopError.authentication }
                    approvals = approvals.filter { $0.value.isActive }
                    if approvals.count >= 128 { approvals.values.forEach { $0.revoke() }; approvals.removeAll() }
                    approvals[scope] = auth
                }
            } catch { auth?.revoke(); throw error }
        }
        guard let auth else { throw MopError.authentication }
        try validate(peer)
        let signature = try signData(identity.id, data, flags, auth)
        try validate(peer)
        try auth.check()
        return signature
    }

    private struct PeerBackend: SSHAgentBackend {
        let session: SSHAgentSession
        let peer: SSHAgentPeer
        func identities() throws -> [SSHAgentIdentity] {
            try session.identities(peer).map { SSHAgentIdentity(blob: $0.blob, comment: $0.name) }
        }
        func sign(blob: Data, data: Data) throws -> Data { try session.sign(peer, blob: blob, data: data, flags: 0) }
        func signature(blob: Data, data: Data, flags: UInt32) throws -> Data {
            let result = try session.sign(peer, blob: blob, data: data, flags: flags)
            return session.wireSignatures ? result : try SSHAgentFraming.sshSignature(der: result)
        }
    }
}
#endif
