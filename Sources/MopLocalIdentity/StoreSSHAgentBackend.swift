import Foundation
import MopCore

/// Enforces protocol purpose even when an untrusted client controls the socket.
public enum SSHSigningPolicy {
    public static func validate(data: Data, key: Data, purpose: LocalIdentityProtocol) throws {
        var offset = 0
        func string() throws -> Data { try SSHAgentFraming.parseString(data, &offset) }
        func text() throws -> String { String(decoding: try string(), as: UTF8.self) }
        switch purpose {
        case .gitSigning:
            guard data.starts(with: Data("SSHSIG".utf8)) else { throw MopError.localIdentityCapability }
            offset = 6
            guard try text() == "git", try string().isEmpty else { throw MopError.localIdentityCapability }
            let hash = try text(), digest = try string()
            guard (hash == "sha256" && digest.count == 32) || (hash == "sha512" && digest.count == 64) else { throw MopError.localIdentityCapability }
        case .ssh:
            let session = try string()
            guard [20, 32, 48, 64].contains(session.count), offset < data.count, data[offset] == 50 else { throw MopError.localIdentityCapability }
            offset += 1
            guard !(try string()).isEmpty, try text() == "ssh-connection" else { throw MopError.localIdentityCapability }
            let method = try text()
            guard ["publickey", "publickey-hostbound-v00@openssh.com"].contains(method),
                  offset < data.count, data[offset] == 1 else { throw MopError.localIdentityCapability }
            offset += 1
            guard try text() == SSHPublicKey.algorithm, try string() == key else { throw MopError.localIdentityCapability }
            if method == "publickey-hostbound-v00@openssh.com" {
                // OpenSSH adds the server's public key to the signed authentication
                // payload. Accepting this format does not verify a session binding
                // or impose destination/forwarding restrictions on the agent.
                guard !(try string()).isEmpty else { throw MopError.localIdentityCapability }
            }
        default: throw MopError.localIdentityCapability
        }
        guard offset == data.count else { throw MopError.localIdentityCapability }
    }
}

public final class StoreSSHAgentBackend: SSHAgentBackend {
    private let store: LocalIdentityStore
    private let authorization: LocalAuthorization
    private let purpose: LocalIdentityProtocol
    private let ids: Set<UUID>
    public init(store: LocalIdentityStore, authorization: LocalAuthorization, purpose: LocalIdentityProtocol, ids: Set<UUID>) throws {
        guard [.ssh, .gitSigning].contains(purpose) else { throw MopError.localIdentityCapability }
        self.store = store; self.authorization = authorization; self.purpose = purpose; self.ids = ids
    }
    private func eligible() throws -> [LocalIdentity] {
        try authorization.check()
        let rows = try store.list().filter { ids.contains($0.id) && $0.protocolType == purpose }
        guard Set(rows.map(\.id)) == ids else { authorization.revoke(); throw MopError.authentication }
        return rows
    }
    public func identities() throws -> [SSHAgentIdentity] {
        try eligible().map { SSHAgentIdentity(blob: try SSHPublicKey.wireBlob(x963: $0.publicKey), comment: $0.sshComment) }
    }
    public func sign(blob: Data, data: Data) throws -> Data {
        guard let identity = try eligible().first(where: { try SSHPublicKey.wireBlob(x963: $0.publicKey) == blob }) else { throw MopError.notFound }
        try SSHSigningPolicy.validate(data: data, key: blob, purpose: purpose)
        return try store.sign(id: identity.id, data: data, authorization: authorization)
    }
}
