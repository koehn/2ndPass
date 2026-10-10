import Foundation
import MopCore

/// Protocol-domain binding prevents reusing a signed control message in another
/// account, vault, purpose or generation of the coordination namespace.
public struct CoordinationEnvelope: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case discovery, enrollmentRequest, enrollmentApproval, enrollmentAcknowledgment, grantRequest, deletion
    }
    public let kind: Kind
    public let scope: EnrollmentScope
    public let identity: UUID
    public let membership: String?
    public let author: DevicePublicKey
    public let payload: Data
    public let signature: Data
    private struct Statement: Encodable {
        let domain = "2ndpass-account-coordination-3"
        let kind: Kind
        let scope: EnrollmentScope
        let identity: UUID
        let membership: String?
        let author: DevicePublicKey
        let payload: Data
    }
    private var statement: Statement { Statement(kind: kind, scope: scope, identity: identity,
        membership: membership, author: author, payload: payload) }

    public static func sign(kind: Kind, scope: EnrollmentScope, identity: UUID, payload: Data,
                            history: TrustedMembershipHistory? = nil, device: any DeviceOperations) throws -> Self {
        let statement = Statement(kind: kind, scope: scope, identity: identity, membership: try history?.current.digest(),
            author: device.identity, payload: payload)
        let result = Self(kind: kind, scope: scope, identity: identity, membership: statement.membership,
            author: device.identity, payload: payload, signature: try device.sign(Codec.encode(statement)))
        try result.verifySignature(scope: scope)
        if let history { try result.verifyAuthority(history: history) }
        else if kind != .enrollmentRequest { throw MopError.vaultUntrusted }
        return result
    }

    /// Signature checking alone never pins authority. Enrollment requests are
    /// self-signed; their admission still requires an unlocked authorized owner.
    public func verifySignature(scope expected: EnrollmentScope) throws {
        try scope.validate(); try author.validate()
        guard scope == expected, author.member == scope.member, signature.count == 64,
              !payload.isEmpty, payload.count <= (kind == .enrollmentApproval ? 12 * 1024 * 1024 : kind == .deletion ? 768 * 1024 : 128 * 1024),
              membership.map(Codec.hash) ?? (kind == .enrollmentRequest),
              author.verifies(signature, message: try Codec.encode(statement)) else { throw MopError.vaultUntrusted }
        if kind == .enrollmentRequest {
            let request = try DeviceEnrollmentRequest.decode(payload)
            guard request.id == identity, request.scope == scope, request.identity == author, membership == nil else { throw MopError.vaultUntrusted }
        }
    }

    public func verifyAuthority(history: TrustedMembershipHistory) throws {
        try verifySignature(scope: scope)
        guard history.vault == scope.vault, let membership else { throw MopError.vaultUntrusted }
        let state = try history.state(forDigest: membership).membership
        guard state.accounts.count == 1, state.accounts[0].id == scope.member,
              state.devices.contains(author), history.current.membership.devices.contains(author) else { throw MopError.vaultUntrusted }
        switch kind {
        case .discovery, .enrollmentApproval, .deletion:
            guard state.role(of: author) == .owner, history.current.membership.role(of: author) == .owner else { throw MopError.cloudPermission }
        case .grantRequest, .enrollmentAcknowledgment: break
        case .enrollmentRequest: throw MopError.vaultUntrusted
        }
        try history.verifyAccountPath(from: membership, allowingDeviceRemoval: true)
    }

    public func encoded() throws -> Data { try verifySignature(scope: scope); return try Codec.encode(self) }
    public static func decode(_ bytes: Data, scope: EnrollmentScope) throws -> Self {
        guard bytes.count <= 16 * 1024 * 1024 else { throw MopError.invalidVault }
        let value = try JSONDecoder().decode(Self.self, from: bytes)
        try value.verifySignature(scope: scope)
        guard try value.encoded() == bytes else { throw MopError.vaultUntrusted }
        return value
    }
}

public struct EnrollmentAcknowledgment: Codable, Equatable, Sendable {
    public let request: UUID
    public let approvalDigest: String
    public init(request: UUID, approvalDigest: String) { self.request = request; self.approvalDigest = approvalDigest }
}

public struct ContentGrantRequest: Codable, Equatable, Sendable {
    public let item: UUID
    public let keyGeneration: UUID
    public let recipient: String
    public init(item: UUID, keyGeneration: UUID, recipient: String) {
        self.item = item; self.keyGeneration = keyGeneration; self.recipient = recipient
    }
}
