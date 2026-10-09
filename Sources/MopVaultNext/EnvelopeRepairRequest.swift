import Foundation
import MopCore

/// A request is not an authorization grant. Responders verify the current
/// membership independently before wrapping any key for the requester.
public struct EnvelopeRepairRequest: Codable, Equatable, Sendable {
    public let scope: EnrollmentScope
    public let record: UUID
    public let version: UUID
    public let membership: String
    public let requester: DevicePublicKey
    public let signature: Data
    private struct Statement: Encodable {
        let domain = "2ndpass-envelope-repair-1"
        let scope: EnrollmentScope
        let record: UUID
        let version: UUID
        let membership: String
        let requester: DevicePublicKey
    }
    private var statement: Statement {
        Statement(scope: scope, record: record, version: version, membership: membership, requester: requester)
    }
    /// Stable across retries, including a nondeterministic ECDSA signature.
    public var identifier: String { get throws { Codec.digest(try Codec.encode(statement)) } }
    public static func create(scope: EnrollmentScope, record: UUID, version: UUID,
                              history: TrustedMembershipHistory, device: any DeviceOperations) throws -> Self {
        let statement = Statement(scope: scope, record: record, version: version,
            membership: try history.current.digest(), requester: device.identity)
        let request = Self(scope: scope, record: record, version: version, membership: statement.membership,
            requester: device.identity, signature: try device.sign(Codec.encode(statement)))
        try request.verify(scope: scope, history: history)
        return request
    }
    public func verify(scope expected: EnrollmentScope, history: TrustedMembershipHistory) throws {
        guard scope == expected, scope.vault == history.vault, scope.member == requester.member,
              history.current.membership.role(of: requester) != nil,
              try history.state(forDigest: membership).membership.role(of: requester) != nil,
              requester.verifies(signature, message: try Codec.encode(statement)) else { throw MopError.cloudPermission }
    }
    public func encoded() throws -> Data { try Codec.encode(self) }
    public static func decode(_ bytes: Data) throws -> Self {
        guard bytes.count <= 65_536 else { throw MopError.invalidVault }
        return try JSONDecoder().decode(Self.self, from: bytes)
    }
}
