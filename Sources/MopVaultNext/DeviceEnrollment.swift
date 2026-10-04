import Foundation
import MopCore

public struct EnrollmentScope: Codable, Equatable, Sendable {
    public let container: String
    public let environment: String
    public let account: String
    public let vault: UUID
    public let member: UUID
    public init(container: String, environment: String, account: String, vault: UUID, member: UUID) {
        self.container = container; self.environment = environment; self.account = account; self.vault = vault; self.member = member
    }
    func validate() throws {
        guard !container.isEmpty, ["Development", "Production"].contains(environment), !account.isEmpty else { throw DeviceEnrollmentFailure.invalidRequest }
    }
}
public enum DeviceEnrollmentFailure: Error, Equatable, Sendable {
    case invalidRequest, expired, invalidApproval
}

public struct DeviceEnrollmentRequest: Codable, Equatable, Sendable {
    public let id: UUID
    public let scope: EnrollmentScope
    public let identity: DevicePublicKey
    public let expiresAt: Date
    public let signature: Data
    private struct Statement: Encodable {
        let domain = "2ndpass-device-enrollment-request-1"
        let id: UUID; let scope: EnrollmentScope; let identity: DevicePublicKey; let expiresAt: Date
    }
    private var statement: Statement { Statement(id: id, scope: scope, identity: identity, expiresAt: expiresAt) }
    public static func create(scope: EnrollmentScope, device: any DeviceOperations, now: Date = Date()) throws -> Self {
        try scope.validate()
        guard device.identity.member == scope.member else { throw DeviceEnrollmentFailure.invalidRequest }
        let statement = Statement(id: UUID(), scope: scope, identity: device.identity, expiresAt: now.addingTimeInterval(900))
        return Self(id: statement.id, scope: scope, identity: device.identity, expiresAt: statement.expiresAt,
            signature: try device.sign(Codec.encode(statement)))
    }
    public func verify(now: Date = Date()) throws {
        try verifyStructure()
        guard expiresAt > now, expiresAt.timeIntervalSince(now) <= 900 else { throw DeviceEnrollmentFailure.expired }
    }
    fileprivate func verifyStructure() throws {
        try scope.validate(); try identity.validate()
        guard identity.member == scope.member, expiresAt.timeIntervalSince1970.isFinite,
              identity.verifies(signature, message: try Codec.encode(statement)) else { throw DeviceEnrollmentFailure.invalidRequest }
    }
    public func encoded() throws -> Data { try verifyStructure(); return try Codec.encode(self) }
    public static func decode(_ data: Data) throws -> Self {
        guard data.count <= 64 * 1024 else { throw DeviceEnrollmentFailure.invalidRequest }
        let value = try JSONDecoder().decode(Self.self, from: data)
        try value.verifyStructure()
        return value
    }
}

/// Admission uses the authenticated same-Apple-account private CloudKit channel
/// as its bootstrap trust boundary. An unlocked existing owner device admits
/// authenticated same-account requests automatically. Native callers must
/// authenticate the account and private database before
/// accepting this object. Signatures alone do not authenticate a remote genesis.
public struct DeviceEnrollmentApproval: Codable, Equatable, Sendable {
    public let request: DeviceEnrollmentRequest
    public let history: [MembershipEnvelope]
    public let successor: MembershipEnvelope
    /// Snapshot count for initial-download presentation, never an authorization or completeness proof.
    public let expectedItemCount: Int?
    public let approvedAt: Date
    public let author: DevicePublicKey
    public let signature: Data
    private struct Statement: Encodable {
        let domain = "2ndpass-device-enrollment-approval-1"
        let request: DeviceEnrollmentRequest; let history: [MembershipEnvelope]
        let expectedItemCount: Int?; let successor: MembershipEnvelope; let approvedAt: Date; let author: DevicePublicKey
    }
    private var statement: Statement { Statement(request: request, history: history, expectedItemCount: expectedItemCount, successor: successor, approvedAt: approvedAt, author: author) }
    public static func create(request: DeviceEnrollmentRequest,
                              history: TrustedMembershipHistory, owner: any DeviceOperations, expectedItemCount: Int? = nil, now: Date = Date()) throws -> Self {
        try request.verify(now: now)
        guard expectedItemCount.map({ $0 >= 0 }) ?? true else { throw DeviceEnrollmentFailure.invalidApproval }
        let previous = history.current.membership
        guard previous.accounts.count == 1, history.vault == request.scope.vault, owner.identity.member == request.scope.member,
              previous.role(of: owner.identity) == .owner,
              previous.accounts.contains(where: { $0.id == request.identity.member }),
              !previous.devices.contains(where: { $0.device == request.identity.device }) else { throw DeviceEnrollmentFailure.invalidApproval }
        let accounts = previous.accounts.map { account in
            AccountMember(id: account.id, role: account.role, devices: account.devices + (account.id == request.identity.member ? [request.identity] : []))
        }
        let membership = try Membership(accounts: accounts, offlineRecovery: previous.offlineRecovery, removedDevices: previous.removedDevices)
        let successor = try MembershipEnvelope.successor(of: history.current, membership: membership, owner: owner)
        let statement = Statement(request: request, history: history.orderedStates, expectedItemCount: expectedItemCount, successor: successor,
            approvedAt: now, author: owner.identity)
        return Self(request: request, history: statement.history, successor: successor, expectedItemCount: expectedItemCount, approvedAt: statement.approvedAt,
            author: statement.author, signature: try owner.sign(Codec.encode(statement)))
    }
    /// Reissues access for an exact current identity without changing membership.
    public static func reconnect(request: DeviceEnrollmentRequest,
                                 history: TrustedMembershipHistory, owner: any DeviceOperations,
                                 expectedItemCount: Int? = nil, now: Date = Date()) throws -> Self {
        try request.verify(now: now)
        let membership = history.current.membership
        guard history.vault == request.scope.vault, membership.accounts.count == 1,
              owner.identity.member == request.scope.member, membership.role(of: owner.identity) == .owner,
              membership.devices.contains(request.identity), expectedItemCount.map({ $0 >= 0 }) ?? true else {
            throw DeviceEnrollmentFailure.invalidApproval
        }
        let statement = Statement(request: request, history: history.orderedStates,
            expectedItemCount: expectedItemCount, successor: history.current, approvedAt: now, author: owner.identity)
        return Self(request: request, history: statement.history, successor: statement.successor,
            expectedItemCount: expectedItemCount, approvedAt: now, author: owner.identity,
            signature: try owner.sign(Codec.encode(statement)))
    }
    public var isReconnect: Bool { history.last == successor }

    public func acceptFromAuthenticatedPrivateCloudKit(request expected: DeviceEnrollmentRequest,
                                                       scope: EnrollmentScope, now: Date = Date()) throws -> TrustedMembershipHistory {
        guard request == expected, request.scope == scope else { throw DeviceEnrollmentFailure.invalidApproval }
        // Owner-approved grants are durable. Request expiry only limits the
        // decision to approve, not a joining device's recovery after being offline.
        guard approvedAt <= now, approvedAt < request.expiresAt else { throw DeviceEnrollmentFailure.invalidApproval }
        return try verifiedHistory()
    }
    /// Structural verification only. Native callers must establish the private
    /// CloudKit account/channel binding before accepting this as a trust anchor.
    public func verifiedHistory() throws -> TrustedMembershipHistory {
        try request.verifyStructure()
        guard expectedItemCount.map({ $0 >= 0 }) ?? true, let genesis = history.first, history.count <= 4096 else { throw DeviceEnrollmentFailure.invalidApproval }
        var result = try TrustedMembershipHistory(genesis: genesis, vault: request.scope.vault, pinnedDigest: genesis.digest())
        for state in history.dropFirst() { try result.append(state) }
        guard result.current.membership.role(of: author) == .owner, author.member == request.scope.member,
              author.verifies(signature, message: try Codec.encode(statement)) else { throw DeviceEnrollmentFailure.invalidApproval }
        if isReconnect {
            guard result.current.membership.accounts.count == 1,
                  result.current.membership.devices.contains(request.identity) else {
                throw DeviceEnrollmentFailure.invalidApproval
            }
        } else {
            try successor.verifyDeviceAddition(of: result.current, device: request.identity)
            try result.append(successor)
        }
        return result
    }
    public func encoded() throws -> Data { try Codec.encode(self) }
    public static func decode(_ data: Data) throws -> Self {
        guard data.count <= Codec.maximumSize else { throw DeviceEnrollmentFailure.invalidApproval }
        let result = try JSONDecoder().decode(Self.self, from: data)
        _ = try result.verifiedHistory()
        return result
    }
}
