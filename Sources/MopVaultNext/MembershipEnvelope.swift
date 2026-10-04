import Foundation
import MopCore

/// The separate authority history for independently synchronized item records.
/// A genesis signature is not a trust anchor: its digest must be pinned through
/// an authenticated enrollment channel before any descendant is accepted.
public struct MembershipEnvelope: Codable, Equatable, Sendable {
    public struct Header: Codable, Equatable, Sendable {
        public let format: String
        public let vault: UUID
        public let generation: UInt64
        public let parent: String?
        public let author: String
    }
    public let header: Header
    public let membership: Membership
    public let signature: Data

    private struct Statement: Encodable {
        let domain = "2ndpass-membership-signature-1"
        let header: Header
        let membership: Membership
    }
    private var statement: Statement { Statement(header: header, membership: membership) }

    public static func genesis(vault: UUID = UUID(), membership: Membership,
                               owner: any DeviceOperations) throws -> Self {
        try membership.validate()
        guard membership.role(of: owner.identity) == .owner,
              membership.removedDevices?.isEmpty ?? true else { throw MopError.cloudPermission }
        return try signed(Header(format: "2ndpass-membership-1", vault: vault, generation: 1,
            parent: nil, author: owner.identity.fingerprint), membership: membership, signer: owner)
    }

    /// The caller supplies a previously authenticated/pinned parent and publishes
    /// this with a conditional head update. This pure operation performs no I/O.
    public static func successor(of parent: Self, membership: Membership,
                                 owner: any DeviceOperations) throws -> Self {
        try parent.validateStructure()
        guard parent.membership.role(of: owner.identity) == .owner,
              parent.header.generation < UInt64.max else { throw MopError.cloudPermission }
        let value = try signed(Header(format: "2ndpass-membership-1", vault: parent.header.vault,
            generation: parent.header.generation + 1, parent: parent.digest(), author: owner.identity.fingerprint),
            membership: membership, signer: owner)
        try value.verifySuccessor(of: parent)
        return value
    }

    public func verifyGenesis(vault: UUID, pinnedDigest: String) throws {
        try validateStructure()
        guard Codec.hash(pinnedDigest), try digest() == pinnedDigest,
              header.vault == vault, header.generation == 1, header.parent == nil,
              membership.removedDevices?.isEmpty ?? true,
              let author = membership.key(header.author), membership.role(of: author) == .owner,
              author.verifies(signature, message: try Codec.encode(statement)) else { throw MopError.vaultUntrusted }
    }

    /// Requires an already authenticated parent. Verifying this edge alone does
    /// not authenticate a chain's genesis, prove server freshness, or bind an
    /// Apple Account to a member UUID.
    public func verifySuccessor(of parent: Self) throws {
        try parent.validateStructure()
        try validateStructure()
        guard parent.header.generation < UInt64.max,
              header.vault == parent.header.vault, header.generation == parent.header.generation + 1,
              header.parent == (try parent.digest()), membership.owner == parent.membership.owner,
              let author = parent.membership.key(header.author), parent.membership.role(of: author) == .owner,
              author.verifies(signature, message: try Codec.encode(statement)) else { throw MopError.vaultUntrusted }
        let previouslyRemoved = Set(parent.membership.removedDevices ?? [])
        let nowRemoved = Set(membership.removedDevices ?? [])
        let previousDevices = Dictionary(uniqueKeysWithValues: parent.membership.devices.map { ($0.device, $0) })
        let currentDevices = Dictionary(uniqueKeysWithValues: membership.devices.map { ($0.device, $0) })
        let removedThisChange = Set(previousDevices.keys).subtracting(currentDevices.keys)
        guard nowRemoved.isSuperset(of: previouslyRemoved.union(removedThisChange)),
              previouslyRemoved.isDisjoint(with: currentDevices.keys),
              currentDevices.allSatisfy({ id, identity in previousDevices[id].map { $0 == identity } ?? true }) else { throw MopError.vaultUntrusted }
    }

    /// Key reuse is permitted only for an exact additive device admission.
    /// Removals, role changes, and recovery changes require separate rekeying.
    public func verifyDeviceAddition(of parent: Self, device: DevicePublicKey) throws {
        try verifySuccessor(of: parent)
        let before = parent.membership, after = membership
        guard before.accounts.count == 1, before.accounts[0].role == .owner,
              before.accounts[0].id == device.member,
              before.offlineRecovery == after.offlineRecovery, before.removedDevices == after.removedDevices,
              before.accounts.count == after.accounts.count,
              !before.devices.contains(where: { $0.device == device.device }),
              before.accounts.contains(where: { $0.id == device.member }),
              after.devices.count == before.devices.count + 1 else { throw MopError.vaultUntrusted }
        for account in before.accounts {
            guard let next = after.accounts.first(where: { $0.id == account.id }), next.role == account.role,
                  Set(next.devices.map(\.fingerprint)) == Set((account.devices + (account.id == device.member ? [device] : [])).map(\.fingerprint)) else {
                throw MopError.vaultUntrusted
            }
        }
    }

    public func encoded() throws -> Data {
        try validateStructure()
        let data = try Codec.encode(self)
        guard data.count <= Codec.maximumSize else { throw MopError.invalidVault }
        return data
    }
    public func digest() throws -> String { try Codec.digest(encoded()) }

    /// Parsing is not authorization. Call verifyGenesis or verifySuccessor using
    /// the independent pin/checkpoint before exposing membership to item readers.
    public static func decode(_ data: Data) throws -> Self {
        guard data.count <= Codec.maximumSize else { throw MopError.invalidVault }
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard try value.encoded() == data else { throw MopError.invalidVault }
        return value
    }
    private static func signed(_ header: Header, membership: Membership,
                               signer: any DeviceOperations) throws -> Self {
        try membership.validate()
        let value = Self(header: header, membership: membership,
            signature: try signer.sign(Codec.encode(Statement(header: header, membership: membership))))
        try value.validateStructure()
        return value
    }
    private func validateStructure() throws {
        try membership.validate()
        guard header.format == "2ndpass-membership-1", header.generation > 0,
              (header.generation == 1) == (header.parent == nil),
              header.parent.map(Codec.hash) ?? true,
              Codec.hash(header.author), signature.count == 64 else { throw MopError.invalidVault }
    }
}
