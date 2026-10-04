import Foundation
import MopCore

/// A verified authority chain rooted in a pin obtained through authenticated
/// enrollment. Constructing this from a cloud-provided pin would not establish
/// trust. Persist the independent pin/checkpoint in the client's trust store.
public struct TrustedMembershipHistory: Sendable {
    public let vault: UUID
    public private(set) var current: MembershipEnvelope
    private var states: [String: MembershipEnvelope]

    public init(genesis: MembershipEnvelope, vault: UUID, pinnedDigest: String) throws {
        try genesis.verifyGenesis(vault: vault, pinnedDigest: pinnedDigest)
        self.vault = vault
        current = genesis
        states = [pinnedDigest: genesis]
    }

    /// Only a direct successor advances authority. A competing branch requires
    /// explicit reconciliation; neither arrival order nor a larger generation
    /// authorizes replacing the current branch.
    public mutating func append(_ successor: MembershipEnvelope) throws {
        let digest = try successor.digest()
        if states[digest] != nil { return }
        try successor.verifySuccessor(of: current)
        states[digest] = successor
        current = successor
    }

    public func state(forDigest digest: String) throws -> MembershipEnvelope {
        guard let value = states[digest] else { throw MopError.vaultUntrusted }
        return value
    }

    public func verifyAdditivePath(from digest: String) throws {
        var parent = try state(forDigest: digest)
        for next in orderedStates where next.header.generation > parent.header.generation {
            let added = next.membership.devices.filter { !parent.membership.devices.contains($0) }
            guard added.count == 1, let device = added.first else { throw MopError.vaultUntrusted }
            try next.verifyDeviceAddition(of: parent, device: device)
            parent = next
        }
        guard try parent.digest() == current.digest() else { throw MopError.vaultUntrusted }
    }

    public var orderedStates: [MembershipEnvelope] { states.values.sorted { $0.header.generation < $1.header.generation } }
    public var count: Int { states.count }
}
