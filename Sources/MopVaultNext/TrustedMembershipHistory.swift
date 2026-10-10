import Foundation
import Synchronization
import MopCore

/// A verified authority chain rooted in a pin obtained through authenticated
/// enrollment. Constructing this from a cloud-provided pin would not establish
/// trust. Persist the independent pin/checkpoint in the client's trust store.
public struct TrustedMembershipHistory: Sendable {
    public let vault: UUID
    public private(set) var current: MembershipEnvelope
    /// Changes only after a successfully verified append; copies share this identity.
    public private(set) var cacheIdentity = UUID()
    public private(set) var orderedStates: [MembershipEnvelope]
    private struct Path: Hashable {
        enum Kind { case additive, contentKey, account }
        let kind: Kind
        let from: String
        var to: String? = nil
        var removal = false
    }
    private final class VerifiedPaths: Sendable {
        let values = Mutex<Set<Path>>([])
        func contains(_ path: Path) -> Bool { values.withLock { $0.contains(path) } }
        func insert(_ path: Path) { values.withLock { if $0.count >= 256 { $0.removeAll() }; $0.insert(path) } }
    }
    // Only successful checks against this immutable chain are memoized. A copy
    // keeps its own authority; append creates a fresh cache for the new chain.
    private var verifiedPaths = VerifiedPaths()
    private var states: [String: MembershipEnvelope]

    public init(genesis: MembershipEnvelope, vault: UUID, pinnedDigest: String) throws {
        try genesis.verifyGenesis(vault: vault, pinnedDigest: pinnedDigest)
        self.vault = vault
        orderedStates = [genesis]
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
        orderedStates.append(successor)
        cacheIdentity = UUID()
        verifiedPaths = VerifiedPaths()
        current = successor
    }

    public func state(forDigest digest: String) throws -> MembershipEnvelope {
        guard let value = states[digest] else { throw MopError.vaultUntrusted }
        return value
    }

    public func verifyAdditivePath(from digest: String, to targetDigest: String? = nil) throws {
        let path = Path(kind: .additive, from: digest, to: targetDigest)
        if verifiedPaths.contains(path) { return }
        var parent = try state(forDigest: digest)
        let target = try targetDigest.map { try state(forDigest: $0) } ?? current
        guard parent.header.generation <= target.header.generation else { throw MopError.vaultUntrusted }
        for next in orderedStates where next.header.generation > parent.header.generation && next.header.generation <= target.header.generation {
            let added = next.membership.devices.filter { !parent.membership.devices.contains($0) }
            guard added.count == 1, let device = added.first else { throw MopError.vaultUntrusted }
            try next.verifyDeviceAddition(of: parent, device: device)
            parent = next
        }
        guard try parent.digest() == target.digest() else { throw MopError.vaultUntrusted }
        verifiedPaths.insert(path)
    }

    /// V3 key reuse excludes recovery-authorized enrollment: recovery is an
    /// explicit rotation even when its membership shape only adds one device.
    public func verifyContentKeyPath(from digest: String, to targetDigest: String? = nil) throws {
        let path = Path(kind: .contentKey, from: digest, to: targetDigest)
        if verifiedPaths.contains(path) { return }
        try verifyAdditivePath(from: digest, to: targetDigest)
        let start = try state(forDigest: digest).header.generation
        let end = try targetDigest.map { try state(forDigest: $0).header.generation } ?? current.header.generation
        guard !orderedStates.contains(where: {
            $0.header.generation > start && $0.header.generation <= end && $0.recoveryRequest != nil
        }) else { throw MopError.vaultUntrusted }
        verifiedPaths.insert(path)
    }

    public func verifyAccountPath(from digest: String, allowingDeviceRemoval: Bool = false) throws {
        let path = Path(kind: .account, from: digest, removal: allowingDeviceRemoval)
        if verifiedPaths.contains(path) { return }
        var parent = try state(forDigest: digest)
        for next in orderedStates where next.header.generation > parent.header.generation {
            try next.verifyAccountTransition(of: parent, allowingDeviceRemoval: allowingDeviceRemoval)
            parent = next
        }
        guard try parent.digest() == current.digest() else { throw MopError.vaultUntrusted }
        verifiedPaths.insert(path)
    }

    public var count: Int { states.count }
}
