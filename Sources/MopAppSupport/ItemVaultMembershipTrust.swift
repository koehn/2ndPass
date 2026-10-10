import Foundation
import Synchronization
import MopCore
import MopVaultNext

/// Successors are immutable checkpoints; the independent genesis pin is never
/// replaced. Each slot must be create-only to reject competing authority branches.
public protocol ItemVaultMembershipTrustStore: ItemVaultTrustStore {
    func membershipHistory(scope: ItemVaultSetupScope) throws -> [Data]
    func reserveMembership(scope: ItemVaultSetupScope, successors: [Data]) throws
}

public enum ItemVaultMembershipAuthority {
    fileprivate struct CachedHistory: Sendable {
        let record: ItemVaultSetupRecord
        let successors: [Data]
        let allowingDeviceRemoval: Bool
        let history: TrustedMembershipHistory
        var bytes: Int { record.genesis.count + successors.reduce(0) { $0 + $1.count } }
    }
    // Exact independently pinned input and validation policy, never a cloud hint.
    // Bounded process-local cache of public authority data; failures are not cached.
    final class Cache: Sendable {
        fileprivate let histories = Mutex<[CachedHistory]>([])
    }
    private static let sharedCache = Cache()

    public static func history(record: ItemVaultSetupRecord, trustStore: any ItemVaultTrustStore, allowingDeviceRemoval: Bool = false) throws -> TrustedMembershipHistory {
        let successors = try (trustStore as? any ItemVaultMembershipTrustStore)?.membershipHistory(scope: record.scope) ?? []
        return try history(record: record, successors: successors, allowingDeviceRemoval: allowingDeviceRemoval)
    }
    public static func history(record: ItemVaultSetupRecord, successors: [Data], allowingDeviceRemoval: Bool = false) throws -> TrustedMembershipHistory {
        try history(record: record, successors: successors, allowingDeviceRemoval: allowingDeviceRemoval, cache: sharedCache)
    }
    static func history(record: ItemVaultSetupRecord, successors: [Data], allowingDeviceRemoval: Bool = false, cache: Cache) throws -> TrustedMembershipHistory {
        guard successors.count <= 4095 else { throw ItemVaultBootstrapFailure.invalidTrust }
        if let cached = cache.histories.withLock({ entries in
            guard let index = entries.firstIndex(where: { $0.record == record && $0.successors == successors && $0.allowingDeviceRemoval == allowingDeviceRemoval }) else { return nil as TrustedMembershipHistory? }
            let entry = entries.remove(at: index)
            entries.append(entry)
            return entry.history
        }) { return cached }
        var history = try TrustedMembershipHistory(genesis: MembershipEnvelope.decode(record.genesis),
            vault: record.scope.binding.vaultID, pinnedDigest: record.pinnedDigest)
        for bytes in successors {
            let next = try MembershipEnvelope.decode(bytes)
            if let request = next.recoveryRequest {
                guard request.scope.container == record.scope.container, request.scope.environment == record.scope.environment,
                      request.scope.account == record.scope.binding.account else { throw ItemVaultBootstrapFailure.invalidTrust }
            }
            try next.verifyAccountTransition(of: history.current, allowingDeviceRemoval: allowingDeviceRemoval)
            try history.append(next)
        }
        let entry = CachedHistory(record: record, successors: successors, allowingDeviceRemoval: allowingDeviceRemoval, history: history)
        if entry.bytes <= 4 * 1024 * 1024 {
            cache.histories.withLock { entries in
                while !entries.isEmpty && (entries.count >= 16 || entries.reduce(0, { $0 + $1.bytes }) + entry.bytes > 4 * 1024 * 1024) { entries.removeFirst() }
                entries.append(entry)
            }
        }
        return history
    }
    /// This stage only admits devices to the same owner account. Removal, role
    /// changes, and shared-account admission require a separate rotation workflow.
    public static func validateAddition(previous: MembershipEnvelope, next: MembershipEnvelope) throws {
        try next.verifyAccountTransition(of: previous)
    }
}
