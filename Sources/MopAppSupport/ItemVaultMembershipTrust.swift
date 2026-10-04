import Foundation
import MopCore
import MopVaultNext

/// Successors are immutable checkpoints; the independent genesis pin is never
/// replaced. Each slot must be create-only to reject competing authority branches.
public protocol ItemVaultMembershipTrustStore: ItemVaultTrustStore {
    func membershipHistory(scope: ItemVaultSetupScope) throws -> [Data]
    func reserveMembership(scope: ItemVaultSetupScope, successors: [Data]) throws
}

public enum ItemVaultMembershipAuthority {
    public static func history(record: ItemVaultSetupRecord, trustStore: any ItemVaultTrustStore) throws -> TrustedMembershipHistory {
        let successors = try (trustStore as? any ItemVaultMembershipTrustStore)?.membershipHistory(scope: record.scope) ?? []
        return try history(record: record, successors: successors)
    }
    public static func history(record: ItemVaultSetupRecord, successors: [Data]) throws -> TrustedMembershipHistory {
        guard successors.count <= 127 else { throw ItemVaultBootstrapFailure.invalidTrust }
        var history = try TrustedMembershipHistory(genesis: MembershipEnvelope.decode(record.genesis),
            vault: record.scope.binding.vaultID, pinnedDigest: record.pinnedDigest)
        for bytes in successors {
            let next = try MembershipEnvelope.decode(bytes)
            try validateAddition(previous: history.current, next: next)
            try history.append(next)
        }
        return history
    }
    /// This stage only admits devices to the same owner account. Removal, role
    /// changes, and shared-account admission require a separate rotation workflow.
    public static func validateAddition(previous: MembershipEnvelope, next: MembershipEnvelope) throws {
        try next.verifySuccessor(of: previous)
        let old = previous.membership, new = next.membership
        guard old.accounts.count == 1, new.accounts.count == 1,
              old.accounts[0].id == new.accounts[0].id,
              old.accounts[0].role == .owner, new.accounts[0].role == .owner,
              old.offlineRecovery == new.offlineRecovery,
              old.removedDevices == new.removedDevices,
              new.devices.count == old.devices.count + 1,
              old.devices.allSatisfy({ new.devices.contains($0) }) else { throw ItemVaultBootstrapFailure.invalidTrust }
    }
}
