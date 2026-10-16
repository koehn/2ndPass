@preconcurrency import CloudKit
import Foundation
import MopCore
import MopSync
import MopVaultNext

/// All inputs originate in the authenticated same-account private database.
/// Cloud discovery is only an address list; callers still verify each history.
struct NativeContentHistoryReader: Sendable {
    let account: NativeItemCloudAccount
    var database: CKDatabase { account.container.privateCloudDatabase }
    func check() async throws {
        try Task.checkCancellation()
        guard try await account.validate() else { throw MopError.cloudAccount }
    }
    func address(_ vault: UUID) -> VaultCloudAddress {
        VaultCloudAddress(vaultID: vault, zoneName: SyncStoreLayout.contentZone(vault: vault), ownerName: CKCurrentUserDefaultName)
    }
    func binding(_ vault: UUID) -> VaultProvisioningBinding {
        VaultProvisioningBinding(scope: VaultScope(account: account.accountNamespace, vaultID: vault),
            address: address(vault), setupID: "recovery", controlDigest: "")
    }
    func history(_ vault: UUID) async throws -> TrustedMembershipHistory {
        try await check()
        let transport = NativeVaultMembershipTransport(database: database), binding = binding(vault)
        let head = try await transport.readHead(binding: binding)
        var states = [try MembershipEnvelope.decode(head.bytes)]
        while let parent = states.last?.header.parent {
            guard states.count < 4096 else { throw MopError.invalidVault }
            let next = try MembershipEnvelope.decode(try await transport.readMembership(binding: binding, digest: parent))
            guard try next.digest() == parent else { throw MopError.vaultUntrusted }
            states.append(next)
        }
        guard let genesis = states.last, genesis.membership.accounts.count == 1,
              genesis.membership.accounts[0].id == account.memberID else { throw MopError.cloudPermission }
        let scope = try account.setupScope(vaultID: vault), store = try KeychainItemVaultTrustStore()
        let pinned = try store.load(scope: scope)
        let rootDigest = try genesis.digest()
        guard pinned == nil || pinned?.pinnedDigest == rootDigest else { throw MopError.vaultUntrusted }
        var history = try TrustedMembershipHistory(genesis: genesis, vault: vault, pinnedDigest: rootDigest)
        for next in states.reversed().dropFirst() {
            if let request = next.recoveryRequest {
                guard request.scope.container == account.containerIdentifier, request.scope.environment == account.environment,
                      request.scope.account == account.accountNamespace else { throw MopError.vaultUntrusted }
            }
            try next.verifyAccountTransition(of: history.current, allowingDeviceRemoval: true); try history.append(next)
        }
        if let pinned {
            let local = try ItemVaultMembershipAuthority.history(record: pinned, trustStore: store, allowingDeviceRemoval: true)
            guard try history.state(forDigest: local.current.digest()) == local.current else { throw MopError.vaultUntrusted }
        }
        try await check()
        return history
    }
}
