import Foundation
import MopCore
import MopSync
import MopVaultNext

/// Authorizes cloud commissioning from independent local trust, never from a
/// downloaded record. Native composition must derive scope from the signed
/// container/environment and authenticated Apple account. Initialization performs
/// no CloudKit writes; provision is explicit. This slice supports owner-only
/// private genesis. Enrollment and membership advancement use separate workflows.
public struct ItemVaultProvisioner: Sendable {
    private let repository: EncryptedItemRepository
    private let trustStore: any ItemVaultTrustStore
    private let scope: ItemVaultSetupScope
    private let session: ItemVaultSession
    private let coordinator: VaultProvisioningCoordinator

    public init(repository: EncryptedItemRepository, trustStore: any ItemVaultTrustStore,
                scope: ItemVaultSetupScope, session: ItemVaultSession, coordinator: VaultProvisioningCoordinator) throws {
        guard scope.binding == session.binding, !scope.container.isEmpty,
              ["Development", "Production"].contains(scope.environment),
              scope.binding.database == "private", scope.binding.zoneOwner == "__defaultOwner__" else {
            throw ItemVaultBootstrapFailure.invalidScope
        }
        self.repository = repository; self.trustStore = trustStore; self.scope = scope
        self.session = session; self.coordinator = coordinator
    }

    /// Adapter ingress validates public authority while the app's private keys
    /// are locked. Explicit session retirement still rejects every late result.
    /// A locked OS Keychain may defer validation; it never substitutes cloud pins.
    public var controlValidator: CloudControlValidator {
        { [self] binding, bytes in
            // Infrastructure failures say nothing about the received signature.
            // Preserve them as retryable instead of permanently blocking a vault.
            let record: ItemVaultSetupRecord
            do {
                guard let stored = try trustStore.load(scope: scope) else { throw CloudSyncAdapterError.storageFailure }
                record = stored
            } catch { throw CloudSyncAdapterError.storageFailure }
            guard record.scope == scope else { throw CloudSyncAdapterError.storageFailure }
            try session.validateProvisioningAuthority(genesisDigest: record.pinnedDigest)
            do {
                guard binding.scope == scope.repositoryScope,
                      binding.address.vaultID == scope.binding.vaultID,
                      binding.address.ownerName == scope.binding.zoneOwner,
                      !binding.address.zoneName.isEmpty,
                      binding.setupID == (try record.setupID), binding.controlDigest == record.pinnedDigest,
                      bytes == record.genesis else { throw CloudSyncAdapterError.untrustedRecord }
                let genesis = try MembershipEnvelope.decode(bytes)
                try genesis.verifyGenesis(vault: scope.binding.vaultID, pinnedDigest: record.pinnedDigest)
                guard genesis.membership.accounts.count == 1, genesis.membership.accounts[0].role == .owner,
                      genesis.membership.devices.count == 1, genesis.membership.offlineRecovery == nil else {
                    throw CloudSyncAdapterError.untrustedRecord
                }
            } catch { throw CloudSyncAdapterError.untrustedRecord }
            let receipt: VaultInitializationReceipt
            let state: VaultProvisioningState
            do {
                guard let saved = try await repository.vaultInitialization(scope.repositoryScope),
                      let provisioned = try await repository.provisioning(scope.repositoryScope) else {
                    throw CloudSyncAdapterError.storageFailure
                }
                receipt = saved; state = provisioned
            } catch { throw CloudSyncAdapterError.storageFailure }
            try session.validateProvisioningAuthority(genesisDigest: record.pinnedDigest)
            guard state.phase == .controlConfirmed else { throw CloudSyncAdapterError.operationInterrupted }
            guard receipt.scope == binding.scope, receipt.setupID == binding.setupID,
                  receipt.membershipState == bytes, state.binding == binding, state.controlBytes == bytes else {
                throw CloudSyncAdapterError.untrustedRecord
            }
        }
    }

    public func provision(address: VaultCloudAddress) async throws -> VaultProvisioningState {
        guard address.vaultID == scope.binding.vaultID, address.ownerName == scope.binding.zoneOwner,
              !address.zoneName.isEmpty else { throw ItemVaultBootstrapFailure.invalidScope }
        guard let record = try trustStore.load(scope: scope) else { throw ItemVaultBootstrapFailure.missingSetup }
        guard record.scope == scope else { throw ItemVaultBootstrapFailure.invalidTrust }
        let genesis = try MembershipEnvelope.decode(record.genesis)
        try genesis.verifyGenesis(vault: scope.binding.vaultID, pinnedDigest: record.pinnedDigest)
        guard genesis.membership.accounts.count == 1, genesis.membership.accounts[0].role == .owner,
              genesis.membership.devices.count == 1, genesis.membership.offlineRecovery == nil else {
            throw ItemVaultBootstrapFailure.invalidTrust
        }
        let authorization = ItemVaultProvisioningPermit(session: session, digest: record.pinnedDigest)
        try authorization.withWritePermission {}
        guard let receipt = try await repository.vaultInitialization(scope.repositoryScope) else {
            throw ItemVaultBootstrapFailure.incompleteSetup
        }
        try authorization.withWritePermission {}
        guard receipt.scope == scope.repositoryScope, receipt.setupID == (try record.setupID),
              receipt.membershipState == record.genesis else { throw ItemVaultBootstrapFailure.invalidTrust }
        let binding = try VaultProvisioningBinding(scope: scope.repositoryScope, address: address,
            setupID: record.setupID, controlDigest: record.pinnedDigest)
        // The transport must read both immutable genesis and initial head back.
        // Neither another valid owner signature nor a self-selected cloud pin
        // authorizes changing the locally reserved creation operation.
        return try await coordinator.provision(binding: binding, controlBytes: record.genesis,
            authorization: authorization) { candidate, bytes in
                try authorization.withWritePermission {
                    guard candidate == binding, bytes == record.genesis else { throw ItemVaultBootstrapFailure.invalidTrust }
                    let readback = try MembershipEnvelope.decode(bytes)
                    try readback.verifyGenesis(vault: self.scope.binding.vaultID, pinnedDigest: record.pinnedDigest)
                }
            }
    }

    /// Call on account/lifecycle retirement alongside session.invalidate(). The
    /// coordinator holds its publication lease until outstanding transport work exits.
    public func stop() async { await coordinator.stop() }
}

private struct ItemVaultProvisioningPermit: RepositoryWritePermit {
    let session: ItemVaultSession
    let digest: String
    func withWritePermission<T>(_ body: () throws -> T) throws -> T {
        try session.withProvisioningPermission(genesisDigest: digest, body)
    }
}
