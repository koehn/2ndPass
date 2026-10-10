import Foundation
import MopCore
import MopSync
import MopVaultNext

/// Executes inside the account engine's existing lease. It never starts an
/// engine, acquires another lease, or requires secret keys for signed genesis.
public struct JournaledContentProvisioner: Sendable {
    private let repository: EncryptedItemRepository
    private let trustStore: any ItemVaultTrustStore
    private let transport: any VaultProvisioningTransport
    private let accountValidator: CloudAccountValidator
    public init(repository: EncryptedItemRepository, trustStore: any ItemVaultTrustStore,
                transport: any VaultProvisioningTransport, accountValidator: @escaping CloudAccountValidator) {
        self.repository = repository; self.trustStore = trustStore; self.transport = transport; self.accountValidator = accountValidator
    }
    private func check(_ permit: any RepositoryWritePermit) async throws {
        try Task.checkCancellation(); try permit.withWritePermission {}
        guard try await accountValidator() else { throw CloudSyncAdapterError.accountChanged }
        try permit.withWritePermission {}; try Task.checkCancellation()
    }
    public func handle(_ operation: SyncOperation, permit: any RepositoryWritePermit) async -> SyncOperationOutcome {
        do {
            try await check(permit)
            guard operation.kind == .provision, repository.layout == .contentPreview3 else { return .attention(.invalidAuthority) }
            let record = try JSONDecoder().decode(ItemVaultSetupRecord.self, from: operation.payload)
            let scope = record.scope.repositoryScope
            guard operation.account == scope.account, operation.database == scope.database,
                  operation.zoneOwner == scope.zoneOwner, operation.vaultID == scope.vaultID,
                  try trustStore.load(scope: record.scope) == record else { return .attention(.invalidAuthority) }
            let genesis = try MembershipEnvelope.decode(record.genesis)
            try genesis.verifyGenesis(vault: scope.vaultID, pinnedDigest: record.pinnedDigest)
            guard genesis.membership.accounts.count == 1, genesis.membership.accounts[0].role == .owner,
                  genesis.membership.devices.count == 1 else { return .attention(.invalidAuthority) }
            let binding = try VaultProvisioningBinding(scope: scope,
                address: VaultCloudAddress(vaultID: scope.vaultID, zoneName: SyncStoreLayout.contentZone(vault: scope.vaultID), ownerName: scope.zoneOwner),
                setupID: record.setupID, controlDigest: record.pinnedDigest)
            var state = try await repository.prepareProvisioning(binding: binding, controlBytes: record.genesis, authorization: permit)
            guard state.phase != .blocked else { return .attention(.invalidAuthority) }
            if state.phase == .controlConfirmed {
                try await repository.confirmOperation(operation, permit: permit)
                return .completed
            }
            try await check(permit)
            if try await !transport.zoneExists(binding: binding) {
                try await check(permit)
                guard state.phase == .prepared else { return .attention(.invalidAuthority) }
                try await transport.createZone(binding: binding)
                try await check(permit)
                guard try await transport.zoneExists(binding: binding) else { return .retry(.transport) }
            }
            try await check(permit)
            if state.phase == .prepared { state = try await repository.advanceProvisioning(state, to: .commissioningStarted, authorization: permit) }
            var head: ProvisioningCloudRecord?
            for kind in [VaultControlRecordKind.genesis, .head] {
                var stored = try await transport.readControl(kind, binding: binding)
                try await check(permit)
                if stored == nil {
                    guard state.phase != .controlConfirmed else { return .attention(.invalidAuthority) }
                    do { _ = try await transport.createControl(kind, binding: binding, bytes: record.genesis) }
                    catch {
                        // Publication may have committed before its response was
                        // lost. Exact readback is the only delivery evidence.
                        try await check(permit)
                        guard let readback = try await transport.readControl(kind, binding: binding), readback.bytes == record.genesis else { throw error }
                    }
                    try await check(permit)
                    stored = try await transport.readControl(kind, binding: binding)
                    try await check(permit)
                }
                guard let stored, stored.bytes == record.genesis else { return .attention(.invalidAuthority) }
                try MembershipEnvelope.decode(stored.bytes).verifyGenesis(vault: scope.vaultID, pinnedDigest: record.pinnedDigest)
                if case .head = kind { head = stored }
            }
            guard let head else { return .retry(.transport) }
            try await check(permit)
            if state.phase != .controlConfirmed {
                _ = try await repository.advanceProvisioning(state, to: .controlConfirmed, headSystemFields: head.systemFields, authorization: permit)
            }
            try await repository.confirmOperation(operation, permit: permit)
            return .completed
        } catch MopError.authentication { return .authorization }
        catch CloudSyncAdapterError.accountChanged { return .retry(.accountChanged) }
        catch ItemVaultBootstrapFailure.invalidTrust { return .attention(.invalidAuthority) }
        catch VaultProvisioningError.invalidBinding { return .attention(.invalidAuthority) }
        catch VaultProvisioningError.controlMismatch { return .attention(.invalidAuthority) }
        catch SyncJournalError.staleOperation { return .retry(.dependency) }
        catch { return .retry(.transport) }
    }
}
