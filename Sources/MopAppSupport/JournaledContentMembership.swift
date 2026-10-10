import Foundation
import MopCore
import MopSync
import MopVaultNext

/// Publishes a previously signed additive membership operation while holding the
/// account engine's lease. Only exact committed readback releases its approval.
public struct JournaledContentMembership: Sendable {
    private let repository: EncryptedItemRepository
    private let trustStore: any ItemVaultMembershipTrustStore
    private let transport: any VaultMembershipTransport
    private let accountValidator: CloudAccountValidator
    private let scope: ItemVaultSetupScope
    private let committed: @Sendable (TrustedMembershipHistory) async throws -> Void
    public init(repository: EncryptedItemRepository, trustStore: any ItemVaultMembershipTrustStore,
                transport: any VaultMembershipTransport, scope: ItemVaultSetupScope,
                accountValidator: @escaping CloudAccountValidator,
                committed: @escaping @Sendable (TrustedMembershipHistory) async throws -> Void) {
        self.repository = repository; self.trustStore = trustStore; self.transport = transport
        self.scope = scope; self.accountValidator = accountValidator; self.committed = committed
    }
    private func check(_ permit: any RepositoryWritePermit) async throws {
        try permit.withWritePermission {}; try Task.checkCancellation()
        guard try await accountValidator() else { throw CloudSyncAdapterError.accountChanged }
        try permit.withWritePermission {}; try Task.checkCancellation()
    }
    public func handle(_ operation: SyncOperation, permit: any RepositoryWritePermit) async -> SyncOperationOutcome {
        do {
            guard operation.kind == .membership, operation.account == scope.binding.account, operation.database == "private",
                  operation.vaultID == scope.binding.vaultID, operation.zoneOwner == scope.binding.zoneOwner,
                  repository.layout == .contentPreview3 else { return .attention(.invalidAuthority) }
            try await check(permit)
            guard let pin = try trustStore.load(scope: scope) else { return .retry(.dependency) }
            let local = try ItemVaultMembershipAuthority.history(record: pin, trustStore: trustStore, allowingDeviceRemoval: true)
            let proposed: TrustedMembershipHistory
            let parent: MembershipEnvelope
            let successorState: MembershipEnvelope
            if let approval = try? DeviceEnrollmentApproval.decode(operation.payload) {
                guard !approval.isReconnect, approval.request.scope.container == scope.container,
                      approval.request.scope.environment == scope.environment, approval.request.scope.account == scope.binding.account,
                      approval.request.scope.vault == scope.binding.vaultID, let previous = approval.history.last else { return .attention(.invalidAuthority) }
                proposed = try approval.verifiedHistory(); parent = previous; successorState = approval.successor
            } else {
                let commit = try JSONDecoder().decode(ContentMembershipCommit.self, from: operation.payload)
                proposed = try commit.verified()
                guard let previous = commit.history.last, proposed.vault == scope.binding.vaultID else { return .attention(.invalidAuthority) }
                parent = previous; successorState = commit.successor
            }
            let common = min(local.count, proposed.count)
            guard Array(local.orderedStates.prefix(common)) == Array(proposed.orderedStates.prefix(common)) else { return .attention(.conflict) }
            guard let provisioned = try await repository.provisioning(scope.repositoryScope), provisioned.phase == .controlConfirmed,
                  provisioned.binding.address.zoneName == SyncStoreLayout.contentZone(vault: scope.binding.vaultID) else { return .retry(.dependency) }
            // A pin is reserved only after exact head readback. A prior attempt
            // may have advanced it and crashed before updating the local index.
            if local.count < proposed.count {
                guard local.current == parent else { return .retry(.dependency) }
                var head = try await transport.readHead(binding: provisioned.binding)
                try await check(permit)
                let successor = try successorState.encoded()
                if head.bytes != successor {
                    guard head.bytes == (try parent.encoded()) else {
                        let incoming = IncomingRecord(id: setupHash(Data((scope.binding.account + scope.binding.vaultID.uuidString + "head").utf8) + head.bytes + head.systemFields),
                            account: scope.binding.account, database: "private", zoneName: SyncStoreLayout.contentZone(vault: scope.binding.vaultID),
                            zoneOwner: scope.binding.zoneOwner, recordName: "membership-head", recordType: NativeVaultProvisioningTransport.recordType,
                            bytes: head.bytes, systemFields: head.systemFields, vaultID: scope.binding.vaultID)
                        try await repository.stageIncoming(incoming, permit: permit)
                        return .retry(.dependency)
                    }
                    try await transport.createMembership(binding: provisioned.binding, digest: successorState.digest(), bytes: successor)
                    try await check(permit)
                    do { _ = try await transport.compareAndSwapHead(binding: provisioned.binding, bytes: successor, expected: head) }
                    catch {
                        try await check(permit)
                        head = try await transport.readHead(binding: provisioned.binding)
                        guard head.bytes == successor else { throw error }
                    }
                    try await check(permit)
                    head = try await transport.readHead(binding: provisioned.binding)
                    try await check(permit)
                }
                guard head.bytes == successor else { return .retry(.dependency) }
                try permit.withWritePermission {
                    try trustStore.reserveMembership(scope: scope, successors: proposed.orderedStates.dropFirst().map { try $0.encoded() })
                }
            }
            let accepted = try ItemVaultMembershipAuthority.history(record: pin, trustStore: trustStore, allowingDeviceRemoval: true)
            let policy = try GrantBackedContentStorage.recipientPolicy(history: accepted)
            let oldPolicy = try await repository.contentRecipients(scope: scope.repositoryScope)
            if let oldPolicy {
                // Authenticate the existing index against the same pinned chain
                // before repairing a crash between Keychain and SQLite commits.
                _ = try accepted.state(forDigest: oldPolicy.membership)
            }
            try await repository.setContentRecipients(scope: scope.repositoryScope, expected: oldPolicy, policy: policy, authorization: permit)
            try await check(permit)
            try await committed(accepted)
            try await check(permit)
            try await repository.confirmOperation(operation, permit: permit)
            return .completed
        } catch MopError.authentication { return .authorization }
        catch CloudSyncAdapterError.accountChanged { return .retry(.accountChanged) }
        catch SyncJournalError.staleOperation { return .retry(.dependency) }
        catch ContentStoreError.staleAuthority { return .retry(.dependency) }
        catch { return .retry(.transport) }
    }
}
