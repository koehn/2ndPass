import Foundation
import MopCore
import MopSync
import MopVaultNext

/// A head can advance only an independently pinned chain. Out-of-order immutable
/// proposals remain candidates; neither their arrival nor discovery installs trust.
public struct GrantBackedMembershipInbox: Sendable {
    public let repository: EncryptedItemRepository
    public let trustStore: any ItemVaultMembershipTrustStore
    public let record: ItemVaultSetupRecord
    public let committed: @Sendable (TrustedMembershipHistory) async throws -> Void

    public init(repository: EncryptedItemRepository, trustStore: any ItemVaultMembershipTrustStore,
                record: ItemVaultSetupRecord, committed: @escaping @Sendable (TrustedMembershipHistory) async throws -> Void) {
        self.repository = repository; self.trustStore = trustStore; self.record = record; self.committed = committed
    }

    public func handle(_ operation: SyncOperation, permit: any RepositoryWritePermit) async -> SyncOperationOutcome {
        do {
            let scope = record.scope.repositoryScope
            guard operation.kind == .applyIncoming, operation.account == scope.account,
                  operation.database == scope.database, operation.vaultID == scope.vaultID,
                  operation.zoneOwner == scope.zoneOwner,
                  let id = String(data: operation.payload, encoding: .utf8) else { return .attention(.invalidAuthority) }
            guard let incoming = try await repository.incomingRecord(id: id, account: scope.account, database: scope.database) else { return .completed }
            do {
                guard incoming.zoneName == SyncStoreLayout.contentZone(vault: scope.vaultID),
                      incoming.recordType == NativeVaultProvisioningTransport.recordType else { throw MopError.vaultUntrusted }
                let candidate = try MembershipEnvelope.decode(incoming.bytes)
                let digest = try candidate.digest()
                if incoming.recordName != "membership-head" {
                    guard incoming.recordName == "membership-" + digest else { throw MopError.vaultUntrusted }
                    let pinned = try ItemVaultMembershipAuthority.history(record: record, trustStore: trustStore, allowingDeviceRemoval: true)
                    if let known = try? pinned.state(forDigest: digest) {
                        guard known == candidate else { throw MopError.vaultUntrusted }
                        try await repository.completeIncoming(incoming, failure: nil, permit: permit)
                        return .completed
                    }
                    // Uncommitted proposals remain in the bounded inbox. Only a
                    // verified committed head may move them into pinned history.
                    return .retry(.dependency)
                }
                var history = try ItemVaultMembershipAuthority.history(record: record, trustStore: trustStore, allowingDeviceRemoval: true)
                // Delayed historical heads acknowledge data without rolling back a pin.
                if let known = try? history.state(forDigest: digest) {
                    guard known == candidate else { throw MopError.vaultUntrusted }
                } else {
                    var cursor = candidate, reversed: [MembershipEnvelope] = []
                    let current = try history.current.digest()
                    while try cursor.digest() != current {
                        guard cursor.header.generation > history.current.header.generation,
                              reversed.count < 4095, let parent = cursor.header.parent else { throw MopError.vaultUntrusted }
                        reversed.append(cursor)
                        if parent == current { break }
                        guard let bytes = try await repository.contentMembershipCandidate(scope: scope, digest: parent) else {
                            let dependency = SyncDependency(.membership, identifier: scope.vaultID.uuidString + ":" + parent)
                            guard let fetch = ContentMembershipFetch(dependency: dependency) else { throw MopError.vaultUntrusted }
                            _ = try await repository.enqueue(fetch.operation(account: scope.account, owner: scope.zoneOwner))
                            return .retry(.dependency)
                        }
                        cursor = try MembershipEnvelope.decode(bytes)
                        guard try cursor.digest() == parent else { throw MopError.vaultUntrusted }
                    }
                    for successor in reversed.reversed() {
                        if let request = successor.recoveryRequest {
                            guard request.scope.container == record.scope.container, request.scope.environment == record.scope.environment,
                                  request.scope.account == record.scope.binding.account else { throw MopError.vaultUntrusted }
                        }
                        try successor.verifyAccountTransition(of: history.current, allowingDeviceRemoval: true)
                        try history.append(successor)
                    }
                    guard history.current == candidate else { throw MopError.vaultUntrusted }
                    try permit.withWritePermission {
                        try trustStore.reserveMembership(scope: record.scope, successors: history.orderedStates.dropFirst().map { try $0.encoded() })
                    }
                }
                // Repair a crash after reserving Keychain checkpoints but before
                // updating the derived SQLite policy. Replays are idempotent.
                let old = try await repository.contentRecipients(scope: scope)
                if let old { _ = try history.state(forDigest: old.membership) }
                try await repository.setContentRecipients(scope: scope, expected: old,
                    policy: GrantBackedContentStorage.recipientPolicy(history: history), authorization: permit)
                if let provisioned = try await repository.provisioning(scope), provisioned.controlBytes != (try history.current.encoded()) {
                    try await repository.acceptMembershipHead(scope: scope, expectedControl: provisioned.controlBytes,
                        control: history.current.encoded(), headSystemFields: history.current == candidate ? incoming.systemFields : nil, authorization: permit)
                }
                try await committed(history)
                try await repository.completeIncoming(incoming, failure: nil, permit: permit)
                return .completed
            } catch let error as MopError where error == .vaultUntrusted || error == .invalidVault {
                try await repository.quarantineIncoming(incoming, permit: permit)
                return .attention(.invalidAuthority)
            } catch is DecodingError {
                try await repository.quarantineIncoming(incoming, permit: permit)
                return .attention(.invalidAuthority)
            }
        } catch SyncJournalError.staleOperation { return .retry(.dependency) }
        catch ContentStoreError.staleAuthority { return .retry(.dependency) }
        catch { return .retry(.storagePressure) }
    }
}
