import Foundation
import MopCore
import MopAuth
import MopSync
import MopVaultNext

/// Only independently verified local evidence may discharge targeted fetches.
/// The dependent operation is left intact and executes its normal checks again.
struct TargetedSyncReconciliation {
    let repository: EncryptedItemRepository
    let account: String
    let history: @Sendable (UUID) async throws -> TrustedMembershipHistory?

    func reconcile(permit: any RepositoryWritePermit, retryMissing: Bool = false) async throws {
        for operation in try await repository.activeOperations(account: account, database: "private") {
            guard operation.state != .completed, operation.zoneOwner == "__defaultOwner__",
                  [.fetchMembership, .fetchContentVersion, .fetchContentHead].contains(operation.kind),
                  let vault = operation.vaultID else { continue }
            try permit.withWritePermission {}
            do {
                guard let trusted = try await history(vault), trusted.vault == vault else { continue }
                var reason: SyncResolution?
                switch operation.kind {
                case .fetchMembership:
                    let request = try JSONDecoder().decode(ContentMembershipFetch.self, from: operation.payload)
                    guard request.vault == vault, try request.operation(account: account, owner: operation.zoneOwner).id == operation.id else { continue }
                    if (try? trusted.state(forDigest: request.digest)) != nil { reason = .verifiedMembershipAvailable }
                case .fetchContentVersion:
                    let request = try JSONDecoder().decode(ContentVersionFetch.self, from: operation.payload)
                    guard request.vault == vault, try request.operation(account: account, owner: operation.zoneOwner).id == operation.id else { continue }
                    let scope = ItemScope(account: account, vaultID: vault, itemID: request.item, database: operation.database, zoneOwner: operation.zoneOwner)
                    if let stored = try await repository.contentVersion(scope: scope, version: request.version) {
                        let envelope = try ContentEnvelope.decode(stored.version.ciphertext, history: trusted, item: request.item)
                        guard envelope.header.version == request.version, stored.version.scope == scope,
                              stored.version.versionID == envelope.header.version,
                              stored.version.baseVersionID == envelope.header.base,
                              stored.version.generation == envelope.header.generation,
                              stored.version.isTombstone == envelope.header.isTombstone,
                              stored.keyGeneration == envelope.header.keyGeneration,
                              stored.contentRevision == envelope.header.contentRevision,
                              stored.membership == envelope.header.membership else { continue }
                        try GrantBackedContentStorage.validateKind(envelope, history: trusted)
                        reason = .verifiedContentAvailable
                    } else if try await retireUnusedSource(operation, request: request, scope: scope, history: trusted, permit: permit) {
                        continue
                    }
                default: break // A mutable head's presence does not prove its fetch obsolete.
                }
                if let reason {
                    try await repository.resolveSyncOperation(operation, reason: reason, permit: permit)
                    AccessSyncTrace.event("targeted operation resolved", operation: operation.id, detail: "reason=\(reason.rawValue)")
                } else if retryMissing, operation.state == .needsAttention, operation.failure == .transport {
                    try permit.withWritePermission {}
                    _ = try await repository.transition(operation,
                        to: operation.retryNotBefore.map { $0 > Date() } == true ? .retryScheduled : .ready,
                        nextAttempt: operation.retryNotBefore, retryNotBefore: operation.retryNotBefore)
                }
            } catch SyncJournalError.staleOperation { continue }
            catch where Authentication.requiresRenewal(error) { throw error }
            catch {
                // Unknown, malformed, or unverifiable evidence cannot erase work.
                AccessSyncTrace.failure("targeted operation retained", operation: operation.id, error: error)
            }
        }
    }
    private func retireUnusedSource(_ operation: SyncOperation, request: ContentVersionFetch, scope: ItemScope,
        history: TrustedMembershipHistory, permit: any RepositoryWritePermit) async throws -> Bool {
        guard let head = try await repository.item(scope) else { return false }
        let current = try ContentEnvelope.decode(head.ciphertext, history: history, item: scope.itemID)
        guard current.header.version == head.versionID, current.header.base == head.baseVersionID,
              current.header.base != request.version,
              current.header.generation == head.generation, current.header.isTombstone == head.isTombstone else { return false }
        try current.verifyForPublication(history: history)
        try GrantBackedContentStorage.validateKind(current, history: history)
        var candidates: [IncomingRecord] = [], replacements: [PreparedContentGrant] = []
        for record in try await repository.incomingRecords(account: account, database: "private") {
            guard record.vaultID == scope.vaultID, record.zoneOwner == scope.zoneOwner,
                  record.recordType == ContentRecordKind.grant.rawValue else { continue }
            let grant = try JSONDecoder().decode(ContentKeyGrant.self, from: record.bytes)
            guard grant.item == scope.itemID, grant.sourceVersion == request.version else { continue }
            let address = try ContentRecordAddress(recordType: record.recordType, zone: record.zoneName, record: record.recordName)
            guard grant.vault == scope.vaultID, address.vault == scope.vaultID, address.item == scope.itemID,
                  address.identity == (try grant.identifier), address.recipient == nil || address.recipient == grant.recipient,
                  try grant.encoded() == record.bytes else { return false }
            try grant.verifySignature(history: history)
            guard grant.keyGeneration != current.header.keyGeneration,
                  try await repository.contentVersion(scope: scope, keyGeneration: grant.keyGeneration) == nil else { return false }
            guard let replacement = try await repository.contentGrants(scope: scope, keyGeneration: current.header.keyGeneration, recipient: grant.recipient).first else { return false }
            let verified = try JSONDecoder().decode(ContentKeyGrant.self, from: replacement.bytes)
            guard replacement.scope == scope, replacement.keyGeneration == current.header.keyGeneration,
                  try verified.identifier == replacement.identifier, verified.keyGeneration == replacement.keyGeneration,
                  try verified.encoded() == replacement.bytes, verified.recipient == grant.recipient else { return false }
            try verified.verify(content: current, history: history)
            candidates.append(record); replacements.append(replacement)
        }
        let retired = try await repository.retireUnneededGrantSource(operation, head: head, grants: candidates,
            replacements: replacements, policy: GrantBackedContentStorage.recipientPolicy(history: history), permit: permit)
        if retired { AccessSyncTrace.event("unused grant source retired", operation: operation.id, item: scope.itemID, detail: "grants=\(candidates.count)") }
        return retired
    }

}
