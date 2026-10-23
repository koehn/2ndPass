import Foundation
import CloudKit

extension EncryptedItemRepository {
    /// Caller verifies the current head and replacement grants. Recheck all local
    /// consumers atomically before archiving only an unneeded incoming grant/fetch.
    public func retireUnneededGrantSource(_ expected: SyncOperation, head: EncryptedItemVersion,
        grants: [IncomingRecord], replacements: [PreparedContentGrant], policy: ContentRecipientPolicy, permit: any RepositoryWritePermit) throws -> Bool {
        try permit.withWritePermission {
            try transaction {
                let scope = head.scope
                guard expected.kind == .fetchContentVersion, expected.account == scope.account,
                      expected.database == scope.database, expected.vaultID == scope.vaultID,
                      expected.zoneOwner == scope.zoneOwner, !grants.isEmpty,
                      try contentPolicy(VaultScope(scope)) == policy,
                      let row = try fetchOne("Item", key: scope.storageKey), try decodeVersion(row) == head,
                      try contentRows("ContentBranch", field: "scopeKey", equals: scope.storageKey).isEmpty else { return false }
                let request = try JSONDecoder().decode(ContentVersionFetch.self, from: expected.payload)
                guard request.item == scope.itemID, request.vault == scope.vaultID,
                      try request.operation(account: scope.account, owner: scope.zoneOwner).id == expected.id,
                      try fetchOne("ContentVersion", key: scope.storageKey + ":" + request.version.uuidString) == nil else { return false }
                let diagnostic: SyncTransportDetail? = try journalValue("StateBlob", key: blobKey(scope.account, "sync-error:" + scope.database + ":" + expected.id.uuidString))
                guard diagnostic?.code == CKError.unknownItem.rawValue else { return false }
                let operations = try activeOperationsInTransaction(account: scope.account, database: scope.database)
                guard operations.first(where: { $0.id == expected.id }) == expected else { throw SyncJournalError.staleOperation }
                struct Source: Decodable { let keyGeneration: UUID }
                let oldKeys = try Set(grants.map { try JSONDecoder().decode(Source.self, from: $0.bytes).keyGeneration })
                for row in try contentRows("ContentVersion", field: "scopeKey", equals: scope.storageKey) {
                    let content: PreparedContentVersion = try contentValue(row)
                    if oldKeys.contains(content.keyGeneration) { return false }
                }
                let saved: [PreparedContentGrant] = try contentRows("ContentGrant", field: "scopeKey", equals: scope.storageKey).map { try contentValue($0) }
                guard !replacements.isEmpty, replacements.allSatisfy({ saved.contains($0) }) else { return false }
                let ids = Set(grants.map(\.operationID)).union([expected.id])
                // Preserve item edits, ancestry/conflict work and all other consumers.
                let itemDependencyPrefix = request.vault.uuidString + ":" + request.item.uuidString + ":"
                guard !operations.contains(where: { !ids.contains($0.id) &&
                    ($0.dependencies.contains(where: { $0.identifier.hasPrefix(itemDependencyPrefix) ||
                        ($0.kind == .operation && UUID(uuidString: $0.identifier).map { ids.contains($0) } == true) }) ||
                     ($0.vaultID == scope.vaultID && [.publishItem, .resolveConflict, .rotateContent].contains($0.kind))) }) else { return false }
                let incoming: [IncomingRecord] = try journalValues("IncomingRecord", account: scope.account, database: scope.database)
                for grant in grants {
                    guard incoming.contains(grant), grant.recordType == ContentRecordKind.grant.rawValue,
                          grant.vaultID == scope.vaultID, grant.zoneOwner == scope.zoneOwner,
                          operations.contains(where: { $0.id == grant.operationID && $0.kind == .applyIncoming }) else { return false }
                }
                for record in incoming where record.vaultID == scope.vaultID && !ids.contains(record.operationID) {
                    if let address = try? ContentRecordAddress(recordType: record.recordType, zone: record.zoneName, record: record.recordName), address.item == scope.itemID { return false }
                }
                for record in grants {
                    try writeJournal(record, entity: "StateBlob", key: blobKey(scope.account, "discarded-incoming:" + record.id))
                    if let row = try journalRow("IncomingRecord", key: journalKey(scope.account, scope.database, record.id)) { context.delete(row) }
                }
                for var operation in operations where ids.contains(operation.id) {
                    try writeJournal(operation, entity: "StateBlob", key: blobKey(scope.account, "discarded-operation:" + operation.id.uuidString))
                    operation.state = .completed; operation.resolution = .unneededGrantSource
                    operation.completedAt = Date(); operation.deliveredAt = nil; operation.revision = UUID()
                    operation.dependencies = []; operation.failure = nil; operation.nextAttempt = nil; operation.retryNotBefore = nil
                    try writeJournal(operation, entity: "SyncOperation", key: journalKey(scope.account, scope.database, operation.id.uuidString), account: scope.account, database: scope.database)
                }
                return true
            }
        }
    }
}
