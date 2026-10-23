@preconcurrency import CoreData
import Foundation

extension EncryptedItemRepository {
    /// Explicit user cancellation, never an automatic age-based security decision.
    /// Archive encrypted work before removing it from active queues; no delivery receipt is fabricated.
    public func discardSyncWork(account: String, interval: DateInterval, permit: any RepositoryWritePermit) throws -> Int {
        try permit.withWritePermission {
            try transaction {
                let operations = try activeOperationsInTransaction(account: account, database: "private")
                    .filter { $0.createdAt >= interval.start && $0.createdAt < interval.end }
                let ids = Set(operations.map(\.id))
                for var operation in operations {
                    try writeJournal(operation, entity: "StateBlob", key: blobKey(account, "discarded-operation:" + operation.id.uuidString))
                    operation.state = .completed; operation.resolution = .discardedByUser
                    operation.completedAt = Date(); operation.deliveredAt = nil; operation.revision = UUID()
                    operation.dependencies = []; operation.failure = nil; operation.nextAttempt = nil; operation.retryNotBefore = nil
                    try writeJournal(operation, entity: "SyncOperation", key: journalKey(account, "private", operation.id.uuidString), account: account, database: "private")
                }
                let incoming: [IncomingRecord] = try journalValues("IncomingRecord", account: account, database: "private")
                for record in incoming where ids.contains(record.operationID) {
                    try writeJournal(record, entity: "StateBlob", key: blobKey(account, "discarded-incoming:" + record.id))
                    if let row = try journalRow("IncomingRecord", key: journalKey(account, "private", record.id)) { context.delete(row) }
                }
                let query = NSFetchRequest<NSManagedObject>(entityName: "PendingMutation")
                query.predicate = NSPredicate(format: "account == %@ AND database == %@", account, "private")
                for row in try context.fetch(query) {
                    guard let id = row.value(forKey: "mutationID") as? UUID, ids.contains(id) else { continue }
                    let version = try decodeVersion(row)
                    try writeJournal(version, entity: "StateBlob", key: blobKey(account, "discarded-edit:" + id.uuidString))
                    try writeJournal(true, entity: "StateBlob", key: "discarded-content-version:" + version.scope.storageKey + ":" + version.versionID.uuidString)
                    if let receipt = try fetchOne("MutationReceipt", key: id.uuidString) {
                        receipt.setValue(MutationDeliveryStatus.superseded.rawValue, forKey: "status")
                    }
                    context.delete(row)
                }
                return operations.count
            }
        }
    }
}
