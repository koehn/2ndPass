@preconcurrency import CoreData
import Foundation

struct ConsumerHistoryCheckpoint: Codable {
    let token: Data
    let updatedAt: Date
}

extension EncryptedItemRepository {
    /// Only the lease holder prunes. An expired consumer receives no checkpoint
    /// and rebuilds its local projection before adopting a fresh history token.
    public func pruneHistory(permit: any RepositoryWritePermit, now: Date = Date()) throws {
        try permit.withWritePermission {
            try transaction(publishLocalChanges: false) {
                let cutoff = now.addingTimeInterval(-30 * 86400)
                let rows = try context.fetch(NSFetchRequest<NSManagedObject>(entityName: "HistoryCheckpoint"))
                var tokens: [NSPersistentHistoryToken] = []
                for row in rows {
                    guard let data = row.value(forKey: "value") as? Data,
                          let checkpoint = try? JSONDecoder().decode(ConsumerHistoryCheckpoint.self, from: data),
                          checkpoint.updatedAt >= cutoff,
                          let token = try NSKeyedUnarchiver.unarchivedObject(ofClass: NSPersistentHistoryToken.self, from: checkpoint.token) else {
                        context.delete(row); continue
                    }
                    tokens.append(token)
                }
                let request = NSPersistentHistoryChangeRequest.fetchHistory(after: nil as NSPersistentHistoryToken?)
                request.resultType = .transactionsOnly
                guard let result = try context.execute(request) as? NSPersistentHistoryResult,
                      let transactions = result.result as? [NSPersistentHistoryTransaction] else { throw ItemRepositoryError.corruptStore }
                // A token absent from retained history needs a full local read;
                // conservatively retain history if an active checkpoint is unknown.
                guard tokens.allSatisfy({ token in transactions.contains { $0.token == token } }) else { return }
                let earliest = transactions.filter { transaction in tokens.contains(transaction.token) }.map(\.timestamp).min()
                let boundary = min(earliest ?? cutoff, cutoff)
                _ = try context.execute(NSPersistentHistoryChangeRequest.deleteHistory(before: boundary))
            }
        }
    }
}
