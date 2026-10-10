@preconcurrency import CoreData
import Foundation

protocol JournalProjectionValue {
    var includeInJournalProjection: Bool { get }
}
/// Queue-confined projections, refreshed from persistent history before every
/// repository transaction. No secrets are decrypted or authority decisions cached.
final class JournalReadCache: @unchecked Sendable {
    struct Metrics: Sendable {
        var fullFetches = 0
        var decodedRows = 0
        var changedRows = 0
        var derivedBuilds = 0
        var summaryUpdates = 0
        var resultBuilds = 0
    }
    private struct Query: Hashable {
        let prefix: String
        let type: ObjectIdentifier
    }
    // Queue-confined reference containers avoid copying nested dictionaries on
    // each row update. Typed storage also avoids copying a summary out of Any.
    private class Summary {
        func apply(_ row: Any, added: Bool) { preconditionFailure("abstract summary") }
    }
    private final class TypedSummary<T, R>: Summary {
        var value: R
        let update: (inout R, T, Bool) -> Void
        init(value: R, update: @escaping (inout R, T, Bool) -> Void) {
            self.value = value; self.update = update
        }
        override func apply(_ row: Any, added: Bool) { update(&value, row as! T, added) }
    }
    private final class Projection {
        var derived: [ObjectIdentifier: Any] = [:]
        var summaries: [ObjectIdentifier: Summary] = [:]
        var values: [NSManagedObjectID: Any]
        let decode: (Data) throws -> Any
        init(values: [NSManagedObjectID: Any], decode: @escaping (Data) throws -> Any) {
            self.values = values; self.decode = decode
        }
    }
    private var projections: [Query: Projection] = [:]
    private var results: [String: Any] = [:]
    private var token: NSPersistentHistoryToken?
    private var checkpointAt = Date()
    private(set) var metrics = Metrics()

    func reset() { projections.removeAll(); results.removeAll(); token = nil }

    func begin(in context: NSManagedObjectContext, persistent: Bool) throws {
        guard !projections.isEmpty else { return }
        guard persistent, checkpointAt.timeIntervalSinceNow > -29 * 86400 else { reset(); return }
        let request = NSPersistentHistoryChangeRequest.fetchHistory(after: token)
        request.resultType = .transactionsAndChanges
        do {
            guard let result = try context.execute(request) as? NSPersistentHistoryResult,
                  let transactions = result.result as? [NSPersistentHistoryTransaction] else {
                throw ItemRepositoryError.corruptStore
            }
            let ids = Set(transactions.flatMap { $0.changes ?? [] }.map(\.changedObjectID)
                .filter { $0.entity.name == "StateBlob" })
            if !ids.isEmpty { results.removeAll() }
            // Remove first: a deleted object has no row to fetch. Updated rows
            // are decoded only for projections whose prefix they match.
            for projection in projections.values {
                for id in ids {
                    if let old = projection.values.removeValue(forKey: id) {
                        projection.derived.removeAll()
                        for summary in projection.summaries.values {
                            summary.apply(old, added: false)
                            metrics.summaryUpdates += 1
                        }
                    }
                }
            }
            if !ids.isEmpty {
                let fetch = NSFetchRequest<NSManagedObject>(entityName: "StateBlob")
                fetch.predicate = NSPredicate(format: "SELF IN %@", Array(ids))
                fetch.returnsObjectsAsFaults = false
                for row in try context.fetch(fetch) { try update(row) }
                metrics.changedRows += ids.count
            }
            if let last = transactions.last { token = last.token }
            checkpointAt = Date()
        } catch {
            // Expired history or a failed incremental read cannot leave stale
            // projections usable. The next query reconstructs from current rows.
            reset()
            throw error
        }
    }

    func values<T: Decodable>(prefix: String, in context: NSManagedObjectContext) throws -> [T] {
        let key = Query(prefix: prefix, type: ObjectIdentifier(T.self))
        if projections[key] == nil {
            if projections.isEmpty {
                // Capture before fetching so a concurrent writer is observed on
                // the next transaction even if it commits during this read.
                token = context.persistentStoreCoordinator?.currentPersistentHistoryToken(fromStores: nil)
                checkpointAt = Date()
            }
            let request = NSFetchRequest<NSManagedObject>(entityName: "StateBlob")
            request.predicate = NSPredicate(format: "key BEGINSWITH %@", prefix)
            request.returnsObjectsAsFaults = false
            let decoder = JSONDecoder()
            var values: [NSManagedObjectID: Any] = [:]
            for row in try context.fetch(request) where !row.isDeleted && !row.isInserted {
                guard let data = row.value(forKey: "value") as? Data else { throw ItemRepositoryError.corruptStore }
                let value = try decoder.decode(T.self, from: data)
                if (value as? any JournalProjectionValue)?.includeInJournalProjection != false { values[row.objectID] = value }
                metrics.decodedRows += 1
            }
            projections[key] = Projection(values: values, decode: { try JSONDecoder().decode(T.self, from: $0) })
            metrics.fullFetches += 1
        }
        // Queries within an atomic batch must include its unsaved changes.
        // Persisted cache entries are refreshed via history on the next call;
        // rollback discards all projections in the repository transaction wrapper.
        var values = projections[key]!.values
        for row in context.insertedObjects.union(context.updatedObjects).union(context.deletedObjects)
            where row.entity.name == "StateBlob" {
            values[row.objectID] = nil
            if !row.isDeleted, let name = row.value(forKey: "key") as? String, name.hasPrefix(prefix) {
                guard let data = row.value(forKey: "value") as? Data else { throw ItemRepositoryError.corruptStore }
                let value = try JSONDecoder().decode(T.self, from: data)
                if (value as? any JournalProjectionValue)?.includeInJournalProjection != false { values[row.objectID] = value }
                metrics.decodedRows += 1
            }
        }
        return try values.values.map {
            guard let value = $0 as? T else { throw ItemRepositoryError.corruptStore }
            return value
        }
    }

    // Derived results are usable only for committed rows. Unsaved transactions
    // use their overlay without publishing a result that could survive rollback.
    func derived<T: Decodable, R>(prefix: String, in context: NSManagedObjectContext,
                                 transform: ([T]) -> R) throws -> R {
        let key = Query(prefix: prefix, type: ObjectIdentifier(T.self)), type = ObjectIdentifier(R.self)
        if !context.hasChanges, let result = projections[key]?.derived[type] as? R { return result }
        let result = transform(try values(prefix: prefix, in: context))
        metrics.derivedBuilds += 1
        if !context.hasChanges { projections[key]?.derived[type] = result }
        return result
    }

    func summary<T: Decodable, R>(prefix: String, in context: NSManagedObjectContext, initial: R,
                                 update: @escaping (inout R, T, Bool) -> Void) throws -> R {
        let key = Query(prefix: prefix, type: ObjectIdentifier(T.self)), type = ObjectIdentifier(R.self)
        if !context.hasChanges, let summary = projections[key]?.summaries[type] as? TypedSummary<T, R> { return summary.value }
        let rows: [T] = try values(prefix: prefix, in: context)
        var result = initial
        for row in rows { update(&result, row, true); metrics.summaryUpdates += 1 }
        if !context.hasChanges {
            projections[key]?.summaries[type] = TypedSummary(value: result, update: update)
        }
        return result
    }

    /// Complete read-only results share the same history checkpoint as projections.
    /// Unsaved writes must never publish an overlay into this cache.
    func result<R>(key: String, in context: NSManagedObjectContext, build: () throws -> R) rethrows -> R {
        if !context.hasChanges, let result = results[key] as? R { return result }
        let result = try build()
        metrics.resultBuilds += 1
        if !context.hasChanges { results[key] = result }
        return result
    }

    private func update(_ row: NSManagedObject) throws {
        guard let name = row.value(forKey: "key") as? String else { throw ItemRepositoryError.corruptStore }
        for (key, projection) in projections where name.hasPrefix(key.prefix) {
            guard let bytes = row.value(forKey: "value") as? Data else { throw ItemRepositoryError.corruptStore }
            let value = try projection.decode(bytes)
            if (value as? any JournalProjectionValue)?.includeInJournalProjection != false {
                projection.values[row.objectID] = value
                projection.derived.removeAll()
                for summary in projection.summaries.values {
                    summary.apply(value, added: true)
                    metrics.summaryUpdates += 1
                }
            }
            metrics.decodedRows += 1
        }
    }
}
