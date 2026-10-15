@preconcurrency import CoreData
import Foundation
import Testing
@testable import MopSync

private enum BenchmarkWait: Error { case metadataNotAvailable }

private struct BenchmarkHealth: Decodable {
    let kind: SyncOperation.Kind
    let id: UUID
    let state: SyncOperationState
    let createdAt: Date
    let deliveredAt: Date?
    let failure: SyncFailure?
}

extension EncryptedItemRepository {
    fileprivate func seedLargeJournal(incomingCount: Int = 200, incomingBytes: Int = 32768) throws {
        try transaction {
            let encoder = JSONEncoder()
            func insert<T: Encodable>(_ value: T, entity: String, id: String) throws {
                let row = NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
                row.setValue("sync-journal-v1:" + entity + ":" + journalKey("benchmark", "private", id), forKey: "key")
                row.setValue(try encoder.encode(value), forKey: "value")
            }
            // A thousand-item vault with retained publication/reception history.
            for index in 0..<11_000 {
                var operation = SyncOperation(account: "benchmark", kind: .publishItem, payload: Data(repeating: 7, count: 1024))
                if index < 10_000 { operation.state = .completed; operation.completedAt = Date() }
                try insert(operation, entity: "SyncOperation", id: operation.id.uuidString)
            }
            for index in 0..<incomingCount {
                let record = IncomingRecord(id: "incoming-\(index)", account: "benchmark", database: "private",
                    zoneName: "zone", zoneOwner: "owner", recordName: "record-\(index)", recordType: "content",
                    bytes: Data(repeating: 1, count: incomingBytes), systemFields: Data())
                try insert(record, entity: "IncomingRecord", id: record.id)
                let operation = SyncOperation(id: record.operationID, account: "benchmark", kind: .applyIncoming,
                    payload: Data(record.id.utf8), now: record.receivedAt)
                try insert(operation, entity: "SyncOperation", id: operation.id.uuidString)
            }
        }
    }

    fileprivate func previousDerivedPass() throws -> Int {
        try transaction {
            let operations: [SyncOperation] = try journalValues("SyncOperation", account: "benchmark", database: "private")
            let sorted = operations.sorted { ($0.createdAt, $0.id.uuidString) < ($1.createdAt, $1.id.uuidString) }
            let assets = Set(sorted.filter { $0.kind == .publishCoordination && $0.state != .completed }.map(\.id))
            let health: [BenchmarkHealth] = try journalValues("SyncOperation", account: "benchmark", database: "private")
            let active = operations.filter { $0.state != .completed }.sorted { ($0.createdAt, $0.id.uuidString) < ($1.createdAt, $1.id.uuidString) }
            return active.count + assets.count + health.filter { $0.state != .completed }.count
        }
    }

    fileprivate func replaceHealthFixture(_ operation: SyncOperation, delete: Bool = false, rollback: Bool = false) throws {
        try transaction {
            let key = journalKey(operation.account, operation.database, operation.id.uuidString)
            if delete {
                if let row = try journalRow("SyncOperation", key: key) { context.delete(row) }
            } else { try writeJournal(operation, entity: "SyncOperation", key: key) }
            if rollback { throw SyncJournalError.invalidOperation }
        }
    }

    fileprivate func previousConflictStatusPass() throws {
        try transaction {
            let operations: [SyncOperation] = try journalValues("SyncOperation", account: "benchmark", database: "private")
            _ = operations.filter { $0.kind == .resolveConflict && ![.completed, .needsAttention].contains($0.state) }
            let request = NSFetchRequest<NSManagedObject>(entityName: "StateBlob")
            request.predicate = NSPredicate(format: "key BEGINSWITH %@", "deletion:")
            _ = try context.fetch(request)
        }
    }
    fileprivate func historyTransactionCount() throws -> Int {
        try transaction {
            let request = NSPersistentHistoryChangeRequest.fetchHistory(after: nil as NSPersistentHistoryToken?)
            request.resultType = .count
            guard let result = try context.execute(request) as? NSPersistentHistoryResult,
                  let count = result.result as? Int else { throw ItemRepositoryError.corruptStore }
            return count
        }
    }
    fileprivate func writeDeletionFixture(_ value: VaultDeletionState?, scope: VaultScope) throws {
        try transaction {
            let key = "deletion:" + scope.storageKey
            if let value { try writeJournal(value, entity: "StateBlob", key: key) }
            else if let row = try journalRow("StateBlob", key: key) { context.delete(row) }
        }
    }

    fileprivate func metrics() -> JournalReadCache.Metrics { journalReadCache.metrics }

    /// The old query shape, retained only in this benchmark for a same-store,
    /// same-process comparison: fault each row and decode the entire journal.
    fileprivate func legacyJournalPass() throws -> Int {
        try transaction {
            func read<T: Decodable>(_ type: T.Type, entity: String) throws -> [T] {
                let request = NSFetchRequest<NSManagedObject>(entityName: "StateBlob")
                request.predicate = NSPredicate(format: "key BEGINSWITH %@", "sync-journal-v1:" + entity + ":" + journalKey("benchmark", "private", ""))
                return try context.fetch(request).map {
                    try JSONDecoder().decode(T.self, from: $0.value(forKey: "value") as! Data)
                }
            }
            let health = try read(BenchmarkHealth.self, entity: "SyncOperation")
            let operations = try read(SyncOperation.self, entity: "SyncOperation")
            let incoming = try read(IncomingRecord.self, entity: "IncomingRecord")
            return health.count + operations.count + incoming.count
        }
    }

    fileprivate func simulatePreviousReadFailureInvalidation() { journalReadCache.reset() }

    fileprivate func waitForBenchmarkMetadata(vault: UUID) throws {
        let scope = ItemScope(account: "benchmark", vaultID: vault,
            itemID: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!)
        // Same boundary as vaultMetadata(): repository read returns nil, then
        // the session reports an expected metadata wait outside the transaction.
        guard try item(scope) != nil else { throw BenchmarkWait.metadataNotAvailable }
    }

    fileprivate func rollbackProjectionChange(_ operation: SyncOperation) throws {
        try transaction {
            var changed = operation; changed.state = .completed
            try writeJournal(changed, entity: "SyncOperation", key: journalKey(operation.account, operation.database, operation.id.uuidString))
            let active = try activeOperationsInTransaction(account: operation.account, database: operation.database)
            guard !active.contains(where: { $0.id == operation.id }) else { throw ItemRepositoryError.corruptStore }
            throw SyncJournalError.invalidOperation
        }
    }
}

@Suite struct JournalPerformanceTests {
    @Test func derivedQueriesAvoidRepeatedSortingAndReceiptScans() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("ContentPreview3/Content3.sqlite")
        let repository = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        try await repository.seedLargeJournal()
        func pass() async throws {
            #expect(try await repository.syncHealth(account: "benchmark", database: "private").pendingCount == 1200)
            #expect(try await repository.activeOperations(account: "benchmark", database: "private").count == 1200)
            #expect(try await repository.pendingCoordinationAssetOperations(account: "benchmark", database: "private").isEmpty)
        }
        try await pass()
        let before = await repository.metrics(), clock = ContinuousClock(), start = clock.now
        for _ in 0..<20 { try await pass() }
        let elapsed = start.duration(to: clock.now), after = await repository.metrics()
        #expect(after.derivedBuilds == before.derivedBuilds)
        #expect(after.summaryUpdates == before.summaryUpdates)
        #expect(after.decodedRows == before.decodedRows)
        _ = try await repository.previousDerivedPass() // Warm the previous decoded projections too.
        let baseline = clock.now
        for _ in 0..<20 { #expect(try await repository.previousDerivedPass() == 2400) }
        print("Derived journal benchmark: 20 health/sorted-work/asset-reference queries, 10,000 completed + 1,200 active; cached=\(elapsed); previous=\(baseline.duration(to: clock.now)); repeated sorts=0, health summary updates=0")
        let writer = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        let operation = try await writer.enqueue(SyncOperation(account: "benchmark", kind: .publishCoordination))
        #expect(try await repository.pendingCoordinationAssetOperations(account: "benchmark", database: "private") == [operation.id])
        #expect(try await repository.syncHealth(account: "benchmark", database: "private").pendingCount == 1201)
        let changed = await repository.metrics()
        #expect(changed.summaryUpdates - after.summaryUpdates == 1)
        let completed = try await writer.transition(operation, to: .completed)
        #expect(try await repository.pendingCoordinationAssetOperations(account: "benchmark", database: "private").isEmpty)
        #expect(try await repository.syncHealth(account: "benchmark", database: "private").pendingCount == 1200)
        #expect(completed.state == .completed)
    }

    @Test func healthSummaryTracksFailuresDeliveriesDeletionAndRollback() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("ContentPreview3/Content3.sqlite")
        let reader = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        let writer = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        var first = SyncOperation(account: "a", kind: .publishCoordination, now: Date(timeIntervalSince1970: 1))
        var second = SyncOperation(account: "a", kind: .publishCoordination, now: Date(timeIntervalSince1970: 2))
        try await writer.replaceHealthFixture(first)
        try await writer.replaceHealthFixture(second)
        #expect(try await reader.syncHealth(account: "a", database: "private").oldestPendingAt == first.createdAt)
        first.state = .needsAttention; first.failure = .authorization
        try await writer.replaceHealthFixture(first)
        #expect(try await reader.pendingCoordinationAssetOperations(account: "a", database: "private") == [first.id, second.id])
        #expect(try await reader.syncHealth(account: "a", database: "private").blockedReasons == [.authorization])
        let delivered = Date(timeIntervalSince1970: 10)
        first.state = .completed; first.failure = nil; first.deliveredAt = delivered
        second.state = .completed; second.deliveredAt = delivered
        try await writer.replaceHealthFixture(first)
        try await writer.replaceHealthFixture(second)
        let completed = try await reader.syncHealth(account: "a", database: "private")
        #expect(completed.pendingCount == 0 && completed.lastDeliveryAt == delivered && completed.blockedReasons.isEmpty)
        await #expect(throws: SyncJournalError.invalidOperation) { try await reader.replaceHealthFixture(first, delete: true, rollback: true) }
        #expect(try await reader.syncHealth(account: "a", database: "private") == completed)
        try await writer.replaceHealthFixture(first, delete: true)
        #expect(try await reader.syncHealth(account: "a", database: "private").lastDeliveryAt == delivered)
        try await writer.replaceHealthFixture(second, delete: true)
        #expect(try await reader.syncHealth(account: "a", database: "private").lastDeliveryAt == nil)
        #expect(try await reader.pendingCoordinationAssetOperations(account: "a", database: "private").isEmpty)
        #expect(try await reader.syncHealth(account: "other", database: "private").pendingCount == 0)
    }

    @Test func incomingHealthUpdatesReuseSnapshotsAndPreserveValueIsolation() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("ContentPreview3/Content3.sqlite")
        let reader = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        try await reader.seedLargeJournal()
        let writer = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        let original = try await reader.syncHealth(account: "benchmark", database: "private")
        let before = await reader.metrics(), start = ContinuousClock.now
        for index in 0..<100 {
            _ = try await writer.stageIncoming(IncomingRecord(id: "health-arrival-\(index)", account: "benchmark", database: "private",
                zoneName: "zone", zoneOwner: "owner", recordName: "health-\(index)", recordType: "content", bytes: Data([1]), systemFields: Data()))
            for _ in 0..<10 {
                #expect(try await reader.syncHealth(account: "benchmark", database: "private").pendingCount == original.pendingCount + index + 1)
            }
        }
        let after = await reader.metrics()
        #expect(original.pendingCount == 1200)
        #expect(after.resultBuilds - before.resultBuilds == 100)
        #expect(after.summaryUpdates - before.summaryUpdates == 200)
        #expect(after.fullFetches == before.fullFetches)
        #expect(after.decodedRows - before.decodedRows == 200)
        print("Incoming health benchmark: 100 commits + 1000 reads, 11200 retained operations=\(start.duration(to: .now)); builds=100, decoded rows=200")
    }

    @Test func largeVaultIngestionBatchesDurableCommits() async throws {
        struct Permit: RepositoryWritePermit { func withWritePermission<T>(_ body: () throws -> T) throws -> T { try body() } }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let records = (0..<1000).map { IncomingRecord(id: "ingest-\($0)", account: "a", database: "private", zoneName: "zone", zoneOwner: "owner",
            recordName: "record-\($0)", recordType: "content", bytes: Data(repeating: 7, count: 32768), systemFields: Data([1])) }
        var elapsed: [Duration] = []
        for batched in [false, true] {
            let url = root.appendingPathComponent(batched ? "batch/store.sqlite" : "single/store.sqlite")
            let repository = try EncryptedItemRepository(storeURL: url)
            let start = ContinuousClock.now
            if batched {
                for offset in stride(from: 0, to: records.count, by: 200) {
                    try await repository.stageIncomingRecords(Array(records[offset..<offset + 200]), permit: Permit())
                }
            } else {
                for record in records { try await repository.stageIncoming(record, permit: Permit()) }
            }
            elapsed.append(start.duration(to: .now))
            #expect(try await repository.historyTransactionCount() == (batched ? 5 : 1000))
            let reopened = try EncryptedItemRepository(storeURL: url)
            #expect(try await reopened.incomingRecords(account: "a", database: "private").count == 1000)
            #expect(try await reopened.activeOperations(account: "a", database: "private").count == 1000)
            #expect(try await reopened.engineState(account: "a", database: "private") == nil)
            if batched {
                try await reopened.stageIncomingRecords(records, permit: Permit())
                #expect(try await reopened.historyTransactionCount() == 5)
            }
        }
        print("Ingestion benchmark: 1000 x 32 KiB; individual=\(elapsed[0]), batched=\(elapsed[1]); durable commits 1000 -> 5")
    }

    @Test func enrollingStatusReadsDoNotScanJournalOrProduceWakeups() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("ContentPreview3/Content3.sqlite")
        let repository = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        try await repository.seedLargeJournal()
        func read() async throws {
            #expect(try await repository.contentConflicts(account: "benchmark").isEmpty)
            #expect(try await repository.deletions(account: "benchmark").isEmpty)
        }
        try await read()
        let before = await repository.metrics(), transactions = try await repository.historyTransactionCount()
        let clock = ContinuousClock(), start = clock.now
        for _ in 0..<100 { try await read() }
        let warm = start.duration(to: clock.now), after = await repository.metrics()
        #expect(after.fullFetches == before.fullFetches && after.decodedRows == before.decodedRows)
        #expect(try await repository.historyTransactionCount() == transactions)
        _ = try await repository.previousConflictStatusPass()
        let baseline = clock.now
        for _ in 0..<100 { try await repository.previousConflictStatusPass() }
        print("Enrolling status benchmark: 100 conflict/deletion reads over 11,200 operations; optimized=\(warm); previous decoded queries=\(baseline.duration(to: clock.now)); repeated full fetches=0, decodes=0, writes=0")
        let writer = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        let scope = VaultScope(account: "benchmark", vaultID: UUID())
        let deletion = VaultDeletionState(scope: scope, notice: Data([1]), phase: .prepared)
        try await writer.writeDeletionFixture(deletion, scope: scope)
        #expect(try await repository.deletions(account: "benchmark") == [deletion])
        #expect(try await repository.deletions(account: "other").isEmpty)
        try await writer.writeDeletionFixture(nil, scope: scope)
        try await read()
        let arrivalsBefore = await repository.metrics()
        for index in 0..<50 {
            _ = try await writer.stageIncoming(IncomingRecord(id: "status-arrival-\(index)", account: "benchmark", database: "private",
                zoneName: "zone", zoneOwner: "owner", recordName: "record-\(index)", recordType: "content", bytes: Data([1]), systemFields: Data()))
            try await read()
        }
        let arrivalsAfter = await repository.metrics()
        #expect(arrivalsAfter.fullFetches == arrivalsBefore.fullFetches)
        // The baseline populated the full operation projection; only each new
        // incoming operation is decoded, never the retained operation history.
        #expect(arrivalsAfter.decodedRows - arrivalsBefore.decodedRows == 50)
    }

    @Test func thousandItemJournalAvoidsRepeatedFetchAndDecode() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try EncryptedItemRepository(storeURL: root.appendingPathComponent("ContentPreview3/Content3.sqlite"), layout: .contentPreview3)
        try await repository.seedLargeJournal()
        let clock = ContinuousClock()
        let coldStart = clock.now
        let health = try await repository.syncHealth(account: "benchmark", database: "private")
        let active = try await repository.activeOperations(account: "benchmark", database: "private")
        _ = try await repository.contentPublications(account: "benchmark")
        let cold = coldStart.duration(to: clock.now)
        #expect(health.pendingCount == 1200 && active.count == 1200)
        let before = await repository.metrics()
        let warmStart = clock.now
        for _ in 0..<10 {
            #expect(try await repository.syncHealth(account: "benchmark", database: "private") == health)
            #expect(try await repository.activeOperations(account: "benchmark", database: "private").count == 1200)
            #expect(try await repository.contentPublications(account: "benchmark").isEmpty)
        }
        let warm = warmStart.duration(to: clock.now)
        let after = await repository.metrics()
        #expect(after.fullFetches == before.fullFetches)
        #expect(after.decodedRows == before.decodedRows)
        let baselineStart = clock.now
        for _ in 0..<10 { #expect(try await repository.legacyJournalPass() == 22_600) }
        let baseline = baselineStart.duration(to: clock.now)
        print("Journal benchmark: 1,000 pending item operations, 10,000 completed, 200 incoming; cold=\(cold); 10 warm passes=\(warm); 10 legacy passes=\(baseline); warm decoded rows=\(after.decodedRows - before.decodedRows), full fetches=\(after.fullFetches - before.fullFetches)")
        // A different repository represents another app-group process. Its
        // writes must be visible without relying on notification delivery.
        let writer = try EncryptedItemRepository(storeURL: root.appendingPathComponent("ContentPreview3/Content3.sqlite"), layout: .contentPreview3)
        let first = try #require(active.first)
        _ = try await writer.transition(first, to: .completed)
        #expect(try await repository.activeOperations(account: "benchmark", database: "private").count == 1199)
        let changed = await repository.metrics()
        #expect(changed.fullFetches == after.fullFetches)
        #expect(changed.decodedRows - after.decodedRows <= 3)
    }

    @Test func metadataWaitsAndIncomingCommitsKeepJournalWarm() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("ContentPreview3/Content3.sqlite")
        let repository = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        try await repository.seedLargeJournal()
        let writer = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        let stale = try await writer.enqueue(SyncOperation(account: "benchmark", kind: .enrollment))
        _ = try await writer.transition(stale, to: .ready)
        let vault = UUID(), clock = ContinuousClock()
        func readPass() async throws {
            _ = try await repository.syncHealth(account: "benchmark", database: "private")
            _ = try await repository.activeOperations(account: "benchmark", database: "private")
            _ = try await repository.contentPublications(account: "benchmark")
            #expect(try await repository.coordinationRemovals(account: "benchmark").isEmpty)
        }
        try await readPass()
        let before = await repository.metrics()
        let started = clock.now
        for index in 0..<50 {
            let record = IncomingRecord(id: "arrival-\(index)", account: "benchmark", database: "private",
                zoneName: "zone", zoneOwner: "owner", recordName: "arrival-\(index)", recordType: "content",
                bytes: Data(repeating: 1, count: 32_768), systemFields: Data())
            _ = try await writer.stageIncoming(record, budget: EncryptedItemRepository.maximumInboxBytes)
            await #expect(throws: BenchmarkWait.metadataNotAvailable) { try await repository.waitForBenchmarkMetadata(vault: vault) }
            // A competing incoming commit made the coordinator's captured
            // operation stale: the exact reset ancestry in the Instruments trace.
            await #expect(throws: SyncJournalError.staleOperation) { try await repository.transition(stale, to: .completed) }
            try await readPass()
        }
        let elapsed = started.duration(to: clock.now)
        let after = await repository.metrics()
        #expect(after.fullFetches == before.fullFetches)
        #expect(after.decodedRows - before.decodedRows <= 50 * 4)
        #expect(after.summaryUpdates - before.summaryUpdates == 100)
        #expect(try await repository.syncHealth(account: "benchmark", database: "private").pendingCount == 1251)
        let baselineStart = clock.now
        for index in 50..<100 {
            let record = IncomingRecord(id: "arrival-\(index)", account: "benchmark", database: "private",
                zoneName: "zone", zoneOwner: "owner", recordName: "arrival-\(index)", recordType: "content",
                bytes: Data(repeating: 1, count: 32_768), systemFields: Data())
            _ = try await writer.stageIncoming(record, budget: EncryptedItemRepository.maximumInboxBytes)
            await #expect(throws: BenchmarkWait.metadataNotAvailable) { try await repository.waitForBenchmarkMetadata(vault: vault) }
            await #expect(throws: SyncJournalError.staleOperation) { try await repository.transition(stale, to: .completed) }
            await repository.simulatePreviousReadFailureInvalidation()
            try await readPass()
        }
        let baseline = baselineStart.duration(to: clock.now)
        let old = await repository.metrics()
        #expect(old.fullFetches - after.fullFetches >= 50 * 4)
        print("Metadata-wait benchmark: 50 incoming commits + missing metadata + stale CAS + health/publication/removal reads; incremental=\(elapsed); previous invalidation=\(baseline); incremental full fetches=\(after.fullFetches - before.fullFetches), decoded rows=\(after.decodedRows - before.decodedRows); invalidating full fetches=\(old.fullFetches - after.fullFetches), decoded rows=\(old.decodedRows - after.decodedRows)")
    }

    @Test func projectionsRespectAtomicChangesRollbackAndDeletion() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite"))
        let operation = try await repository.enqueue(SyncOperation(account: "a", kind: .enrollment))
        #expect(try await repository.activeOperations(account: "a", database: "private") == [operation])
        await #expect(throws: SyncJournalError.invalidOperation) { try await repository.rollbackProjectionChange(operation) }
        #expect(try await repository.activeOperations(account: "a", database: "private") == [operation])
        _ = try await repository.transition(operation, to: .completed, now: Date().addingTimeInterval(-40 * 86400))
        #expect(try await repository.activeOperations(account: "a", database: "private").isEmpty)
        #expect(try await repository.operations(account: "a", database: "private").count == 1)
        try await repository.pruneCompletedOperations(account: "a", database: "private")
        #expect(try await repository.operations(account: "a", database: "private").isEmpty)
    }
}

private struct BaselineOperationSummary {
    var unfinished: [UUID: BenchmarkHealth] = [:]
    var deliveries: [Date: Int] = [:]
    var latest: Date?
    mutating func update(_ row: BenchmarkHealth, added: Bool) {
        if row.state != .completed { unfinished[row.id] = added ? row : nil }
        if let date = row.deliveredAt {
            let count = deliveries[date, default: 0] + (added ? 1 : -1)
            deliveries[date] = count == 0 ? nil : count
            if added { latest = max(latest ?? date, date) }
            else if latest == date && count == 0 { latest = deliveries.keys.max() }
        }
    }
}
private struct BaselineIncomingHealth: Decodable {
    let id: String
    let receivedAt: Date
    let failure: SyncFailure?
}
private struct BaselineIncomingSize: Decodable {
    let bytes: Data
    let systemFields: Data
}
extension EncryptedItemRepository {
    fileprivate func previousHealthSnapshot() throws -> SyncHealthSnapshot {
        try transaction {
            let operations = try journalReadCache.summary(
                prefix: "sync-journal-v1:SyncOperation:" + journalKey("benchmark", "private", ""),
                in: context, initial: BaselineOperationSummary()) {
                    (summary: inout BaselineOperationSummary, row: BenchmarkHealth, added: Bool) in summary.update(row, added: added)
                }
            let incoming: [BaselineIncomingHealth] = try journalValues("IncomingRecord", account: "benchmark", database: "private")
            let unfinished = operations.unfinished.values
            let ids = Set(incoming.map { IncomingRecord.operationID(for: $0.id) })
            let pending = unfinished.filter { !ids.contains($0.id) }
            let delivery: Date? = try journalValue("StateBlob", key: "sync-last-delivery:" + journalKey("benchmark", "private", ""))
            return SyncHealthSnapshot(pendingCount: pending.count + incoming.count,
                oldestPendingAt: (pending.map(\.createdAt) + incoming.map(\.receivedAt)).min(),
                lastDeliveryAt: [operations.latest, delivery].compactMap { $0 }.max(),
                blockedReasons: Set(unfinished.compactMap(\.failure) + incoming.compactMap(\.failure)),
                pendingKinds: Set(unfinished.filter { $0.state != .needsAttention }.map(\.kind)))
        }
    }
    fileprivate func previousCapacityRead() throws -> Bool {
        try transaction {
            let records: [BaselineIncomingSize] = try journalValues("IncomingRecord", account: "benchmark")
            return records.reduce(0) { $0 + $1.bytes.count + $1.systemFields.count } <= Self.maximumInboxBytes / 2
        }
    }
    fileprivate func capacityOverlayMustRollback(_ first: IncomingRecord, _ second: IncomingRecord) throws {
        try transaction {
            _ = try stageIncomingInTransaction(first, budget: 100)
            _ = try stageIncomingInTransaction(first, budget: 100) // replay must not double count
            _ = try stageIncomingInTransaction(second, budget: 100)
        }
    }
}
extension JournalPerformanceTests {
    @Test func incrementalStatusAndCapacityBenchmark() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = SyncStoreLayout.contentPreviewURL(in: root)
        let reader = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        let writer = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        try await writer.seedLargeJournal(incomingCount: 5000, incomingBytes: 1024)
        _ = try await reader.syncHealth(account: "benchmark", database: "private")
        _ = try await reader.inboxReadyToResume(account: "benchmark")
        _ = try await reader.previousHealthSnapshot()
        _ = try await reader.previousCapacityRead()
        let before = await reader.metrics()
        var statusTime = Duration.zero, oldStatusTime = Duration.zero
        var capacityTime = Duration.zero, oldCapacityTime = Duration.zero
        let clock = ContinuousClock()
        for index in 0..<100 {
            let record = IncomingRecord(id: "incremental-\(index)", account: "benchmark", database: "private",
                zoneName: "zone", zoneOwner: "owner", recordName: "incremental-\(index)", recordType: "content",
                bytes: Data(repeating: 1, count: 32768), systemFields: Data([1, 2, 3]))
            _ = try await writer.stageIncoming(record)
            // Charge history-refresh work equally: perform it before timing.
            _ = try await reader.activeOperations(account: "benchmark", database: "private")
            var start = clock.now
            let status = try await reader.syncHealth(account: "benchmark", database: "private")
            statusTime += start.duration(to: clock.now)
            start = clock.now
            let oldStatus = try await reader.previousHealthSnapshot()
            oldStatusTime += start.duration(to: clock.now)
            #expect(status == oldStatus)
            start = clock.now
            let capacity = try await reader.inboxReadyToResume(account: "benchmark")
            capacityTime += start.duration(to: clock.now)
            start = clock.now
            let oldCapacity = try await reader.previousCapacityRead()
            oldCapacityTime += start.duration(to: clock.now)
            #expect(capacity == oldCapacity)
        }
        let after = await reader.metrics()
        // Three aggregate updates per incoming+operation pair, independent of
        // the 16,000 retained rows. Timing is reported, not a flaky assertion.
        #expect(after.summaryUpdates - before.summaryUpdates == 400) // 300 optimized + 100 baseline
        print("Incremental status/capacity: 100 changes over 16,000 operations + 5,000 inbox rows; health=\(statusTime), previous health=\(oldStatusTime); capacity=\(capacityTime), previous capacity=\(oldCapacityTime); aggregate updates=300")
    }

    @Test func capacityAggregateIncludesUnsavedRowsAndDiscardsRollback() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = SyncStoreLayout.contentPreviewURL(in: root)
        let reader = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        let writer = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        func record(_ id: String) -> IncomingRecord {
            IncomingRecord(id: id, account: "a", database: "private", zoneName: "z", zoneOwner: "o", recordName: id,
                recordType: "test", bytes: Data(repeating: 1, count: 50), systemFields: Data([1]))
        }
        #expect(try await reader.inboxReadyToResume(account: "a", budget: 100))
        await #expect(throws: SyncJournalError.inboxFull) {
            try await reader.capacityOverlayMustRollback(record("one"), record("two"))
        }
        #expect(try await reader.incomingRecords(account: "a", database: "private").isEmpty)
        #expect(try await reader.inboxReadyToResume(account: "a", budget: 100))
        let first = record("one")
        _ = try await writer.stageIncoming(first, budget: 100)
        #expect(try await !reader.inboxReadyToResume(account: "a", budget: 100))
        try await writer.completeIncoming(first)
        #expect(try await reader.inboxReadyToResume(account: "a", budget: 100))
        let reopened = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        #expect(try await reopened.inboxReadyToResume(account: "a", budget: 100))
    }
}

extension JournalPerformanceTests {
    @Test func joinedHealthMatchesReferenceAcrossPartialReceiptTransitions() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = SyncStoreLayout.contentPreviewURL(in: root)
        let reader = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        let writer = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        func check() async throws {
            let actual = try await reader.syncHealth(account: "benchmark", database: "private")
            let previous = try await reader.previousHealthSnapshot()
            // The old query has no dependency-specific diagnostics; compare its
            // original fields while dedicated tests exercise the new groups.
            #expect(actual.pendingCount == previous.pendingCount)
            #expect(actual.oldestPendingAt == previous.oldestPendingAt)
            #expect(actual.lastDeliveryAt == previous.lastDeliveryAt)
            #expect(actual.blockedReasons == previous.blockedReasons)
            #expect(actual.pendingKinds == previous.pendingKinds)
        }
        try await check()
        for index in 0..<12 {
            let record = IncomingRecord(id: "joined-\(index)", account: "benchmark", database: "private",
                zoneName: "zone", zoneOwner: "owner", recordName: "r-\(index)", recordType: "content",
                bytes: Data([1]), systemFields: Data(), now: Date(timeIntervalSince1970: Double(index)))
            _ = try await writer.stageIncoming(record)
            try await check()
            var operation = try #require(await writer.operations(account: "benchmark", database: "private").first { $0.id == record.operationID })
            operation.state = .needsAttention; operation.failure = .invalidAuthority
            try await writer.replaceHealthFixture(operation)
            try await check()
            // Completed receipt with a retained inbox row must still count once.
            operation.state = .completed; operation.deliveredAt = Date(timeIntervalSince1970: 100)
            try await writer.replaceHealthFixture(operation)
            try await check()
            await #expect(throws: SyncJournalError.invalidOperation) {
                try await writer.replaceHealthFixture(operation, delete: true, rollback: true)
            }
            try await check()
            try await writer.replaceHealthFixture(operation, delete: true)
            try await check() // orphan inbox still counts, with its original date
            try await writer.completeIncoming(record)
            try await check()
        }
        #expect(try await reader.syncHealth(account: "benchmark", database: "private").pendingCount == 0)
    }
}
