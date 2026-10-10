@preconcurrency import CoreData
import Foundation
import CloudKit
import CryptoKit

// Health reads never need encrypted payloads, dependencies, or system fields.
private struct OperationHealthFields: Decodable {
    let id: UUID
    let state: SyncOperationState
    let createdAt: Date
    let deliveredAt: Date?
    let failure: SyncFailure?
}
private struct OperationHealthSummary {
    var unfinished: [UUID: OperationHealthFields] = [:]
    var deliveries: [Date: Int] = [:]
    var latest: Date?
    mutating func update(_ row: OperationHealthFields, added: Bool) {
        if row.state != .completed { unfinished[row.id] = added ? row : nil }
        if let date = row.deliveredAt {
            let count = (deliveries[date] ?? 0) + (added ? 1 : -1)
            deliveries[date] = count == 0 ? nil : count
            if added { latest = max(latest ?? date, date) }
            else if date == latest && count == 0 { latest = deliveries.keys.max() }
        }
    }
}
private struct IncomingHealthFields: Decodable {
    let id: String
    let receivedAt: Date
    let failure: SyncFailure?
    let operationID: UUID
    private enum CodingKeys: String, CodingKey { case id, receivedAt, failure }
    init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        id = try fields.decode(String.self, forKey: .id)
        receivedAt = try fields.decode(Date.self, forKey: .receivedAt)
        failure = try fields.decodeIfPresent(SyncFailure.self, forKey: .failure)
        operationID = IncomingRecord.operationID(for: id)
    }
}

private struct PendingOperation: Decodable, JournalProjectionValue {
    let operation: SyncOperation?
    var includeInJournalProjection: Bool { operation != nil }
    private enum CodingKeys: String, CodingKey { case state }
    init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        operation = try fields.decode(SyncOperationState.self, forKey: .state) == .completed
            ? nil : SyncOperation(from: decoder)
    }
}

private struct ConflictDecisionOperation: Decodable, JournalProjectionValue {
    let operation: SyncOperation?
    var includeInJournalProjection: Bool { operation != nil }
    private enum CodingKeys: String, CodingKey { case state, kind }
    init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try fields.decode(SyncOperation.Kind.self, forKey: .kind)
        let state = try fields.decode(SyncOperationState.self, forKey: .state)
        operation = kind == .resolveConflict && ![.completed, .needsAttention].contains(state) ? try SyncOperation(from: decoder) : nil
    }
}

private struct IncomingAddressFields: Decodable {
    let recordName: String
    let zoneName: String
    let zoneOwner: String
}

private struct IncomingBudgetFields: Decodable {
    let size: Int
    private enum CodingKeys: String, CodingKey { case bytes, systemFields }
    init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        size = try fields.decode(Data.self, forKey: .bytes).count + fields.decode(Data.self, forKey: .systemFields).count
    }
}

private struct QuarantinedSyncRecord: Codable {
    let digest: String
    let receivedAt: Date
    var payload: Data?
}

extension EncryptedItemRepository {
    public static let maximumInboxBytes = 256 * 1024 * 1024
    public static let maximumQuarantineBytes = 32 * 1024 * 1024

    public func pendingAssetVersions(account: String, database: String) throws -> Set<UUID> {
        try transaction {
            let request = NSFetchRequest<NSDictionary>(entityName: "PendingMutation")
            request.resultType = .dictionaryResultType
            request.propertiesToFetch = ["versionID"]
            request.predicate = NSPredicate(format: "account == %@ AND database == %@", account, database)
            return try Set(context.fetch(request).map {
                guard let id = $0["versionID"] as? UUID else { throw ItemRepositoryError.corruptStore }
                return id
            })
        }
    }

    /// Asset cleanup needs references, not payloads or a sorted receipt history.
    public func pendingCoordinationAssetOperations(account: String, database: String) throws -> Set<UUID> {
        try transaction {
            try journalReadCache.derived(prefix: journalPrefix("SyncOperation", account: account, database: database), in: context) { (values: [PendingOperation]) in
                Set(values.compactMap(\.operation).filter { $0.kind == .publishCoordination }.map(\.id))
            }
        }
    }

    /// Only terminal entries expire. Missing receipts remain explicitly unknown
    /// to callers; absence never counts as cloud confirmation.
    public func pruneCompletedOperations(account: String, database: String, now: Date = Date()) throws {
        try transaction {
            let cutoff = now.addingTimeInterval(-30 * 24 * 60 * 60)
            let operations: [SyncOperation] = try journalValues("SyncOperation", account: account, database: database)
            let receipts = NSFetchRequest<NSManagedObject>(entityName: "StateBlob")
            receipts.predicate = NSPredicate(format: "key BEGINSWITH %@", "enrollment3:" + journalKey(account, database, ""))
            for row in try context.fetch(receipts) {
                guard let data = row.value(forKey: "value") as? Data else { throw ItemRepositoryError.corruptStore }
                let receipt = try JSONDecoder().decode(CompletedEnrollmentReceipt.self, from: data)
                if receipt.completedAt < cutoff { context.delete(row) }
            }
            let referenced = Set(operations.filter { $0.state != .completed }.flatMap(\.dependencies).filter { $0.kind == .operation }.map(\.identifier))
            for operation in operations where operation.state == .completed && (operation.completedAt ?? .distantFuture) < cutoff {
                if referenced.contains(operation.id.uuidString), operation.deliveredAt != nil {
                    try writeJournal(true, entity: "StateBlob", key: "sync-delivered:" + journalKey(account, database, operation.id.uuidString))
                }
                if operation.kind == .publishItem, let receipt = try fetchOne("MutationReceipt", key: operation.id.uuidString) {
                    let status = receipt.value(forKey: "status") as? String
                    guard [MutationDeliveryStatus.cloudConfirmed.rawValue, MutationDeliveryStatus.superseded.rawValue].contains(status) else { continue }
                    if status == MutationDeliveryStatus.superseded.rawValue,
                       let scope = receipt.value(forKey: "scopeKey") as? String,
                       let version = receipt.value(forKey: "versionID") as? UUID {
                        // Receipt retention must not remove the replay watermark.
                        try writeJournal(true, entity: "StateBlob", key: "superseded:" + version.uuidString + ":" + scope)
                    }
                    context.delete(receipt)
                }
                if let row = try journalRow("SyncOperation", key: journalKey(account, database, operation.id.uuidString)) { context.delete(row) }
            }
        }
    }

    /// For journaled application-owned cloud writes after exact readback. Merely
    /// completing a local handler must never manufacture a delivery receipt.
    public func confirmOperation(_ expected: SyncOperation, permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission {
            try transaction {
                let key = journalKey(expected.account, expected.database, expected.id.uuidString)
                guard let current: SyncOperation = try journalValue("SyncOperation", key: key), current == expected else { throw SyncJournalError.staleOperation }
                try finishPublicationInTransaction(current.id, account: current.account, database: current.database, confirmed: true)
            }
        }
    }

    public func operationIsDelivered(_ id: UUID, account: String, database: String = "private") throws -> Bool {
        try transaction { try operationDeliveredInTransaction(id, account: account, database: database) }
    }

    func operationDeliveredInTransaction(_ id: UUID, account: String, database: String) throws -> Bool {
        let key = journalKey(account, database, id.uuidString)
        if let operation: SyncOperation = try journalValue("SyncOperation", key: key), operation.state == .completed, operation.deliveredAt != nil { return true }
        return try journalValue("StateBlob", key: "sync-delivered:" + key) as Bool? == true
    }

    /// Keep diagnostic identity after evicting ciphertext. Duplicate bad records
    /// do not allocate new rows or continually refresh their retention order.
    public func quarantine(_ bytes: Data, account: String, database: String, zone: String, owner: String,
                           record: String, now: Date = Date(), budget: Int = maximumQuarantineBytes) throws {
        try transaction { try quarantineInTransaction(bytes, account: account, database: database, zone: zone,
            owner: owner, record: record, now: now, budget: budget) }
    }

    public func quarantineIncoming(_ incoming: IncomingRecord, permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission {
            try transaction {
                try requireIncomingInTransaction(incoming)
                try quarantineInTransaction(incoming.bytes, account: incoming.account, database: incoming.database,
                    zone: incoming.zoneName, owner: incoming.zoneOwner, record: incoming.recordName,
                    now: Date(), budget: Self.maximumQuarantineBytes)
                try completeIncomingInTransaction(incoming, failure: .invalidAuthority)
            }
        }
    }

    private func quarantineInTransaction(_ bytes: Data, account: String, database: String, zone: String, owner: String,
                                         record: String, now: Date, budget: Int) throws {
        guard budget >= 0, !account.isEmpty, ["private", "shared"].contains(database) else { throw SyncJournalError.invalidOperation }
        let scope = try JSONEncoder().encode([database, zone, owner, record])
        let digest = SHA256.hash(data: scope + bytes).map { String(format: "%02x", $0) }.joined()
        let prefix = "sync-quarantine:" + Data(account.utf8).base64EncodedString() + ":"
        let key = prefix + digest
        guard try fetchOne("StateBlob", key: key) == nil else { return }
        try writeJournal(UUID(), entity: "StateBlob", key: prefix + "boundary")
        var rows = try quarantineRows(account: account)
        let candidate = QuarantinedSyncRecord(digest: digest, receivedAt: now, payload: bytes.count <= budget ? bytes : nil)
        try writeJournal(candidate, entity: "StateBlob", key: key)
        if let row = try fetchOne("StateBlob", key: key) { rows.append((row, candidate)) }
        var total = rows.reduce(0) { $0 + ($1.1.payload?.count ?? 0) }
        for (row, value) in rows.sorted(by: { ($0.1.receivedAt, $0.1.digest) < ($1.1.receivedAt, $1.1.digest) }) where total > budget {
            var value = value
            total -= value.payload?.count ?? 0; value.payload = nil
            row.setValue(try JSONEncoder().encode(value), forKey: "value")
        }
    }

    public func quarantineSummary(account: String) throws -> (records: Int, retainedBytes: Int) {
        try transaction {
            let rows = try quarantineRows(account: account)
            return (rows.count, rows.reduce(0) { $0 + ($1.1.payload?.count ?? 0) })
        }
    }

    private func quarantineRows(account: String) throws -> [(NSManagedObject, QuarantinedSyncRecord)] {
        let prefix = "sync-quarantine:" + Data(account.utf8).base64EncodedString() + ":"
        let query = NSFetchRequest<NSManagedObject>(entityName: "StateBlob")
        query.predicate = NSPredicate(format: "key BEGINSWITH %@ AND key != %@", prefix, prefix + "boundary")
        return try context.fetch(query).map { row in
            guard let bytes = row.value(forKey: "value") as? Data else { throw ItemRepositoryError.corruptStore }
            return (row, try JSONDecoder().decode(QuarantinedSyncRecord.self, from: bytes))
        }
    }

    @discardableResult
    public func enqueue(_ operation: SyncOperation) throws -> SyncOperation {
        try transaction { try enqueueInTransaction(operation) }
    }

    func enqueueInTransaction(_ operation: SyncOperation) throws -> SyncOperation {
        guard !operation.account.isEmpty, ["private", "shared"].contains(operation.database),
              operation.attempts == 0, operation.completedAt == nil,
              operation.payload.count <= Self.maximumCiphertextBytes else { throw SyncJournalError.invalidOperation }
        let key = journalKey(operation.account, operation.database, operation.id.uuidString)
        if let old: SyncOperation = try journalValue("SyncOperation", key: key) {
            guard old.kind == operation.kind, old.payload == operation.payload, old.vaultID == operation.vaultID,
                  old.zoneOwner == operation.zoneOwner else {
                throw SyncJournalError.identityCollision
            }
            return old
        }
        if layout == .contentPreview3, operation.kind == .membership {
            let pending: [SyncOperation] = try journalValues("SyncOperation", account: operation.account, database: operation.database)
            guard !pending.contains(where: { $0.kind == .membership && $0.vaultID == operation.vaultID && $0.state != .completed }) else { throw ContentStoreError.staleAuthority }
        }
        try writeJournal(operation, entity: "SyncOperation", key: key, account: operation.account, database: operation.database)
        return operation
    }

    /// Retire redundant wake hints left by earlier preview builds. This changes
    /// no publication, receipt or inbox record and never confirms cloud delivery.
    public func coalesceReconciliationRequests(account: String, database: String) throws {
        try transaction {
            let operations: [SyncOperation] = try journalValues("SyncOperation", account: account, database: database)
            let requests = operations.compactMap { operation -> (SyncOperation, DurableSyncRequest)? in
                guard operation.kind == .reconcile, operation.state != .completed,
                      let request = try? JSONDecoder().decode(DurableSyncRequest.self, from: operation.payload),
                      request.account == account, request.database == database else { return nil }
                return (operation, request)
            }
            guard let latest = requests.max(by: { ($0.1.generation, $0.0.id.uuidString) < ($1.1.generation, $1.0.id.uuidString) }) else { return }
            if let earliest = requests.compactMap({ $0.0.retryNotBefore }).max(), earliest > Date() {
                var retained = latest.0
                retained.state = .retryScheduled; retained.failure = .transport
                retained.nextAttempt = max(retained.nextAttempt ?? earliest, earliest)
                retained.retryNotBefore = earliest; retained.revision = UUID()
                try writeJournal(retained, entity: "SyncOperation", key: journalKey(account, database, retained.id.uuidString))
            }
            for (var operation, _) in requests where operation.id != latest.0.id {
                operation.state = .completed; operation.completedAt = Date(); operation.revision = UUID()
                operation.nextAttempt = nil; operation.retryNotBefore = nil; operation.failure = nil
                try writeJournal(operation, entity: "SyncOperation", key: journalKey(account, database, operation.id.uuidString))
            }
        }
    }

    public func operations(account: String, database: String) throws -> [SyncOperation] {
        try transaction { try journalValues("SyncOperation", account: account, database: database)
            .sorted { ($0.createdAt, $0.id.uuidString) < ($1.createdAt, $1.id.uuidString) } }
    }

    public func activeOperations(account: String, database: String) throws -> [SyncOperation] {
        try transaction {
            try journalReadCache.derived(prefix: journalPrefix("SyncOperation", account: account, database: database), in: context) { (values: [PendingOperation]) in
                values.compactMap(\.operation).map { ($0, $0.id.uuidString) }
                    .sorted { ($0.0.createdAt, $0.1) < ($1.0.createdAt, $1.1) }.map { $0.0 }
            }
        }
    }

    func activeOperationsInTransaction(account: String, database: String) throws -> [SyncOperation] {
        let values: [PendingOperation] = try journalValues("SyncOperation", account: account, database: database)
        return values.compactMap(\.operation)
    }

    func conflictDecisionOperationsInTransaction(account: String) throws -> [SyncOperation] {
        let values: [ConflictDecisionOperation] = try journalValues("SyncOperation", account: account, database: "private")
        return values.compactMap(\.operation)
    }

    /// CAS prevents a late worker from completing newly updated or retired work.
    @discardableResult
    public func transition(_ expected: SyncOperation, to state: SyncOperationState,
                           dependencies: Set<SyncDependency> = [], failure: SyncFailure? = nil,
                           nextAttempt: Date? = nil, retryNotBefore: Date? = nil, retryAttempts: Int? = nil,
                           attempted: Bool = false, now: Date = Date()) throws -> SyncOperation {
        try transaction {
            let key = journalKey(expected.account, expected.database, expected.id.uuidString)
            guard let current: SyncOperation = try journalValue("SyncOperation", key: key), current == expected,
                  current.state != .completed else { throw SyncJournalError.staleOperation }
            guard state != .retryScheduled || nextAttempt != nil,
                  state != .waitingForDependency || !dependencies.isEmpty,
                  !attempted || current.attempts < Int.max else { throw SyncJournalError.invalidOperation }
            var updated = current
            updated.state = state; updated.dependencies = dependencies; updated.failure = failure
            updated.nextAttempt = nextAttempt; updated.attempts += attempted ? 1 : 0
            updated.retryNotBefore = retryNotBefore
            updated.retryAttempts = retryAttempts
            updated.completedAt = state == .completed ? now : nil; updated.revision = UUID()
            try writeJournal(updated, entity: "SyncOperation", key: key, account: updated.account, database: updated.database)
            return updated
        }
    }

    /// Enforces the account budget in the same transaction as its cross-process boundary.
    @discardableResult
    public func stageIncoming(_ record: IncomingRecord, budget: Int = maximumInboxBytes) throws -> IncomingRecord {
        try transaction { try stageIncomingInTransaction(record, budget: budget) }
    }

    public func stageIncoming(_ record: IncomingRecord, permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission {
            try transaction { _ = try stageIncomingInTransaction(record, budget: Self.maximumInboxBytes) }
        }
    }

    func stageIncomingInTransaction(_ record: IncomingRecord, budget: Int) throws -> IncomingRecord {
        guard budget > 0, !record.account.isEmpty, ["private", "shared"].contains(record.database),
              !record.id.isEmpty, !record.bytes.isEmpty,
              record.bytes.count <= Self.maximumCiphertextBytes * 4 / 3 + 16_384,
              record.systemFields.count <= 1024 * 1024 else { throw SyncJournalError.invalidOperation }
        let key = journalKey(record.account, record.database, record.id)
        if let old: IncomingRecord = try journalValue("IncomingRecord", key: key) {
            guard old.bytes == record.bytes, old.systemFields == record.systemFields,
                  old.zoneName == record.zoneName, old.zoneOwner == record.zoneOwner,
                  old.recordName == record.recordName, old.recordType == record.recordType, old.vaultID == record.vaultID else {
                throw SyncJournalError.identityCollision
            }
            return old
        }
        // Concurrent insertions must contend even when record IDs differ.
        let boundaryKey = journalKey(record.account, "inbox-boundary", "")
        try writeJournal(UUID(), entity: "StateBlob", key: boundaryKey)
        // Refresh after touching the boundary: commits before it must be in
        // the budget, and commits after it must conflict at save.
        try journalReadCache.begin(in: context, persistent: context.persistentStoreCoordinator?.persistentStores.first?.type == NSSQLiteStoreType)
        let all: [IncomingBudgetFields] = try journalValues("IncomingRecord", account: record.account)
        let size = all.reduce(0) { $0 + $1.size }
        let added = record.bytes.count + record.systemFields.count
        guard all.isEmpty || (added <= budget && size <= budget - added) else { throw SyncJournalError.inboxFull }
        try writeJournal(record, entity: "IncomingRecord", key: key, account: record.account, database: record.database)
        _ = try enqueueInTransaction(SyncOperation(id: record.operationID, account: record.account, database: record.database,
            vaultID: record.vaultID, zoneOwner: record.zoneOwner, kind: .applyIncoming, payload: Data(record.id.utf8), now: record.receivedAt))
        // A token rollback may replay a completed or quarantined event. Rearm its
        // handler so the newly staged inbox row cannot become permanently orphaned.
        let operationKey = journalKey(record.account, record.database, record.operationID.uuidString)
        if var operation: SyncOperation = try journalValue("SyncOperation", key: operationKey),
           operation.state == .completed || operation.state == .needsAttention {
            operation.state = .ready; operation.completedAt = nil; operation.revision = UUID()
            operation.attempts = 0; operation.nextAttempt = nil; operation.retryNotBefore = nil; operation.failure = nil
            try writeJournal(operation, entity: "SyncOperation", key: operationKey, account: record.account, database: record.database)
        }
        return record
    }

    /// A transport checkpoint cannot escape ahead of its materialized records.
    /// One budget failure rolls back the entire batch and its engine state.
    public func stageIncomingBatch(_ records: [IncomingRecord], checkpoint: Data, account: String, database: String,
                                   budget: Int = maximumInboxBytes, permit: any RepositoryWritePermit) throws {
        guard !account.isEmpty, ["private", "shared"].contains(database),
              records.allSatisfy({ $0.account == account && $0.database == database }) else { throw SyncJournalError.invalidOperation }
        try permit.withWritePermission {
            try transaction {
                for record in records { _ = try stageIncomingInTransaction(record, budget: budget) }
                let key = blobKey(account, database)
                let row = try fetchOne("StateBlob", key: key) ?? NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
                row.setValue(key, forKey: "key"); row.setValue(checkpoint, forKey: "value")
            }
        }
    }

    public func saveEngineState(_ state: Data, account: String, database: String, permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission { try saveEngineState(state, account: account, database: database) }
    }

    public func incomingRecord(id: String, account: String, database: String) throws -> IncomingRecord? {
        try transaction { try journalValue("IncomingRecord", key: journalKey(account, database, id)) }
    }

    public func completeIncoming(_ expected: IncomingRecord, failure: SyncFailure?, permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission { try transaction { try completeIncomingInTransaction(expected, failure: failure) } }
    }

    public func incomingRecords(account: String, database: String) throws -> [IncomingRecord] {
        try transaction { try journalValues("IncomingRecord", account: account, database: database)
            .sorted { ($0.receivedAt, $0.id) < ($1.receivedAt, $1.id) } }
    }

    /// A server readback/acknowledgment must be authenticated and applied before
    /// retrying that address. Merely staging it never claims delivery.
    func incomingCloudRecordIDsInTransaction(account: String, database: String) throws -> Set<CKRecord.ID> {
        let records: [IncomingAddressFields] = try journalValues("IncomingRecord", account: account, database: database)
        return Set(records.map {
            CKRecord.ID(recordName: $0.recordName, zoneID: CKRecordZone.ID(zoneName: $0.zoneName, ownerName: $0.zoneOwner))
        })
    }

    /// Deferral and its targeted fetch requests share one commit. A crash cannot
    /// leave a durable dependency without the work needed to retrieve it.
    public func deferContentIncoming(_ expected: IncomingRecord, dependencies: Set<SyncDependency>,
                                     permit: any RepositoryWritePermit) throws {
        guard layout == .contentPreview3, expected.database == "private" else { throw ContentStoreError.wrongLayout }
        try permit.withWritePermission {
            try transaction {
                try requireIncomingInTransaction(expected)
                for dependency in dependencies where dependency.kind == .content {
                    guard let fetch = ContentVersionFetch(dependency: dependency), fetch.vault == expected.vaultID else {
                        throw SyncJournalError.invalidOperation
                    }
                    _ = try enqueueInTransaction(fetch.operation(account: expected.account, owner: expected.zoneOwner))
                }
                for dependency in dependencies where dependency.kind == .membership {
                    guard let fetch = ContentMembershipFetch(dependency: dependency), fetch.vault == expected.vaultID else { throw SyncJournalError.invalidOperation }
                    _ = try enqueueInTransaction(fetch.operation(account: expected.account, owner: expected.zoneOwner))
                }
                var current = expected
                current.dependencies = dependencies; current.failure = .dependency
                try writeJournal(current, entity: "IncomingRecord", key: journalKey(current.account, current.database, current.id),
                    account: current.account, database: current.database)
            }
        }
    }

    public func stageMembershipFetch(_ expected: SyncOperation, incoming: [IncomingRecord], permit: any RepositoryWritePermit) throws {
        guard layout == .contentPreview3, expected.kind == .fetchMembership,
              let request = try? JSONDecoder().decode(ContentMembershipFetch.self, from: expected.payload),
              request.vault == expected.vaultID, expected.database == "private", incoming.count == 2 else { throw SyncJournalError.invalidOperation }
        try permit.withWritePermission {
            try transaction {
                guard let current: SyncOperation = try journalValue("SyncOperation", key: journalKey(expected.account, expected.database, expected.id.uuidString)), current == expected else { throw SyncJournalError.staleOperation }
                for (id, record) in zip(request.records(owner: expected.zoneOwner), incoming) {
                    guard record.account == expected.account, record.database == expected.database, record.vaultID == expected.vaultID,
                          record.zoneName == id.zoneID.zoneName, record.zoneOwner == id.zoneID.ownerName,
                          record.recordName == id.recordName, record.recordType == NativeVaultProvisioningTransport.recordType else { throw SyncJournalError.invalidOperation }
                    _ = try stageIncomingInTransaction(record, budget: Self.maximumInboxBytes)
                }
            }
        }
    }

    /// Publication is not acknowledged here. This only records a fetched version
    /// in the inbox and completes its exact request in the same transaction.
    public func finishContentVersionFetch(_ expected: SyncOperation, incoming: IncomingRecord,
                                          permit: any RepositoryWritePermit) throws {
        guard layout == .contentPreview3 else { throw ContentStoreError.wrongLayout }
        try permit.withWritePermission {
            try transaction {
                let key = journalKey(expected.account, expected.database, expected.id.uuidString)
                guard var current: SyncOperation = try journalValue("SyncOperation", key: key), current == expected,
                      current.state != .completed else { throw SyncJournalError.staleOperation }
                guard expected.kind == .fetchContentVersion, current.attempts < Int.max,
                      let fetch = try? JSONDecoder().decode(ContentVersionFetch.self, from: expected.payload),
                      expected.vaultID == fetch.vault, incoming.vaultID == fetch.vault,
                      incoming.account == expected.account, incoming.database == "private", expected.database == "private",
                      incoming.zoneOwner == expected.zoneOwner,
                      incoming.zoneName == SyncStoreLayout.contentZone(vault: fetch.vault),
                      incoming.recordName == fetch.item.uuidString + ":" + fetch.version.uuidString,
                      incoming.recordType == ContentRecordKind.version.rawValue else { throw SyncJournalError.invalidOperation }
                _ = try stageIncomingInTransaction(incoming, budget: Self.maximumInboxBytes)
                current.state = .completed; current.completedAt = Date(); current.revision = UUID()
                current.failure = nil; current.nextAttempt = nil; current.retryNotBefore = nil; current.attempts += 1
                try writeJournal(current, entity: "SyncOperation", key: key, account: current.account, database: current.database)
            }
        }
    }

    public func deferIncoming(_ expected: IncomingRecord, dependencies: Set<SyncDependency>, failure: SyncFailure,
                              permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission { try deferIncoming(expected, dependencies: dependencies, failure: failure) }
    }

    public func deferIncoming(_ expected: IncomingRecord, dependencies: Set<SyncDependency>, failure: SyncFailure) throws {
        try transaction {
            let key = journalKey(expected.account, expected.database, expected.id)
            guard var current: IncomingRecord = try journalValue("IncomingRecord", key: key), current == expected else {
                throw SyncJournalError.staleOperation
            }
            guard current.dependencies != dependencies || current.failure != failure else { return }
            current.dependencies = dependencies; current.failure = failure
            try writeJournal(current, entity: "IncomingRecord", key: key, account: current.account, database: current.database)
        }
    }

    /// Called only after application/quarantine has committed. A crash between the
    /// two transactions replays the record; it never loses unapplied ciphertext.
    public func completeIncoming(_ expected: IncomingRecord, failure: SyncFailure? = nil) throws {
        try transaction { try completeIncomingInTransaction(expected, failure: failure) }
    }

    func requireIncomingInTransaction(_ expected: IncomingRecord) throws {
        guard let current: IncomingRecord = try journalValue("IncomingRecord", key: journalKey(expected.account, expected.database, expected.id)),
              current == expected else { throw SyncJournalError.staleOperation }
    }

    func completeIncomingInTransaction(_ expected: IncomingRecord, failure: SyncFailure? = nil) throws {
        let key = journalKey(expected.account, expected.database, expected.id)
        guard let row = try journalRow("IncomingRecord", key: key) else { return }
        guard let current: IncomingRecord = try journalValue("IncomingRecord", key: key), current == expected else {
            throw SyncJournalError.staleOperation
        }
        context.delete(row)
        if let failure {
            let operationKey = journalKey(expected.account, expected.database, expected.operationID.uuidString)
            guard var operation: SyncOperation = try journalValue("SyncOperation", key: operationKey) else { throw ItemRepositoryError.corruptStore }
            operation.state = .needsAttention; operation.failure = failure; operation.revision = UUID()
            operation.nextAttempt = nil; operation.retryNotBefore = nil
            try writeJournal(operation, entity: "SyncOperation", key: operationKey, account: expected.account, database: expected.database)
        } else {
            try finishPublicationInTransaction(expected.operationID, account: expected.account, database: expected.database, confirmed: false)
        }
    }

    public func syncHealth(account: String, database: String) throws -> SyncHealthSnapshot {
        try transaction {
            try journalReadCache.result(key: "health:" + journalKey(account, database, ""), in: context) {
                let operations = try journalReadCache.summary(prefix: journalPrefix("SyncOperation", account: account, database: database), in: context,
                    initial: OperationHealthSummary()) { (summary: inout OperationHealthSummary, row: OperationHealthFields, added: Bool) in
                        summary.update(row, added: added)
                    }
                let incoming: [IncomingHealthFields] = try journalValues("IncomingRecord", account: account, database: database)
                let unfinished = operations.unfinished.values
                let incomingOperations = Set(incoming.map(\.operationID))
                let pending = unfinished.filter { !incomingOperations.contains($0.id) }
                let lastDelivery: Date? = try journalValue("StateBlob", key: "sync-last-delivery:" + journalKey(account, database, ""))
                return SyncHealthSnapshot(pendingCount: pending.count + incoming.count,
                    oldestPendingAt: (pending.map(\.createdAt) + incoming.map(\.receivedAt)).min(),
                    lastDeliveryAt: [operations.latest, lastDelivery].compactMap { $0 }.max(),
                    blockedReasons: Set(unfinished.compactMap(\.failure) + incoming.compactMap(\.failure)))
            }
        }
    }

    func finishPublicationInTransaction(_ id: UUID, account: String, database: String, confirmed: Bool = true) throws {
        let key = journalKey(account, database, id.uuidString)
        guard var operation: SyncOperation = try journalValue("SyncOperation", key: key) else { return }
        operation.state = .completed; operation.completedAt = Date(); operation.failure = nil
        operation.deliveredAt = confirmed ? operation.completedAt : nil
        if confirmed, let delivered = operation.deliveredAt {
            try writeJournal(delivered, entity: "StateBlob", key: "sync-last-delivery:" + journalKey(account, database, ""))
        }
        operation.nextAttempt = nil; operation.retryNotBefore = nil; operation.dependencies = []; operation.revision = UUID()
        try writeJournal(operation, entity: "SyncOperation", key: key, account: account, database: database)
    }

    func conflictPublicationInTransaction(_ id: UUID, scope: ItemScope) throws {
        let key = journalKey(scope.account, scope.database, id.uuidString)
        guard var operation: SyncOperation = try journalValue("SyncOperation", key: key) else { return }
        operation.state = .needsAttention; operation.failure = .conflict; operation.revision = UUID()
        try writeJournal(operation, entity: "SyncOperation", key: key, account: scope.account, database: scope.database)
    }

    func purgeSyncJournalInTransaction(_ scope: VaultScope) throws {
        let operations: [SyncOperation] = try journalValues("SyncOperation", account: scope.account, database: scope.database)
        for operation in operations where operation.vaultID == scope.vaultID && operation.zoneOwner == scope.zoneOwner && !(layout == .contentPreview3 && operation.kind == .deletion) {
            if let row = try journalRow("SyncOperation", key: journalKey(scope.account, scope.database, operation.id.uuidString)) { context.delete(row) }
        }
        let incoming: [IncomingRecord] = try journalValues("IncomingRecord", account: scope.account, database: scope.database)
        for record in incoming where record.vaultID == scope.vaultID && record.zoneOwner == scope.zoneOwner {
            if let row = try journalRow("IncomingRecord", key: journalKey(scope.account, scope.database, record.id)) { context.delete(row) }
        }
    }

    func journalKey(_ account: String, _ database: String, _ id: String) -> String {
        [account, database, id].map { Data($0.utf8).base64EncodedString() }.joined(separator: ":")
    }
    func journalValue<T: Decodable>(_ entity: String, key: String) throws -> T? {
        guard let row = try journalRow(entity, key: key) else { return nil }
        guard let data = row.value(forKey: "value") as? Data else { throw ItemRepositoryError.corruptStore }
        return try JSONDecoder().decode(T.self, from: data)
    }
    func journalValues<T: Decodable>(_ entity: String, account: String, database: String? = nil) throws -> [T] {
        return try journalReadCache.values(prefix: journalPrefix(entity, account: account, database: database), in: context)
    }
    private func journalPrefix(_ entity: String, account: String, database: String?) -> String {
        var prefix = "sync-journal-v1:" + entity + ":" + Data(account.utf8).base64EncodedString() + ":"
        if let database { prefix += Data(database.utf8).base64EncodedString() + ":" }
        return prefix
    }
    func writeJournal<T: Encodable>(_ value: T, entity: String, key: String, account: String? = nil, database: String? = nil) throws {
        let bytes = try JSONEncoder().encode(value)
        let row = try journalRow(entity, key: key) ?? NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
        row.setValue(journalStorageKey(entity, key: key), forKey: "key"); row.setValue(bytes, forKey: "value")
    }
    /// Use the existing opaque-state table while v3 remains isolated. This keeps
    /// the foundation transactional without migrating the legacy store's schema.
    private func journalStorageKey(_ entity: String, key: String) -> String {
        entity == "StateBlob" ? key : "sync-journal-v1:" + entity + ":" + key
    }
    func journalRow(_ entity: String, key: String) throws -> NSManagedObject? {
        try fetchOne("StateBlob", key: journalStorageKey(entity, key: key))
    }
}
