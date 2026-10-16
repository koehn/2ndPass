@preconcurrency import CoreData
import Foundation

extension EncryptedItemRepository {
    /// Immutable prepared control publications share the account outbox. No
    /// screen owns retries, and replay never signs a replacement request.
    public func enqueueCoordination(_ record: PreparedCoordinationRecord, prerequisites: [SyncOperation] = [],
                                     authorization: any RepositoryWritePermit) throws -> SyncOperation {

        return try authorization.withWritePermission {
            try transaction {
                let candidate = try record.operation(dependencies: Set(prerequisites.map { SyncDependency(.operation, identifier: $0.id.uuidString) }))
                if let existing: SyncOperation = try journalValue("SyncOperation", key: journalKey(record.account, "private", candidate.id.uuidString)) {
                    guard existing.kind == candidate.kind, existing.payload == candidate.payload, existing.vaultID == candidate.vaultID, existing.zoneOwner == candidate.zoneOwner else { throw SyncJournalError.identityCollision }
                    return existing
                }
                for prerequisite in prerequisites {
                    guard prerequisite.account == record.account, prerequisite.database == "private",
                          prerequisite.zoneOwner == record.zoneOwner, prerequisite.vaultID == record.vault else { throw SyncJournalError.invalidOperation }
                    _ = try enqueueInTransaction(prerequisite)
                }
                return try enqueueInTransaction(candidate)
            }
        }
    }

    public func preparedCoordination(account: String, vault: UUID, kind: CoordinationRecordKind, identity: UUID) throws -> PreparedCoordinationRecord? {

        let address = try PreparedCoordinationRecord(account: account, vault: vault, kind: kind, identity: identity, bytes: Data([0]))
        return try transaction {
            let key = journalKey(account, "private", address.operationID.uuidString)
            if let operation: SyncOperation = try journalValue("SyncOperation", key: key) {
                guard operation.kind == .publishCoordination else { throw ContentStoreError.identityCollision }
                return try JSONDecoder().decode(PreparedCoordinationRecord.self, from: operation.payload)
            }
            return try journalValue("StateBlob", key: coordinationKey(address))
        }
    }

    public func coordinationPublications(account: String, limit: Int = 100) throws -> [PreparedCoordinationRecord] {
        guard limit > 0, limit <= 100 else { throw ContentStoreError.wrongLayout }
        return try transaction {
            let receiving = try incomingCloudRecordIDsInTransaction(account: account, database: "private")
            let operations = try activeOperationsInTransaction(account: account, database: "private")
                .filter { $0.kind == .publishCoordination && $0.state != .needsAttention }
            var result: [PreparedCoordinationRecord] = []
            for operation in operations.sorted(by: { ($0.createdAt, $0.id.uuidString) < ($1.createdAt, $1.id.uuidString) }) {
                guard operation.state != .retryScheduled || (operation.nextAttempt ?? .distantPast) <= Date() else { continue }
                guard try operation.dependencies.allSatisfy({ dependency in
                    guard dependency.kind == .operation, let id = UUID(uuidString: dependency.identifier) else { return false }
                    return try operationDeliveredInTransaction(id, account: account, database: "private")
                }) else { continue }
                let record = try JSONDecoder().decode(PreparedCoordinationRecord.self, from: operation.payload)
                guard record.account == account, record.operationID == operation.id, record.vault == operation.vaultID,
                      record.zoneOwner == operation.zoneOwner else { throw ItemRepositoryError.corruptStore }
                if record.kind != .deletion,
                   try deletionInTransaction(VaultScope(account: account, vaultID: record.vault)) != nil { continue }
                guard !receiving.contains(record.recordID) else { continue }
                result.append(record)
                if result.count == limit { break }
            }
            return result
        }
    }

    /// The caller verifies public authority and semantic payload bindings first.
    /// Reception and delivery acknowledgment are one transaction. A different
    /// payload at an immutable address cannot acknowledge our pending operation.
    public func receiveCoordination(_ record: PreparedCoordinationRecord, from incoming: IncomingRecord,
                                     work: [SyncOperation] = [], equivalentPending: PreparedCoordinationRecord? = nil,
                                     permit: any RepositoryWritePermit) throws {
        guard incoming.account == record.account, incoming.database == "private",
              incoming.zoneName == SyncStoreLayout.contentCoordinationZone, incoming.zoneOwner == record.zoneOwner,
              incoming.recordName == record.recordName, incoming.recordType == record.kind.recordType,
              incoming.vaultID == record.vault, incoming.bytes == record.bytes else { throw ContentStoreError.invalidRecord }
        try permit.withWritePermission {
            try transaction {
                try requireIncomingInTransaction(incoming)
                let key = coordinationKey(record)
                if let accepted: PreparedCoordinationRecord = try journalValue("StateBlob", key: key), accepted != record { throw ContentStoreError.identityCollision }
                let opKey = journalKey(record.account, "private", record.operationID.uuidString)
                if let pending: SyncOperation = try journalValue("SyncOperation", key: opKey) {
                    let prepared = try JSONDecoder().decode(PreparedCoordinationRecord.self, from: pending.payload)
                    if prepared == record {
                        try finishPublicationInTransaction(pending.id, account: record.account, database: "private", confirmed: true)
                    } else {
                        guard prepared == equivalentPending, [.enrollmentApproval, .deletion].contains(record.kind),
                              pending.deliveredAt == nil, pending.state != .completed else { throw ContentStoreError.identityCollision }
                        // The server's authenticated equivalent statement wins. This local
                        // representation was superseded, never cloud confirmed.
                        var accepted = try record.operation()
                        accepted.state = .completed; accepted.completedAt = Date()
                        try writeJournal(accepted, entity: "SyncOperation", key: opKey, account: record.account, database: "private")
                    }
                }
                for operation in work {
                    guard operation.account == record.account, operation.database == "private", operation.vaultID == record.vault, operation.zoneOwner == record.zoneOwner, [.enrollment, .deletion].contains(operation.kind) else { throw SyncJournalError.invalidOperation }
                    _ = try enqueueInTransaction(operation)
                }
                try writeJournal(record, entity: "StateBlob", key: key)
                try completeIncomingInTransaction(incoming)
            }
        }
    }

    public func coordinationRecords(account: String, kind: CoordinationRecordKind? = nil, vault: UUID? = nil) throws -> [PreparedCoordinationRecord] {

        return try transaction {
            let query = NSFetchRequest<NSManagedObject>(entityName: "StateBlob")
            query.predicate = NSPredicate(format: "key BEGINSWITH %@", coordinationPrefix(account))
            return try context.fetch(query).map { row in
                guard let bytes = row.value(forKey: "value") as? Data else { throw ItemRepositoryError.corruptStore }
                return try JSONDecoder().decode(PreparedCoordinationRecord.self, from: bytes)
            }.filter { (kind == nil || $0.kind == kind) && (vault == nil || $0.vault == vault) }
        }
    }
    private func coordinationPrefix(_ account: String) -> String { "coordination3:" + Data(account.utf8).base64EncodedString() + ":" }
    private func coordinationKey(_ record: PreparedCoordinationRecord) -> String { coordinationPrefix(record.account) + record.zoneOwner + ":" + record.recordName }
}

extension EncryptedItemRepository {
    public func contentMembershipCandidate(scope: VaultScope, digest: String) throws -> Data? {
        try incomingRecords(account: scope.account, database: scope.database).first {
            $0.vaultID == scope.vaultID && $0.zoneOwner == scope.zoneOwner &&
            $0.zoneName == SyncStoreLayout.contentZone(vault: scope.vaultID) &&
            $0.recordName == "membership-" + digest
        }?.bytes
    }

}

extension EncryptedItemRepository {
    public func contentDiscovery(account: String) throws -> [VaultCloudAddress] {
        try transaction { try journalValue("StateBlob", key: "discovery3:" + journalKey(account, "private", "index")) ?? [] }
    }
    public func retainContentDiscovery(account: String, addresses: [VaultCloudAddress], authorization: any RepositoryWritePermit) throws {
        guard addresses.allSatisfy({ $0.zoneName == SyncStoreLayout.contentZone(vault: $0.vaultID) && $0.ownerName == "__defaultOwner__" }) else { throw ContentStoreError.invalidRecord }
        try authorization.withWritePermission {
            try transaction {
                let key = "discovery3:" + journalKey(account, "private", "index")
                var values: [VaultCloudAddress] = try journalValue("StateBlob", key: key) ?? []
                for address in addresses where !values.contains(address) {
                    // Zone existence is a routing hint, not evidence that a
                    // signed deletion was undone. Cleanup may still be pending.
                    guard try deletionInTransaction(VaultScope(account: account, vaultID: address.vaultID)) == nil else { continue }
                    values.append(address)
                    // Deterministic durable bootstrap request; its handler still
                    // needs an authorized device before signing enrollment.
                    _ = try enqueueInTransaction(SyncOperation(id: address.vaultID, account: account, vaultID: address.vaultID, kind: .enrollment))
                }
                if !addresses.isEmpty { try writeJournal(values, entity: "StateBlob", key: key) }
            }
        }
    }
}

public struct CompletedEnrollmentReceipt: Codable, Sendable {
    public let request: UUID
    public let vault: UUID
    public let approvalDigest: String
    public let completedAt: Date
    public init(request: UUID, vault: UUID, approvalDigest: String, completedAt: Date = Date()) {
        self.request = request; self.vault = vault; self.approvalDigest = approvalDigest; self.completedAt = completedAt
    }
}

extension EncryptedItemRepository {
    public func enrollmentReceipt(account: String, vault: UUID, request: UUID, now: Date = Date()) throws -> CompletedEnrollmentReceipt? {
        try transaction {
            let value: CompletedEnrollmentReceipt? = try journalValue("StateBlob", key: "enrollment3:" + journalKey(account, "private", vault.uuidString + ":" + request.uuidString))
            return value.flatMap { now.timeIntervalSince($0.completedAt) < 30 * 86400 ? $0 : nil }
        }
    }
    /// Called only after verifying the recipient's exact acknowledgment. The
    /// receipt and transport deletions commit together, and survive interruption.
    public func completeContentEnrollment(_ receipt: CompletedEnrollmentReceipt, account: String, permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission {
            try transaction {
                let key = "enrollment3:" + journalKey(account, "private", receipt.vault.uuidString + ":" + receipt.request.uuidString)
                if let existing: CompletedEnrollmentReceipt = try journalValue("StateBlob", key: key) {
                    guard existing.approvalDigest == receipt.approvalDigest else { throw ContentStoreError.identityCollision }; return
                }
                try writeJournal(receipt, entity: "StateBlob", key: key)
                let work: [SyncOperation] = try journalValues("SyncOperation", account: account, database: "private")
                for operation in work where operation.kind == .enrollment && operation.vaultID == receipt.vault {
                    if let record = try? JSONDecoder().decode(PreparedCoordinationRecord.self, from: operation.payload),
                       record.identity == receipt.request, [.enrollmentRequest, .enrollmentApproval, .enrollmentAcknowledgment].contains(record.kind),
                       let row = try journalRow("SyncOperation", key: journalKey(account, "private", operation.id.uuidString)) { context.delete(row) }
                }
                for kind: CoordinationRecordKind in [.enrollmentRequest, .enrollmentApproval, .enrollmentAcknowledgment] {
                    let address = try PreparedCoordinationRecord(account: account, vault: receipt.vault, kind: kind, identity: receipt.request, bytes: Data([0]))
                    let operation = SyncOperation(account: account, vaultID: receipt.vault, kind: .removeCoordination, payload: Data(address.recordName.utf8))
                    _ = try enqueueInTransaction(operation)
                    if let row = try journalRow("StateBlob", key: coordinationKey(address)) { context.delete(row) }
                    // Public relay ciphertext is no longer needed after the
                    // durable recipient acknowledgment; compact receipts remain.
                    if let row = try journalRow("SyncOperation", key: journalKey(account, "private", address.operationID.uuidString)) { context.delete(row) }
                }
            }
        }
    }
    public func coordinationRemovals(account: String) throws -> [SyncOperation] {
        try transaction {
            try activeOperationsInTransaction(account: account, database: "private")
                .filter { $0.kind == .removeCoordination }
                .sorted { ($0.createdAt, $0.id.uuidString) < ($1.createdAt, $1.id.uuidString) }
        }
    }
    public func acknowledgeCoordinationRemoval(account: String, record: String, permit: any RepositoryWritePermit) throws {
        for operation in try coordinationRemovals(account: account) where operation.payload == Data(record.utf8) {
            try confirmOperation(operation, permit: permit)
        }
    }
}

// Public configuration and its prerequisite operations share one transaction.
extension EncryptedItemRepository {
    public func saveContentWorkflowState(_ data: Data, account: String, name: String,
                                        operations: [SyncOperation], permit: any RepositoryWritePermit) throws {
        guard operations.allSatisfy({ $0.account == account && $0.database == "private" }) else { throw ContentStoreError.invalidRecord }
        try permit.withWritePermission {
            try transaction {
                let row = try fetchOne("StateBlob", key: blobKey(account, name)) ?? NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
                row.setValue(blobKey(account, name), forKey: "key"); row.setValue(data, forKey: "value")
                for operation in operations { _ = try enqueueInTransaction(operation) }
            }
        }
    }
}

extension EncryptedItemRepository {
    /// Replace a membership proposal proven absent from the accepted chain.
    /// Its approval cannot have been sent: the exact membership prerequisite is
    /// still undelivered. Both replacements commit before either can be selected.
    public func rebaseUncommittedMembership(_ expected: SyncOperation, payload: Data?,
                                           approval: PreparedCoordinationRecord?, permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission {
            try transaction {
                let key = journalKey(expected.account, expected.database, expected.id.uuidString)
                guard let current: SyncOperation = try journalValue("SyncOperation", key: key), current == expected,
                      current.kind == .membership, current.deliveredAt == nil, current.state != .completed else { throw SyncJournalError.staleOperation }
                let operations: [SyncOperation] = try journalValues("SyncOperation", account: expected.account, database: expected.database)
                let dependency = SyncDependency(.operation, identifier: expected.id.uuidString)
                for publication in operations where publication.kind == .publishCoordination && publication.dependencies.contains(dependency) {
                    guard publication.deliveredAt == nil, publication.state != .completed else { throw ContentStoreError.staleAuthority }
                    let old = try JSONDecoder().decode(PreparedCoordinationRecord.self, from: publication.payload)
                    if let approval {
                        guard old.kind == .enrollmentApproval, old.recordName == approval.recordName, old.account == approval.account else { throw ContentStoreError.invalidRecord }
                        let next = try approval.operation(dependencies: payload == nil ? [] : publication.dependencies)
                        try writeJournal(next, entity: "SyncOperation", key: journalKey(next.account, next.database, next.id.uuidString), account: next.account, database: next.database)
                    } else {
                        try finishPublicationInTransaction(publication.id, account: expected.account, database: expected.database, confirmed: false)
                    }
                }
                if let payload {
                    let next = SyncOperation(id: current.id, account: current.account, database: current.database, vaultID: current.vaultID,
                        zoneOwner: current.zoneOwner, kind: .membership, payload: payload, now: current.createdAt)
                    try writeJournal(next, entity: "SyncOperation", key: key, account: next.account, database: next.database)
                } else { try finishPublicationInTransaction(current.id, account: current.account, database: current.database, confirmed: false) }
            }
        }
    }
}

extension EncryptedItemRepository {
    /// Discovery is only an address hint. Removing it never removes pinned trust,
    /// content, receipts or an enrolled vault's local projection.
    public func removeContentDiscovery(account: String, vault: UUID, publishRemoval: Bool,
                                       permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission {
            try transaction {
                let key = "discovery3:" + journalKey(account, "private", "index")
                let values: [VaultCloudAddress] = try journalValue("StateBlob", key: key) ?? []
                let retained = values.filter { $0.vaultID != vault }
                if retained != values { try writeJournal(retained, entity: "StateBlob", key: key) }
                if publishRemoval {
                    let record = try PreparedCoordinationRecord(account: account, vault: vault, kind: .discovery, identity: vault, bytes: Data([0]))
                    let payload = Data(record.recordName.utf8)
                    let operations: [SyncOperation] = try journalValues("SyncOperation", account: account, database: "private")
                    if !operations.contains(where: { $0.kind == .removeCoordination && $0.payload == payload }) {
                        _ = try enqueueInTransaction(SyncOperation(account: account, vaultID: vault, kind: .removeCoordination, payload: payload))
                    }
                }
            }
        }
    }
}
