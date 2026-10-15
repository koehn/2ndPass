@preconcurrency import CloudKit
import Foundation

/// Used inside the engine owner's bounded publication barrier. Cancellation
/// alone is not proof that a prior publication failed: authenticate an exact
/// readback through the inbox before choosing the rotation's accepted base.
public struct ContentRotationReadback: Sendable {
    private let repository: EncryptedItemRepository
    private let account: String
    private let fetch: ContentVersionFetcher.Fetch
    public init(repository: EncryptedItemRepository, account: String, fetch: @escaping ContentVersionFetcher.Fetch) {
        self.repository = repository; self.account = account; self.fetch = fetch
    }

    public func perform(scope: ItemScope, permit: any RepositoryWritePermit,
                        check: @Sendable () async throws -> Void,
                        apply: @Sendable (SyncOperation, any RepositoryWritePermit) async -> SyncOperationOutcome,
                        rotate: @Sendable () async throws -> SyncOperationOutcome) async throws -> SyncOperationOutcome {
        guard scope.account == account, scope.database == "private" else { throw CloudSyncAdapterError.invalidBinding }
        try await check(); try permit.withWritePermission {}
        let id = CKRecord.ID(recordName: scope.itemID.uuidString,
            zoneID: CKRecordZone.ID(zoneName: SyncStoreLayout.contentZone(vault: scope.vaultID), ownerName: scope.zoneOwner))
        do {
            let record = try await fetch(id)
            try await check(); try permit.withWritePermission {}
            guard record.recordID == id, record.recordType == ContentRecordKind.head.rawValue else { throw CloudSyncAdapterError.invalidBinding }
            let incoming = try ContentRecordTransport.materialize(record, account: account)
            AccessSyncTrace.event("rotation readback returned", item: scope.itemID, record: id.recordName,
                detail: "payloadBytes=\(incoming.bytes.count) systemFieldBytes=\(incoming.systemFields.count)")
            try await repository.stageIncoming(incoming, permit: permit)
            let operation = SyncOperation(id: incoming.operationID, account: account, vaultID: scope.vaultID,
                zoneOwner: scope.zoneOwner, kind: .applyIncoming, payload: Data(incoming.id.utf8))
            let applyStart = ContinuousClock.now
            let outcome = await apply(operation, permit)
            AccessSyncTrace.elapsed("rotation verified application", since: applyStart, item: scope.itemID)
            guard case .completed = outcome else { return outcome }
        } catch let error as CKError where error.code == .unknownItem {
            try await check(); try permit.withWritePermission {}
            // A disappeared accepted record is not authorization to resurrect it.
            if try await repository.acceptedVersion(scope) != nil { return .attention(.conflict) }
        }
        try await check(); try permit.withWritePermission {}
        let rotationStart = ContinuousClock.now
        defer { AccessSyncTrace.elapsed("rotation local work", since: rotationStart, item: scope.itemID) }
        return try await rotate()
    }
}

/// A bounded readback group shares the adapter's cancellation barrier, but each
/// head still passes through the ordinary authenticated inbox before rotation.
/// Partial failures never supply evidence for another item; results are in input order.
public struct ContentRotationBatchReadback: Sendable {
    public typealias Fetch = @Sendable ([CKRecord.ID]) async throws -> [CKRecord.ID: Result<CKRecord, any Error>]
    private let repository: EncryptedItemRepository
    private let account: String
    private let fetch: Fetch
    public init(repository: EncryptedItemRepository, account: String, fetch: @escaping Fetch) {
        self.repository = repository; self.account = account; self.fetch = fetch
    }

    public func perform(scopes: [ItemScope], permit: any RepositoryWritePermit,
                        check: @escaping @Sendable () async throws -> Void,
                        apply: @escaping @Sendable (SyncOperation, any RepositoryWritePermit) async -> SyncOperationOutcome,
                        rotate: @escaping @Sendable (ItemScope) async throws -> SyncOperationOutcome) async throws -> [SyncOperationOutcome] {
        guard !scopes.isEmpty, scopes.count <= DurableSyncCoordinator.rotationBatchLimit,
              scopes.allSatisfy({ $0.account == account && $0.database == "private" }),
              Set(scopes.map(\.storageKey)).count == scopes.count else { throw CloudSyncAdapterError.invalidBinding }
        try await check(); try permit.withWritePermission {}
        let ids = scopes.map {
            CKRecord.ID(recordName: $0.itemID.uuidString,
                        zoneID: CKRecordZone.ID(zoneName: SyncStoreLayout.contentZone(vault: $0.vaultID), ownerName: $0.zoneOwner))
        }
        let start = ContinuousClock.now
        let records: [CKRecord.ID: Result<CKRecord, any Error>]
        do {
            records = try await fetch(ids)
        } catch {
            AccessSyncTrace.elapsed("rotation batch fetch", since: start, detail: "records=\(ids.count) success=false")
            throw error
        }
        AccessSyncTrace.elapsed("rotation batch fetch", since: start, detail: "records=\(ids.count) success=true")
        // An account/lease change while fetching prevents every subsequent effect.
        try await check(); try permit.withWritePermission {}
        var outcomes: [SyncOperationOutcome] = []
        for (scope, id) in zip(scopes, ids) {
            let result = records[id]
            let readback = ContentRotationReadback(repository: repository, account: account) { _ in
                // A missing batch response is not CKError.unknownItem and must
                // never authorize creation of an apparently absent cloud head.
                guard let result else { throw CKError(.internalError) }
                return try result.get()
            }
            do {
                outcomes.append(try await readback.perform(scope: scope, permit: permit, check: check,
                    apply: apply, rotate: { try await rotate(scope) }))
            } catch let error as CKError {
                outcomes.append(.retry(.transport, retryAfter: error.retryAfterSeconds))
            } catch CloudSyncAdapterError.operationInterrupted {
                outcomes.append(.retry(.authorization))
            } catch {
                outcomes.append(.retry(.transport))
            }
        }
        return outcomes
    }
}
