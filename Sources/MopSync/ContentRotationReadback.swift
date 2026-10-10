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
            try await repository.stageIncoming(incoming, permit: permit)
            let operation = SyncOperation(id: incoming.operationID, account: account, vaultID: scope.vaultID,
                zoneOwner: scope.zoneOwner, kind: .applyIncoming, payload: Data(incoming.id.utf8))
            let outcome = await apply(operation, permit)
            guard case .completed = outcome else { return outcome }
        } catch let error as CKError where error.code == .unknownItem {
            try await check(); try permit.withWritePermission {}
            // A disappeared accepted record is not authorization to resurrect it.
            if try await repository.acceptedVersion(scope) != nil { return .attention(.conflict) }
        }
        try await check(); try permit.withWritePermission {}
        return try await rotate()
    }
}
