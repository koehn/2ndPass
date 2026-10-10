@preconcurrency import CloudKit
import CryptoKit
import Foundation

/// Only immutable version IDs can be fetched by this operation. A key-generation
/// dependency is deliberately different: it is not a CloudKit record identity.
public struct ContentVersionFetch: Codable, Equatable, Sendable {
    public let vault: UUID
    public let item: UUID
    public let version: UUID

    public init?(dependency: SyncDependency) {
        let parts = dependency.identifier.split(separator: ":", omittingEmptySubsequences: false)
        guard dependency.kind == .content, parts.count == 3,
              let vault = UUID(uuidString: String(parts[0])), parts[0] == Substring(vault.uuidString),
              let item = UUID(uuidString: String(parts[1])), parts[1] == Substring(item.uuidString),
              let version = UUID(uuidString: String(parts[2])), parts[2] == Substring(version.uuidString) else { return nil }
        self.vault = vault; self.item = item; self.version = version
    }

    public func recordID(owner: String) -> CKRecord.ID {
        CKRecord.ID(recordName: item.uuidString + ":" + version.uuidString,
            zoneID: CKRecordZone.ID(zoneName: SyncStoreLayout.contentZone(vault: vault), ownerName: owner))
    }

    public func operation(account: String, owner: String) throws -> SyncOperation {
        // Stable across process exit and duplicate dependents, scoped to account/owner.
        let identity = try JSONEncoder().encode(["content-version-fetch-v3", account, owner,
            vault.uuidString, item.uuidString, version.uuidString])
        let hash = Array(SHA256.hash(data: identity).prefix(16))
        let id = UUID(uuid: (hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
                            hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]))
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        return SyncOperation(id: id, account: account, vaultID: vault, zoneOwner: owner,
            kind: .fetchContentVersion, payload: try encoder.encode(self))
    }
}

/// Application-owned targeted fetches use the account coordinator's persisted
/// retry policy, not another timer. Success means durable reception, not trust or
/// delivery: the existing inbox handler still authenticates the fetched version.
public struct ContentVersionFetcher: Sendable {
    public typealias Fetch = @Sendable (CKRecord.ID) async throws -> CKRecord
    private let repository: EncryptedItemRepository
    private let account: String
    private let fetch: Fetch
    public init(repository: EncryptedItemRepository, account: String, fetch: @escaping Fetch) {
        self.repository = repository; self.account = account; self.fetch = fetch
    }

    public func handle(_ operation: SyncOperation, permit: any RepositoryWritePermit) async -> SyncOperationOutcome {
        do {
            guard operation.kind == .fetchContentVersion, operation.account == account, operation.database == "private",
                  let request = try? JSONDecoder().decode(ContentVersionFetch.self, from: operation.payload),
                  request.vault == operation.vaultID,
                  try request.operation(account: account, owner: operation.zoneOwner).id == operation.id else {
                return .attention(.invalidAuthority)
            }
            try permit.withWritePermission {}
            let id = request.recordID(owner: operation.zoneOwner)
            let record = try await fetch(id)
            try permit.withWritePermission {}
            guard record.recordID == id, record.recordType == ContentRecordKind.version.rawValue else {
                return .attention(.invalidAuthority)
            }
            let incoming = try ContentRecordTransport.materialize(record, account: account)
            try await repository.finishContentVersionFetch(operation, incoming: incoming, permit: permit)
            return .completed
        } catch SyncJournalError.staleOperation { return .retry(.dependency) }
        catch SyncJournalError.inboxFull { return .retry(.storagePressure) }
        catch CloudSyncAdapterError.operationInterrupted { return .retry(.authorization) }
        catch let error as CKError {
            // unknownItem can be publication ordering, never proof of deletion.
            return .retry(.transport, retryAfter: (error.userInfo[CKErrorRetryAfterKey] as? NSNumber)?.doubleValue)
        } catch let error as CloudSyncAdapterError {
            return error == .malformedRecord ? .attention(.invalidAuthority) : .retry(.transport)
        } catch { return .retry(.transport) }
    }
}
