@preconcurrency import CloudKit
import CryptoKit
import Foundation

/// Fetch the mutable item head by its canonical address, never by key generation.
public struct ContentHeadFetch: Codable, Equatable, Sendable {
    public let vault: UUID
    public let item: UUID
    /// One refresh per observed item/membership state; duplicates stay coalesced.
    public let observation: String?

    public init(vault: UUID, item: UUID, observedVersion: UUID?, membership: String) {
        self.vault = vault; self.item = item
        observation = (observedVersion?.uuidString ?? "missing") + ":" + membership
    }

    public init?(dependency: SyncDependency) {
        let parts = dependency.identifier.split(separator: ":", omittingEmptySubsequences: false)
        guard dependency.kind == .contentHead, parts.count == 2,
              let vault = UUID(uuidString: String(parts[0])), parts[0] == Substring(vault.uuidString),
              let item = UUID(uuidString: String(parts[1])), parts[1] == Substring(item.uuidString) else { return nil }
        self.vault = vault; self.item = item; observation = nil
    }

    public func recordID(owner: String) -> CKRecord.ID {
        CKRecord.ID(recordName: item.uuidString,
            zoneID: CKRecordZone.ID(zoneName: SyncStoreLayout.contentZone(vault: vault), ownerName: owner))
    }

    public func operation(account: String, owner: String) throws -> SyncOperation {
        // Stable across process exit and duplicate dependents, scoped to account/owner.
        var parts = ["content-head-fetch-v3", account, owner, vault.uuidString, item.uuidString]
        if let observation { parts.append(observation) }
        let identity = try JSONEncoder().encode(parts)
        let hash = Array(SHA256.hash(data: identity).prefix(16))
        let id = UUID(uuid: (hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
                            hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]))
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        return SyncOperation(id: id, account: account, vaultID: vault, zoneOwner: owner,
            kind: .fetchContentHead, payload: try encoder.encode(self))
    }
}

/// Application-owned targeted fetches use the account coordinator's persisted
/// retry policy, not another timer. Success means durable reception, not trust or
/// delivery: the existing inbox handler still authenticates the fetched head.
public struct ContentHeadFetcher: Sendable {
    public typealias Fetch = @Sendable (CKRecord.ID) async throws -> CKRecord
    private let repository: EncryptedItemRepository
    private let account: String
    private let fetch: Fetch
    public init(repository: EncryptedItemRepository, account: String, fetch: @escaping Fetch) {
        self.repository = repository; self.account = account; self.fetch = fetch
    }

    public func handle(_ operation: SyncOperation, permit: any RepositoryWritePermit) async -> SyncOperationOutcome {
        do {
            guard operation.kind == .fetchContentHead, operation.account == account, operation.database == "private",
                  let request = try? JSONDecoder().decode(ContentHeadFetch.self, from: operation.payload),
                  request.vault == operation.vaultID,
                  try request.operation(account: account, owner: operation.zoneOwner).id == operation.id else {
                return .attention(.invalidAuthority)
            }
            try permit.withWritePermission {}
            let id = request.recordID(owner: operation.zoneOwner)
            let record = try await fetch(id)
            try permit.withWritePermission {}
            guard record.recordID == id, record.recordType == ContentRecordKind.head.rawValue else {
                return .attention(.invalidAuthority)
            }
            let incoming = try ContentRecordTransport.materialize(record, account: account)
            try await repository.finishContentHeadFetch(operation, incoming: incoming, permit: permit)
            return .completed
        } catch SyncJournalError.staleOperation { return .retry(.dependency) }
        catch SyncJournalError.inboxFull { return .retry(.inboxFull) }
        catch CloudSyncAdapterError.operationInterrupted { return .retry(.authorization) }
        catch CloudSyncAdapterError.contentZoneUnavailable(let vault) {
            guard vault == operation.vaultID else { return .attention(.invalidAuthority) }
            return .waiting([.init(.trustedContentZone, identifier: vault.uuidString)])
        }
        catch CloudSyncAdapterError.invalidBinding { return .attention(.invalidAuthority) }
        catch let error as CKError {
            try? await repository.recordSyncTransportFailure(operation, error: error)
            // unknownItem can be publication ordering, never proof of deletion.
            return .retry(.transport, retryAfter: (error.userInfo[CKErrorRetryAfterKey] as? NSNumber)?.doubleValue)
        } catch let error as CloudSyncAdapterError {
            return error == .malformedRecord ? .attention(.invalidAuthority) : .retry(.transport)
        } catch { return .retry(.transport) }
    }
}
