@preconcurrency import CloudKit
import CryptoKit
import Foundation

public struct ContentMembershipFetch: Codable, Equatable, Sendable {
    public let vault: UUID
    public let digest: String
    public var dependency: SyncDependency { SyncDependency(.membership, identifier: vault.uuidString + ":" + digest) }
    public init?(dependency: SyncDependency) {
        let parts = dependency.identifier.split(separator: ":", omittingEmptySubsequences: false)
        guard dependency.kind == .membership, parts.count == 2,
              let vault = UUID(uuidString: String(parts[0])), parts[0] == Substring(vault.uuidString),
              parts[1].utf8.count == 64, parts[1].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { return nil }
        self.vault = vault; digest = String(parts[1])
    }
    public func operation(account: String, owner: String) throws -> SyncOperation {
        let bytes = try JSONEncoder().encode(["membership-fetch-v3", account, owner, vault.uuidString, digest])
        let hash = Array(SHA256.hash(data: bytes).prefix(16))
        let id = UUID(uuid: (hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]))
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return SyncOperation(id: id, account: account, vaultID: vault, zoneOwner: owner, kind: .fetchMembership, payload: try encoder.encode(self))
    }
    public func records(owner: String) -> [CKRecord.ID] {
        let zone = CKRecordZone.ID(zoneName: SyncStoreLayout.contentZone(vault: vault), ownerName: owner)
        return [CKRecord.ID(recordName: "membership-" + digest, zoneID: zone), CKRecord.ID(recordName: "membership-head", zoneID: zone)]
    }
}

/// Fetches both the immutable authority and its committed head. An immutable
/// proposal alone never establishes membership. Until pinned application catches
/// up this operation retries durably, so a missed head notification cannot strand
/// its dependents. It owns no timer or secret keys.
public struct ContentMembershipFetcher: Sendable {
    private let repository: EncryptedItemRepository
    private let account: String
    private let fetch: ContentVersionFetcher.Fetch
    private let available: @Sendable (SyncDependency) async throws -> Bool
    public init(repository: EncryptedItemRepository, account: String, fetch: @escaping ContentVersionFetcher.Fetch,
                available: @escaping @Sendable (SyncDependency) async throws -> Bool) {
        self.repository = repository; self.account = account; self.fetch = fetch; self.available = available
    }
    public func handle(_ operation: SyncOperation, permit: any RepositoryWritePermit) async -> SyncOperationOutcome {
        do {
            guard operation.kind == .fetchMembership, operation.account == account, operation.database == "private",
                  let request = try? JSONDecoder().decode(ContentMembershipFetch.self, from: operation.payload),
                  ContentMembershipFetch(dependency: request.dependency) == request, request.vault == operation.vaultID,
                  try request.operation(account: account, owner: operation.zoneOwner).id == operation.id else { return .attention(.invalidAuthority) }
            try permit.withWritePermission {}
            if try await available(request.dependency) { return .completed }
            var incoming: [IncomingRecord] = []
            for id in request.records(owner: operation.zoneOwner) {
                AccessSyncTrace.event("membership fetch starting", operation: operation.id, record: id.recordName)
                let record = try await fetch(id)
                AccessSyncTrace.event("membership fetch returned", operation: operation.id, record: id.recordName)
                try permit.withWritePermission {}
                guard record.recordID == id else { return .attention(.invalidAuthority) }
                incoming.append(try ContentMembershipTransport.materialize(record, account: account))
            }
            try await repository.stageMembershipFetch(operation, incoming: incoming, permit: permit)
            return .retry(.dependency)
        } catch SyncJournalError.inboxFull { return .retry(.inboxFull) }
        catch SyncJournalError.staleOperation { return .retry(.dependency) }
        catch CloudSyncAdapterError.contentZoneUnavailable(let vault) {
            guard vault == operation.vaultID else { return .attention(.invalidAuthority) }
            return .waiting([.init(.trustedContentZone, identifier: vault.uuidString)])
        }
        catch CloudSyncAdapterError.invalidBinding { return .attention(.invalidAuthority) }
        catch let error as CKError {
            try? await repository.recordSyncTransportFailure(operation, error: error)
            AccessSyncTrace.failure("membership fetch cloud failure", operation: operation.id, error: error)
            return .retry(.transport, retryAfter: (error.userInfo[CKErrorRetryAfterKey] as? NSNumber)?.doubleValue)
        }
        catch CloudSyncAdapterError.malformedRecord { return .attention(.invalidAuthority) }
        catch {
            AccessSyncTrace.failure("membership fetch failed", operation: operation.id, error: error)
            return .retry(.transport)
        }
    }
}
