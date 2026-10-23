import Foundation
import CloudKit

public enum SyncResolution: String, Codable, Sendable {
    case verifiedMembershipAvailable, verifiedContentAvailable, obsoleteGrantRequester, discardedByUser, unneededGrantSource, obsoleteGrantGeneration
}
public struct SyncTransportDetail: Codable, Equatable, Sendable {
    public let code: Int
    public let category: String
    public let occurredAt: Date
    public init(error: CKError, now: Date = Date()) {
        code = error.code.rawValue; occurredAt = now
        switch error.code {
        case .unknownItem, .zoneNotFound: category = "Required cloud record is missing"
        case .permissionFailure, .notAuthenticated: category = "Cloud account or permission needs attention"
        case .requestRateLimited, .zoneBusy, .serviceUnavailable: category = "Cloud service requested a retry"
        case .networkUnavailable, .networkFailure: category = "Network request failed"
        default: category = "Cloud request failed"
        }
    }
}
public struct SyncOperationDiagnostic: Identifiable, Sendable {
    public let id: UUID
    public let kind: SyncOperation.Kind
    public let vault: UUID?
    public let item: UUID?
    public let state: SyncOperationState
    public let failure: SyncFailure?
    public let attempts: Int
    public let createdAt: Date
    public let nextAttempt: Date?
    public let resolution: SyncResolution?
    public let completedAt: Date?
    public let membership: String?
    public let dependencies: [String]
    public let records: [String]
    public let transport: SyncTransportDetail?
    init(operation: SyncOperation, transport: SyncTransportDetail?) {
        id = operation.id; kind = operation.kind; vault = operation.vaultID
        state = operation.state; failure = operation.failure; attempts = operation.attempts
        createdAt = operation.createdAt; nextAttempt = operation.nextAttempt
        resolution = operation.resolution; completedAt = operation.completedAt; self.transport = transport
        let decoder = JSONDecoder()
        membership = operation.kind == .fetchMembership
            ? (try? decoder.decode(ContentMembershipFetch.self, from: operation.payload).digest) : nil
        if operation.kind == .fetchContentVersion, let request = try? decoder.decode(ContentVersionFetch.self, from: operation.payload) {
            item = request.item; records = [request.recordID(owner: operation.zoneOwner).recordName]
        } else if operation.kind == .fetchContentHead, let request = try? decoder.decode(ContentHeadFetch.self, from: operation.payload) {
            item = request.item; records = [request.recordID(owner: operation.zoneOwner).recordName]
        } else if operation.kind == .fetchMembership, let request = try? decoder.decode(ContentMembershipFetch.self, from: operation.payload) {
            item = nil; records = request.records(owner: operation.zoneOwner).map(\.recordName)
        } else { item = nil; records = [] }
        dependencies = operation.dependencies.map { dependency in
            dependency.kind.rawValue + ": " + (dependency.kind == .membership ? dependency.identifier : AccessSyncTrace.token(dependency.identifier))
        }.sorted()
    }
}

// Avoid decoding and retaining completed publication payloads for a diagnostics read.
private struct DiagnosticOperation: Decodable, JournalProjectionValue {
    let operation: SyncOperation?
    var includeInJournalProjection: Bool { operation != nil }
    private enum CodingKeys: String, CodingKey { case state, resolution }
    init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        let state = try fields.decode(SyncOperationState.self, forKey: .state)
        let resolution = try fields.decodeIfPresent(SyncResolution.self, forKey: .resolution)
        operation = state == .completed && resolution == nil ? nil : try SyncOperation(from: decoder)
    }
}

extension EncryptedItemRepository {
    public func recordSyncTransportFailure(_ operation: SyncOperation, error: CKError) throws {
        try transaction {
            let key = journalKey(operation.account, operation.database, operation.id.uuidString)
            guard let current: SyncOperation = try journalValue("SyncOperation", key: key),
                  current == operation, current.state != .completed else { return }
            // Store separately so diagnostic writes cannot invalidate worker CAS.
            try writeJournal(SyncTransportDetail(error: error), entity: "StateBlob",
                key: blobKey(operation.account, "sync-error:" + operation.database + ":" + operation.id.uuidString))
        }
    }
    public func syncOperationDiagnostics(account: String, database: String) throws -> [SyncOperationDiagnostic] {
        try transaction {
            let operations: [DiagnosticOperation] = try journalValues("SyncOperation", account: account, database: database)
            return try operations.compactMap(\.operation)
                .sorted { ($0.state == .completed ? 1 : 0, $0.createdAt) < ($1.state == .completed ? 1 : 0, $1.createdAt) }
                .map { operation in
                    SyncOperationDiagnostic(operation: operation, transport: try journalValue("StateBlob",
                        key: blobKey(account, "sync-error:" + database + ":" + operation.id.uuidString)))
                }
        }
    }
    /// Caller supplies verified evidence. Never implies cloud delivery of an edit.
    public func resolveSyncOperation(_ expected: SyncOperation, reason: SyncResolution, permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission {
            try transaction {
                let permitted: Bool
                switch reason {
                case .discardedByUser, .unneededGrantSource: permitted = false // Only the explicit archival transaction may discard work.
                case .verifiedMembershipAvailable: permitted = expected.kind == .fetchMembership
                case .verifiedContentAvailable: permitted = expected.kind == .fetchContentVersion
                case .obsoleteGrantRequester, .obsoleteGrantGeneration: permitted = expected.kind == .enrollment
                }
                guard permitted else { throw SyncJournalError.invalidOperation }
                let key = journalKey(expected.account, expected.database, expected.id.uuidString)
                guard let current: SyncOperation = try journalValue("SyncOperation", key: key), current == expected,
                      current.state != .completed else { throw SyncJournalError.staleOperation }
                var resolved = current
                resolved.state = .completed; resolved.resolution = reason; resolved.completedAt = Date()
                resolved.failure = nil; resolved.dependencies = []; resolved.nextAttempt = nil; resolved.retryNotBefore = nil
                resolved.revision = UUID()
                try writeJournal(resolved, entity: "SyncOperation", key: key, account: expected.account, database: expected.database)
            }
        }
    }
}
