import Foundation
import CryptoKit

/// Public diagnostics deliberately contain no record contents, names, or error descriptions.
public enum SyncFailure: String, Codable, Sendable {
    case transport, authorization, dependency, storagePressure, processing, invalidAuthority, conflict, accountChanged
}

public enum SyncOperationState: String, Codable, Sendable {
    case ready, waitingForDependency, waitingForAuthorization, retryScheduled, completed, needsAttention
}

public struct SyncDependency: Hashable, Codable, Sendable {
    public enum Kind: String, Codable, Sendable { case membership, grant, content, contentKeyGeneration, operation, authorization }
    public let kind: Kind
    public let identifier: String
    public init(_ kind: Kind, identifier: String) { self.kind = kind; self.identifier = identifier }
}

public struct SyncOperation: Equatable, Codable, Sendable, Identifiable {
    public enum Kind: String, Codable, Sendable {
        case publishItem, provision, membership, enrollment, grant, deletion, reconcile, applyIncoming, recoverTransport, prepareGrant, rotateContent, fetchContentVersion, publishCoordination, fetchMembership, recovery, removeCoordination, resolveConflict
    }
    public let id: UUID
    public let account: String
    public let database: String
    public let vaultID: UUID?
    public let zoneOwner: String
    public let kind: Kind
    public let createdAt: Date
    /// Exact opaque signed publication, if any. Randomization happens before enqueueing.
    public let payload: Data
    public var state: SyncOperationState
    public var dependencies: Set<SyncDependency>
    public var attempts: Int
    /// Consecutive backoff attempts; foreground/owner-release resets this without losing total attempts.
    public var retryAttempts: Int?
    public var nextAttempt: Date?
    public var retryNotBefore: Date?
    public var failure: SyncFailure?
    public var completedAt: Date?
    public var deliveredAt: Date?
    public var revision: UUID

    public init(id: UUID = UUID(), account: String, database: String = "private", vaultID: UUID? = nil,
                zoneOwner: String = "__defaultOwner__", kind: Kind, payload: Data = Data(), dependencies: Set<SyncDependency> = [], now: Date = Date()) {
        self.id = id; self.account = account; self.database = database; self.vaultID = vaultID
        self.kind = kind; self.payload = payload; self.createdAt = now; self.dependencies = dependencies
        self.zoneOwner = zoneOwner
        state = dependencies.isEmpty ? .ready : .waitingForDependency
        attempts = 0; revision = UUID()
    }
}

public struct IncomingRecord: Equatable, Codable, Sendable, Identifiable {
    public var operationID: UUID { Self.operationID(for: id) }
    static func operationID(for id: String) -> UUID {
        let hash = Array(SHA256.hash(data: Data(id.utf8)).prefix(16))
        return UUID(uuid: (hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
            hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]))
    }
    public let id: String
    public let account: String
    public let database: String
    public let zoneName: String
    public let zoneOwner: String
    public let recordName: String
    public let recordType: String
    public let vaultID: UUID?
    /// Asset contents are materialized here before a token may be checkpointed.
    public let bytes: Data
    public let systemFields: Data
    public let receivedAt: Date
    public var dependencies: Set<SyncDependency>
    public var failure: SyncFailure?

    public init(id: String, account: String, database: String, zoneName: String, zoneOwner: String,
                recordName: String, recordType: String, bytes: Data, systemFields: Data, vaultID: UUID? = nil, now: Date = Date()) {
        self.id = id; self.account = account; self.database = database; self.zoneName = zoneName
        self.zoneOwner = zoneOwner; self.recordName = recordName; self.recordType = recordType
        self.vaultID = vaultID
        self.bytes = bytes; self.systemFields = systemFields; receivedAt = now; dependencies = []
    }
}

public struct SyncHealthSnapshot: Equatable, Sendable {
    public let pendingCount: Int
    public let oldestPendingAt: Date?
    public let lastDeliveryAt: Date?
    public let blockedReasons: Set<SyncFailure>
    public init(pendingCount: Int, oldestPendingAt: Date?, lastDeliveryAt: Date?, blockedReasons: Set<SyncFailure>) {
        self.pendingCount = pendingCount; self.oldestPendingAt = oldestPendingAt
        self.lastDeliveryAt = lastDeliveryAt; self.blockedReasons = blockedReasons
    }
}

public enum SyncJournalError: Error, Equatable {
    case invalidOperation, identityCollision, staleOperation, inboxFull
}

public enum SyncRetryPolicy {
    /// Inject jitter in tests. Respect server throttles even when they exceed our cap.
    public static func delay(attempt: Int, jitter: Double, retryAfter: TimeInterval? = nil) -> TimeInterval {
        let base = min(300, 2 * pow(2, Double(min(20, max(0, attempt - 1)))))
        let boundedJitter = jitter.isFinite ? min(1, max(-1, jitter)) : 0
        let throttle = retryAfter.flatMap { $0.isFinite ? max(0, $0) : nil } ?? 0
        return max(base * (1 + 0.2 * boundedJitter), throttle)
    }
}
