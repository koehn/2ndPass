import Foundation

/// Session-owned synchronous permit. Implementations serialize lock invalidation
/// with the entire supplied durable transaction, not only an initial check.
public protocol RepositoryWritePermit: Sendable {
    func withWritePermission<T>(_ body: () throws -> T) throws -> T
}

/// `account` is an opaque binding of container, environment and Apple account,
/// never an email address or display name. Database and zone owner scope records
/// independently so identical vault UUIDs in different shared zones cannot collide.
public struct ItemScope: Hashable, Codable, Sendable {
    public let account: String
    public let vaultID: UUID
    public let itemID: UUID
    public let database: String
    public let zoneOwner: String

    public init(account: String, vaultID: UUID, itemID: UUID,
                database: String = "private", zoneOwner: String = "__defaultOwner__") {
        self.account = account
        self.vaultID = vaultID
        self.itemID = itemID
        self.database = database
        self.zoneOwner = zoneOwner
    }

    var storageKey: String {
        [account, database, zoneOwner].map { Data($0.utf8).base64EncodedString() }.joined(separator: ":")
            + ":" + vaultID.uuidString + ":" + itemID.uuidString
    }
}

/// Payload encryption and authentication are performed before the repository boundary.
/// Tombstones also carry authenticated ciphertext; absence is not proof of deletion.
public struct EncryptedItemVersion: Codable, Equatable, Sendable {
    public let scope: ItemScope
    public let versionID: UUID
    public let baseVersionID: UUID?
    public let ciphertext: Data
    public let isTombstone: Bool
    public let healthItemID: UUID?
    public let generation: UInt64

    public init(scope: ItemScope, versionID: UUID = UUID(), baseVersionID: UUID?,
                ciphertext: Data, isTombstone: Bool = false, generation: UInt64 = 1, healthItemID: UUID? = nil) {
        self.scope = scope
        self.versionID = versionID
        self.baseVersionID = baseVersionID
        self.ciphertext = ciphertext
        self.healthItemID = healthItemID
        self.isTombstone = isTombstone
        self.generation = generation
    }
}

public struct PendingItemMutation: Equatable, Sendable, Identifiable {
    public let id: UUID
    public let version: EncryptedItemVersion
    public let createdAt: Date
    public let sequence: Int64
}

public struct EncryptedItemConflict: Equatable, Sendable, Identifiable {
    public let id: UUID
    public let local: EncryptedItemVersion
    public let remote: EncryptedItemVersion
    public let serverSystemFields: Data
}

public struct RepositoryHistoryBatch: Sendable {
    public let transactionCount: Int
    public let token: Data?
}

public enum MutationDeliveryStatus: String, Codable, Sendable {
    case queued, cloudConfirmed, conflict, superseded
}

/// Retained independently of the pending queue, so absence of work never masquerades
/// as confirmation that CloudKit accepted an operation.
public struct MutationDeliveryReceipt: Equatable, Sendable, Identifiable {
    public let id: UUID
    public let scope: ItemScope
    public let versionID: UUID
    public let status: MutationDeliveryStatus
}

public enum SyncRequestReason: String, Codable, Sendable {
    case localSave, manual, foreground, networkRestored
}

public struct DurableSyncRequest: Equatable, Sendable {
    public let account: String
    public let database: String
    public let generation: Int64
    public let reason: SyncRequestReason
}

public enum ItemRepositoryError: Error, Equatable, Sendable {
    case invalidInitialization
    case existingVault
    case initializationMismatch
    case invalidScope
    case invalidGeneration
    case emptyCiphertext
    case oversizedCiphertext
    case staleLocalVersion
    case staleConflict
    case duplicateVersion
    case missingMutation
    case outOfOrderAcknowledgement
    case corruptStore
    case pendingLocalChanges
    case unresolvedConflict
    case remoteVersionConflict
}

/// Complete local storage boundary for one owned or shared vault.
public struct VaultScope: Hashable, Codable, Sendable {
    public let account: String
    public let vaultID: UUID
    public let database: String
    public let zoneOwner: String
    public init(account: String, vaultID: UUID, database: String = "private", zoneOwner: String = "__defaultOwner__") {
        self.account = account; self.vaultID = vaultID; self.database = database; self.zoneOwner = zoneOwner
    }
    init(_ item: ItemScope) {
        self.init(account: item.account, vaultID: item.vaultID, database: item.database, zoneOwner: item.zoneOwner)
    }
    var storageKey: String {
        [account, database, zoneOwner].map { Data($0.utf8).base64EncodedString() }.joined(separator: ":") + ":" + vaultID.uuidString
    }
}

/// Immutable creation receipt, retained after subsequent edits and uploads.
/// Membership bytes must be authenticated by the domain layer before this boundary.
public struct VaultInitializationReceipt: Codable, Equatable, Sendable {
    public let scope: VaultScope
    public let setupID: String
    public let membershipState: Data
    public let inputDigest: Data
    public let mutationIDs: [UUID]
}

/// Disposable encrypted projection. Never enters the item outbox.
public struct EncryptedDisplayCatalogRow: Codable, Sendable {
    public let itemID: UUID
    public let versionID: UUID
    public let keyID: UUID
    public let ciphertext: Data
    public init(itemID: UUID, versionID: UUID, keyID: UUID, ciphertext: Data) {
        self.itemID = itemID; self.versionID = versionID; self.keyID = keyID; self.ciphertext = ciphertext
    }
}
