@preconcurrency import CoreData
import CryptoKit
import Foundation

/// Stable paths and cloud identifiers for the sole supported content store.
public enum SyncStoreLayout: Sendable {
    public static let contentSubscriptionID = "mop-content-v3-private"

    public static func contentPreviewURL(in root: URL) -> URL {
        root.appendingPathComponent("ContentPreview3", isDirectory: true).appendingPathComponent("Content3.sqlite")
    }
    public static let contentCoordinationZone = "MopCoordination3"
    public static func contentZone(vault: UUID) -> String { "MopContent3-" + vault.uuidString }

    static func validate(storeURL: URL) throws {
        let resolved = storeURL.standardizedFileURL.resolvingSymlinksInPath()
        let isPreview = resolved.lastPathComponent.lowercased() == "content3.sqlite"
            && resolved.deletingLastPathComponent().lastPathComponent.lowercased() == "contentpreview3"
        guard isPreview else { throw ContentStoreError.wrongLayout }
    }
}

public enum ContentStoreError: Error, Equatable { case wrongLayout, invalidRecord, staleAuthority, identityCollision }

/// Public routing fields must be verified against the signed payload before this
/// storage boundary. MopSync does not possess keys or establish cloud trust.
public struct PreparedContentVersion: Codable, Equatable, Sendable {
    public let version: EncryptedItemVersion
    public let keyGeneration: UUID
    public let contentRevision: UUID
    public let membership: String
    public let keyAuthority: String
    public init(version: EncryptedItemVersion, keyGeneration: UUID, contentRevision: UUID, membership: String, keyAuthority: String) {
        self.version = version; self.keyGeneration = keyGeneration
        self.contentRevision = contentRevision; self.membership = membership; self.keyAuthority = keyAuthority
    }
}

/// Small public metadata index; grant reconciliation never loads item ciphertext.
public struct ContentKeyState: Codable, Equatable, Sendable {
    var rotationOperationID: UUID?
    public let scope: ItemScope
    public let versionID: UUID
    public let keyGeneration: UUID
    public let contentRevision: UUID
    public let membership: String
    public let keyAuthority: String
    init(_ content: PreparedContentVersion) {
        scope = content.version.scope; versionID = content.version.versionID
        keyGeneration = content.keyGeneration; contentRevision = content.contentRevision
        membership = content.membership; keyAuthority = content.keyAuthority
    }
}

public struct PreparedContentGrant: Codable, Equatable, Sendable {
    public let scope: ItemScope
    public let keyGeneration: UUID
    public let recipient: String
    public let identifier: String
    public let bytes: Data
    public init(scope: ItemScope, keyGeneration: UUID, recipient: String, identifier: String, bytes: Data) {
        self.scope = scope; self.keyGeneration = keyGeneration; self.recipient = recipient
        self.identifier = identifier; self.bytes = bytes
    }
}

public struct PreparedContentPublication: Codable, Equatable, Sendable {
    public let content: PreparedContentVersion
    public let grants: [PreparedContentGrant]
    public init(content: PreparedContentVersion, grants: [PreparedContentGrant]) { self.content = content; self.grants = grants }
}

/// Small durable decision references already encrypted versions, never plaintext.
public struct ContentConflictDecision: Codable, Equatable, Sendable {
    public let scope: ItemScope
    public let local: UUID
    public let remote: UUID
    public let serverSystemFields: Data
    public let replacement: UUID?
}

public struct ContentRecipientPolicy: Codable, Equatable, Sendable {
    public let membership: String
    public let recipients: Set<String>
    /// Membership digest at the most recent required security rotation; stable
    /// during additive enrollment. Verified by the crypto adapter, not this store.
    public let keyAuthority: String
    public init(membership: String, recipients: Set<String>, keyAuthority: String) {
        self.membership = membership; self.recipients = recipients; self.keyAuthority = keyAuthority
    }
}

public enum ContentGrantDeliveryStatus: Sendable { case queued, cloudConfirmed, superseded, expiredOrUnknown }
private struct ContentGrantDelivery: Codable {
    let systemFields: Data
    let acknowledgedAt: Date
}

public struct MissingContentGrant: Codable, Equatable, Sendable {
    public let scope: ItemScope
    public let keyGeneration: UUID
    public let recipient: String
    public let operationID: UUID
}

public struct ContentGrantPreparationSnapshot: Sendable {
    public let version: EncryptedItemVersion
    public let sourceGrant: PreparedContentGrant?
}

extension EncryptedItemRepository {
    /// Setting authority is a CAS against independently pinned membership. This
    /// indexes newly missing grants once on admission, not on routine wakes.
    public func setContentRecipients(scope: VaultScope, expected: ContentRecipientPolicy?,
                                     policy: ContentRecipientPolicy, authorization: any RepositoryWritePermit) throws {
        guard !scope.account.isEmpty, scope.database == "private", !scope.zoneOwner.isEmpty,
              validContentDigest(policy.membership), validContentDigest(policy.keyAuthority), !policy.recipients.isEmpty, policy.recipients.count <= 129,
              policy.recipients.allSatisfy(validContentDigest) else { throw ContentStoreError.invalidRecord }
        try authorization.withWritePermission {
            try transaction {
                let old = try contentPolicy(scope)
                if old == policy { return }
                guard old == expected else { throw ContentStoreError.staleAuthority }
                try touchVaultBoundary(scope)
                let key = "content-policy:" + contentVaultKey(scope)
                let row = try fetchOne("StateBlob", key: key) ?? NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
                row.setValue(key, forKey: "key"); row.setValue(try contentEncode(policy), forKey: "value")
                for row in try contentRows("ContentKeyState", field: "vaultKey", equals: contentVaultKey(scope)) {
                    let content: ContentKeyState = try contentValue(row)
                    try reconcileGrantRequirements(content, policy: policy)
                }
            }
        }
    }

    public func contentRecipients(scope: VaultScope) throws -> ContentRecipientPolicy? {
        return try transaction { try contentPolicy(scope) }
    }

    /// Content, exact randomized grants, outbox records, receipts and missing-key
    /// work commit together. A rejected grant or stale authority rolls it all back.
    public func commitContent(_ content: PreparedContentVersion, grants: [PreparedContentGrant],
                              expectedPolicy: ContentRecipientPolicy, prerequisites: [SyncOperation] = [],
                              authorization: any RepositoryWritePermit) throws -> PendingItemMutation {
        try authorization.withWritePermission {
            try transaction { try commitContentInTransaction(content, grants: grants, expectedPolicy: expectedPolicy, prerequisites: prerequisites) }
        }
    }

    private func commitContentInTransaction(_ content: PreparedContentVersion, grants: [PreparedContentGrant],
                                            expectedPolicy: ContentRecipientPolicy, prerequisites: [SyncOperation]) throws -> PendingItemMutation {
        try validate(content.version)
        guard validContentDigest(content.membership),
              content.keyAuthority == expectedPolicy.keyAuthority else { throw ContentStoreError.invalidRecord }
        let scope = VaultScope(content.version.scope)
        guard try contentPolicy(scope) == expectedPolicy else { throw ContentStoreError.staleAuthority }
        if let row = try fetchOne("ContentKeyState", key: content.version.scope.storageKey) {
            let old: ContentKeyState = try contentValue(row)
            guard old.keyAuthority == content.keyAuthority || old.keyGeneration != content.keyGeneration else {
                throw ContentStoreError.staleAuthority
            }
            if let id = old.rotationOperationID {
                try finishPublicationInTransaction(id, account: content.version.scope.account,
                    database: content.version.scope.database, confirmed: false)
            }
        }
        for prerequisite in prerequisites {
            guard prerequisite.account == scope.account, prerequisite.database == scope.database,
                  prerequisite.vaultID == scope.vaultID, prerequisite.zoneOwner == scope.zoneOwner,
                  [.membership, .provision].contains(prerequisite.kind) else { throw ContentStoreError.invalidRecord }
            _ = try enqueueInTransaction(prerequisite)
        }
        let dependencies = Set(prerequisites.map { SyncDependency(.operation, identifier: $0.id.uuidString) })
        let mutation = try commitLocalMutationInTransaction(content.version, dependencies: dependencies)
        try archiveContent(content)
        try storeContentValue(ContentKeyState(content), entity: "ContentKeyState", key: content.version.scope.storageKey,
            scope: content.version.scope, keyGeneration: content.keyGeneration, recipient: "")
        for grant in grants {
            guard grant.scope == content.version.scope, grant.keyGeneration == content.keyGeneration, expectedPolicy.recipients.contains(grant.recipient) else { throw ContentStoreError.invalidRecord }
            try storeContentGrant(grant, publish: true, dependencies: dependencies)
        }
        try reconcileGrantRequirements(ContentKeyState(content), policy: expectedPolicy)
        let rotation = contentOperationID("rotate:" + content.version.scope.storageKey + ":" + expectedPolicy.keyAuthority)
        try finishPublicationInTransaction(rotation, account: content.version.scope.account,
            database: content.version.scope.database, confirmed: false)
        return mutation
    }

    /// One durable import boundary: either all content, grants, outbox entries,
    /// policy and provisioning work exist, or none of them does. A retry of the
    /// pinned setup returns its original receipt without replacing later edits.
    public func initializeContentVault(scope: VaultScope, publications: [PreparedContentPublication],
                                       policy: ContentRecipientPolicy, membershipState: Data, setupID: String,
                                       provision: SyncOperation, authorization: any RepositoryWritePermit) throws -> VaultInitializationReceipt {
        guard !publications.isEmpty, !setupID.isEmpty, !membershipState.isEmpty,
              membershipState.count <= Self.maximumCiphertextBytes,
              validContentDigest(policy.membership), validContentDigest(policy.keyAuthority),
              !policy.recipients.isEmpty, policy.recipients.count <= 129, policy.recipients.allSatisfy(validContentDigest),
              provision.kind == .provision, provision.account == scope.account, provision.database == scope.database,
              provision.zoneOwner == scope.zoneOwner, provision.vaultID == scope.vaultID,
              Set(publications.map { $0.content.version.scope.itemID }).count == publications.count else { throw ItemRepositoryError.invalidInitialization }
        for publication in publications {
            let version = publication.content.version
            try validate(version)
            guard VaultScope(version.scope) == scope, version.generation == 1, version.baseVersionID == nil,
                  publication.content.membership == policy.membership,
                  Set(publication.grants.map(\.recipient)) == policy.recipients,
                  publication.grants.count == policy.recipients.count else { throw ItemRepositoryError.invalidInitialization }
        }
        return try authorization.withWritePermission {
            try transaction {
                if let boundary = try fetchOne("VaultBoundary", key: scope.storageKey) {
                    guard let bytes = boundary.value(forKey: "initialization") as? Data else { throw ItemRepositoryError.existingVault }
                    let receipt = try JSONDecoder().decode(VaultInitializationReceipt.self, from: bytes)
                    guard receipt.scope == scope, receipt.setupID == setupID, receipt.membershipState == membershipState else { throw ItemRepositoryError.initializationMismatch }
                    return receipt
                }
                guard try contentPolicy(scope) == nil else { throw ItemRepositoryError.existingVault }
                for entity in ["Item", "PendingMutation", "Conflict", "ContentKeyState", "ContentVersion", "ContentGrant", "ContentBranch"] {
                    let query = NSFetchRequest<NSManagedObject>(entityName: entity)
                    query.fetchLimit = 1
                    if ["Item", "PendingMutation", "Conflict"].contains(entity) {
                        query.predicate = NSPredicate(format: "account == %@ AND vaultID == %@ AND database == %@ AND zoneOwner == %@", scope.account, scope.vaultID as NSUUID, scope.database, scope.zoneOwner)
                    } else { query.predicate = NSPredicate(format: "vaultKey == %@", contentVaultKey(scope)) }
                    guard try context.fetch(query).isEmpty else { throw ItemRepositoryError.existingVault }
                }
                try touchVaultBoundary(scope)
                try writeJournal(policy, entity: "StateBlob", key: "content-policy:" + contentVaultKey(scope))
                var ids: [UUID] = [], hash = SHA256()
                hash.update(data: Data("MopContentInitialization3".utf8))
                hash.update(data: try contentEncode([setupID, policy.membership]))
                for publication in publications.sorted(by: { $0.content.version.scope.itemID.uuidString < $1.content.version.scope.itemID.uuidString }) {
                    hash.update(data: Data(SHA256.hash(data: try contentEncode(publication))))
                    ids.append(try commitContentInTransaction(publication.content, grants: publication.grants,
                        expectedPolicy: policy, prerequisites: [provision]).id)
                }
                let receipt = VaultInitializationReceipt(scope: scope, setupID: setupID, membershipState: membershipState,
                    inputDigest: Data(hash.finalize()), mutationIDs: ids)
                guard let boundary = try fetchOne("VaultBoundary", key: scope.storageKey) else { throw ItemRepositoryError.corruptStore }
                boundary.setValue(try contentEncode(receipt), forKey: "initialization")
                return receipt
            }
        }
    }

    /// The crypto layer has re-encrypted the latest local plaintext against the
    /// accepted cloud base. Preserve it while retiring only obsolete-key outbox
    /// representations; ordinary same-key edits still keep separate receipts.
    public func commitContentRotation(_ content: PreparedContentVersion, grants: [PreparedContentGrant],
                                      expectedLocal: UUID, expectedAccepted: UUID?, expectedPolicy: ContentRecipientPolicy,
                                      authorization: any RepositoryWritePermit) throws -> PendingItemMutation {
        try validate(content.version)
        return try authorization.withWritePermission {
            try transaction {
                let scope = content.version.scope
                guard try contentPolicy(VaultScope(scope)) == expectedPolicy,
                      content.keyAuthority == expectedPolicy.keyAuthority,
                      let stateRow = try fetchOne("ContentKeyState", key: scope.storageKey),
                      let item = try fetchOne("Item", key: scope.storageKey),
                      try decodeVersion(item).versionID == expectedLocal else { throw ContentStoreError.staleAuthority }
                let previous: ContentKeyState = try contentValue(stateRow)
                guard previous.keyAuthority != expectedPolicy.keyAuthority, previous.keyGeneration != content.keyGeneration,
                      previous.contentRevision == content.contentRevision,
                      try contentRows("ContentBranch", field: "scopeKey", equals: scope.storageKey).isEmpty else { throw ContentStoreError.invalidRecord }
                let accepted = try (item.value(forKey: "acceptedVersion") as? Data).map { try JSONDecoder().decode(EncryptedItemVersion.self, from: $0) }
                guard accepted?.versionID == expectedAccepted, content.version.baseVersionID == expectedAccepted,
                      content.version.generation == (accepted?.generation ?? 0) + 1 else { throw ItemRepositoryError.staleLocalVersion }
                let operations: [SyncOperation] = try journalValues("SyncOperation", account: scope.account, database: scope.database)
                let dependencies = try pendingContentPrerequisites(scope: scope, operations: operations)
                try supersedeObsoleteGrants(scope: scope, keyGeneration: content.keyGeneration, operations: operations)
                try touchVaultBoundary(VaultScope(scope))
                try supersedePending(scope: scope)
                encode(content.version, into: item)
                let mutation = try insertPending(content.version, status: .queued, dependencies: dependencies)
                try archiveContent(content)
                try storeContentValue(ContentKeyState(content), entity: "ContentKeyState", key: scope.storageKey,
                    scope: scope, keyGeneration: content.keyGeneration, recipient: "")
                for grant in grants {
                    guard grant.scope == scope, grant.keyGeneration == content.keyGeneration,
                          expectedPolicy.recipients.contains(grant.recipient) else { throw ContentStoreError.invalidRecord }
                    try storeContentGrant(grant, publish: true, dependencies: dependencies)
                }
                if let rotation = previous.rotationOperationID {
                    try finishPublicationInTransaction(rotation, account: scope.account, database: scope.database, confirmed: false)
                }
                try reconcileGrantRequirements(ContentKeyState(content), policy: expectedPolicy)
                return mutation
            }
        }
    }

    private func pendingContentPrerequisites(scope: ItemScope, operations: [SyncOperation]) throws -> Set<SyncDependency> {
        let request = NSFetchRequest<NSDictionary>(entityName: "PendingMutation")
        request.resultType = .dictionaryResultType; request.propertiesToFetch = ["mutationID"]
        request.predicate = NSPredicate(format: "key == %@", scope.storageKey)
        let ids = Set(try context.fetch(request).compactMap { $0["mutationID"] as? UUID })
        return Set(operations.filter { ids.contains($0.id) }.flatMap(\.dependencies))
    }

    private func supersedeObsoleteGrants(scope: ItemScope, keyGeneration: UUID, operations: [SyncOperation]) throws {
        for operation in operations where operation.kind == .grant && operation.state != .completed {
            let grant = try JSONDecoder().decode(PreparedContentGrant.self, from: operation.payload)
            if grant.scope == scope, grant.keyGeneration != keyGeneration {
                try finishPublicationInTransaction(operation.id, account: scope.account, database: scope.database, confirmed: false)
                let key = "content-grant-superseded:" + contentGrantKey(scope: scope, keyGeneration: grant.keyGeneration, suffix: grant.identifier)
                try writeJournal(Date(), entity: "StateBlob", key: key)
            }
        }
    }

    /// Additive access work never changes content, its outbox, or its receipts.
    /// Retries use these exact persisted bytes; different randomization with the
    /// same signed identity is rejected instead of replacing an in-flight grant.
    public func commitContentGrant(_ grant: PreparedContentGrant, expectedPolicy: ContentRecipientPolicy,
                                   authorization: any RepositoryWritePermit) throws {
        try authorization.withWritePermission {
            try transaction {
                guard try contentPolicy(VaultScope(grant.scope)) == expectedPolicy,
                      expectedPolicy.recipients.contains(grant.recipient) else { throw ContentStoreError.staleAuthority }
                guard let row = try fetchOne("ContentKeyState", key: grant.scope.storageKey) else { throw ContentStoreError.invalidRecord }
                let content: ContentKeyState = try contentValue(row)
                guard content.keyGeneration == grant.keyGeneration, content.keyAuthority == expectedPolicy.keyAuthority else { throw ContentStoreError.staleAuthority }
                try touchVaultBoundary(VaultScope(grant.scope))
                try storeContentGrant(grant, publish: true)
                try reconcileGrantRequirements(content, policy: expectedPolicy)
            }
        }
    }

    public func acknowledgeContentGrant(_ grant: PreparedContentGrant, serverSystemFields: Data, now: Date = Date()) throws {
        guard !serverSystemFields.isEmpty, serverSystemFields.count <= 1_048_576 else { throw ContentStoreError.invalidRecord }
        try transaction { try acknowledgeContentGrantInTransaction(grant, serverSystemFields: serverSystemFields, now: now) }
    }

    func acknowledgeContentGrantInTransaction(_ grant: PreparedContentGrant, serverSystemFields: Data, now: Date) throws {
        let key = contentGrantKey(scope: grant.scope, keyGeneration: grant.keyGeneration, suffix: grant.identifier)
        guard let row = try fetchOne("ContentGrant", key: key) else { throw ContentStoreError.invalidRecord }
        let stored: PreparedContentGrant = try contentValue(row)
        guard stored == grant else { throw ContentStoreError.identityCollision }
        let receiptKey = "content-grant-delivery4:" + key
        if let repair = try fetchOne("StateBlob", key: "grant-repair4:" + key) { context.delete(repair) }
        // Replay must not turn a 30-day receipt into perpetual confirmation.
        if try fetchOne("StateBlob", key: receiptKey) != nil {
            // A source-repair pass may have rearmed the exact publication. An
            // identical grant acknowledgment completes it without renewing TTL.
            try finishPublicationInTransaction(contentOperationID("publish:" + key), account: grant.scope.account,
                database: grant.scope.database, confirmed: true)
            return
        }
        try touchVaultBoundary(VaultScope(grant.scope))
        let receipt = NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
        receipt.setValue(receiptKey, forKey: "key")
        receipt.setValue(try contentEncode(ContentGrantDelivery(systemFields: serverSystemFields, acknowledgedAt: now)), forKey: "value")
        do {
            try finishPublicationInTransaction(contentOperationID("publish:" + key), account: grant.scope.account,
                database: grant.scope.database, confirmed: true)
        }
    }

    public func contentGrantDelivery(_ grant: PreparedContentGrant, now: Date = Date()) throws -> ContentGrantDeliveryStatus {
        return try transaction {
            let key = contentGrantKey(scope: grant.scope, keyGeneration: grant.keyGeneration, suffix: grant.identifier)
            guard let row = try fetchOne("ContentGrant", key: key) else { return .expiredOrUnknown }
            let stored: PreparedContentGrant = try contentValue(row)
            guard stored == grant else { return .expiredOrUnknown }
            guard let receipt = try fetchOne("StateBlob", key: "content-grant-delivery4:" + key) else {
                if let date: Date = try journalValue("StateBlob", key: "content-grant-superseded:" + key) {
                    return now.timeIntervalSince(date) < 30 * 86_400 ? .superseded : .expiredOrUnknown
                }
                return .queued
            }
            let delivery: ContentGrantDelivery = try contentValue(receipt)
            return now.timeIntervalSince(delivery.acknowledgedAt) < 30 * 86_400 ? .cloudConfirmed : .expiredOrUnknown
        }
    }

    public func contentState(scope: ItemScope) throws -> ContentKeyState? {
        return try transaction { try fetchOne("ContentKeyState", key: scope.storageKey).map { try contentValue($0) } }
    }

    public func contentGrant(scope: ItemScope, keyGeneration: UUID, identifier: String) throws -> PreparedContentGrant? {
        return try transaction {
            try fetchOne("ContentGrant", key: contentGrantKey(scope: scope, keyGeneration: keyGeneration, suffix: identifier)).map { try contentValue($0) }
        }
    }

    public func contentGrants(scope: ItemScope, keyGeneration: UUID, recipient: String? = nil) throws -> [PreparedContentGrant] {
        return try transaction {
            let request = NSFetchRequest<NSManagedObject>(entityName: "ContentGrant")
            var predicates = [NSPredicate(format: "scopeKey == %@ AND keyGeneration == %@", scope.storageKey, keyGeneration as NSUUID)]
            if let recipient { predicates.append(NSPredicate(format: "recipient == %@", recipient)) }
            request.predicate = NSCompoundPredicate(andPredicateWithSubpredicates: predicates)
            request.sortDescriptors = [NSSortDescriptor(key: "key", ascending: true)]
            if recipient != nil { request.fetchLimit = 1 }
            return try context.fetch(request).map { try contentValue($0) }.sorted { $0.identifier < $1.identifier }
        }
    }

    /// A bounded, consistent preparation snapshot. The final commit still checks
    /// live authority and key generation; this read never authorizes publication.
    public func contentGrantPreparation(_ missing: MissingContentGrant, sourceRecipient: String) throws -> ContentGrantPreparationSnapshot? {
        return try transaction {
            grantPreparationReads += 1
            let key = contentGrantKey(scope: missing.scope, keyGeneration: missing.keyGeneration, suffix: missing.recipient)
            guard let row = try fetchOne("MissingContentGrant", key: key) else { return nil }
            grantPreparationRows += 1
            let indexed: MissingContentGrant = try contentValue(row)
            guard indexed == missing else { throw SyncJournalError.staleOperation }
            guard let item = try fetchOne("Item", key: missing.scope.storageKey),
                  let stateRow = try fetchOne("ContentKeyState", key: missing.scope.storageKey) else { throw ContentStoreError.staleAuthority }
            grantPreparationRows += 2
            let state: ContentKeyState = try contentValue(stateRow)
            let version = try decodeVersion(item)
            guard state.keyGeneration == missing.keyGeneration, state.versionID == version.versionID else { throw ContentStoreError.staleAuthority }
            let request = NSFetchRequest<NSManagedObject>(entityName: "ContentGrant")
            request.predicate = NSPredicate(format: "scopeKey == %@ AND keyGeneration == %@ AND recipient == %@",
                missing.scope.storageKey, missing.keyGeneration as NSUUID, sourceRecipient)
            request.sortDescriptors = [NSSortDescriptor(key: "key", ascending: true)]
            request.fetchLimit = 1
            let grant: PreparedContentGrant? = try context.fetch(request).first.map { row in
                grantPreparationRows += 1
                return try contentValue(row)
            }
            return ContentGrantPreparationSnapshot(version: version, sourceGrant: grant)
        }
    }

    public func missingContentGrants(scope: VaultScope) throws -> [MissingContentGrant] {
        return try transaction {
            let rows = try contentRows("MissingContentGrant", field: "vaultKey", equals: contentVaultKey(scope))
            missingGrantScanRows += rows.count
            return try rows.map { try contentValue($0) }.sorted { $0.operationID.uuidString < $1.operationID.uuidString }
        }
    }

    public func setContentUploadBlocked(_ id: UUID, account: String, blocked: Bool, permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission {
            try transaction {
                let key = journalKey(account, "private", id.uuidString)
                guard var operation: SyncOperation = try journalValue("SyncOperation", key: key),
                      [.publishItem, .grant, .publishCoordination].contains(operation.kind), ![.completed, .needsAttention].contains(operation.state) else { return }
                if blocked {
                    guard operation.state != .waitingForAuthorization || operation.failure != .authorization else { return }
                    operation.state = .waitingForAuthorization; operation.failure = .authorization
                } else {
                    guard operation.state == .waitingForAuthorization || operation.state == .retryScheduled else { return }
                    // A previously captured candidate must not bypass a newer
                    // server throttle while its preparation was in flight.
                    guard operation.retryNotBefore.map({ $0 <= Date() }) ?? true else { return }
                    operation.state = operation.dependencies.isEmpty ? .ready : .waitingForDependency; operation.failure = nil
                    operation.nextAttempt = nil; operation.retryNotBefore = nil
                }
                operation.revision = UUID()
                try writeJournal(operation, entity: "SyncOperation", key: key, account: account, database: "private")
            }
        }
    }

    /// Preflight authority reads and asset staging are app-owned work, unlike
    /// CKSyncEngine's upload retry. Persist a wake when they fail before a batch.
    public func deferContentUpload(_ id: UUID, account: String, failure: SyncFailure,
                                   retryAfter: TimeInterval? = nil, now: Date = Date(), jitter: Double = 0,
                                   permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission {
            try transaction {
                let key = journalKey(account, "private", id.uuidString)
                guard var operation: SyncOperation = try journalValue("SyncOperation", key: key),
                      [.publishItem, .grant, .publishCoordination].contains(operation.kind),
                      ![.completed, .needsAttention].contains(operation.state) else { return }
                if operation.state == .retryScheduled, let next = operation.nextAttempt, next > now { return }
                if failure == .authorization || failure == .invalidAuthority {
                    operation.state = .waitingForAuthorization
                    operation.nextAttempt = nil; operation.retryNotBefore = nil; operation.retryAttempts = nil
                } else {
                    let attempt = min(operation.retryAttempts ?? 0, Int.max - 1) + 1
                    operation.state = .retryScheduled; operation.retryAttempts = attempt
                    operation.nextAttempt = now.addingTimeInterval(SyncRetryPolicy.delay(attempt: attempt, jitter: jitter, retryAfter: retryAfter))
                    operation.retryNotBefore = retryAfter.flatMap { $0.isFinite ? now.addingTimeInterval(max(0, $0)) : nil }
                }
                operation.failure = failure; operation.revision = UUID()
                try writeJournal(operation, entity: "SyncOperation", key: key, account: account, database: "private")
            }
        }
    }

    private func contentVersionDeliveryKey(_ content: PreparedContentVersion) -> String {
        "content-version-delivered:" + content.version.scope.storageKey + ":" + content.version.versionID.uuidString
    }

    /// Repair publications from builds that sent grants before their immutable
    /// source. Re-arm only exact retained grant publications, never discarded work.
    public func repairUnpublishedGrantSources(account: String, permit: any RepositoryWritePermit) throws -> Int {
        try permit.withWritePermission {
            try transaction {
                struct Candidate: Decodable {
                    let operation: SyncOperation?
                    enum CodingKeys: String, CodingKey { case kind, state, resolution }
                    init(from decoder: any Decoder) throws {
                        let fields = try decoder.container(keyedBy: CodingKeys.self)
                        operation = try fields.decode(SyncOperation.Kind.self, forKey: .kind) == .grant
                            && fields.decode(SyncOperationState.self, forKey: .state) == .completed
                            && fields.decodeIfPresent(SyncResolution.self, forKey: .resolution) != .discardedByUser
                            ? SyncOperation(from: decoder) : nil
                    }
                }
                struct Source: Decodable { let sourceVersion: UUID }
                let candidates: [Candidate] = try journalValues("SyncOperation", account: account, database: "private")
                var repaired = 0
                var delivery: [String: Bool] = [:]
                for candidate in candidates {
                    guard var operation = candidate.operation,
                          let grant = try? JSONDecoder().decode(PreparedContentGrant.self, from: operation.payload),
                          grant.scope.account == account, grant.scope.database == "private",
                          let sourceID = try? JSONDecoder().decode(Source.self, from: grant.bytes).sourceVersion else { continue }
                    let key = grant.scope.storageKey + ":" + sourceID.uuidString
                    if delivery[key] == true { continue }
                    let discarded: Bool = try journalValue("StateBlob", key: "discarded-content-version:" + key) ?? false
                    if discarded { continue }
                    guard let row = try fetchOne("ContentVersion", key: key) else { continue }
                    let source: PreparedContentVersion = try contentValue(row)
                    let delivered: Bool = try journalValue("StateBlob", key: contentVersionDeliveryKey(source)) ?? false
                    delivery[key] = delivered
                    guard !delivered, source.version.scope == grant.scope, source.keyGeneration == grant.keyGeneration,
                          let policy = try contentPolicy(VaultScope(grant.scope)), policy.keyAuthority == source.keyAuthority,
                          policy.recipients.contains(grant.recipient), try deletionInTransaction(VaultScope(grant.scope)) == nil else { continue }
                    operation.state = .ready; operation.completedAt = nil; operation.resolution = nil
                    operation.failure = nil; operation.nextAttempt = nil; operation.retryNotBefore = nil; operation.revision = UUID()
                    try writeJournal(operation, entity: "SyncOperation", key: journalKey(account, "private", operation.id.uuidString), account: account, database: "private")
                    repaired += 1
                }
                return repaired
            }
        }
    }

    /// Select the oldest unsent edit per item. Immutable versions precede heads;
    /// independent signed grants never replace content or its mutation receipts.
    public func contentPublications(account: String) throws -> [ContentUpload] {
        return try transaction {
            let now = Date()
            return try journalReadCache.storeResult(key: "content-publications:" + account, in: context, now: now) {
                // Reuse repeated reads while building this candidate snapshot.
                // History invalidation observes membership and content changes.
                let started = ContinuousClock.now
                var policyReads = 0, contentDecodes = 0, selectedCount = 0
                var grantSkips: [String: Int] = [:]
                defer {
                    AccessSyncTrace.elapsed("publication candidate reads", since: started,
                        detail: "policyReads=\(policyReads) contentDecodes=\(contentDecodes) selected=\(selectedCount) grantSkips=\(grantSkips.keys.sorted().map { "\($0):\(grantSkips[$0]!)" }.joined(separator: ","))")
                }
                var policies: [VaultScope: ContentRecipientPolicy] = [:]
                var missingPolicies: Set<VaultScope> = []
                func policy(_ scope: VaultScope) throws -> ContentRecipientPolicy? {
                    if let cached = policies[scope] { return cached }
                    if missingPolicies.contains(scope) { return nil }
                    policyReads += 1
                    let value = try contentPolicy(scope)
                    if let value { policies[scope] = value } else { missingPolicies.insert(scope) }
                    return value
                }
                var decodedContent: [NSManagedObjectID: PreparedContentVersion] = [:]
                func decodeContent(_ row: NSManagedObject) throws -> PreparedContentVersion {
                    if let cached = decodedContent[row.objectID] { return cached }
                    contentDecodes += 1
                    let value: PreparedContentVersion = try contentValue(row)
                    // Bound memory even when many candidates are blocked.
                    if decodedContent.count >= 128 { decodedContent.removeAll(keepingCapacity: true) }
                    decodedContent[row.objectID] = value
                    return value
                }
                let receiving = try incomingCloudRecordIDsInTransaction(account: account, database: "private")
                let pending = try activeOperationsInTransaction(account: account, database: "private")
                var deletedVaults: Set<UUID> = []
                for vault in Set(pending.compactMap(\.vaultID)) {
                    if try deletionInTransaction(VaultScope(account: account, vaultID: vault)) != nil { deletedVaults.insert(vault) }
                }
                let operations = pending.filter { $0.vaultID.map { !deletedVaults.contains($0) } ?? true }
                let byID = Dictionary(uniqueKeysWithValues: operations.map { ($0.id, $0) })
                let prerequisiteIDs = Set(operations.flatMap(\.dependencies).filter { $0.kind == .operation }.compactMap { UUID(uuidString: $0.identifier) })
                var delivered: Set<UUID> = []
                for id in prerequisiteIDs where try operationDeliveredInTransaction(id, account: account, database: "private") { delivered.insert(id) }
                func eligible(_ operation: SyncOperation) -> Bool {
                    guard ![.completed, .needsAttention].contains(operation.state),
                          operation.state != .retryScheduled || (operation.nextAttempt ?? .distantPast) <= now else { return false }
                    return operation.dependencies.allSatisfy { dependency in
                        guard dependency.kind == .operation, let id = UUID(uuidString: dependency.identifier) else { return false }
                        return delivered.contains(id)
                    }
                }
                // Reserve a bounded share for grants while immutable versions/heads
                // are pending. Otherwise every 100-record page can contain only
                // content, delaying usable access until the whole vault is sent.
                let contentLimit = operations.contains { $0.kind == .grant && eligible($0) } ? 84 : 100
                var result: [ContentUpload] = [], totalBytes = 0
                let request = NSFetchRequest<NSDictionary>(entityName: "PendingMutation")
                request.resultType = .dictionaryResultType
                request.propertiesToFetch = ["key", "mutationID", "versionID"]
                request.predicate = NSPredicate(format: "account == %@ AND database == %@", account, "private")
                request.sortDescriptors = [NSSortDescriptor(key: "sequence", ascending: true)]
                var seen = Set<String>()
                for metadata in try context.fetch(request) {
                    guard let key = metadata["key"] as? String, let id = metadata["mutationID"] as? UUID,
                          let versionID = metadata["versionID"] as? UUID else { throw ItemRepositoryError.corruptStore }
                    guard seen.insert(key).inserted, let operation = byID[id], eligible(operation),
                          let row = try fetchOne("ContentVersion", key: key + ":" + versionID.uuidString) else { continue }
                    let content = try decodeContent(row)
                    guard try policy(VaultScope(content.version.scope))?.keyAuthority == content.keyAuthority,
                          try contentRows("ContentBranch", field: "scopeKey", equals: key).isEmpty else { continue }
                    let detail = NSFetchRequest<NSManagedObject>(entityName: "PendingMutation")
                    detail.predicate = NSPredicate(format: "mutationID == %@", id as NSUUID); detail.fetchLimit = 1
                    guard let pending = try context.fetch(detail).first, try decodeVersion(pending) == content.version else { throw ContentStoreError.identityCollision }
                    let delivered: Bool = try journalValue("StateBlob", key: contentVersionDeliveryKey(content)) ?? false
                    let fields = delivered ? try fetchOne("Item", key: key)?.value(forKey: "serverSystemFields") as? Data : nil
                    let upload = ContentUpload(operationID: operation.id, content: content, grant: nil,
                        kind: delivered ? .head : .version, systemFields: fields)
                    guard !receiving.contains(upload.recordID) else { continue }
                    if !result.isEmpty, content.version.ciphertext.count > 16 * 1024 * 1024 - min(totalBytes, 16 * 1024 * 1024) { break }
                    result.append(upload)
                    totalBytes += content.version.ciphertext.count
                    if result.count == contentLimit || totalBytes >= 16 * 1024 * 1024 { break }
                }
                // Dictionary-backed journal projections have no stable order.
                // Keep the same oldest eligible grants registered across unrelated
                // commits instead of replacing most of the 100-record window.
                let grants = operations.filter { $0.kind == .grant && eligible($0) }
                    .map { ($0, $0.id.uuidString) }
                    .sorted { ($0.0.createdAt, $0.1) < ($1.0.createdAt, $1.1) }
                for (operation, _) in grants {
                    guard result.count < 100 else { break }
                    let grant = try JSONDecoder().decode(PreparedContentGrant.self, from: operation.payload)
                    guard grant.scope.account == account, grant.scope.database == "private", grant.scope.vaultID == operation.vaultID,
                          grant.scope.zoneOwner == operation.zoneOwner else { throw ContentStoreError.invalidRecord }
                    let request = NSFetchRequest<NSManagedObject>(entityName: "ContentVersion")
                    request.predicate = NSPredicate(format: "scopeKey == %@ AND keyGeneration == %@", grant.scope.storageKey, grant.keyGeneration as NSUUID)
                    request.fetchLimit = 1
                    guard let row = try context.fetch(request).first else { grantSkips["missingGeneration", default: 0] += 1; continue }
                    let content = try decodeContent(row)
                    guard let policy = try policy(VaultScope(grant.scope)), policy.keyAuthority == content.keyAuthority,
                          policy.recipients.contains(grant.recipient) else { grantSkips["policy", default: 0] += 1; continue }
                    // A grant can outlive the local head that created it (for example
                    // concurrent rotations). Publish its immutable verification source
                    // before the grant, even when that head's mutation was superseded.
                    struct Source: Decodable { let sourceVersion: UUID }
                    let sourceID = (try? JSONDecoder().decode(Source.self, from: grant.bytes))?.sourceVersion ?? content.version.versionID
                    let discarded: Bool = try journalValue("StateBlob", key: "discarded-content-version:" + grant.scope.storageKey + ":" + sourceID.uuidString) ?? false
                    guard !discarded, let sourceRow = try fetchOne("ContentVersion", key: grant.scope.storageKey + ":" + sourceID.uuidString) else { grantSkips["missingOrDiscardedSource", default: 0] += 1; continue }
                    let source = try decodeContent(sourceRow)
                    guard source.keyGeneration == grant.keyGeneration, source.version.scope == grant.scope else { grantSkips["sourceBinding", default: 0] += 1; continue }
                    let sourceDelivered: Bool = try journalValue("StateBlob", key: contentVersionDeliveryKey(source)) ?? false
                    let upload = ContentUpload(operationID: operation.id, content: source,
                        grant: sourceDelivered ? grant : nil, kind: sourceDelivered ? .grant : .version, systemFields: nil)
                    guard !receiving.contains(upload.recordID) else { grantSkips["incoming", default: 0] += 1; continue }
                    guard !result.contains(where: { $0.recordID == upload.recordID }) else { grantSkips["duplicateSource", default: 0] += 1; continue }
                    let sourceBytes = sourceDelivered ? 0 : source.version.ciphertext.count
                    if !result.isEmpty, sourceBytes > 16 * 1024 * 1024 - min(totalBytes, 16 * 1024 * 1024) { continue }
                    result.append(upload)
                    totalBytes += sourceBytes
                    if result.count >= 100 { break }
                }
                selectedCount = result.count
                let deadline = operations.filter { $0.state == .retryScheduled }
                    .compactMap(\.nextAttempt).filter { $0 > now }.min()
                return (result, deadline)
            }
        }
    }

    public enum IncomingContentAction: Sendable { case archive, install, duplicate, keepLocal, branch, supersede }

    /// Caller authenticates the signed version and ancestry first. The local-head
    /// and authority CAS close races with edits, unlock and membership updates.
    public func receiveContent(_ content: PreparedContentVersion, from incoming: IncomingRecord,
                               action: IncomingContentAction, expectedHead: UUID?, expectedPolicy: ContentRecipientPolicy,
                               permit: any RepositoryWritePermit) throws {
        try validate(content.version)
        try permit.withWritePermission {
            try transaction {
                try requireIncomingInTransaction(incoming)
                let scope = content.version.scope
                guard incoming.account == scope.account, incoming.database == scope.database,
                      incoming.vaultID == scope.vaultID, incoming.zoneOwner == scope.zoneOwner,
                      incoming.bytes == content.version.ciphertext,
                      try contentPolicy(VaultScope(scope)) == expectedPolicy else { throw ContentStoreError.staleAuthority }
                try touchVaultBoundary(VaultScope(scope))
                try archiveContent(content)
                if action == .archive {
                    guard incoming.recordType == ContentRecordKind.version.rawValue,
                          incoming.recordName == scope.itemID.uuidString + ":" + content.version.versionID.uuidString else {
                        throw ContentStoreError.invalidRecord
                    }
                    try writeJournal(true, entity: "StateBlob", key: contentVersionDeliveryKey(content))
                }
                if action != .archive {
                    let current = try fetchOne("Item", key: scope.storageKey)
                    let previous = try current.map(decodeVersion)
                    guard previous?.versionID == expectedHead else { throw ItemRepositoryError.staleLocalVersion }
                    if action == .install || action == .supersede {
                        if action == .supersede { try supersedePending(scope: scope) }
                        else {
                            let pending = NSFetchRequest<NSManagedObject>(entityName: "PendingMutation")
                            pending.predicate = NSPredicate(format: "key == %@", scope.storageKey)
                            pending.fetchLimit = 1
                            guard try context.fetch(pending).isEmpty else { throw ItemRepositoryError.pendingLocalChanges }
                        }
                        let item = current ?? NSEntityDescription.insertNewObject(forEntityName: "Item", into: context)
                        encode(content.version, into: item)
                        let bytes = try contentEncode(content.version)
                        item.setValue(bytes, forKey: "acceptedVersion"); item.setValue(bytes, forKey: "publicationBaseVersion")
                        item.setValue(incoming.systemFields, forKey: "serverSystemFields")
                        try storeContentValue(ContentKeyState(content), entity: "ContentKeyState", key: scope.storageKey,
                            scope: scope, keyGeneration: content.keyGeneration, recipient: "")
                        try reconcileGrantRequirements(ContentKeyState(content), policy: expectedPolicy)
                    } else if action == .duplicate {
                        guard previous == content.version else { throw ContentStoreError.identityCollision }
                        let pending = NSFetchRequest<NSManagedObject>(entityName: "PendingMutation")
                        pending.predicate = NSPredicate(format: "key == %@ AND versionID == %@", scope.storageKey, content.version.versionID as NSUUID)
                        for row in try context.fetch(pending) {
                            guard let id = row.value(forKey: "mutationID") as? UUID,
                                  let receipt = try fetchOne("MutationReceipt", key: id.uuidString) else { throw ItemRepositoryError.corruptStore }
                            receipt.setValue(MutationDeliveryStatus.cloudConfirmed.rawValue, forKey: "status")
                            try finishPublicationInTransaction(id, account: scope.account, database: scope.database)
                            context.delete(row)
                        }
                        try supersedePending(scope: scope)
                        current?.setValue(incoming.systemFields, forKey: "serverSystemFields")
                        current?.setValue(try contentEncode(content.version), forKey: "acceptedVersion")
                        current?.setValue(try contentEncode(content.version), forKey: "publicationBaseVersion")
                    } else if action == .keepLocal {
                        // An echo of an earlier queued edit confirms that exact
                        // receipt without replacing the newer working version.
                        let pending = NSFetchRequest<NSManagedObject>(entityName: "PendingMutation")
                        pending.predicate = NSPredicate(format: "key == %@ AND versionID == %@", scope.storageKey, content.version.versionID as NSUUID)
                        for row in try context.fetch(pending) {
                            guard try decodeVersion(row) == content.version,
                                  let id = row.value(forKey: "mutationID") as? UUID else { throw ContentStoreError.identityCollision }
                            try acknowledgeInTransaction(mutationID: id, account: scope.account, serverSystemFields: incoming.systemFields)
                        }
                        // The server can return unchanged accepted content with
                        // a newer change tag. Refresh that base without touching
                        // the working overlay or acknowledging another mutation.
                        if let bytes = current?.value(forKey: "acceptedVersion") as? Data,
                           try JSONDecoder().decode(EncryptedItemVersion.self, from: bytes) == content.version {
                            current?.setValue(incoming.systemFields, forKey: "serverSystemFields")
                        }
                    } else if action == .branch {
                        try writeJournal(incoming.systemFields, entity: "StateBlob", key: "content-branch-fields:" + scope.storageKey + ":" + content.version.versionID.uuidString)
                        try writeJournal(incoming.operationID, entity: "StateBlob", key: "content-branch-operation:" + scope.storageKey + ":" + content.version.versionID.uuidString)
                        try storeContentValue(ContentKeyState(content), entity: "ContentBranch", key: scope.storageKey + ":" + content.version.versionID.uuidString,
                            scope: scope, keyGeneration: content.keyGeneration, recipient: "")
                    }
                }
                try completeIncomingInTransaction(incoming, failure: action == .branch ? .conflict : nil)
            }
        }
    }

    /// Authorized reconciliation proved that the server branch was access-only.
    /// Accept its CloudKit base and queue the preserved local edit under its keys
    /// atomically, without claiming that the superseded old ciphertext was sent.
    public func receiveRebasedContent(_ content: PreparedContentVersion, remote: PreparedContentVersion,
                                     from incoming: IncomingRecord, expectedHead: UUID,
                                     expectedPolicy: ContentRecipientPolicy, permit: any RepositoryWritePermit) throws {
        try validate(content.version)
        try permit.withWritePermission {
            try transaction {
                try requireIncomingInTransaction(incoming)
                let scope = content.version.scope
                guard remote.version.scope == scope, incoming.account == scope.account, incoming.database == scope.database,
                      incoming.zoneOwner == scope.zoneOwner, incoming.vaultID == scope.vaultID,
                      incoming.recordType == ContentRecordKind.head.rawValue,
                      incoming.bytes == remote.version.ciphertext,
                      content.keyAuthority == expectedPolicy.keyAuthority,
                      remote.keyAuthority == expectedPolicy.keyAuthority,
                      content.keyGeneration == remote.keyGeneration,
                      content.version.baseVersionID == remote.version.versionID,
                      content.version.generation == remote.version.generation + 1,
                      try contentPolicy(VaultScope(scope)) == expectedPolicy,
                      let item = try fetchOne("Item", key: scope.storageKey),
                      try decodeVersion(item).versionID == expectedHead else { throw ContentStoreError.staleAuthority }
                guard try contentRows("ContentBranch", field: "scopeKey", equals: scope.storageKey).isEmpty else {
                    throw ItemRepositoryError.unresolvedConflict
                }
                try touchVaultBoundary(VaultScope(scope))
                try archiveContent(remote); try archiveContent(content)
                let operations: [SyncOperation] = try journalValues("SyncOperation", account: scope.account, database: scope.database)
                let dependencies = try pendingContentPrerequisites(scope: scope, operations: operations)
                try supersedeObsoleteGrants(scope: scope, keyGeneration: content.keyGeneration, operations: operations)
                if let row = try fetchOne("ContentKeyState", key: scope.storageKey) {
                    let previous: ContentKeyState = try contentValue(row)
                    guard previous.contentRevision == content.contentRevision else { throw ContentStoreError.invalidRecord }
                    if let rotation = previous.rotationOperationID {
                        try finishPublicationInTransaction(rotation, account: scope.account, database: scope.database, confirmed: false)
                    }
                }
                try supersedePending(scope: scope)
                encode(content.version, into: item)
                let accepted = try contentEncode(remote.version)
                item.setValue(accepted, forKey: "acceptedVersion"); item.setValue(accepted, forKey: "publicationBaseVersion")
                item.setValue(incoming.systemFields, forKey: "serverSystemFields")
                _ = try insertPending(content.version, status: .queued, dependencies: dependencies)
                try storeContentValue(ContentKeyState(content), entity: "ContentKeyState", key: scope.storageKey,
                    scope: scope, keyGeneration: content.keyGeneration, recipient: "")
                try reconcileGrantRequirements(ContentKeyState(content), policy: expectedPolicy)
                try completeIncomingInTransaction(incoming, failure: nil)
            }
        }
    }

    public func receiveContentGrant(_ grant: PreparedContentGrant, from incoming: IncomingRecord,
                                    expectedPolicy: ContentRecipientPolicy, permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission {
            try transaction {
                try requireIncomingInTransaction(incoming)
                guard incoming.account == grant.scope.account, incoming.database == grant.scope.database,
                      incoming.vaultID == grant.scope.vaultID, incoming.zoneOwner == grant.scope.zoneOwner,
                      incoming.bytes == grant.bytes,
                      try contentPolicy(VaultScope(grant.scope)) == expectedPolicy else { throw ContentStoreError.staleAuthority }
                try touchVaultBoundary(VaultScope(grant.scope))
                try storeContentGrant(grant, publish: false)
                try acknowledgeContentGrantInTransaction(grant, serverSystemFields: incoming.systemFields, now: incoming.receivedAt)
                if let row = try fetchOne("ContentKeyState", key: grant.scope.storageKey) {
                    let current: ContentKeyState = try contentValue(row)
                    try reconcileGrantRequirements(current, policy: expectedPolicy)
                }
                try completeIncomingInTransaction(incoming)
            }
        }
    }

    public func archiveIncomingContent(_ content: PreparedContentVersion, from incoming: IncomingRecord,
                                       expectedPolicy: ContentRecipientPolicy, permit: any RepositoryWritePermit) throws {
        try validate(content.version)
        try permit.withWritePermission {
            try transaction {
                try requireIncomingInTransaction(incoming)
                guard incoming.account == content.version.scope.account, incoming.vaultID == content.version.scope.vaultID,
                      incoming.database == content.version.scope.database, incoming.zoneOwner == content.version.scope.zoneOwner,
                      incoming.bytes == content.version.ciphertext,
                      try contentPolicy(VaultScope(content.version.scope)) == expectedPolicy else { throw ContentStoreError.staleAuthority }
                try touchVaultBoundary(VaultScope(content.version.scope))
                try archiveContent(content)
            }
        }
    }

    public func contentVersion(scope: ItemScope, version: UUID) throws -> PreparedContentVersion? {
        return try transaction {
            try fetchOne("ContentVersion", key: scope.storageKey + ":" + version.uuidString).map { try contentValue($0) }
        }
    }

    public func contentVersion(scope: ItemScope, keyGeneration: UUID) throws -> PreparedContentVersion? {
        return try transaction {
            let request = NSFetchRequest<NSManagedObject>(entityName: "ContentVersion")
            request.predicate = NSPredicate(format: "scopeKey == %@ AND keyGeneration == %@", scope.storageKey, keyGeneration as NSUUID)
            request.fetchLimit = 1
            return try context.fetch(request).first.map { try contentValue($0) }
        }
    }

    public func contentVersions(scope: ItemScope) throws -> [PreparedContentVersion] {
        return try transaction { try contentRows("ContentVersion", field: "scopeKey", equals: scope.storageKey).map { try contentValue($0) } }
    }

    public func contentBranches(scope: ItemScope) throws -> [PreparedContentVersion] {
        return try transaction {
            try contentRows("ContentBranch", field: "scopeKey", equals: scope.storageKey).map { row in
                let branch: ContentKeyState = try contentValue(row)
                guard let version = try fetchOne("ContentVersion", key: scope.storageKey + ":" + branch.versionID.uuidString) else { throw ItemRepositoryError.corruptStore }
                return try contentValue(version)
            }
        }
    }

    private func archiveContent(_ content: PreparedContentVersion) throws {
        let scope = content.version.scope, key = content.version.scope.storageKey + ":" + content.version.versionID.uuidString
        if let row = try fetchOne("ContentVersion", key: key) {
            let old: PreparedContentVersion = try contentValue(row)
            guard old == content else { throw ContentStoreError.identityCollision }
        } else {
            try storeContentValue(content, entity: "ContentVersion", key: key, scope: scope, keyGeneration: content.keyGeneration, recipient: "")
        }
    }

    /// Only independently accepted local metadata can skip the rotation barrier.
    /// Missing state is not evidence that another device finished the work.
    public func contentRotationSatisfied(scope: ItemScope) throws -> Bool {
        return try transaction {
            guard let row = try fetchOne("ContentKeyState", key: scope.storageKey),
                  let policy = try contentPolicy(VaultScope(scope)) else { return false }
            let state: ContentKeyState = try contentValue(row)
            return state.keyAuthority == policy.keyAuthority
        }
    }

    private func reconcileGrantRequirements(_ content: ContentKeyState, policy: ContentRecipientPolicy) throws {
        let scope = content.scope
        let existing = try contentRows("ContentGrant", field: "scopeKey", equals: scope.storageKey)
        let needsRotation = content.keyAuthority != policy.keyAuthority
        let covered = Set(existing.filter { $0.value(forKey: "keyGeneration") as? UUID == content.keyGeneration }
            .compactMap { $0.value(forKey: "recipient") as? String })
        for row in try contentRows("MissingContentGrant", field: "scopeKey", equals: scope.storageKey) {
            let missing: MissingContentGrant = try contentValue(row)
            if needsRotation || missing.keyGeneration != content.keyGeneration || !policy.recipients.contains(missing.recipient) || covered.contains(missing.recipient) {
                try completeContentPreparation(missing)
                context.delete(row)
            }
        }
        if needsRotation {
            let key = scope.storageKey + ":" + policy.keyAuthority
            let operationID = contentOperationID("rotate:" + key)
            if let old = content.rotationOperationID, old != operationID {
                try finishPublicationInTransaction(old, account: scope.account, database: scope.database, confirmed: false)
            }
            var indexed = content
            indexed.rotationOperationID = operationID
            try storeContentValue(indexed, entity: "ContentKeyState", key: scope.storageKey, scope: scope,
                keyGeneration: content.keyGeneration, recipient: "")
            // Content can arrive after the unlock wake has already drained.
            // Let the handler use an existing session or defer if still locked.
            let operation = SyncOperation(id: operationID, account: scope.account,
                database: scope.database, vaultID: scope.vaultID, zoneOwner: scope.zoneOwner,
                kind: .rotateContent, payload: try contentEncode(scope))
            _ = try enqueueInTransaction(operation)
            return
        }
        // An authenticated remote head can satisfy a queued rotation too.
        // Its newly installed state no longer carries rotationOperationID, so
        // retire the deterministic operation for this authority explicitly.
        let rotation = contentOperationID("rotate:" + scope.storageKey + ":" + policy.keyAuthority)
        try finishPublicationInTransaction(rotation, account: scope.account, database: scope.database, confirmed: false)
        for recipient in policy.recipients.subtracting(covered) {
            let key = contentGrantKey(scope: scope, keyGeneration: content.keyGeneration, suffix: recipient)
            guard try fetchOne("MissingContentGrant", key: key) == nil else { continue }
            let operationID = contentOperationID("prepare:" + key)
            let missing = MissingContentGrant(scope: scope, keyGeneration: content.keyGeneration, recipient: recipient, operationID: operationID)
            try storeContentValue(missing, entity: "MissingContentGrant", key: key, scope: scope,
                keyGeneration: content.keyGeneration, recipient: recipient)
            _ = try enqueueInTransaction(SyncOperation(id: operationID, account: scope.account, database: scope.database,
                vaultID: scope.vaultID, zoneOwner: scope.zoneOwner, kind: .prepareGrant, payload: try contentEncode(missing)))
        }
    }

    private func storeContentGrant(_ grant: PreparedContentGrant, publish: Bool, publishExisting: Bool = false, dependencies: Set<SyncDependency> = []) throws {
        guard validContentDigest(grant.identifier), validContentDigest(grant.recipient),
              !grant.bytes.isEmpty, grant.bytes.count <= 16_384 else { throw ContentStoreError.invalidRecord }
        let key = contentGrantKey(scope: grant.scope, keyGeneration: grant.keyGeneration, suffix: grant.identifier)
        if let row = try fetchOne("ContentGrant", key: key) {
            let previous: PreparedContentGrant = try contentValue(row)
            guard previous == grant else { throw ContentStoreError.identityCollision }
            if !publishExisting { return }
        } else {
            try storeContentValue(grant, entity: "ContentGrant", key: key, scope: grant.scope,
                keyGeneration: grant.keyGeneration, recipient: grant.recipient)
        }
        if publish {
            _ = try enqueueInTransaction(SyncOperation(id: contentOperationID("publish:" + key), account: grant.scope.account,
                database: grant.scope.database, vaultID: grant.scope.vaultID, zoneOwner: grant.scope.zoneOwner,
                kind: .grant, payload: try contentEncode(grant), dependencies: dependencies))
        }
    }

    private func completeContentPreparation(_ missing: MissingContentGrant) throws {
        // The indexed dependency is local preparation only. This must not set
        // deliveredAt: grant upload and admission coverage have separate receipts.
        try finishPublicationInTransaction(missing.operationID, account: missing.scope.account,
            database: missing.scope.database, confirmed: false)
    }

    func contentEncode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        return try encoder.encode(value)
    }

    private func validContentDigest(_ text: String) -> Bool { text.utf8.count == 64 && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    func contentVaultKey(_ scope: VaultScope) -> String {
        [scope.account, scope.database, scope.zoneOwner, scope.vaultID.uuidString].map { Data($0.utf8).base64EncodedString() }.joined(separator: ":")
    }
    func contentGrantKey(scope: ItemScope, keyGeneration: UUID, suffix: String) -> String {
        scope.storageKey + ":" + keyGeneration.uuidString + ":" + suffix
    }
    func contentOperationID(_ text: String) -> UUID {
        let hash = Array(SHA256.hash(data: Data(text.utf8)).prefix(16))
        return UUID(uuid: (hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]))
    }
    func contentPolicy(_ scope: VaultScope) throws -> ContentRecipientPolicy? {
        guard let row = try fetchOne("StateBlob", key: "content-policy:" + contentVaultKey(scope)) else { return nil }
        return try contentValue(row)
    }
    func contentRows(_ entity: String, field: String, equals value: String) throws -> [NSManagedObject] {
        let request = NSFetchRequest<NSManagedObject>(entityName: entity)
        request.predicate = NSPredicate(format: "%K == %@", field, value)
        return try context.fetch(request)
    }
    func contentValue<T: Decodable>(_ row: NSManagedObject) throws -> T {
        guard let bytes = row.value(forKey: "value") as? Data else { throw ItemRepositoryError.corruptStore }
        return try JSONDecoder().decode(T.self, from: bytes)
    }
    private func storeContentValue<T: Encodable>(_ value: T, entity: String, key: String,
                                                scope: ItemScope, keyGeneration: UUID, recipient: String) throws {
        let row = try fetchOne(entity, key: key) ?? NSEntityDescription.insertNewObject(forEntityName: entity, into: context)
        row.setValue(key, forKey: "key"); row.setValue(scope.storageKey, forKey: "scopeKey")
        row.setValue(contentVaultKey(VaultScope(scope)), forKey: "vaultKey")
        row.setValue(keyGeneration, forKey: "keyGeneration"); row.setValue(recipient, forKey: "recipient")
        row.setValue(try contentEncode(value), forKey: "value")
    }
}

extension EncryptedItemRepository {
    public func contentConflicts(account: String, includePendingDecisions: Bool = false) throws -> [EncryptedItemConflict] {
        return try transaction {
            let rows = try context.fetch(NSFetchRequest<NSManagedObject>(entityName: "ContentBranch"))
            // The normal no-conflict path must not inspect the operation journal.
            guard !rows.isEmpty else { return [] }
            let decisions: [ContentConflictDecision]
            if includePendingDecisions { decisions = [] }
            else {
                let operations = try conflictDecisionOperationsInTransaction(account: account)
                decisions = try operations.map { try JSONDecoder().decode(ContentConflictDecision.self, from: $0.payload) }
            }
            let states: [ContentKeyState] = try rows.map { try contentValue($0) }
                .filter { $0.scope.account == account }
            let items = try conflictRows("Item", keys: states.map { $0.scope.storageKey })
            let versions = try conflictRows("ContentVersion", keys: states.map { $0.scope.storageKey + ":" + $0.versionID.uuidString })
            let fields = try conflictRows("StateBlob", keys: states.map { "content-branch-fields:" + $0.scope.storageKey + ":" + $0.versionID.uuidString })
            return try states.compactMap { state in
                let key = state.scope.storageKey + ":" + state.versionID.uuidString
                guard let item = items[state.scope.storageKey], let remote = versions[key],
                      let fieldRow = fields["content-branch-fields:" + key] else { return nil }
                guard let bytes = fieldRow.value(forKey: "value") as? Data else { throw ItemRepositoryError.corruptStore }
                let serverFields = try JSONDecoder().decode(Data.self, from: bytes)
                let prepared: PreparedContentVersion = try contentValue(remote)
                let local = try decodeVersion(item)
                if !includePendingDecisions, decisions.contains(where: { $0.scope == state.scope && $0.local == local.versionID && $0.remote == state.versionID }) { return nil }
                return EncryptedItemConflict(id: state.versionID, local: local, remote: prepared.version, serverSystemFields: serverFields)
            }
        }
    }
    public func reviewedContentConflict(_ expected: EncryptedItemConflict) throws -> EncryptedItemConflict {
        try transaction {
            let scope = expected.local.scope
            let key = scope.storageKey + ":" + expected.remote.versionID.uuidString
            guard let branch = try fetchOne("ContentBranch", key: key),
                  let item = try fetchOne("Item", key: scope.storageKey),
                  let remote = try fetchOne("ContentVersion", key: key),
                  let fields: Data = try journalValue("StateBlob", key: "content-branch-fields:" + key) else {
                throw ItemRepositoryError.staleConflict
            }
            let state: ContentKeyState = try contentValue(branch)
            let prepared: PreparedContentVersion = try contentValue(remote)
            let current = EncryptedItemConflict(id: state.versionID, local: try decodeVersion(item),
                remote: prepared.version, serverSystemFields: fields)
            guard state.scope == scope, state.versionID == expected.remote.versionID,
                  current == expected else { throw ItemRepositoryError.staleConflict }
            return current
        }
    }

    /// The caller proves signed ancestry. Retire only the reviewed branch and its
    /// diagnostic; preserve the head, pending edits, archived ciphertext and grants.
    public func retireObsoleteContentBranch(_ expected: EncryptedItemConflict, policy: ContentRecipientPolicy,
                                            permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission {
            try transaction {
                let scope = expected.local.scope
                let key = scope.storageKey + ":" + expected.remote.versionID.uuidString
                guard try contentPolicy(VaultScope(scope)) == policy,
                      let item = try fetchOne("Item", key: scope.storageKey), try decodeVersion(item) == expected.local,
                      let branch = try fetchOne("ContentBranch", key: key),
                      let remote = try fetchOne("ContentVersion", key: key),
                      (try contentValue(remote) as PreparedContentVersion).version == expected.remote,
                      try journalValue("StateBlob", key: "content-branch-fields:" + key) as Data? == expected.serverSystemFields else {
                    throw ItemRepositoryError.staleConflict
                }
                let state: ContentKeyState = try contentValue(branch)
                guard state.scope == scope, state.versionID == expected.remote.versionID else { throw ContentStoreError.invalidRecord }
                try touchVaultBoundary(VaultScope(scope))
                let diagnosticKey = "content-branch-operation:" + key
                if let operation: UUID = try journalValue("StateBlob", key: diagnosticKey) {
                    try finishPublicationInTransaction(operation, account: scope.account, database: scope.database, confirmed: false)
                }
                context.delete(branch)
                for key in [diagnosticKey, "content-branch-fields:" + key] {
                    if let row = try fetchOne("StateBlob", key: key) { context.delete(row) }
                }
                try resumeConflictBlockedRotation(scope, policy: policy)
            }
        }
    }

    private func resumeConflictBlockedRotation(_ scope: ItemScope, policy: ContentRecipientPolicy) throws {
        guard try contentRows("ContentBranch", field: "scopeKey", equals: scope.storageKey).isEmpty else { return }
        let id = contentOperationID("rotate:" + scope.storageKey + ":" + policy.keyAuthority)
        let key = journalKey(scope.account, scope.database, id.uuidString)
        guard var operation: SyncOperation = try journalValue("SyncOperation", key: key),
              operation.kind == .rotateContent, operation.state == .needsAttention, operation.failure == .conflict else { return }
        operation.state = .ready; operation.failure = nil; operation.nextAttempt = nil
        operation.retryNotBefore = nil; operation.revision = UUID()
        try writeJournal(operation, entity: "SyncOperation", key: key)
    }

    /// Bound SQL parameters and share reads across branches of the same item.
    /// Rows remain confined to the caller's transaction; this is not a trust cache.
    private func conflictRows(_ entity: String, keys: [String]) throws -> [String: NSManagedObject] {
        let keys = Array(Set(keys))
        var result: [String: NSManagedObject] = [:]
        for offset in stride(from: 0, to: keys.count, by: 256) {
            let request = NSFetchRequest<NSManagedObject>(entityName: entity)
            request.predicate = NSPredicate(format: "key IN %@", Array(keys[offset..<min(offset + 256, keys.count)]))
            conflictBatchReads += 1
            for row in try context.fetch(request) {
                guard let key = row.value(forKey: "key") as? String else { throw ItemRepositoryError.corruptStore }
                result[key] = row
            }
        }
        return result
    }

    /// Called within the engine's bounded publication barrier after exact head
    /// readback. Other unresolved branches survive the explicit user choice.
    public func resolveContentConflict(_ expected: EncryptedItemConflict, replacement: PreparedContentPublication?,
                                       serverSystemFields: Data, policy: ContentRecipientPolicy, decision: SyncOperation? = nil,
                                       permit: any RepositoryWritePermit) throws -> PendingItemMutation? {
        try permit.withWritePermission {
            try transaction {
                let scope = expected.local.scope
                if let decision {
                    let stored: SyncOperation? = try journalValue("SyncOperation", key: journalKey(scope.account, scope.database, decision.id.uuidString))
                    guard stored == decision, decision.kind == .resolveConflict else { throw SyncJournalError.staleOperation }
                    let value = try JSONDecoder().decode(ContentConflictDecision.self, from: decision.payload)
                    guard value.scope == scope, value.local == expected.local.versionID, value.remote == expected.remote.versionID,
                          value.serverSystemFields == expected.serverSystemFields, value.replacement == replacement?.content.version.versionID else { throw ContentStoreError.invalidRecord }
                }
                guard let current = try fetchOne("Item", key: scope.storageKey), try decodeVersion(current) == expected.local,
                      try fetchOne("ContentBranch", key: scope.storageKey + ":" + expected.remote.versionID.uuidString) != nil,
                      let reviewedFields: Data = try journalValue("StateBlob", key: "content-branch-fields:" + scope.storageKey + ":" + expected.remote.versionID.uuidString),
                      reviewedFields == expected.serverSystemFields else { throw ItemRepositoryError.staleConflict }
                guard try contentPolicy(VaultScope(scope)) == policy,
                      let item = try fetchOne("Item", key: scope.storageKey),
                      let remoteRow = try fetchOne("ContentVersion", key: scope.storageKey + ":" + expected.remote.versionID.uuidString) else { throw ContentStoreError.staleAuthority }
                let remote: PreparedContentVersion = try contentValue(remoteRow)
                let selected = replacement?.content ?? remote
                guard selected.version.scope == scope, selected.keyAuthority == policy.keyAuthority else { throw ContentStoreError.staleAuthority }
                if replacement != nil {
                    guard selected.version.baseVersionID == remote.version.versionID,
                          selected.version.generation == remote.version.generation + 1 else { throw ContentStoreError.invalidRecord }
                }
                try touchVaultBoundary(VaultScope(scope)); try supersedePending(scope: scope)
                try archiveContent(selected)
                encode(selected.version, into: item)
                item.setValue(try contentEncode(remote.version), forKey: "acceptedVersion")
                item.setValue(try contentEncode(remote.version), forKey: "publicationBaseVersion")
                item.setValue(serverSystemFields, forKey: "serverSystemFields")
                if let branch = try fetchOne("ContentBranch", key: scope.storageKey + ":" + remote.version.versionID.uuidString) { context.delete(branch) }
                let diagnosticKey = "content-branch-operation:" + scope.storageKey + ":" + remote.version.versionID.uuidString
                if let operation: UUID = try journalValue("StateBlob", key: diagnosticKey) {
                    try finishPublicationInTransaction(operation, account: scope.account, database: scope.database, confirmed: false)
                }
                for key in [diagnosticKey, "content-branch-fields:" + scope.storageKey + ":" + remote.version.versionID.uuidString] {
                    if let row = try fetchOne("StateBlob", key: key) { context.delete(row) }
                }
                try storeContentValue(ContentKeyState(selected), entity: "ContentKeyState", key: scope.storageKey,
                    scope: scope, keyGeneration: selected.keyGeneration, recipient: "")
                if let replacement {
                    for grant in replacement.grants { try storeContentGrant(grant, publish: true, publishExisting: true) }
                }
                try reconcileGrantRequirements(ContentKeyState(selected), policy: policy)
                try resumeConflictBlockedRotation(scope, policy: policy)
                let mutation = try replacement.map { try insertPending($0.content.version, status: .queued) }
                if let decision { try finishPublicationInTransaction(decision.id, account: scope.account, database: scope.database, confirmed: false) }
                return mutation
            }
        }
    }
}

enum ContentGrantRequestBlockReason: String {
    case policyMismatch, recipientExcluded, missingKeyState, generationMismatch

    static func assess(policyMatches: Bool, recipientIncluded: Bool, currentGeneration: UUID?, requestedGeneration: UUID) -> Self? {
        if !policyMatches { return .policyMismatch }
        if !recipientIncluded { return .recipientExcluded }
        guard let currentGeneration else { return .missingKeyState }
        return currentGeneration == requestedGeneration ? nil : .generationMismatch
    }
}

extension EncryptedItemRepository {
    /// Scheduling hint only. A resumed request must repeat signature, membership,
    /// recipient policy and generation verification before producing any grants.
    public func contentKeyStateAvailable(scope: ItemScope, keyGeneration: UUID) throws -> Bool {
        try transaction {
            guard let row = try fetchOne("ContentKeyState", key: scope.storageKey) else { return false }
            let value: ContentKeyState = try contentValue(row)
            return value.keyGeneration == keyGeneration
        }
    }

    public func reconcileSupersededGrantRequest(scope: ItemScope, expected: ContentKeyState, recipient: String,
                                               policy: ContentRecipientPolicy, permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission {
            try transaction {
                guard expected.scope == scope, try contentPolicy(VaultScope(scope)) == policy,
                      policy.recipients.contains(recipient), let row = try fetchOne("ContentKeyState", key: scope.storageKey),
                      try contentValue(row) as ContentKeyState == expected else { throw ContentStoreError.staleAuthority }
                try reconcileGrantRequirements(expected, policy: policy)
            }
        }
    }

    public func reconcileContentGrantRequest(scope: ItemScope, keyGeneration: UUID, recipient: String,
                                            policy: ContentRecipientPolicy, permit: any RepositoryWritePermit) throws -> SyncDependency? {
        try permit.withWritePermission {
            try transaction {
                let value: ContentKeyState? = try fetchOne("ContentKeyState", key: scope.storageKey).map { try contentValue($0) }
                if let reason = ContentGrantRequestBlockReason.assess(
                    policyMatches: try contentPolicy(VaultScope(scope)) == policy,
                    recipientIncluded: policy.recipients.contains(recipient),
                    currentGeneration: value?.keyGeneration, requestedGeneration: keyGeneration) {
                    AccessSyncTrace.event("grant request blocked", item: scope.itemID, generation: keyGeneration,
                        recipient: recipient, detail: "reason=\(reason.rawValue) currentGeneration=\(value.map { AccessSyncTrace.token($0.keyGeneration.uuidString) } ?? "-")")
                    if reason == .missingKeyState {
                        return SyncDependency(.contentKeyState,
                            identifier: scope.vaultID.uuidString + ":" + scope.itemID.uuidString + ":" + keyGeneration.uuidString)
                    }
                    throw ContentStoreError.staleAuthority
                }
                guard let value else { throw ContentStoreError.staleAuthority }
                try reconcileGrantRequirements(value, policy: policy)
                return nil
            }
        }
    }
}

extension EncryptedItemRepository {
    public func pendingContentConflictDecision(_ expected: EncryptedItemConflict) throws -> ContentConflictDecision? {
        let operations = try operations(account: expected.local.scope.account, database: expected.local.scope.database)
        return try operations.filter { $0.kind == .resolveConflict && ![.completed, .needsAttention].contains($0.state) }
            .map { try JSONDecoder().decode(ContentConflictDecision.self, from: $0.payload) }
            .first { $0.scope == expected.local.scope && $0.local == expected.local.versionID && $0.remote == expected.remote.versionID }
    }
    public func enqueueContentConflictDecision(_ expected: EncryptedItemConflict, replacement: PreparedContentPublication?,
                                              policy: ContentRecipientPolicy, permit: any RepositoryWritePermit) throws -> SyncOperation {
        return try permit.withWritePermission {
            try transaction {
                let scope = expected.local.scope
                guard let item = try fetchOne("Item", key: scope.storageKey), try decodeVersion(item) == expected.local,
                      let remote = try fetchOne("ContentVersion", key: scope.storageKey + ":" + expected.remote.versionID.uuidString),
                      try fetchOne("ContentBranch", key: scope.storageKey + ":" + expected.remote.versionID.uuidString) != nil,
                      try contentPolicy(VaultScope(scope)) == policy else { throw ItemRepositoryError.staleConflict }
                let remoteContent: PreparedContentVersion = try contentValue(remote)
                guard remoteContent.version == expected.remote,
                      try journalValue("StateBlob", key: "content-branch-fields:" + scope.storageKey + ":" + expected.remote.versionID.uuidString) as Data? == expected.serverSystemFields else { throw ItemRepositoryError.staleConflict }
                let operations: [SyncOperation] = try journalValues("SyncOperation", account: scope.account, database: scope.database)
                for existing in operations where existing.kind == .resolveConflict && ![.completed, .needsAttention].contains(existing.state) {
                    let decision = try JSONDecoder().decode(ContentConflictDecision.self, from: existing.payload)
                    if decision.scope == scope, decision.local == expected.local.versionID, decision.remote == expected.remote.versionID {
                        guard (decision.replacement == nil) == (replacement == nil) else { throw ItemRepositoryError.staleConflict }
                        return existing
                    }
                }
                try touchVaultBoundary(VaultScope(scope))
                if let replacement {
                    guard replacement.content.version.scope == scope, replacement.content.version.baseVersionID == expected.remote.versionID,
                          replacement.content.version.generation == expected.remote.generation + 1,
                          replacement.content.keyAuthority == policy.keyAuthority else { throw ContentStoreError.invalidRecord }
                    try archiveContent(replacement.content)
                    for grant in replacement.grants {
                        guard grant.scope == scope, grant.keyGeneration == replacement.content.keyGeneration else { throw ContentStoreError.invalidRecord }
                        try storeContentGrant(grant, publish: false)
                    }
                }
                // Review is complete, but both encrypted branches remain until
                // the durable decision passes the owner's exact cloud readback.
                let diagnosticKey = "content-branch-operation:" + scope.storageKey + ":" + expected.remote.versionID.uuidString
                if let diagnostic: UUID = try journalValue("StateBlob", key: diagnosticKey) {
                    try finishPublicationInTransaction(diagnostic, account: scope.account, database: scope.database, confirmed: false)
                }
                let value = ContentConflictDecision(scope: scope, local: expected.local.versionID, remote: expected.remote.versionID,
                    serverSystemFields: expected.serverSystemFields, replacement: replacement?.content.version.versionID)
                return try enqueueInTransaction(SyncOperation(account: scope.account, vaultID: scope.vaultID, zoneOwner: scope.zoneOwner,
                    kind: .resolveConflict, payload: contentEncode(value)))
            }
        }
    }
    public func contentConflictDecision(_ operation: SyncOperation) throws -> (EncryptedItemConflict, PreparedContentPublication?) {
        return try transaction {
            let value = try JSONDecoder().decode(ContentConflictDecision.self, from: operation.payload)
            let scope = value.scope
            guard operation.kind == .resolveConflict, operation.account == scope.account, operation.vaultID == scope.vaultID,
                  operation.database == scope.database, operation.zoneOwner == scope.zoneOwner else { throw ContentStoreError.invalidRecord }
            let stored: SyncOperation? = try journalValue("SyncOperation", key: journalKey(scope.account, scope.database, operation.id.uuidString))
            guard stored == operation else { throw SyncJournalError.staleOperation }
            func version(_ id: UUID) throws -> PreparedContentVersion {
                guard let row = try fetchOne("ContentVersion", key: scope.storageKey + ":" + id.uuidString) else { throw ItemRepositoryError.staleConflict }
                return try contentValue(row)
            }
            let expected = try EncryptedItemConflict(id: value.remote, local: version(value.local).version,
                remote: version(value.remote).version, serverSystemFields: value.serverSystemFields)
            let replacement: PreparedContentPublication?
            if let id = value.replacement {
                let content = try version(id)
                let grants: [PreparedContentGrant] = try contentRows("ContentGrant", field: "scopeKey", equals: scope.storageKey)
                    .map { try contentValue($0) }.filter { $0.keyGeneration == content.keyGeneration }
                replacement = PreparedContentPublication(content: content, grants: grants)
            } else { replacement = nil }
            return (expected, replacement)
        }
    }
}

extension EncryptedItemRepository {
    public func enrollmentProgressRecipient(scope: VaultScope) throws -> String? {
        try transaction { try journalValue("StateBlob", key: "enrollment-progress-recipient:" + scope.storageKey) }
    }

    /// Presentation only, based on applied content and grants. Fetch indexed
    /// public columns once per discovery refresh, never ciphertext or keys.
    public func enrollmentDownloadProgress(scope: VaultScope, recipient: String, metadata: UUID) throws -> (ready: Int, total: Int)? {
        return try transaction {
            let key = "enrollment-progress-total:" + scope.storageKey
            let expected: Int? = try journalValue("StateBlob", key: key)
                ?? journalValue("StateBlob", key: "initial-download:" + scope.storageKey)
            guard let expected else { return nil }
            guard expected >= 0, expected < Int.max else { throw ItemRepositoryError.corruptStore }
            let vaultKey = contentVaultKey(scope)
            func rows(_ entity: String, recipient: String? = nil) throws -> [NSDictionary] {
                let request = NSFetchRequest<NSDictionary>(entityName: entity)
                request.resultType = .dictionaryResultType
                request.propertiesToFetch = ["scopeKey", "keyGeneration"]
                request.predicate = recipient.map { NSPredicate(format: "vaultKey == %@ AND recipient == %@", vaultKey, $0) }
                    ?? NSPredicate(format: "vaultKey == %@", vaultKey)
                return try context.fetch(request)
            }
            let states = try rows("ContentKeyState"), grants = try rows("ContentGrant", recipient: recipient)
            func identity(_ row: NSDictionary) throws -> String {
                guard let scope = row["scopeKey"] as? String, let generation = row["keyGeneration"] as? UUID else { throw ItemRepositoryError.corruptStore }
                return scope + ":" + generation.uuidString
            }
            let covered = try Set(grants.map(identity))
            let ready = try states.filter { covered.contains(try identity($0)) }
            let metadataScope = ItemScope(account: scope.account, vaultID: scope.vaultID, itemID: metadata, database: scope.database, zoneOwner: scope.zoneOwner).storageKey
            let hasMetadata = states.contains { $0["scopeKey"] as? String == metadataScope }
            let total = max(expected + 1, states.count + (hasMetadata ? 0 : 1))
            if ready.count >= total && ready.contains(where: { $0["scopeKey"] as? String == metadataScope }) {
                if let row = try journalRow("StateBlob", key: key) { context.delete(row) }
                if let row = try journalRow("StateBlob", key: "enrollment-progress-recipient:" + scope.storageKey) { context.delete(row) }
                if let row = try journalRow("StateBlob", key: "initial-download:" + scope.storageKey) { context.delete(row) }
                return nil
            }
            if try journalRow("StateBlob", key: key) == nil { try writeJournal(expected, entity: "StateBlob", key: key) }
            return (ready.count, total)
        }
    }
}

extension EncryptedItemRepository {
    /// Migration admission uses the same durable membership queue as enrollment.
    /// Recheck authorization inside the actor, after any suspension at the caller.
    public func enqueueDeviceMigration(_ operation: SyncOperation, authorization: any RepositoryWritePermit) throws {
        try authorization.withWritePermission {
            guard operation.kind == .membership else { throw ContentStoreError.invalidRecord }
            try transaction {
                let pending: [SyncOperation] = try journalValues("SyncOperation", account: operation.account, database: operation.database)
                // App and AutoFill may both stage the same replacement. One
                // membership proposal per vault wins atomically; the next pinned
                // head causes any remaining migration work to be reconsidered.
                guard !pending.contains(where: { $0.kind == .membership && $0.vaultID == operation.vaultID && $0.state != .completed }) else { return }
                _ = try enqueueInTransaction(operation)
            }
        }
    }

    /// Verified additive grant transfer preserves archived versions and pending
    /// user edits. Only current-generation grants are published; historical copies
    /// are local, retaining the existing publication rules for obsolete heads.
    public func commitDeviceMigrationGrant(_ grant: PreparedContentGrant, sourceVersion: PreparedContentVersion,
                                          expectedPolicy: ContentRecipientPolicy, authorization: any RepositoryWritePermit) throws {
        try authorization.withWritePermission {
            try transaction {
                guard grant.scope == sourceVersion.version.scope, grant.keyGeneration == sourceVersion.keyGeneration,
                      try contentPolicy(VaultScope(grant.scope)) == expectedPolicy,
                      expectedPolicy.recipients.contains(grant.recipient),
                      let stored = try fetchOne("ContentVersion", key: grant.scope.storageKey + ":" + sourceVersion.version.versionID.uuidString),
                      try contentValue(stored) as PreparedContentVersion == sourceVersion else { throw ContentStoreError.staleAuthority }
                // Concurrent app/extension migration may have randomized the same
                // grant already. Keep the verified durable winner rather than replace.
                let request = NSFetchRequest<NSManagedObject>(entityName: "ContentGrant")
                request.predicate = NSPredicate(format: "scopeKey == %@ AND keyGeneration == %@ AND recipient == %@",
                    grant.scope.storageKey, grant.keyGeneration as NSUUID, grant.recipient)
                request.fetchLimit = 1
                if try !context.fetch(request).isEmpty { return }
                guard let row = try fetchOne("ContentKeyState", key: grant.scope.storageKey) else { throw ContentStoreError.invalidRecord }
                let current: ContentKeyState = try contentValue(row)
                try touchVaultBoundary(VaultScope(grant.scope))
                try storeContentGrant(grant, publish: current.keyGeneration == grant.keyGeneration && current.keyAuthority == expectedPolicy.keyAuthority)
                try reconcileGrantRequirements(current, policy: expectedPolicy)
            }
        }
    }
}
