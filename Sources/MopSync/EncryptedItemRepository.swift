@preconcurrency import CoreData
import Foundation
import Darwin
import MopCore
import CryptoKit

/// Transactional ciphertext storage. This actor never decrypts data or performs network I/O.
/// Core Data optimistic locking rejects conflicting writers across app-group processes.
public actor EncryptedItemRepository {
    public static let maximumCiphertextBytes = 256 * 1024 * 1024
    private let container: NSPersistentContainer
    let context: NSManagedObjectContext
    let journalReadCache = JournalReadCache()
    var itemRevisionIndexReads = 0
    var displayValidationRows = 0
    var grantPreparationReads = 0
    var grantPreparationRows = 0
    var missingGrantScanRows = 0
    var conflictBatchReads = 0
    private let supportsQueryGenerations: Bool
    private var changeObserver: StoreChangeObserver?
    private var changeStreams: [UUID: AsyncStream<Void>.Continuation] = [:]

    public init(storeURL: URL, inMemory: Bool = false) throws {
        try SyncStoreLayout.validate(storeURL: storeURL)
        supportsQueryGenerations = !inMemory
        container = NSPersistentContainer(name: "MopEncryptedItems", managedObjectModel: RepositoryModel.make())
        var options: [AnyHashable: Any] = [
            NSPersistentHistoryTrackingKey: true,
            NSPersistentStoreRemoteChangeNotificationPostOptionKey: true,
            NSMigratePersistentStoresAutomaticallyOption: false,
            NSInferMappingModelAutomaticallyOption: false
        ]
        #if os(iOS)
        options[NSPersistentStoreFileProtectionKey] = FileProtectionType.complete
        #endif
        if !inMemory {
            var directory = storeURL.deletingLastPathComponent()
            try LocalFile.privateDirectory(directory)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try directory.setResourceValues(values)
            for suffix in ["", "-wal", "-shm"] {
                let path = storeURL.path + suffix
                var info = stat()
                if lstat(path, &info) == 0 {
                    guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(),
                          info.st_mode & 0o077 == 0 else { throw MopError.filePermissions }
                } else if errno != ENOENT { throw MopError.inputOutput }
            }
        }
        if !inMemory, FileManager.default.fileExists(atPath: storeURL.path) {
            // Reject retired models before opening them; never rewrite an older store.
            let metadata = try NSPersistentStoreCoordinator.metadataForPersistentStore(ofType: NSSQLiteStoreType, at: storeURL)
            let raw = metadata[NSStoreModelVersionIdentifiersKey]
            let identifiers = (raw as? [String]) ?? Array((raw as? Set<String>) ?? [])
            guard identifiers == ["MopContentPreview3"] else { throw ContentStoreError.wrongLayout }
        }
        try container.persistentStoreCoordinator.addPersistentStore(ofType: inMemory ? NSInMemoryStoreType : NSSQLiteStoreType,
            configurationName: nil, at: inMemory ? nil : storeURL, options: options)
        if !inMemory {
            for suffix in ["", "-wal", "-shm"] where FileManager.default.fileExists(atPath: storeURL.path + suffix) {
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: storeURL.path + suffix)
            }
        }
        context = container.newBackgroundContext()
        context.name = "MopEncryptedItemRepository"
        context.transactionAuthor = "MopEncryptedItemRepository"
        context.mergePolicy = NSErrorMergePolicy
        context.undoManager = nil
        context.stalenessInterval = 0
    }

    public func deletion(_ scope: VaultScope) throws -> VaultDeletionState? {
        try transaction { try deletionInTransaction(scope) }
    }
    public func deletions(account: String) throws -> [VaultDeletionState] {
        try transaction {
            let values: [VaultDeletionState] = try journalReadCache.values(prefix: "deletion:", in: context)
            return values.filter { $0.scope.account == account }
        }
    }
    func deletionInTransaction(_ scope: VaultScope) throws -> VaultDeletionState? {
        guard let bytes = try fetchOne("StateBlob", key: "deletion:" + scope.storageKey)?.value(forKey: "value") as? Data else { return nil }
        let value = try JSONDecoder().decode(VaultDeletionState.self, from: bytes)
        guard value.scope == scope else { throw ItemRepositoryError.corruptStore }
        return value
    }
    private func requireLiveVault(_ scope: VaultScope) throws {
        if let deletion = try deletionInTransaction(scope), deletion.phase != .prepared { throw VaultDeletionFailure.deleted }
    }
    /// The authenticated domain coordinator owns authorization. Commitment and
    /// removal of ciphertext/outbox are one optimistic-lock transaction.
    public func saveDeletion(scope: VaultScope, notice: Data, phase: VaultDeletionPhase,
                             publication: PreparedCoordinationRecord? = nil, cleanup: SyncOperation? = nil, authorization: any RepositoryWritePermit) throws -> VaultDeletionState {
        try authorization.withWritePermission {
            try transaction {
                let old = try deletionInTransaction(scope)
                guard !notice.isEmpty, notice.count <= 1_048_576 else { throw VaultDeletionFailure.invalidNotice }
                if let cleanup {
                    guard phase == .prepared, cleanup.kind == .deletion, cleanup.account == scope.account,
                          cleanup.database == scope.database, cleanup.zoneOwner == scope.zoneOwner,
                          cleanup.vaultID == scope.vaultID,
                          let record = try? JSONDecoder().decode(PreparedCoordinationRecord.self, from: cleanup.payload),
                          record.account == scope.account, record.vault == scope.vaultID, record.zoneOwner == scope.zoneOwner,
                          record.kind == .deletion, record.identity == scope.vaultID, record.bytes == notice else { throw VaultDeletionFailure.invalidNotice }
                    _ = try enqueueInTransaction(cleanup)
                }
                if let publication {
                    guard phase == .prepared, publication.kind == .deletion,
                          publication.account == scope.account, publication.vault == scope.vaultID,
                          publication.identity == scope.vaultID, publication.zoneOwner == scope.zoneOwner,
                          publication.bytes == notice else { throw VaultDeletionFailure.invalidNotice }
                    _ = try enqueueInTransaction(publication.operation())
                }
                if let old, old.phase == phase, old.notice == notice { return old }
                let allowed: Bool
                switch (old?.phase, phase) {
                case (nil, .prepared), (nil, .committed), (.prepared?, .publishing),
                     (.prepared?, .committed), (.publishing?, .committed),
                     (.committed?, .cloudDeleted), (.cloudDeleted?, .complete): allowed = true
                default: allowed = false
                }
                guard allowed,
                      old == nil || old?.notice == notice || phase == .committed else { throw VaultDeletionFailure.staleState }
                if phase == .publishing, old?.phase == .prepared { try touchVaultBoundary(scope) }
                var assets = old?.assetVersions ?? []
                if phase == .committed && (old == nil || old?.phase == .prepared || old?.phase == .publishing) {
                    try purgeSyncJournalInTransaction(scope)

                    for entity in ["ContentKeyState", "ContentGrant", "MissingContentGrant", "ContentVersion", "ContentBranch"] {
                        for row in try contentRows(entity, field: "vaultKey", equals: contentVaultKey(scope)) { context.delete(row) }
                    }

                    // Dirty the same boundary used by all local item writers.
                    let boundary = try fetchOne("VaultBoundary", key: scope.storageKey)
                        ?? NSEntityDescription.insertNewObject(forEntityName: "VaultBoundary", into: context)
                    boundary.setValue(scope.storageKey, forKey: "key"); boundary.setValue(UUID(), forKey: "nonce")
                    let predicate = NSPredicate(format: "account == %@ AND vaultID == %@ AND database == %@ AND zoneOwner == %@",
                        scope.account, scope.vaultID as NSUUID, scope.database, scope.zoneOwner)
                    for entity in ["Item", "AdmissionItem", "PendingMutation", "Conflict"] {
                        let request = NSFetchRequest<NSManagedObject>(entityName: entity)
                        request.predicate = predicate
                        for row in try context.fetch(request) {
                            if entity != "Conflict", let version = row.value(forKey: "versionID") as? UUID { assets.append(version) }
                            context.delete(row)
                        }
                    }
                    let receipts = NSFetchRequest<NSManagedObject>(entityName: "MutationReceipt")
                    receipts.predicate = NSPredicate(format: "account == %@", scope.account)
                    for row in try context.fetch(receipts) {
                        guard let bytes = row.value(forKey: "scope") as? Data else { throw ItemRepositoryError.corruptStore }
                        if VaultScope(try JSONDecoder().decode(ItemScope.self, from: bytes)) == scope {
                            if let version = row.value(forKey: "versionID") as? UUID { assets.append(version) }
                            context.delete(row)
                        }
                    }
                    let blobs = NSFetchRequest<NSManagedObject>(entityName: "StateBlob")
                    blobs.predicate = NSCompoundPredicate(orPredicateWithSubpredicates: [
                        NSPredicate(format: "key ENDSWITH %@", ":" + scope.storageKey),
                        NSPredicate(format: "key BEGINSWITH %@", "display-row:" + scope.storageKey + ":"),
                        NSPredicate(format: "key BEGINSWITH %@", "local-health:" + scope.storageKey + ":")])
                    for row in try context.fetch(blobs) where row.value(forKey: "key") as? String != "deletion:" + scope.storageKey { context.delete(row) }
                    try fetchOne("VaultBoundary", key: scope.storageKey)?.setValue(nil, forKey: "initialization")
                }
                let state = VaultDeletionState(scope: scope, notice: notice, phase: phase,
                    assetVersions: phase == .complete ? [] : Array(Set(assets)))
                let key = "deletion:" + scope.storageKey
                let row = try fetchOne("StateBlob", key: key) ?? NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
                row.setValue(key, forKey: "key"); row.setValue(try JSONEncoder().encode(state), forKey: "value")
                return state
            }
        }
    }

    /// Returns the durable receipt of an atomic vault initialization.
    public func vaultInitialization(_ scope: VaultScope) throws -> VaultInitializationReceipt? {
        try transaction {
            guard let bytes = try fetchOne("VaultBoundary", key: scope.storageKey)?.value(forKey: "initialization") as? Data else { return nil }
            let receipt = try JSONDecoder().decode(VaultInitializationReceipt.self, from: bytes)
            guard receipt.scope == scope else { throw ItemRepositoryError.corruptStore }
            return receipt
        }
    }

    /// A shared uniqueness/optimistic-lock boundary serializes bootstrap against
    /// unrelated first-item creation by another process in the same vault.
    func touchVaultBoundary(_ scope: VaultScope) throws {
        try requireLiveVault(scope)
        let row = try fetchOne("VaultBoundary", key: scope.storageKey)
            ?? NSEntityDescription.insertNewObject(forEntityName: "VaultBoundary", into: context)
        row.setValue(scope.storageKey, forKey: "key")
        row.setValue(UUID(), forKey: "nonce")
    }

    public func provisioning(_ scope: VaultScope) throws -> VaultProvisioningState? {
        try transaction { try provisioningInTransaction(scope) }
    }

    public func prepareProvisioning(binding: VaultProvisioningBinding, controlBytes: Data,
                                    authorization: any RepositoryWritePermit) throws -> VaultProvisioningState {
        guard binding.scope.database == "private", binding.scope.zoneOwner == "__defaultOwner__",
              binding.address.ownerName == binding.scope.zoneOwner, binding.address.vaultID == binding.scope.vaultID,
              !binding.address.zoneName.isEmpty, !binding.setupID.isEmpty,
              binding.controlDigest.count == 64,
              binding.controlDigest.allSatisfy({ "0123456789abcdef".contains($0) }),
              Data(SHA256.hash(data: controlBytes)).map({ String(format: "%02x", $0) }).joined() == binding.controlDigest else {
            throw VaultProvisioningError.invalidBinding
        }
        return try authorization.withWritePermission {
            try transaction {
                guard let bytes = try fetchOne("VaultBoundary", key: binding.scope.storageKey)?.value(forKey: "initialization") as? Data else {
                    throw VaultProvisioningError.missingInitialization
                }
                let receipt = try JSONDecoder().decode(VaultInitializationReceipt.self, from: bytes)
                guard receipt.scope == binding.scope, receipt.setupID == binding.setupID,
                      receipt.membershipState == controlBytes else { throw VaultProvisioningError.invalidBinding }
                if let existing = try provisioningInTransaction(binding.scope) {
                    guard existing.binding == binding, existing.controlBytes == controlBytes else { throw VaultProvisioningError.invalidBinding }
                    return existing
                }
                let state = VaultProvisioningState(binding: binding, controlBytes: controlBytes, phase: .prepared, headSystemFields: nil)
                try writeProvisioning(state)
                return state
            }
        }
    }

    public func advanceProvisioning(_ expected: VaultProvisioningState, to phase: VaultProvisioningPhase,
                                    headSystemFields: Data? = nil,
                                    authorization: any RepositoryWritePermit) throws -> VaultProvisioningState {
        try authorization.withWritePermission {
            try transaction {
                guard try provisioningInTransaction(expected.binding.scope) == expected else { throw VaultProvisioningError.staleState }
                guard (expected.phase == .prepared && phase == .commissioningStarted)
                    || (expected.phase == .commissioningStarted && phase == .controlConfirmed && headSystemFields != nil)
                    || (expected.phase != .blocked && phase == .blocked) else { throw VaultProvisioningError.staleState }
                let state = VaultProvisioningState(binding: expected.binding, controlBytes: expected.controlBytes,
                    phase: phase, headSystemFields: headSystemFields ?? expected.headSystemFields)
                try writeProvisioning(state)
                return state
            }
        }
    }

    /// Fail-closed observation; this can only revoke publication, never authorize it.
    public func blockProvisioning(_ scope: VaultScope) throws {
        try transaction {
            guard let current = try provisioningInTransaction(scope), current.phase != .blocked else { return }
            try writeProvisioning(VaultProvisioningState(binding: current.binding, controlBytes: current.controlBytes,
                phase: .blocked, headSystemFields: current.headSystemFields))
        }
    }

    private func provisioningInTransaction(_ scope: VaultScope) throws -> VaultProvisioningState? {
        guard let bytes = try fetchOne("StateBlob", key: "provisioning:" + scope.storageKey)?.value(forKey: "value") as? Data else { return nil }
        let state = try JSONDecoder().decode(VaultProvisioningState.self, from: bytes)
        guard state.binding.scope == scope else { throw ItemRepositoryError.corruptStore }
        return state
    }
    private func writeProvisioning(_ state: VaultProvisioningState) throws {
        try requireLiveVault(state.binding.scope)
        let key = "provisioning:" + state.binding.scope.storageKey
        let row = try fetchOne("StateBlob", key: key) ?? NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
        row.setValue(key, forKey: "key")
        row.setValue(try JSONEncoder().encode(state), forKey: "value")
    }

    public func initializeEnrolledContentVault(scope: VaultScope, policy: ContentRecipientPolicy, expectedItemCount: Int? = nil, enrollmentRecipient: String? = nil, membershipState: Data, currentControl: Data,
        setupID: String, authorization: any RepositoryWritePermit) throws -> VaultInitializationReceipt {

        guard scope.database == "private", scope.zoneOwner == "__defaultOwner__",
              !membershipState.isEmpty, !currentControl.isEmpty, !setupID.isEmpty,
              membershipState.count <= 512 * 1024, currentControl.count <= 512 * 1024 else { throw ItemRepositoryError.invalidInitialization }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        var hash = SHA256()
        hash.update(data: Data("mop-enrolled-content-vault-3".utf8)); hash.update(data: try encoder.encode(scope))
        hash.update(data: Data(setupID.utf8)); hash.update(data: membershipState)
        let digest = Data(hash.finalize())
        return try authorization.withWritePermission {
            try transaction {
                if let bytes = try fetchOne("VaultBoundary", key: scope.storageKey)?.value(forKey: "initialization") as? Data {
                    let receipt = try JSONDecoder().decode(VaultInitializationReceipt.self, from: bytes)
                    guard receipt.scope == scope, receipt.setupID == setupID,
                          receipt.membershipState == membershipState, receipt.inputDigest == digest else { throw ItemRepositoryError.initializationMismatch }
                    return receipt
                }
                try touchVaultBoundary(scope)
                for entity in ["Item", "PendingMutation", "Conflict"] {
                    let request = NSFetchRequest<NSManagedObject>(entityName: entity)
                    request.predicate = NSPredicate(format: "account == %@ AND vaultID == %@ AND database == %@ AND zoneOwner == %@",
                        scope.account, scope.vaultID as NSUUID, scope.database, scope.zoneOwner)
                    request.fetchLimit = 1
                    guard try context.fetch(request).isEmpty else { throw ItemRepositoryError.existingVault }
                }
                let receiptQuery = NSFetchRequest<NSManagedObject>(entityName: "MutationReceipt")
                receiptQuery.predicate = NSPredicate(format: "scopeKey BEGINSWITH %@", scope.storageKey + ":")
                receiptQuery.fetchLimit = 1
                guard try context.fetch(receiptQuery).isEmpty, try provisioningInTransaction(scope) == nil else { throw ItemRepositoryError.existingVault }
                let receipt = VaultInitializationReceipt(scope: scope, setupID: setupID,
                    membershipState: membershipState, inputDigest: digest, mutationIDs: [])
                guard let boundary = try fetchOne("VaultBoundary", key: scope.storageKey) else { throw ItemRepositoryError.corruptStore }
                boundary.setValue(try encoder.encode(receipt), forKey: "initialization")
                if let enrollmentRecipient {
                    try writeJournal(enrollmentRecipient, entity: "StateBlob", key: "enrollment-progress-recipient:" + scope.storageKey)
                }
                if let expectedItemCount {
                    try writeJournal(expectedItemCount, entity: "StateBlob", key: "enrollment-progress-total:" + scope.storageKey)
                }
                if let expectedItemCount, expectedItemCount > 0 {
                    let progress = NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
                    progress.setValue("initial-download:" + scope.storageKey, forKey: "key")
                    progress.setValue(try encoder.encode(expectedItemCount), forKey: "value")
                }
                let rootDigest = SHA256.hash(data: membershipState).map { String(format: "%02x", $0) }.joined()
                let binding = VaultProvisioningBinding(scope: scope,
                    address: VaultCloudAddress(vaultID: scope.vaultID, zoneName: SyncStoreLayout.contentZone(vault: scope.vaultID), ownerName: scope.zoneOwner),
                    setupID: setupID, controlDigest: rootDigest)
                try writeProvisioning(VaultProvisioningState(binding: binding, controlBytes: currentControl,
                    phase: .controlConfirmed, headSystemFields: nil))
                try writeJournal(policy, entity: "StateBlob", key: "content-policy:" + contentVaultKey(scope))
                return receipt
            }
        }
    }

    /// A durable presentation hint from the admitting device's snapshot. Local
    /// arrivals (including tombstones) satisfy it; it never gates vault access.
    public func initialDownloadExpectedCount(scope: VaultScope) throws -> Int? {
        try transaction {
            guard let row = try fetchOne("StateBlob", key: "initial-download:" + scope.storageKey),
                  let data = row.value(forKey: "value") as? Data else { return nil }
            let expected = try JSONDecoder().decode(Int.self, from: data)
            let request = NSFetchRequest<NSFetchRequestResult>(entityName: "Item")
            request.predicate = NSPredicate(format: "account == %@ AND vaultID == %@ AND database == %@ AND zoneOwner == %@ AND healthItemID == nil",
                scope.account, scope.vaultID as NSUUID, scope.database, scope.zoneOwner)
            if try context.count(for: request) - 1 >= expected {
                context.delete(row)
                return nil
            }
            return expected
        }
    }

    /// Stores a verified remote authority head without altering item data. The
    /// independent trust checkpoint must already include this exact successor.
    public func acceptMembershipHead(scope: VaultScope, expectedControl: Data, control: Data,
                                     headSystemFields: Data?, authorization: any RepositoryWritePermit) throws {
        try authorization.withWritePermission {
            try transaction {
                guard let state = try provisioningInTransaction(scope), state.phase == .controlConfirmed else { throw VaultProvisioningError.staleState }
                if state.controlBytes == control { return }
                guard state.controlBytes == expectedControl else { throw VaultProvisioningError.staleState }
                try writeProvisioning(VaultProvisioningState(binding: state.binding, controlBytes: control,
                    phase: .controlConfirmed, headSystemFields: headSystemFields))
                _ = try updateSyncRequest(account: scope.account, database: scope.database, reason: .localSave)
            }
        }
    }

    func commitLocalMutationInTransaction(_ version: EncryptedItemVersion,
                                          dependencies: Set<SyncDependency> = []) throws -> PendingItemMutation {
        try touchVaultBoundary(VaultScope(version.scope))
        let current = try fetchOne("Item", key: version.scope.storageKey)
        let previous = try current.map(decodeVersion)
        guard previous?.versionID == version.baseVersionID else { throw ItemRepositoryError.staleLocalVersion }
        guard previous?.versionID != version.versionID else { throw ItemRepositoryError.duplicateVersion }
        let previousGeneration = previous?.generation ?? 0
        guard previousGeneration < UInt64(Int64.max), version.generation == previousGeneration + 1 else {
            throw ItemRepositoryError.invalidGeneration
        }
        let duplicate = NSFetchRequest<NSManagedObject>(entityName: "PendingMutation")
        duplicate.predicate = NSPredicate(format: "key == %@ AND versionID == %@", version.scope.storageKey, version.versionID as NSUUID)
        duplicate.fetchLimit = 1
        guard try context.fetch(duplicate).isEmpty else { throw ItemRepositoryError.duplicateVersion }
        let item = current ?? NSEntityDescription.insertNewObject(forEntityName: "Item", into: context)
        encode(version, into: item)
        let conflicts = try contentRows("ContentBranch", field: "scopeKey", equals: version.scope.storageKey)
        return try insertPending(version, status: conflicts.isEmpty ? .queued : .conflict, dependencies: dependencies)
    }

    public func item(_ scope: ItemScope) throws -> EncryptedItemVersion? {
        try transaction { try fetchOne("Item", key: scope.storageKey).map(decodeVersion) }
    }

    public func itemRevisionIndex(account: String, vaultID: UUID, database: String = "private",
                                   zoneOwner: String = "__defaultOwner__") throws -> [UUID: UUID] {
        itemRevisionIndexReads += 1
        return try transaction { try revisionIndexInTransaction(VaultScope(account: account, vaultID: vaultID,
            database: database, zoneOwner: zoneOwner)) }
    }

    private func revisionIndexInTransaction(_ scope: VaultScope) throws -> [UUID: UUID] {
        let request = NSFetchRequest<NSDictionary>(entityName: "Item")
        request.resultType = .dictionaryResultType
        request.propertiesToFetch = ["itemID", "versionID"]
        request.predicate = NSPredicate(format: "account == %@ AND vaultID == %@ AND database == %@ AND zoneOwner == %@",
            scope.account, scope.vaultID as NSUUID, scope.database, scope.zoneOwner)
        var index: [UUID: UUID] = [:]
        for row in try context.fetch(request) {
            guard let item = row["itemID"] as? UUID, let version = row["versionID"] as? UUID else { throw ItemRepositoryError.corruptStore }
            index[item] = version
        }
        return index
    }

    /// Disposable device-encrypted, signed derived data. The domain layer must
    /// authenticate/decrypt this blob and check full revision coverage before use.
    /// It is never synchronized and has no authority over stored item ciphertext.
    public func displayCatalogKey(scope: VaultScope) throws -> Data? {
        try readBlob(entity: "StateBlob", key: "display-key:" + scope.storageKey)
    }

    /// Compare-and-swap handles competing app/CLI builders and corrupt-key repair.
    public func reserveDisplayCatalogKey(scope: VaultScope, candidate: Data, replacing expected: Data?,
                                        authorization: any RepositoryWritePermit) throws -> Data {
        guard !candidate.isEmpty, candidate.count <= 64 * 1024 else { throw ItemRepositoryError.invalidScope }
        return try authorization.withWritePermission {
            try transaction(publishLocalChanges: false) {
                try touchVaultBoundary(scope)
                let key = "display-key:" + scope.storageKey
                let row = try fetchOne("StateBlob", key: key)
                let current = row?.value(forKey: "value") as? Data
                if current != expected, let current { return current }
                let target = row ?? NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
                target.setValue(key, forKey: "key"); target.setValue(candidate, forKey: "value")
                let request = NSFetchRequest<NSManagedObject>(entityName: "StateBlob")
                request.predicate = NSPredicate(format: "key BEGINSWITH %@", "display-row:" + scope.storageKey + ":")
                for row in try context.fetch(request) { context.delete(row) }
                return candidate
            }
        }
    }

    public func displayCatalogRows(scope: VaultScope) throws -> [EncryptedDisplayCatalogRow] {
        try transaction(publishLocalChanges: false) {
            let index = try revisionIndexInTransaction(scope)
            let request = NSFetchRequest<NSManagedObject>(entityName: "StateBlob")
            request.predicate = NSPredicate(format: "key BEGINSWITH %@", "display-row:" + scope.storageKey + ":")
            return try context.fetch(request).compactMap { row in
                guard let bytes = row.value(forKey: "value") as? Data,
                      let value = try? JSONDecoder().decode(EncryptedDisplayCatalogRow.self, from: bytes),
                      row.value(forKey: "key") as? String == "display-row:" + scope.storageKey + ":" + value.itemID.uuidString else { return nil }
                // Prune missing items once when loading the cache, rather than
                // scanning the whole cache after every projected batch.
                guard index[value.itemID] != nil else { context.delete(row); return nil }
                return value
            }
        }
    }

    /// A version mismatch is durable pending projection work, including changes
    /// received while locked. Updating the projection cannot overwrite an item.
    public func saveDisplayCatalogRows(scope: VaultScope, rows: [EncryptedDisplayCatalogRow], keyEnvelope: Data,
                                       authorization: any RepositoryWritePermit) throws {
        try authorization.withWritePermission {
            try transaction(publishLocalChanges: false) {
                try touchVaultBoundary(scope)
                guard try fetchOne("StateBlob", key: "display-key:" + scope.storageKey)?.value(forKey: "value") as? Data == keyEnvelope else {
                    throw ItemRepositoryError.staleLocalVersion
                }
                // Validate only this batch against authoritative item versions.
                // The vault boundary still serializes concurrent item changes.
                let request = NSFetchRequest<NSDictionary>(entityName: "Item")
                request.resultType = .dictionaryResultType
                request.propertiesToFetch = ["itemID", "versionID"]
                request.predicate = NSPredicate(format: "key IN %@", rows.map { ItemScope(account: scope.account, vaultID: scope.vaultID, itemID: $0.itemID, database: scope.database, zoneOwner: scope.zoneOwner).storageKey })
                let index = try Dictionary(uniqueKeysWithValues: context.fetch(request).map { row -> (UUID, UUID) in
                    guard let item = row["itemID"] as? UUID, let version = row["versionID"] as? UUID else { throw ItemRepositoryError.corruptStore }
                    return (item, version)
                })
                displayValidationRows += index.count
                for value in rows {
                    guard index[value.itemID] == value.versionID else { throw ItemRepositoryError.staleLocalVersion }
                    guard !value.ciphertext.isEmpty, value.ciphertext.count <= 16 * 1024 * 1024 else { throw ItemRepositoryError.invalidScope }
                    let key = "display-row:" + scope.storageKey + ":" + value.itemID.uuidString
                    let row = try fetchOne("StateBlob", key: key) ?? NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
                    row.setValue(key, forKey: "key")
                    row.setValue(try JSONEncoder().encode(value), forKey: "value")
                }

            }
        }
    }

    public func localNameIndex(scope: VaultScope) throws -> Data? {
        guard let bytes = try readBlob(entity: "StateBlob", key: "local-name-index:" + scope.storageKey),
              !bytes.isEmpty, bytes.count <= 16 * 1024 * 1024 else { return nil }
        return bytes
    }

    /// Saves only against the exact authoritative map, including vault metadata.
    /// The shared boundary serializes this comparison against other processes'
    /// item creation, edits, and conflict resolution. No outbox or sync wake is made.
    public func saveLocalNameIndex(scope: VaultScope, bytes: Data, expectedVersions: [UUID: UUID],
                                   authorization: any RepositoryWritePermit) throws {
        guard !bytes.isEmpty, bytes.count <= 16 * 1024 * 1024,
              !scope.account.isEmpty, ["private", "shared"].contains(scope.database),
              !scope.zoneOwner.isEmpty else { throw ItemRepositoryError.invalidScope }
        try authorization.withWritePermission {
            try transaction(publishLocalChanges: false) {
                let key = "local-name-index:" + scope.storageKey
                let existing = try fetchOne("StateBlob", key: key)
                if existing?.value(forKey: "value") as? Data == bytes {
                    guard try revisionIndexInTransaction(scope) == expectedVersions else { throw ItemRepositoryError.staleLocalVersion }
                    return
                }
                // Read/dirty the serialization boundary before projecting items:
                // a concurrent writer between these operations then fails this save.
                try touchVaultBoundary(scope)
                guard try revisionIndexInTransaction(scope) == expectedVersions else { throw ItemRepositoryError.staleLocalVersion }
                let row = existing ?? NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
                row.setValue(key, forKey: "key")
                row.setValue(bytes, forKey: "value")
            }
        }
    }

    public func conflictedItemIDs(account: String, vaultID: UUID, database: String = "private",
                                   zoneOwner: String = "__defaultOwner__") throws -> Set<UUID> {
        try transaction {
            Set(try currentConflictScopesInTransaction(account: account).filter {
                $0.vaultID == vaultID && $0.database == database && $0.zoneOwner == zoneOwner
            }.map(\.itemID))
        }
    }

    public func items(account: String, vaultID: UUID, database: String = "private",
                      zoneOwner: String = "__defaultOwner__") throws -> [EncryptedItemVersion] {
        try transaction {
            let request = NSFetchRequest<NSManagedObject>(entityName: "Item")
            request.predicate = NSPredicate(format: "account == %@ AND vaultID == %@ AND database == %@ AND zoneOwner == %@",
                account, vaultID as NSUUID, database, zoneOwner)
            request.sortDescriptors = [NSSortDescriptor(key: "itemID", ascending: true)]
            return try context.fetch(request).map(decodeVersion)
        }
    }

    // Device-local encrypted health observations never enter Item or PendingMutation.
    private func localHealthPrefix(_ scope: VaultScope) -> String {
        "local-health:" + scope.storageKey + ":"
    }
    public func localHealthItem(_ scope: ItemScope) throws -> EncryptedItemVersion? {
        let key = localHealthPrefix(VaultScope(scope)) + scope.itemID.uuidString
        guard let bytes = try readBlob(entity: "StateBlob", key: key) else { return nil }
        return try? JSONDecoder().decode(EncryptedItemVersion.self, from: bytes)
    }
    public func discardLocalHealth(_ scope: ItemScope, expectedVersion: UUID,
                                   authorization: any RepositoryWritePermit) throws {
        try authorization.withWritePermission {
            try transaction(publishLocalChanges: false) {
                let key = localHealthPrefix(VaultScope(scope)) + scope.itemID.uuidString
                guard let row = try fetchOne("StateBlob", key: key),
                      let bytes = row.value(forKey: "value") as? Data,
                      let current = try? JSONDecoder().decode(EncryptedItemVersion.self, from: bytes),
                      current.versionID == expectedVersion else { throw ItemRepositoryError.staleLocalVersion }
                context.delete(row)
            }
        }
    }
    public func localHealthItems(scope: VaultScope) throws -> [EncryptedItemVersion] {
        try transaction {
            let request = NSFetchRequest<NSManagedObject>(entityName: "StateBlob")
            request.predicate = NSPredicate(format: "key BEGINSWITH %@", localHealthPrefix(scope))
            return try context.fetch(request).compactMap { row in
                guard let data = row.value(forKey: "value") as? Data,
                      let version = try? JSONDecoder().decode(EncryptedItemVersion.self, from: data),
                      VaultScope(version.scope) == scope, version.healthItemID != nil else { return nil }
                return version
            }
        }
    }
    public func saveLocalHealth(_ version: EncryptedItemVersion, expectedParent: UUID,
                               authorization: any RepositoryWritePermit) throws {
        try validate(version)
        try authorization.withWritePermission {
            try transaction(publishLocalChanges: false) {
                try touchVaultBoundary(VaultScope(version.scope))
                guard let parent = version.healthItemID else { throw ItemRepositoryError.invalidScope }
                let scope = version.scope
                let parentScope = ItemScope(account: scope.account, vaultID: scope.vaultID, itemID: parent,
                                            database: scope.database, zoneOwner: scope.zoneOwner)
                guard let row = try fetchOne("Item", key: parentScope.storageKey),
                      try decodeVersion(row).versionID == expectedParent else { throw ItemRepositoryError.staleLocalVersion }
                let key = localHealthPrefix(VaultScope(scope)) + scope.itemID.uuidString
                let existing = try fetchOne("StateBlob", key: key)
                let previous = (existing?.value(forKey: "value") as? Data).flatMap { try? JSONDecoder().decode(EncryptedItemVersion.self, from: $0) }
                guard previous?.versionID == version.baseVersionID else { throw ItemRepositoryError.staleLocalVersion }
                let blob = existing ?? NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
                blob.setValue(key, forKey: "key")
                blob.setValue(try JSONEncoder().encode(version), forKey: "value")
            }
        }
    }

    #if DEBUG
    /// Caller holds the account's sync lease and has confirmed revocation.
    /// This deliberately resets only the isolated V3 database, never legacy stores.
    public func debugClearEnrollmentStore(authorization: any RepositoryWritePermit) throws {

        try authorization.withWritePermission {
            try transaction {
                guard try context.count(for: NSFetchRequest<NSFetchRequestResult>(entityName: "PendingMutation")) == 0,
                      try context.count(for: NSFetchRequest<NSFetchRequestResult>(entityName: "ContentBranch")) == 0 else {
                    throw ItemRepositoryError.pendingLocalChanges
                }
                for entity in container.managedObjectModel.entities {
                    guard let name = entity.name else { continue }
                    for row in try context.fetch(NSFetchRequest<NSManagedObject>(entityName: name)) { context.delete(row) }
                }
            }
        }
    }
    #endif

    public func pendingMutations(account: String) throws -> [PendingItemMutation] {
        try transaction {
            let request = NSFetchRequest<NSManagedObject>(entityName: "PendingMutation")
            request.predicate = NSPredicate(format: "account == %@", account)
            request.sortDescriptors = [NSSortDescriptor(key: "sequence", ascending: true), NSSortDescriptor(key: "mutationID", ascending: true)]
            return try context.fetch(request).map { value in
                guard let id = value.value(forKey: "mutationID") as? UUID,
                      let created = value.value(forKey: "createdAt") as? Date,
                      let sequence = value.value(forKey: "sequence") as? Int64 else { throw ItemRepositoryError.corruptStore }
                return PendingItemMutation(id: id, version: try decodeVersion(value), createdAt: created, sequence: sequence)
            }
        }
    }

    public func pendingScopes(account: String, excludingConflicts: Bool = false) throws -> Set<ItemScope> {
        try transaction {
            let pending = try scopeProjection(entity: "PendingMutation", account: account)
            return excludingConflicts
                ? try pending.subtracting(currentConflictScopesInTransaction(account: account)) : pending
        }
    }

    public func conflictedScopes(account: String) throws -> Set<ItemScope> {
        try transaction { try currentConflictScopesInTransaction(account: account) }
    }

    /// Current branch metadata contains scopes without loading version ciphertext.
    private func currentConflictScopesInTransaction(account: String) throws -> Set<ItemScope> {
        let request = NSFetchRequest<NSDictionary>(entityName: "ContentBranch")
        request.resultType = .dictionaryResultType
        request.propertiesToFetch = ["value"]
        return Set(try context.fetch(request).compactMap { row in
            guard let bytes = row["value"] as? Data else { throw ItemRepositoryError.corruptStore }
            let state = try JSONDecoder().decode(ContentKeyState.self, from: bytes)
            return state.scope.account == account ? state.scope : nil
        })
    }

    /// Projects queue metadata first; large ciphertext is fetched only for selected
    /// heads. An oversized first item travels alone rather than starving forever.
    public func pendingMutationHeads(account: String, database: String, excluding: Set<ItemScope> = [],
                                     maximumAggregateCiphertextBytes: Int = 16 * 1024 * 1024) throws -> [PendingItemMutation] {
        guard maximumAggregateCiphertextBytes > 0 else { throw ItemRepositoryError.invalidScope }
        return try transaction {
            let request = NSFetchRequest<NSDictionary>(entityName: "PendingMutation")
            request.resultType = .dictionaryResultType
            request.propertiesToFetch = ["account", "vaultID", "itemID", "database", "zoneOwner", "mutationID", "ciphertextSize"]
            request.predicate = NSPredicate(format: "account == %@ AND database == %@", account, database)
            request.sortDescriptors = [NSSortDescriptor(key: "sequence", ascending: true), NSSortDescriptor(key: "mutationID", ascending: true)]
            var seen = Set<ItemScope>(), total = 0
            var result: [PendingItemMutation] = []
            for metadata in try context.fetch(request) {
                let scope = try projectedScope(metadata)
                guard !excluding.contains(scope), seen.insert(scope).inserted else { continue }
                guard let id = metadata["mutationID"] as? UUID,
                      let count = metadata["ciphertextSize"] as? NSNumber else { throw ItemRepositoryError.corruptStore }
                let size = count.intValue
                guard size > 0, size <= Self.maximumCiphertextBytes else { throw ItemRepositoryError.corruptStore }
                if !result.isEmpty, size > maximumAggregateCiphertextBytes - min(total, maximumAggregateCiphertextBytes) { break }
                let detail = NSFetchRequest<NSManagedObject>(entityName: "PendingMutation")
                detail.predicate = NSPredicate(format: "mutationID == %@", id as NSUUID)
                detail.fetchLimit = 1
                guard let row = try context.fetch(detail).first else { continue }
                result.append(try decodePending(row))
                total += size
                if total >= maximumAggregateCiphertextBytes || result.count == 100 { break }
            }
            return result
        }
    }

    public func pendingMutation(matching version: EncryptedItemVersion) throws -> PendingItemMutation? {
        try transaction {
            let request = NSFetchRequest<NSManagedObject>(entityName: "PendingMutation")
            request.predicate = NSPredicate(format: "key == %@ AND versionID == %@", version.scope.storageKey, version.versionID as NSUUID)
            request.fetchLimit = 1
            guard let row = try context.fetch(request).first else { return nil }
            let pending = try decodePending(row)
            return pending.version == version ? pending : nil
        }
    }

    public func oldestPendingMutation(scope: ItemScope) throws -> PendingItemMutation? {
        try transaction {
            let request = NSFetchRequest<NSManagedObject>(entityName: "PendingMutation")
            request.predicate = NSPredicate(format: "key == %@", scope.storageKey)
            request.sortDescriptors = [NSSortDescriptor(key: "sequence", ascending: true)]
            request.fetchLimit = 1
            return try context.fetch(request).first.map(decodePending)
        }
    }

    /// A local snapshot, never a claim that every cloud item is present. A pinned
    /// query generation prevents another process inserting a conflict between checks.
    public func itemsForPortableExport(account: String, vaultID: UUID, database: String = "private",
                                       zoneOwner: String = "__defaultOwner__") throws -> [EncryptedItemVersion] {
        try transaction {
            if supportsQueryGenerations { try context.setQueryGenerationFrom(.current) }
            let predicate = NSPredicate(format: "account == %@ AND vaultID == %@ AND database == %@ AND zoneOwner == %@",
                account, vaultID as NSUUID, database, zoneOwner)
            let conflicts = NSFetchRequest<NSManagedObject>(entityName: "ContentBranch")
            conflicts.predicate = NSPredicate(format: "vaultKey == %@", contentVaultKey(VaultScope(account: account, vaultID: vaultID, database: database, zoneOwner: zoneOwner)))
            conflicts.fetchLimit = 1
            guard try context.fetch(conflicts).isEmpty else { throw ItemRepositoryError.unresolvedConflict }
            let items = NSFetchRequest<NSManagedObject>(entityName: "Item")
            items.predicate = predicate
            items.sortDescriptors = [NSSortDescriptor(key: "itemID", ascending: true)]
            return try context.fetch(items).map(decodeVersion)
        }
    }

    /// Acknowledges exactly one submitted operation. A later working version is never overwritten.

    func acknowledgeInTransaction(mutationID: UUID, account: String, serverSystemFields: Data) throws {
        let request = NSFetchRequest<NSManagedObject>(entityName: "PendingMutation")
        request.predicate = NSPredicate(format: "account == %@ AND mutationID == %@", account, mutationID as NSUUID)
        guard let pending = try context.fetch(request).first else {
            if let receipt = try fetchOne("MutationReceipt", key: mutationID.uuidString),
               receipt.value(forKey: "account") as? String == account,
               let status = receipt.value(forKey: "status") as? String,
               [MutationDeliveryStatus.cloudConfirmed.rawValue, MutationDeliveryStatus.superseded.rawValue].contains(status) { return }
            throw ItemRepositoryError.missingMutation
        }
        let version = try decodeVersion(pending)
        if let predecessor = version.baseVersionID {
            let earlier = NSFetchRequest<NSManagedObject>(entityName: "PendingMutation")
            earlier.predicate = NSPredicate(format: "key == %@ AND versionID == %@", version.scope.storageKey, predecessor as NSUUID)
            earlier.fetchLimit = 1
            guard try context.fetch(earlier).isEmpty else { throw ItemRepositoryError.outOfOrderAcknowledgement }
        }
        guard let item = try fetchOne("Item", key: version.scope.storageKey) else { throw ItemRepositoryError.corruptStore }
        item.setValue(serverSystemFields, forKey: "serverSystemFields")
        item.setValue(try JSONEncoder().encode(version), forKey: "acceptedVersion")
        item.setValue(try JSONEncoder().encode(version), forKey: "publicationBaseVersion")
        guard let receipt = try fetchOne("MutationReceipt", key: mutationID.uuidString),
              receipt.value(forKey: "account") as? String == account else { throw ItemRepositoryError.corruptStore }
        receipt.setValue(MutationDeliveryStatus.cloudConfirmed.rawValue, forKey: "status")
        try finishPublicationInTransaction(mutationID, account: account, database: version.scope.database)
        context.delete(pending)
    }

    public func serverSystemFields(_ scope: ItemScope) throws -> Data? {
        try transaction { try fetchOne("Item", key: scope.storageKey)?.value(forKey: "serverSystemFields") as? Data }
    }

    public func acceptedVersion(_ scope: ItemScope) throws -> EncryptedItemVersion? {
        try transaction {
            guard let bytes = try fetchOne("Item", key: scope.storageKey)?.value(forKey: "acceptedVersion") as? Data else { return nil }
            return try JSONDecoder().decode(EncryptedItemVersion.self, from: bytes)
        }
    }

    public func saveEngineState(_ data: Data, account: String, database: String) throws {
        try saveBlob(data, entity: "StateBlob", key: blobKey(account, database))
    }

    public func mutationReceipt(id: UUID, account: String) throws -> MutationDeliveryReceipt? {
        try transaction {
            guard let value = try fetchOne("MutationReceipt", key: id.uuidString),
                  value.value(forKey: "account") as? String == account else { return nil }
            guard let bytes = value.value(forKey: "scope") as? Data,
                  let versionID = value.value(forKey: "versionID") as? UUID,
                  let rawStatus = value.value(forKey: "status") as? String,
                  let status = MutationDeliveryStatus(rawValue: rawStatus) else { throw ItemRepositoryError.corruptStore }
            return MutationDeliveryReceipt(id: id, scope: try JSONDecoder().decode(ItemScope.self, from: bytes), versionID: versionID, status: status)
        }
    }

    @discardableResult
    public func requestSync(account: String, database: String, reason: SyncRequestReason = .manual) throws -> DurableSyncRequest {
        guard !account.isEmpty, ["private", "shared"].contains(database) else { throw ItemRepositoryError.invalidScope }
        return try transaction { try updateSyncRequest(account: account, database: database, reason: reason) }
    }

    /// Setup reconciliation observes the latest request even if an existing
    /// engine already handled its transfer wake before discovering a new vault.
    public func latestSyncRequest(account: String, database: String) throws -> DurableSyncRequest? {
        try transaction {
            guard let value = try fetchOne("SyncRequest", key: blobKey(account, database)) else { return nil }
            guard let generation = value.value(forKey: "generation") as? Int64,
                  let raw = value.value(forKey: "reason") as? String,
                  let reason = SyncRequestReason(rawValue: raw) else { throw ItemRepositoryError.corruptStore }
            return DurableSyncRequest(account: account, database: database, generation: generation, reason: reason)
        }
    }

    public func pendingSyncRequests(account: String, database: String) throws -> [DurableSyncRequest] {
        try transaction {
            guard let value = try fetchOne("SyncRequest", key: blobKey(account, database)),
                  let generation = value.value(forKey: "generation") as? Int64,
                  let handled = value.value(forKey: "handledGeneration") as? Int64 else { return [] }
            guard generation > handled else { return [] }
            guard let raw = value.value(forKey: "reason") as? String,
                  let reason = SyncRequestReason(rawValue: raw) else { throw ItemRepositoryError.corruptStore }
            return [DurableSyncRequest(account: account, database: database, generation: generation, reason: reason)]
        }
    }

    /// Records that an owner handled this wake-up. It makes no claim about uploads;
    /// each caller observes its MutationDeliveryReceipt for cloud confirmation.
    public func markSyncRequestHandled(_ request: DurableSyncRequest) throws {
        try transaction {
            guard let value = try fetchOne("SyncRequest", key: blobKey(request.account, request.database)),
                  let current = value.value(forKey: "generation") as? Int64,
                  let handled = value.value(forKey: "handledGeneration") as? Int64,
                  request.generation <= current else { throw ItemRepositoryError.corruptStore }
            value.setValue(max(handled, request.generation), forKey: "handledGeneration")
        }
    }

    /// Native store notifications wake consumers in other processes. The initial yield
    /// guarantees startup reconciliation even if a notification preceded subscription.
    public func changes() -> AsyncStream<Void> {
        if changeObserver == nil {
            changeObserver = StoreChangeObserver(coordinator: container.persistentStoreCoordinator) { [weak self] in
                Task { await self?.publishChange() }
            }
        }
        let id = UUID()
        let (stream, continuation) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        changeStreams[id] = continuation
        continuation.onTermination = { [weak self] _ in Task { await self?.removeChangeStream(id) } }
        continuation.yield(())
        return stream
    }

    public func engineState(account: String, database: String) throws -> Data? {
        try readBlob(entity: "StateBlob", key: blobKey(account, database))
    }

    public func checkpointHistory(token: Data, consumer: String, account: String) throws {
        try saveBlob(JSONEncoder().encode(ConsumerHistoryCheckpoint(token: token, updatedAt: Date())), entity: "HistoryCheckpoint", key: blobKey(account, consumer))
    }

    public func historyCheckpoint(consumer: String, account: String) throws -> Data? {
        guard let bytes = try readBlob(entity: "HistoryCheckpoint", key: blobKey(account, consumer)),
              let checkpoint = try? JSONDecoder().decode(ConsumerHistoryCheckpoint.self, from: bytes),
              checkpoint.updatedAt.timeIntervalSinceNow > -30 * 86400 else { return nil }
        return checkpoint.token
    }

    /// Callers refresh scoped queries, then checkpoint the token after consuming the changes.
    /// Tokens are deliberately separate for each app-group consumer.
    public func history(after token: Data?) throws -> RepositoryHistoryBatch {
        try transaction {
            let decoded: NSPersistentHistoryToken?
            if let token {
                guard let value = try NSKeyedUnarchiver.unarchivedObject(ofClass: NSPersistentHistoryToken.self, from: token) else {
                    throw ItemRepositoryError.corruptStore
                }
                decoded = value
            } else { decoded = nil }
            let request = NSPersistentHistoryChangeRequest.fetchHistory(after: decoded)
            request.resultType = .transactionsOnly
            guard let result = try context.execute(request) as? NSPersistentHistoryResult,
                  let transactions = result.result as? [NSPersistentHistoryTransaction] else { throw ItemRepositoryError.corruptStore }
            let last = try transactions.last.map { try NSKeyedArchiver.archivedData(withRootObject: $0.token, requiringSecureCoding: true) }
            return RepositoryHistoryBatch(transactionCount: transactions.count, token: last ?? token)
        }
    }

    func transaction<T>(publishLocalChanges: Bool = true, _ body: () throws -> T) throws -> T {
        // performAndWait is synchronous: the actor cannot resume another operation
        // while this queue-confined closure runs, and no managed object escapes.
        for attempt in 0..<3 {
            do {
                let (value, changed) = try performTransaction {
                    let result = try body()
                    for row in Array(context.insertedObjects.union(context.updatedObjects)) where !row.isDeleted {
                        if let attributes = row.entity.attributesByName["vaultID"], attributes.name == "vaultID",
                           let account = row.value(forKey: "account") as? String,
                           let vault = row.value(forKey: "vaultID") as? UUID,
                           let database = row.value(forKey: "database") as? String,
                           let owner = row.value(forKey: "zoneOwner") as? String {
                            try touchVaultBoundary(VaultScope(account: account, vaultID: vault, database: database, zoneOwner: owner))
                        }
                    }
                    return result
                }
                if changed && publishLocalChanges { publishChange() }
                return value
            } catch {
                let native = error as NSError
                guard attempt < 2, native.domain == NSCocoaErrorDomain,
                      [NSManagedObjectMergeError, NSManagedObjectConstraintMergeError, NSPersistentStoreSaveConflictsError].contains(native.code) else { throw error }
                // A shared SyncRequest row may contend even for independent items.
                // Rollback/reset and rerun every CAS check; never merge secret edits.
            }
        }
        throw ItemRepositoryError.corruptStore
    }

    private func performTransaction<T>(_ body: () throws -> T) throws -> (T, Bool) {
        try withoutActuallyEscaping(body) { operation in
            nonisolated(unsafe) let synchronousOperation = operation
            return try context.performAndWait {
                context.reset()
                if supportsQueryGenerations { try context.setQueryGenerationFrom(nil) }
                var attemptedSave = false
                do {
                    try journalReadCache.begin(in: context, persistent: supportsQueryGenerations)
                    let result = try synchronousOperation()
                    let changed = context.hasChanges
                    if changed { attemptedSave = true; try context.save() }
                    return (result, changed)
                } catch {
                    let changed = attemptedSave || context.hasChanges
                    context.rollback()
                    // A rejected CAS/read has not changed any cached data.
                    // Preserve warm projections; invalidating them here turns
                    // normal competing sync transitions into full journal scans.
                    if changed { journalReadCache.reset() }
                    throw error
                }
            }
        }
    }

    private func highestPendingSequence() throws -> Int64 {
        let request = NSFetchRequest<NSDictionary>(entityName: "PendingMutation")
        request.resultType = .dictionaryResultType
        request.propertiesToFetch = ["sequence"]
        request.sortDescriptors = [NSSortDescriptor(key: "sequence", ascending: false)]
        request.fetchLimit = 1
        let persistedLast = (try context.fetch(request).first?["sequence"] as? NSNumber)?.int64Value ?? 0
        // Dictionary projections exclude unsaved inserts. Atomic batch creation
        // must reserve each subsequent sequence from the in-flight transaction too.
        let stagedLast = context.insertedObjects.lazy.filter { $0.entity.name == "PendingMutation" }
            .compactMap { ($0.value(forKey: "sequence") as? NSNumber)?.int64Value }.max() ?? 0
        return max(persistedLast, stagedLast)
    }

    func insertPending(_ version: EncryptedItemVersion, status: MutationDeliveryStatus,
                               reservedSequence: Int64? = nil, dependencies: Set<SyncDependency> = []) throws -> PendingItemMutation {
        let sequence: Int64
        if let reservedSequence { sequence = reservedSequence }
        else {
            let last = try highestPendingSequence()
            guard last < Int64.max else { throw ItemRepositoryError.corruptStore }
            sequence = last + 1
        }
        let pending = NSEntityDescription.insertNewObject(forEntityName: "PendingMutation", into: context)
        encode(version, into: pending)
        let id = UUID(), date = Date()
        pending.setValue(id, forKey: "mutationID")
        pending.setValue(date, forKey: "createdAt")
        pending.setValue(sequence, forKey: "sequence")
        let receipt = NSEntityDescription.insertNewObject(forEntityName: "MutationReceipt", into: context)
        receipt.setValue(id.uuidString, forKey: "key")
        receipt.setValue(id, forKey: "mutationID")
        receipt.setValue(version.scope.account, forKey: "account")
        receipt.setValue(version.scope.storageKey, forKey: "scopeKey")
        receipt.setValue(try JSONEncoder().encode(version.scope), forKey: "scope")
        receipt.setValue(version.versionID, forKey: "versionID")
        receipt.setValue(status.rawValue, forKey: "status")
        var operation = SyncOperation(id: id, account: version.scope.account, database: version.scope.database,
            vaultID: version.scope.vaultID, zoneOwner: version.scope.zoneOwner, kind: .publishItem, dependencies: dependencies, now: date)
        if status == .conflict { operation.state = .needsAttention; operation.failure = .conflict }
        _ = try enqueueInTransaction(operation)
        _ = try updateSyncRequest(account: version.scope.account, database: version.scope.database, reason: .localSave)
        return PendingItemMutation(id: id, version: version, createdAt: date, sequence: sequence)
    }

    func supersedePending(scope: ItemScope) throws {
        let request = NSFetchRequest<NSManagedObject>(entityName: "PendingMutation")
        request.predicate = NSPredicate(format: "key == %@", scope.storageKey)
        request.includesPropertyValues = false
        for pending in try context.fetch(request) {
            guard let id = pending.value(forKey: "mutationID") as? UUID,
                  let receipt = try fetchOne("MutationReceipt", key: id.uuidString) else { throw ItemRepositoryError.corruptStore }
            receipt.setValue(MutationDeliveryStatus.superseded.rawValue, forKey: "status")
            try finishPublicationInTransaction(id, account: scope.account, database: scope.database, confirmed: false)
            context.delete(pending)
        }
    }

    private func updateSyncRequest(account: String, database: String, reason: SyncRequestReason) throws -> DurableSyncRequest {
        let key = blobKey(account, database)
        let row = try fetchOne("SyncRequest", key: key) ?? NSEntityDescription.insertNewObject(forEntityName: "SyncRequest", into: context)
        let previous = row.value(forKey: "generation") as? Int64 ?? 0
        guard previous < Int64.max else { throw ItemRepositoryError.corruptStore }
        row.setValue(key, forKey: "key")
        row.setValue(account, forKey: "account")
        row.setValue(database, forKey: "database")
        row.setValue(previous + 1, forKey: "generation")
        if row.value(forKey: "handledGeneration") == nil { row.setValue(Int64(0), forKey: "handledGeneration") }
        row.setValue(reason.rawValue, forKey: "reason")
        let request = DurableSyncRequest(account: account, database: database, generation: previous + 1, reason: reason)
        // A wake is a generation hint, not an independent network job. Replacing
        // this row changes its revision so a running older request cannot finish it.
        let hash = Array(SHA256.hash(data: Data(("reconcile:" + key).utf8)).prefix(16))
        let id = UUID(uuid: (hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
            hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]))
        var operation = SyncOperation(id: id, account: account, database: database, kind: .reconcile,
            payload: try JSONEncoder().encode(request))
        if let previous: SyncOperation = try journalValue("SyncOperation", key: journalKey(account, database, id.uuidString)),
           let earliest = previous.retryNotBefore, earliest > Date() {
            operation.state = .retryScheduled; operation.failure = previous.failure
            operation.nextAttempt = max(previous.nextAttempt ?? earliest, earliest)
            operation.retryNotBefore = earliest; operation.attempts = previous.attempts
            operation.retryAttempts = previous.retryAttempts
        }
        try writeJournal(operation, entity: "SyncOperation", key: journalKey(account, database, id.uuidString))
        return request
    }

    private func publishChange() { for continuation in changeStreams.values { continuation.yield(()) } }
    private func removeChangeStream(_ id: UUID) { changeStreams.removeValue(forKey: id) }

    func validate(_ version: EncryptedItemVersion) throws {
        guard !version.scope.account.isEmpty, ["private", "shared"].contains(version.scope.database),
              !version.scope.zoneOwner.isEmpty else { throw ItemRepositoryError.invalidScope }
        guard !version.ciphertext.isEmpty else { throw ItemRepositoryError.emptyCiphertext }
        guard version.generation > 0, version.generation <= UInt64(Int64.max) else { throw ItemRepositoryError.invalidGeneration }
        guard version.ciphertext.count <= Self.maximumCiphertextBytes else { throw ItemRepositoryError.oversizedCiphertext }
    }

    func fetchOne(_ entity: String, key: String) throws -> NSManagedObject? {
        let request = NSFetchRequest<NSManagedObject>(entityName: entity)
        request.predicate = NSPredicate(format: "key == %@", key)
        request.fetchLimit = 1
        return try context.fetch(request).first
    }

    func encode(_ version: EncryptedItemVersion, into object: NSManagedObject) {
        object.setValue(version.scope.storageKey, forKey: "key")
        object.setValue(version.scope.account, forKey: "account")
        object.setValue(version.scope.vaultID, forKey: "vaultID")
        object.setValue(version.scope.itemID, forKey: "itemID")
        object.setValue(version.scope.database, forKey: "database")
        object.setValue(version.scope.zoneOwner, forKey: "zoneOwner")
        object.setValue(version.versionID, forKey: "versionID")
        object.setValue(version.baseVersionID, forKey: "baseVersionID")
        object.setValue(version.ciphertext, forKey: "ciphertext")
        object.setValue(version.healthItemID, forKey: "healthItemID")
        object.setValue(version.isTombstone, forKey: "isTombstone")
        object.setValue(String(version.generation), forKey: "generation")
        object.setValue(Int64(version.ciphertext.count), forKey: "ciphertextSize")
    }

    func decodeVersion(_ object: NSManagedObject) throws -> EncryptedItemVersion {
        guard let account = object.value(forKey: "account") as? String,
              let vault = object.value(forKey: "vaultID") as? UUID,
              let item = object.value(forKey: "itemID") as? UUID,
              let database = object.value(forKey: "database") as? String,
              let owner = object.value(forKey: "zoneOwner") as? String,
              let version = object.value(forKey: "versionID") as? UUID,
              let ciphertext = object.value(forKey: "ciphertext") as? Data,
              let rawGeneration = object.value(forKey: "generation") as? String,
              let generation = UInt64(rawGeneration),
              let tombstone = object.value(forKey: "isTombstone") as? Bool else { throw ItemRepositoryError.corruptStore }
        return EncryptedItemVersion(scope: ItemScope(account: account, vaultID: vault, itemID: item, database: database, zoneOwner: owner),
            versionID: version, baseVersionID: object.value(forKey: "baseVersionID") as? UUID,
            ciphertext: ciphertext, isTombstone: tombstone, generation: generation, healthItemID: object.value(forKey: "healthItemID") as? UUID)
    }

    func blobKey(_ account: String, _ name: String) -> String {
        Data(account.utf8).base64EncodedString() + ":" + Data(name.utf8).base64EncodedString()
    }

    private func decodePending(_ row: NSManagedObject) throws -> PendingItemMutation {
        guard let id = row.value(forKey: "mutationID") as? UUID,
              let created = row.value(forKey: "createdAt") as? Date,
              let sequence = row.value(forKey: "sequence") as? Int64 else { throw ItemRepositoryError.corruptStore }
        return PendingItemMutation(id: id, version: try decodeVersion(row), createdAt: created, sequence: sequence)
    }

    private func scopeProjection(entity: String, account: String) throws -> Set<ItemScope> {
        let request = NSFetchRequest<NSDictionary>(entityName: entity)
        request.resultType = .dictionaryResultType
        request.returnsDistinctResults = true
        request.propertiesToFetch = ["account", "vaultID", "itemID", "database", "zoneOwner"]
        request.predicate = NSPredicate(format: "account == %@", account)
        return Set(try context.fetch(request).map(projectedScope))
    }

    private func projectedScope(_ row: NSDictionary) throws -> ItemScope {
        guard let account = row["account"] as? String, let vault = row["vaultID"] as? UUID,
              let item = row["itemID"] as? UUID, let database = row["database"] as? String,
              let owner = row["zoneOwner"] as? String else { throw ItemRepositoryError.corruptStore }
        return ItemScope(account: account, vaultID: vault, itemID: item, database: database, zoneOwner: owner)
    }

    private func saveBlob(_ data: Data, entity: String, key: String) throws {
        try transaction {
            let value = try fetchOne(entity, key: key) ?? NSEntityDescription.insertNewObject(forEntityName: entity, into: context)
            value.setValue(key, forKey: "key")
            value.setValue(data, forKey: "value")
        }
    }

    private func readBlob(entity: String, key: String) throws -> Data? {
        try transaction { try fetchOne(entity, key: key)?.value(forKey: "value") as? Data }
    }
}
