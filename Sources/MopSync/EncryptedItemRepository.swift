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
    private let context: NSManagedObjectContext
    private let supportsQueryGenerations: Bool
    private var changeObserver: StoreChangeObserver?
    private var changeStreams: [UUID: AsyncStream<Void>.Continuation] = [:]

    public init(storeURL: URL, inMemory: Bool = false) throws {
        supportsQueryGenerations = !inMemory
        container = NSPersistentContainer(name: "MopEncryptedItems", managedObjectModel: RepositoryModel.make())
        var options: [AnyHashable: Any] = [
            NSPersistentHistoryTrackingKey: true,
            NSPersistentStoreRemoteChangeNotificationPostOptionKey: true,
            NSMigratePersistentStoresAutomaticallyOption: true,
            NSInferMappingModelAutomaticallyOption: true
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

    /// Initializes only an entirely absent vault. The signed control bytes and all
    /// initial ciphertext/outbox rows become visible together at the SQLite commit.
    /// Exact retries return the creation receipt, never replacing later edits.
    public func initializeVault(scope: VaultScope, versions: [EncryptedItemVersion],
                                membershipState: Data, setupID: String,
                                authorization: any RepositoryWritePermit) throws -> VaultInitializationReceipt {
        guard !versions.isEmpty, !membershipState.isEmpty, !setupID.isEmpty,
              membershipState.count <= Self.maximumCiphertextBytes,
              Set(versions.map { $0.scope.itemID }).count == versions.count else {
            throw ItemRepositoryError.invalidInitialization
        }
        for version in versions {
            try validate(version)
            guard VaultScope(version.scope) == scope, version.generation == 1,
                  version.baseVersionID == nil else { throw ItemRepositoryError.invalidInitialization }
        }
        let ordered = versions.sorted { $0.scope.itemID.uuidString < $1.scope.itemID.uuidString }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        // Hash each bounded input separately, so initialization does not duplicate
        // the complete vault into one large serialized buffer.
        var hash = SHA256()
        hash.update(data: Data("MopVaultInitialization1".utf8))
        hash.update(data: Data(SHA256.hash(data: try encoder.encode(scope))))
        hash.update(data: Data(SHA256.hash(data: Data(setupID.utf8))))
        hash.update(data: Data(SHA256.hash(data: membershipState)))
        for version in ordered { hash.update(data: Data(SHA256.hash(data: try encoder.encode(version)))) }
        let digest = Data(hash.finalize())
        return try authorization.withWritePermission {
            try transaction {
                if let boundary = try fetchOne("VaultBoundary", key: scope.storageKey) {
                    guard let bytes = boundary.value(forKey: "initialization") as? Data else { throw ItemRepositoryError.existingVault }
                    let receipt = try JSONDecoder().decode(VaultInitializationReceipt.self, from: bytes)
                    guard receipt.scope == scope, receipt.setupID == setupID,
                          receipt.inputDigest == digest, receipt.membershipState == membershipState else {
                        throw ItemRepositoryError.initializationMismatch
                    }
                    return receipt
                }
                // Also refuse pre-boundary stores, and any orphaned retained data.
                for entity in ["Item", "PendingMutation", "Conflict"] {
                    let request = NSFetchRequest<NSManagedObject>(entityName: entity)
                    request.fetchLimit = 1
                    request.predicate = NSPredicate(format: "account == %@ AND vaultID == %@ AND database == %@ AND zoneOwner == %@",
                        scope.account, scope.vaultID as NSUUID, scope.database, scope.zoneOwner)
                    guard try context.fetch(request).isEmpty else { throw ItemRepositoryError.existingVault }
                }
                let receipts = NSFetchRequest<NSManagedObject>(entityName: "MutationReceipt")
                receipts.fetchLimit = 1
                receipts.predicate = NSPredicate(format: "scopeKey BEGINSWITH %@", scope.storageKey + ":")
                guard try context.fetch(receipts).isEmpty else { throw ItemRepositoryError.existingVault }
                try touchVaultBoundary(scope)
                var ids: [UUID] = []
                let lastSequence = try highestPendingSequence()
                guard UInt64(ordered.count) <= UInt64(Int64.max - lastSequence) else { throw ItemRepositoryError.corruptStore }
                for (offset, version) in ordered.enumerated() {
                    let item = NSEntityDescription.insertNewObject(forEntityName: "Item", into: context)
                    encode(version, into: item)
                    ids.append(try insertPending(version, status: .queued, reservedSequence: lastSequence + Int64(offset) + 1).id)
                }
                let receipt = VaultInitializationReceipt(scope: scope, setupID: setupID,
                    membershipState: membershipState, inputDigest: digest, mutationIDs: ids)
                guard let boundary = try fetchOne("VaultBoundary", key: scope.storageKey) else { throw ItemRepositoryError.corruptStore }
                boundary.setValue(try encoder.encode(receipt), forKey: "initialization")
                return receipt
            }
        }
    }

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
    private func touchVaultBoundary(_ scope: VaultScope) throws {
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
        let key = "provisioning:" + state.binding.scope.storageKey
        let row = try fetchOne("StateBlob", key: key) ?? NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
        row.setValue(key, forKey: "key")
        row.setValue(try JSONEncoder().encode(state), forKey: "value")
    }

    /// Registers an existing private CloudKit vault only after the domain has
    /// authenticated enrollment and independently checked the admitted metadata.
    /// It never publishes a new zone or fabricates local item mutations.
    public func initializeEnrolledVault(scope: VaultScope, metadata: EncryptedItemVersion,
        metadataSystemFields: Data? = nil, expectedItemCount: Int? = nil, membershipState: Data, currentControl: Data,
        setupID: String, authorization: any RepositoryWritePermit) throws -> VaultInitializationReceipt {
        try validate(metadata)
        guard scope.database == "private", scope.zoneOwner == "__defaultOwner__",
              VaultScope(metadata.scope) == scope,
              metadata.scope.itemID == UUID(uuidString: "00000000-0000-0000-0000-000000000001"),
              !membershipState.isEmpty, !currentControl.isEmpty, !setupID.isEmpty,
              membershipState.count <= 512 * 1024, currentControl.count <= 512 * 1024 else { throw ItemRepositoryError.invalidInitialization }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        var hash = SHA256()
        hash.update(data: Data("mop-enrolled-vault-1".utf8)); hash.update(data: try encoder.encode(scope))
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
                for entity in ["Item", "PendingMutation", "Conflict", "AdmissionItem"] {
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
                let item = NSEntityDescription.insertNewObject(forEntityName: "Item", into: context)
                encode(metadata, into: item)
                item.setValue(try encoder.encode(metadata), forKey: "acceptedVersion")
                item.setValue(try encoder.encode(metadata), forKey: "publicationBaseVersion")
                item.setValue(metadataSystemFields, forKey: "serverSystemFields")
                let receipt = VaultInitializationReceipt(scope: scope, setupID: setupID,
                    membershipState: membershipState, inputDigest: digest, mutationIDs: [])
                guard let boundary = try fetchOne("VaultBoundary", key: scope.storageKey) else { throw ItemRepositoryError.corruptStore }
                boundary.setValue(try encoder.encode(receipt), forKey: "initialization")
                if let expectedItemCount, expectedItemCount > 0 {
                    let progress = NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
                    progress.setValue("initial-download:" + scope.storageKey, forKey: "key")
                    progress.setValue(try encoder.encode(expectedItemCount), forKey: "value")
                }
                let rootDigest = SHA256.hash(data: membershipState).map { String(format: "%02x", $0) }.joined()
                let binding = VaultProvisioningBinding(scope: scope,
                    address: VaultCloudAddress(vaultID: scope.vaultID, zoneName: "MopItems-" + scope.vaultID.uuidString, ownerName: scope.zoneOwner),
                    setupID: setupID, controlDigest: rootDigest)
                try writeProvisioning(VaultProvisioningState(binding: binding, controlBytes: currentControl,
                    phase: .controlConfirmed, headSystemFields: nil))
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

    public func admission(scope: VaultScope) throws -> VaultAdmissionPlan? {
        try transaction { try admissionInTransaction(scope) }
    }
    private func admissionInTransaction(_ scope: VaultScope) throws -> VaultAdmissionPlan? {
        guard let bytes = try fetchOne("StateBlob", key: "admission:" + scope.storageKey)?.value(forKey: "value") as? Data else { return nil }
        let plan = try JSONDecoder().decode(VaultAdmissionPlan.self, from: bytes)
        guard plan.scope == scope else { throw ItemRepositoryError.corruptStore }
        return plan
    }
    private func assertNoAdmission(_ scope: VaultScope) throws {
        guard try admissionInTransaction(scope)?.phase != .prepared else { throw ItemRepositoryError.pendingLocalChanges }
    }
    private func writeAdmission(_ plan: VaultAdmissionPlan) throws {
        let key = "admission:" + plan.scope.storageKey
        let row = try fetchOne("StateBlob", key: key) ?? NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
        row.setValue(key, forKey: "key"); row.setValue(try JSONEncoder().encode(plan), forKey: "value")
    }
    /// Caller must own and quiesce the database uploader. This durable journal
    /// blocks competing local edits until exact cloud head readback and activation.
    public func prepareAdmission(scope: VaultScope, requestID: UUID, approval: Data,
        parentControl: Data, successorControl: Data, expectedVersions: [UUID: UUID],
        versions: [EncryptedItemVersion], authorization: any RepositoryWritePermit) throws -> VaultAdmissionPlan {
        guard !approval.isEmpty, approval.count <= 512 * 1024,
              !parentControl.isEmpty, parentControl.count <= 512 * 1024,
              !successorControl.isEmpty, successorControl.count <= 512 * 1024,
              versions.count == expectedVersions.count, !versions.isEmpty,
              Set(versions.map { $0.scope.itemID }).count == versions.count else { throw ItemRepositoryError.invalidInitialization }
        for version in versions {
            try validate(version)
            guard VaultScope(version.scope) == scope, version.baseVersionID == expectedVersions[version.scope.itemID] else {
                throw ItemRepositoryError.invalidInitialization
            }
        }
        let plan = VaultAdmissionPlan(scope: scope, requestID: requestID, approval: approval,
            parentControl: parentControl, successorControl: successorControl, expectedVersions: expectedVersions, phase: .prepared)
        return try authorization.withWritePermission {
            try transaction {
                if let existing = try admissionInTransaction(scope), existing.phase == .prepared || existing.requestID == requestID {
                    guard existing.requestID == requestID, existing.approval == approval else { throw ItemRepositoryError.pendingLocalChanges }
                    return existing
                }
                try touchVaultBoundary(scope)
                guard try revisionIndexInTransaction(scope) == expectedVersions,
                      let state = try provisioningInTransaction(scope), state.phase == .controlConfirmed,
                      state.controlBytes == parentControl else { throw ItemRepositoryError.staleLocalVersion }
                for entity in ["PendingMutation", "Conflict"] {
                    let request = NSFetchRequest<NSManagedObject>(entityName: entity)
                    request.predicate = NSPredicate(format: "account == %@ AND vaultID == %@ AND database == %@ AND zoneOwner == %@",
                        scope.account, scope.vaultID as NSUUID, scope.database, scope.zoneOwner)
                    request.fetchLimit = 1
                    guard try context.fetch(request).isEmpty else { throw ItemRepositoryError.pendingLocalChanges }
                }
                for version in versions {
                    guard let current = try fetchOne("Item", key: version.scope.storageKey).map(decodeVersion),
                          current.generation < UInt64(Int64.max), version.generation == current.generation + 1 else { throw ItemRepositoryError.invalidGeneration }
                    let staged = try fetchOne("AdmissionItem", key: version.scope.storageKey)
                        ?? NSEntityDescription.insertNewObject(forEntityName: "AdmissionItem", into: context)
                    encode(version, into: staged)
                }
                try writeAdmission(plan)
                _ = try updateSyncRequest(account: scope.account, database: scope.database, reason: .manual)
                return plan
            }
        }
    }
    /// Only after independently verified exact cloud head readback and durable
    /// membership checkpoint. Every staged item/outbox row activates atomically.
    public func completeAdmission(_ expected: VaultAdmissionPlan, headSystemFields: Data,
                                   authorization: any RepositoryWritePermit) throws -> VaultAdmissionPlan {
        try authorization.withWritePermission {
            try transaction {
                guard let current = try admissionInTransaction(expected.scope),
                      current.requestID == expected.requestID, current.approval == expected.approval else { throw ItemRepositoryError.staleLocalVersion }
                if current.phase == .complete { return current }
                guard current == expected else { throw ItemRepositoryError.staleLocalVersion }
                try touchVaultBoundary(current.scope)
                guard try revisionIndexInTransaction(current.scope) == current.expectedVersions,
                      let state = try provisioningInTransaction(current.scope), state.phase == .controlConfirmed,
                      state.controlBytes == current.parentControl else { throw ItemRepositoryError.staleLocalVersion }
                let lastSequence = try highestPendingSequence()
                guard UInt64(current.expectedVersions.count) <= UInt64(Int64.max - lastSequence) else { throw ItemRepositoryError.corruptStore }
                let first = lastSequence + 1
                var offset: Int64 = 0
                for id in current.expectedVersions.keys.sorted(by: { $0.uuidString < $1.uuidString }) {
                    let scope = ItemScope(account: current.scope.account, vaultID: current.scope.vaultID, itemID: id,
                        database: current.scope.database, zoneOwner: current.scope.zoneOwner)
                    guard let staged = try fetchOne("AdmissionItem", key: scope.storageKey),
                          let item = try fetchOne("Item", key: scope.storageKey) else { throw ItemRepositoryError.corruptStore }
                    let version = try decodeVersion(staged)
                    encode(version, into: item)
                    _ = try insertPending(version, status: .queued, reservedSequence: first + offset)
                    offset += 1
                    context.delete(staged)
                }
                try writeProvisioning(VaultProvisioningState(binding: state.binding, controlBytes: current.successorControl,
                    phase: .controlConfirmed, headSystemFields: headSystemFields))
                let done = VaultAdmissionPlan(scope: current.scope, requestID: current.requestID, approval: current.approval,
                    parentControl: current.parentControl, successorControl: current.successorControl,
                    expectedVersions: current.expectedVersions, phase: .complete)
                try writeAdmission(done)
                return done
            }
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
            }
        }
    }

    public func commitLocalMutation(_ version: EncryptedItemVersion, expectedHealthParentVersion: UUID? = nil) throws -> PendingItemMutation {
        try validate(version)
        return try transaction {
            try assertNoAdmission(VaultScope(version.scope))
            try touchVaultBoundary(VaultScope(version.scope))
            if let expectedHealthParentVersion {
                guard let parent = version.healthItemID else { throw ItemRepositoryError.staleLocalVersion }
                let parentScope = ItemScope(account: version.scope.account, vaultID: version.scope.vaultID, itemID: parent,
                    database: version.scope.database, zoneOwner: version.scope.zoneOwner)
                guard let row = try fetchOne("Item", key: parentScope.storageKey),
                      try decodeVersion(row).versionID == expectedHealthParentVersion else { throw ItemRepositoryError.staleLocalVersion }
            }
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
            let conflict = try fetchOne("Conflict", key: version.scope.storageKey)
            if let conflict {
                conflict.setValue(try JSONEncoder().encode(version), forKey: "local")
                conflict.setValue(UUID(), forKey: "conflictID")
            }
            return try insertPending(version, status: conflict == nil ? .queued : .conflict)
        }
    }

    public func commitLocalMutation(_ version: EncryptedItemVersion,
                                    authorization: any RepositoryWritePermit, expectedHealthParentVersion: UUID? = nil) throws -> PendingItemMutation {
        try authorization.withWritePermission { try commitLocalMutation(version, expectedHealthParentVersion: expectedHealthParentVersion) }
    }

    /// Additive membership catch-up preserves the latest local plaintext while
    /// replacing obsolete recipient wrappers. The caller holds the publication
    /// lease with its uploader stopped; prior receipts become superseded, never
    /// falsely cloud-confirmed. Conflicts still require explicit resolution.
    public func commitMembershipCatchUp(_ version: EncryptedItemVersion,
                                       authorization: any RepositoryWritePermit) throws -> PendingItemMutation {
        try validate(version)
        return try authorization.withWritePermission {
            try transaction {
                try assertNoAdmission(VaultScope(version.scope))
                try touchVaultBoundary(VaultScope(version.scope))
                guard let item = try fetchOne("Item", key: version.scope.storageKey) else { throw ItemRepositoryError.staleLocalVersion }
                let previous = try decodeVersion(item)
                guard previous.versionID == version.baseVersionID else { throw ItemRepositoryError.staleLocalVersion }
                guard previous.generation < UInt64(Int64.max), version.generation == previous.generation + 1,
                      previous.versionID != version.versionID else { throw ItemRepositoryError.invalidGeneration }
                guard try fetchOne("Conflict", key: version.scope.storageKey) == nil else { throw ItemRepositoryError.unresolvedConflict }
                try supersedePending(scope: version.scope)
                encode(version, into: item)
                return try insertPending(version, status: .queued)
            }
        }
    }

    public func item(_ scope: ItemScope) throws -> EncryptedItemVersion? {
        try transaction { try fetchOne("Item", key: scope.storageKey).map(decodeVersion) }
    }

    public func itemRevisionIndex(account: String, vaultID: UUID, database: String = "private",
                                   zoneOwner: String = "__defaultOwner__", includeHealth: Bool = false) throws -> [UUID: UUID] {
        try transaction { try revisionIndexInTransaction(VaultScope(account: account, vaultID: vaultID,
            database: database, zoneOwner: zoneOwner), includeHealth: includeHealth) }
    }

    public func healthRevisionIndex(scope: VaultScope) throws -> [UUID: UUID] {
        try transaction { try revisionIndexInTransaction(scope, onlyHealth: true) }
    }

    private func revisionIndexInTransaction(_ scope: VaultScope, includeHealth: Bool = true, onlyHealth: Bool = false) throws -> [UUID: UUID] {
        let request = NSFetchRequest<NSDictionary>(entityName: "Item")
        request.resultType = .dictionaryResultType
        request.propertiesToFetch = ["itemID", "versionID"]
        request.predicate = NSPredicate(format: "account == %@ AND vaultID == %@ AND database == %@ AND zoneOwner == %@",
            scope.account, scope.vaultID as NSUUID, scope.database, scope.zoneOwner)
        if onlyHealth { request.predicate = NSCompoundPredicate(andPredicateWithSubpredicates: [request.predicate!, NSPredicate(format: "healthItemID != nil")]) }
        if !includeHealth { request.predicate = NSCompoundPredicate(andPredicateWithSubpredicates: [request.predicate!, NSPredicate(format: "healthItemID == nil")]) }
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
        try transaction {
            let request = NSFetchRequest<NSManagedObject>(entityName: "StateBlob")
            request.predicate = NSPredicate(format: "key BEGINSWITH %@", "display-row:" + scope.storageKey + ":")
            return try context.fetch(request).compactMap { row in
                guard let bytes = row.value(forKey: "value") as? Data,
                      let value = try? JSONDecoder().decode(EncryptedDisplayCatalogRow.self, from: bytes),
                      row.value(forKey: "key") as? String == "display-row:" + scope.storageKey + ":" + value.itemID.uuidString else { return nil }
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
                let index = try revisionIndexInTransaction(scope, includeHealth: true)
                for value in rows {
                    guard index[value.itemID] == value.versionID else { throw ItemRepositoryError.staleLocalVersion }
                    guard !value.ciphertext.isEmpty, value.ciphertext.count <= 16 * 1024 * 1024 else { throw ItemRepositoryError.invalidScope }
                    let key = "display-row:" + scope.storageKey + ":" + value.itemID.uuidString
                    let row = try fetchOne("StateBlob", key: key) ?? NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
                    row.setValue(key, forKey: "key")
                    row.setValue(try JSONEncoder().encode(value), forKey: "value")
                }
                let request = NSFetchRequest<NSManagedObject>(entityName: "StateBlob")
                request.predicate = NSPredicate(format: "key BEGINSWITH %@", "display-row:" + scope.storageKey + ":")
                for row in try context.fetch(request) {
                    guard let key = row.value(forKey: "key") as? String,
                          let item = UUID(uuidString: String(key.suffix(36))),
                          index[item] != nil else { context.delete(row); continue }
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
                    guard try revisionIndexInTransaction(scope, includeHealth: false) == expectedVersions else { throw ItemRepositoryError.staleLocalVersion }
                    return
                }
                // Read/dirty the serialization boundary before projecting items:
                // a concurrent writer between these operations then fails this save.
                try touchVaultBoundary(scope)
                guard try revisionIndexInTransaction(scope, includeHealth: false) == expectedVersions else { throw ItemRepositoryError.staleLocalVersion }
                let row = existing ?? NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
                row.setValue(key, forKey: "key")
                row.setValue(bytes, forKey: "value")
            }
        }
    }

    public func conflictedItemIDs(account: String, vaultID: UUID, database: String = "private",
                                   zoneOwner: String = "__defaultOwner__") throws -> Set<UUID> {
        try transaction {
            let request = NSFetchRequest<NSDictionary>(entityName: "Conflict")
            request.resultType = .dictionaryResultType
            request.propertiesToFetch = ["itemID"]
            request.predicate = NSPredicate(format: "account == %@ AND vaultID == %@ AND database == %@ AND zoneOwner == %@",
                account, vaultID as NSUUID, database, zoneOwner)
            return Set(try context.fetch(request).map { row in
                guard let id = row["itemID"] as? UUID else { throw ItemRepositoryError.corruptStore }
                return id
            })
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

    public func healthItems(account: String, vaultID: UUID, database: String = "private", zoneOwner: String = "__defaultOwner__") throws -> [EncryptedItemVersion] {
        try transaction {
            let request = NSFetchRequest<NSManagedObject>(entityName: "Item")
            request.predicate = NSPredicate(format: "account == %@ AND vaultID == %@ AND database == %@ AND zoneOwner == %@ AND healthItemID != nil", account, vaultID as NSUUID, database, zoneOwner)
            return try context.fetch(request).map(decodeVersion)
        }
    }

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
                ? try pending.subtracting(scopeProjection(entity: "Conflict", account: account)) : pending
        }
    }

    public func conflictedScopes(account: String) throws -> Set<ItemScope> {
        try transaction { try scopeProjection(entity: "Conflict", account: account) }
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
            let conflicts = NSFetchRequest<NSManagedObject>(entityName: "Conflict")
            conflicts.predicate = predicate
            conflicts.fetchLimit = 1
            guard try context.fetch(conflicts).isEmpty else { throw ItemRepositoryError.unresolvedConflict }
            let items = NSFetchRequest<NSManagedObject>(entityName: "Item")
            items.predicate = predicate
            items.sortDescriptors = [NSSortDescriptor(key: "itemID", ascending: true)]
            return try context.fetch(items).map(decodeVersion)
        }
    }

    /// Acknowledges exactly one submitted operation. A later working version is never overwritten.
    public func acknowledge(mutationID: UUID, account: String, serverSystemFields: Data) throws {
        try transaction {
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
            context.delete(pending)
        }
    }

    /// Caller must authenticate the remote envelope and membership before applying it.
    public func applyRemote(_ version: EncryptedItemVersion, serverSystemFields: Data) throws {
        try validate(version)
        try transaction {
            try assertNoAdmission(VaultScope(version.scope))
            try touchVaultBoundary(VaultScope(version.scope))
            let request = NSFetchRequest<NSManagedObject>(entityName: "PendingMutation")
            request.predicate = NSPredicate(format: "key == %@", version.scope.storageKey)
            request.fetchLimit = 1
            guard try context.fetch(request).isEmpty else { throw ItemRepositoryError.pendingLocalChanges }
            guard try fetchOne("Conflict", key: version.scope.storageKey) == nil else { throw ItemRepositoryError.unresolvedConflict }
            let existing = try fetchOne("Item", key: version.scope.storageKey)
            if let bytes = existing?.value(forKey: "acceptedVersion") as? Data {
                let accepted = try JSONDecoder().decode(EncryptedItemVersion.self, from: bytes)
                let superseded = try isSuperseded(version)
                guard version == accepted || !superseded else { throw ItemRepositoryError.remoteVersionConflict }
                let newer = version.generation > accepted.generation && version.versionID != accepted.versionID
                let immediateSuccessor = accepted.generation < UInt64.max && version.generation == accepted.generation + 1
                guard version == accepted || (newer && (!immediateSuccessor || version.baseVersionID == accepted.versionID)) else {
                    throw ItemRepositoryError.remoteVersionConflict
                }
            } else if existing != nil { throw ItemRepositoryError.corruptStore }
            else if try isSuperseded(version) { throw ItemRepositoryError.remoteVersionConflict }
            let item = existing ?? NSEntityDescription.insertNewObject(forEntityName: "Item", into: context)
            encode(version, into: item)
            item.setValue(serverSystemFields, forKey: "serverSystemFields")
            item.setValue(try JSONEncoder().encode(version), forKey: "acceptedVersion")
            item.setValue(try JSONEncoder().encode(version), forKey: "publicationBaseVersion")
        }
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

    /// Refresh metadata for an already accepted base without overwriting a local overlay.
    public func rememberAcceptedVersion(_ version: EncryptedItemVersion, serverSystemFields: Data) throws {
        try validate(version)
        try transaction {
            guard let item = try fetchOne("Item", key: version.scope.storageKey) else { throw ItemRepositoryError.staleLocalVersion }
            let bytes = (item.value(forKey: "publicationBaseVersion") as? Data) ?? (item.value(forKey: "acceptedVersion") as? Data)
            guard let bytes, try JSONDecoder().decode(EncryptedItemVersion.self, from: bytes) == version else {
                throw ItemRepositoryError.remoteVersionConflict
            }
            item.setValue(serverSystemFields, forKey: "serverSystemFields")
            item.setValue(try JSONEncoder().encode(version), forKey: "publicationBaseVersion")
        }
    }

    /// Preserve authenticated competing ciphertext before presenting any resolution UI.
    @discardableResult
    public func recordConflict(remote: EncryptedItemVersion, serverSystemFields: Data) throws -> EncryptedItemConflict {
        try validate(remote)
        return try transaction {
            guard let item = try fetchOne("Item", key: remote.scope.storageKey) else { throw ItemRepositoryError.staleLocalVersion }
            let local = try decodeVersion(item)
            let value = try fetchOne("Conflict", key: remote.scope.storageKey)
                ?? NSEntityDescription.insertNewObject(forEntityName: "Conflict", into: context)
            let id = value.value(forKey: "conflictID") as? UUID ?? UUID()
            value.setValue(remote.scope.storageKey, forKey: "key")
            value.setValue(remote.scope.account, forKey: "account")
            value.setValue(remote.scope.vaultID, forKey: "vaultID")
            value.setValue(remote.scope.itemID, forKey: "itemID")
            value.setValue(remote.scope.database, forKey: "database")
            value.setValue(remote.scope.zoneOwner, forKey: "zoneOwner")
            value.setValue(id, forKey: "conflictID")
            value.setValue(try JSONEncoder().encode(local), forKey: "local")
            value.setValue(try JSONEncoder().encode(remote), forKey: "remote")
            value.setValue(serverSystemFields, forKey: "serverSystemFields")
            item.setValue(serverSystemFields, forKey: "serverSystemFields")
            let receipts = NSFetchRequest<NSManagedObject>(entityName: "MutationReceipt")
            receipts.predicate = NSPredicate(format: "scopeKey == %@ AND status == %@", remote.scope.storageKey,
                MutationDeliveryStatus.queued.rawValue)
            for receipt in try context.fetch(receipts) { receipt.setValue(MutationDeliveryStatus.conflict.rawValue, forKey: "status") }
            return EncryptedItemConflict(id: id, local: local, remote: remote, serverSystemFields: serverSystemFields)
        }
    }

    public func conflicts(account: String) throws -> [EncryptedItemConflict] {
        try transaction {
            let request = NSFetchRequest<NSManagedObject>(entityName: "Conflict")
            request.predicate = NSPredicate(format: "account == %@", account)
            return try context.fetch(request).map(decodeConflict)
        }
    }

    public func conflict(_ scope: ItemScope) throws -> EncryptedItemConflict? {
        try transaction { try fetchOne("Conflict", key: scope.storageKey).map(decodeConflict) }
    }

    public func reviewedConflict(_ expected: EncryptedItemConflict) throws -> EncryptedItemConflict {
        try transaction {
            if supportsQueryGenerations { try context.setQueryGenerationFrom(.current) }
            let (_, conflict) = try checkedConflict(expected)
            return try decodeConflict(conflict)
        }
    }

    /// Low-level operation: caller must own the database publication lease and have
    /// quiesced its uploader. Production callers use CloudKitSyncAdapter's wrapper.
    /// This accepts the reviewed server state; it does not claim a new cloud write.
    public func resolveConflictUsingRemote(_ expected: EncryptedItemConflict,
                                           authorization: any RepositoryWritePermit) throws -> EncryptedItemVersion {
        try authorization.withWritePermission {
            try transaction {
                try assertNoAdmission(VaultScope(expected.local.scope))
                try touchVaultBoundary(VaultScope(expected.local.scope))
                let (item, conflict) = try checkedConflict(expected)
                if let bytes = item.value(forKey: "acceptedVersion") as? Data {
                    let accepted = try JSONDecoder().decode(EncryptedItemVersion.self, from: bytes)
                    guard expected.remote.generation >= accepted.generation else { throw ItemRepositoryError.remoteVersionConflict }
                }
                try supersedePending(scope: expected.local.scope)
                encode(expected.remote, into: item)
                item.setValue(try JSONEncoder().encode(expected.remote), forKey: "acceptedVersion")
                item.setValue(try JSONEncoder().encode(expected.remote), forKey: "publicationBaseVersion")
                item.setValue(expected.serverSystemFields, forKey: "serverSystemFields")
                context.delete(conflict)
                _ = try updateSyncRequest(account: expected.local.scope.account, database: expected.local.scope.database, reason: .manual)
                return expected.remote
            }
        }
    }

    /// A new signed resolution is based on the reviewed remote version, with a
    /// generation above both competing versions. Earlier saves are superseded,
    /// never falsely marked cloud-confirmed. The receipt returned here is queued.
    public func resolveConflict(_ expected: EncryptedItemConflict, with resolved: EncryptedItemVersion,
                                authorization: any RepositoryWritePermit) throws -> PendingItemMutation {
        try validate(resolved)
        return try authorization.withWritePermission {
            try transaction {
                try assertNoAdmission(VaultScope(expected.local.scope))
                try touchVaultBoundary(VaultScope(expected.local.scope))
                let (item, conflict) = try checkedConflict(expected)
                let highest = max(expected.local.generation, expected.remote.generation)
                guard highest < UInt64(Int64.max), resolved.generation == highest + 1,
                      resolved.scope == expected.local.scope,
                      resolved.baseVersionID == expected.remote.versionID,
                      resolved.versionID != expected.local.versionID,
                      resolved.versionID != expected.remote.versionID else { throw ItemRepositoryError.invalidGeneration }
                if let bytes = item.value(forKey: "acceptedVersion") as? Data {
                    guard try JSONDecoder().decode(EncryptedItemVersion.self, from: bytes).generation <= highest else {
                        throw ItemRepositoryError.staleConflict
                    }
                }
                try supersedePending(scope: expected.local.scope)
                encode(resolved, into: item)
                let acceptedBytes = item.value(forKey: "acceptedVersion") as? Data
                let accepted = try acceptedBytes.map { try JSONDecoder().decode(EncryptedItemVersion.self, from: $0) }
                if accepted == nil || expected.remote.generation >= accepted!.generation {
                    item.setValue(try JSONEncoder().encode(expected.remote), forKey: "acceptedVersion")
                }
                item.setValue(try JSONEncoder().encode(expected.remote), forKey: "publicationBaseVersion")
                item.setValue(expected.serverSystemFields, forKey: "serverSystemFields")
                context.delete(conflict)
                return try insertPending(resolved, status: .queued)
            }
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
        try saveBlob(token, entity: "HistoryCheckpoint", key: blobKey(account, consumer))
    }

    public func historyCheckpoint(consumer: String, account: String) throws -> Data? {
        try readBlob(entity: "HistoryCheckpoint", key: blobKey(account, consumer))
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

    private func transaction<T>(publishLocalChanges: Bool = true, _ body: () throws -> T) throws -> T {
        // performAndWait is synchronous: the actor cannot resume another operation
        // while this queue-confined closure runs, and no managed object escapes.
        for attempt in 0..<3 {
            do {
                let (value, changed) = try performTransaction(body)
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
                do {
                    let result = try synchronousOperation()
                    let changed = context.hasChanges
                    if changed { try context.save() }
                    return (result, changed)
                } catch {
                    context.rollback()
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

    private func insertPending(_ version: EncryptedItemVersion, status: MutationDeliveryStatus,
                               reservedSequence: Int64? = nil) throws -> PendingItemMutation {
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
        _ = try updateSyncRequest(account: version.scope.account, database: version.scope.database, reason: .localSave)
        return PendingItemMutation(id: id, version: version, createdAt: date, sequence: sequence)
    }

    private func decodeConflict(_ value: NSManagedObject) throws -> EncryptedItemConflict {
        guard let id = value.value(forKey: "conflictID") as? UUID,
              let local = value.value(forKey: "local") as? Data,
              let remote = value.value(forKey: "remote") as? Data,
              let fields = value.value(forKey: "serverSystemFields") as? Data else { throw ItemRepositoryError.corruptStore }
        return EncryptedItemConflict(id: id, local: try JSONDecoder().decode(EncryptedItemVersion.self, from: local),
            remote: try JSONDecoder().decode(EncryptedItemVersion.self, from: remote), serverSystemFields: fields)
    }

    private func checkedConflict(_ expected: EncryptedItemConflict) throws -> (NSManagedObject, NSManagedObject) {
        guard expected.local.scope == expected.remote.scope,
              let conflict = try fetchOne("Conflict", key: expected.local.scope.storageKey),
              try decodeConflict(conflict) == expected,
              let item = try fetchOne("Item", key: expected.local.scope.storageKey),
              try decodeVersion(item) == expected.local,
              item.value(forKey: "serverSystemFields") as? Data == expected.serverSystemFields else { throw ItemRepositoryError.staleConflict }
        return (item, conflict)
    }

    private func supersedePending(scope: ItemScope) throws {
        let request = NSFetchRequest<NSManagedObject>(entityName: "PendingMutation")
        request.predicate = NSPredicate(format: "key == %@", scope.storageKey)
        request.includesPropertyValues = false
        for pending in try context.fetch(request) {
            guard let id = pending.value(forKey: "mutationID") as? UUID,
                  let receipt = try fetchOne("MutationReceipt", key: id.uuidString) else { throw ItemRepositoryError.corruptStore }
            receipt.setValue(MutationDeliveryStatus.superseded.rawValue, forKey: "status")
            context.delete(pending)
        }
    }

    private func isSuperseded(_ version: EncryptedItemVersion) throws -> Bool {
        let request = NSFetchRequest<NSManagedObject>(entityName: "MutationReceipt")
        request.predicate = NSPredicate(format: "scopeKey == %@ AND versionID == %@ AND status == %@",
            version.scope.storageKey, version.versionID as NSUUID, MutationDeliveryStatus.superseded.rawValue)
        request.fetchLimit = 1
        return try !context.fetch(request).isEmpty
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
        return DurableSyncRequest(account: account, database: database, generation: previous + 1, reason: reason)
    }

    private func publishChange() { for continuation in changeStreams.values { continuation.yield(()) } }
    private func removeChangeStream(_ id: UUID) { changeStreams.removeValue(forKey: id) }

    private func validate(_ version: EncryptedItemVersion) throws {
        guard !version.scope.account.isEmpty, ["private", "shared"].contains(version.scope.database),
              !version.scope.zoneOwner.isEmpty else { throw ItemRepositoryError.invalidScope }
        guard !version.ciphertext.isEmpty else { throw ItemRepositoryError.emptyCiphertext }
        guard version.generation > 0, version.generation <= UInt64(Int64.max) else { throw ItemRepositoryError.invalidGeneration }
        guard version.ciphertext.count <= Self.maximumCiphertextBytes else { throw ItemRepositoryError.oversizedCiphertext }
    }

    private func fetchOne(_ entity: String, key: String) throws -> NSManagedObject? {
        let request = NSFetchRequest<NSManagedObject>(entityName: entity)
        request.predicate = NSPredicate(format: "key == %@", key)
        request.fetchLimit = 1
        return try context.fetch(request).first
    }

    private func encode(_ version: EncryptedItemVersion, into object: NSManagedObject) {
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

    private func decodeVersion(_ object: NSManagedObject) throws -> EncryptedItemVersion {
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

    private func blobKey(_ account: String, _ name: String) -> String {
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
