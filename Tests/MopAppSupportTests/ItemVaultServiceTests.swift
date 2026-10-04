import Foundation
import Synchronization
import Testing
import MopCore
@testable import MopSync
@testable import MopVaultNext
@testable import MopAppSupport

private final class SoftwareItemBackend: ItemVaultServiceBackend {
    let repository: EncryptedItemRepository
    private let inventoryStore: MemoryItemInventory
    private let owner: Mutex<SessionDevice>
    private let sessions = Mutex<[UUID: ItemVaultSession]>([:])
    private let names = Mutex<[UUID: String]>([:])
    private let unwraps = SessionUnwrapCounter()
    var unwrapCount: Int { unwraps.value.withLock { $0 } }
    let confirmsDelivery = Mutex(false)
    let locksAfterCreate = Mutex(false)
    let waitedMutations = Mutex<[[UUID]]>([])
    init(repository: EncryptedItemRepository) throws {
        self.repository = repository; inventoryStore = MemoryItemInventory(); owner = Mutex(try SessionDevice())
    }
    private init(repository: EncryptedItemRepository, inventoryStore: MemoryItemInventory, owner: sending SessionDevice) {
        self.repository = repository; self.inventoryStore = inventoryStore; self.owner = Mutex(owner)
    }
    func reopened(repository: EncryptedItemRepository) async throws -> SoftwareItemBackend {
        let copiedOwner = owner.withLock { SessionDevice(copying: $0) }
        let result = SoftwareItemBackend(repository: repository, inventoryStore: inventoryStore, owner: copiedOwner)
        for (id, name) in names.withLock({ $0 }) {
            let scope = ItemVaultSetupScope(container: "iCloud.test", environment: "Development",
                binding: ItemVaultBinding(account: "service", database: "private", zoneOwner: "__defaultOwner__", vaultID: id))
            let device = result.owner.withLock { SessionDevice(copying: $0, unwrapCounter: result.unwraps) }
            let session = try await ItemVaultBootstrap(repository: repository, trustStore: inventoryStore, scope: scope, device: device).open()
            result.sessions.withLock { $0[id] = session }; result.names.withLock { $0[id] = name }
        }
        return result
    }
    func inventory() async throws -> [VaultDescriptor] {
        names.withLock { values in values.map { VaultDescriptor(id: $0.key.uuidString, name: $0.value, format: "mop-items-v2", enrolled: true) } }
    }
    func open(_ vaultID: UUID) async throws -> ItemVaultSession {
        guard let session = sessions.withLock({ $0[vaultID] }) else { throw MopError.vaultMissing }
        return session
    }
    func existing(_ vaultID: UUID) async -> ItemVaultSession? {
        sessions.withLock { $0[vaultID].flatMap { $0.isUnlocked ? $0 : nil } }
    }
    func create(name: String, id: UUID, archiveData: Data?, recoveryKey: SecretBytes?) async throws -> ItemVaultSession {
        let scope = ItemVaultSetupScope(container: "iCloud.test", environment: "Development",
            binding: ItemVaultBinding(account: "service", database: "private", zoneOwner: "__defaultOwner__", vaultID: id))
        let device = owner.withLock { SessionDevice(copying: $0, unwrapCounter: unwraps) }
        let bootstrap = try ItemVaultBootstrap(repository: repository, trustStore: inventoryStore, scope: scope, device: device)
        let session: ItemVaultSession
        if let archiveData, let recoveryKey { session = try await bootstrap.restore(archiveData: archiveData, recoveryKey: recoveryKey, name: name) }
        else { session = try await bootstrap.create(name: name) }
        sessions.withLock { $0[id] = session }; names.withLock { $0[id] = name }
        if locksAfterCreate.withLock({ $0 }) {
            session.lock()
            let receipt = try #require(try await repository.vaultInitialization(scope.repositoryScope))
            throw ItemVaultBootstrapFailure.committedButLocked(receipt)
        }
        return session
    }
    func changes() async -> AsyncStream<Void> { await repository.changes() }
    func requestSync() async throws { _ = try await repository.requestSync(account: "service", database: "private", reason: .manual) }
    func waitForDelivery(_ mutationIDs: [UUID], timeout: Duration) async throws -> Bool {
        waitedMutations.withLock { $0.append(mutationIDs) }
        if confirmsDelivery.withLock({ $0 }) {
            for mutation in try await repository.pendingMutations(account: "service") {
                try await repository.acknowledge(mutationID: mutation.id, account: "service", serverSystemFields: Data([1]))
            }
        }
        for id in mutationIDs {
            guard try await repository.mutationReceipt(id: id, account: "service")?.status == .cloudConfirmed else { return false }
        }
        return true
    }
    func lock() { sessions.withLock { Array($0.values) }.forEach { $0.lock() } }
}

@Test func itemServiceReportsCommittedCreationReceiptWhenLockWinsAfterSave() async throws {
    let directory = try serviceLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let backend = try SoftwareItemBackend(repository: repository), service = ItemVaultService(backend: backend), id = UUID()
    backend.locksAfterCreate.withLock { $0 = true }
    let result = try await service.execute(.create(name: "locked"), vault: id.uuidString, offline: false)
    #expect(result.defaultVault == id.uuidString && result.catalog == nil)
    #expect(result.saveStatus == .local)
    let receipt = try #require(try await repository.vaultInitialization(VaultScope(account: "service", vaultID: id)))
    #expect(result.mutationIDs == receipt.mutationIDs && !result.mutationIDs.isEmpty)
}

@Test func itemServiceCloudDeliveryReportsOnlyExactMutationAcknowledgements() async throws {
    let directory = try serviceLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let backend = try SoftwareItemBackend(repository: repository)
    let service = ItemVaultService(backend: backend, delivery: .cloudConfirmed(timeout: .zero))
    let id = UUID()
    _ = try await service.execute(.create(name: "receipt"), vault: id.uuidString, offline: false)
    let reference = try SecretReference("sp://receipt/Login/password")
    let queued = try await service.execute(.write(reference, "first", replace: false), vault: id.uuidString, offline: true)
    #expect(queued.message.contains("confirmation is pending"))
    #expect(queued.mutationIDs.count == 1)
    #expect(backend.waitedMutations.withLock { $0.last } == queued.mutationIDs)
    #expect(try await repository.mutationReceipt(id: queued.mutationIDs[0], account: "service")?.status == .queued)
    backend.confirmsDelivery.withLock { $0 = true }
    let confirmed = try await service.execute(.write(reference, "second", replace: true), vault: id.uuidString, offline: true)
    #expect(confirmed.message == "Saved and confirmed by iCloud.")
    #expect(confirmed.mutationIDs.count == 1 && confirmed.mutationIDs != queued.mutationIDs)
    #expect(backend.waitedMutations.withLock { $0.last } == confirmed.mutationIDs)
    #expect(try await repository.mutationReceipt(id: confirmed.mutationIDs[0], account: "service")?.status == .cloudConfirmed)
}

private func serviceLocation() throws -> URL {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-item-service-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return directory
}

@Test func itemServiceIndependentItemEditsPreserveCiphertextAndRejectSameItemStaleness() async throws {
    let directory = try serviceLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let backend = try SoftwareItemBackend(repository: repository), id = UUID()
    let service = ItemVaultService(backend: backend)
    _ = try await service.execute(.create(name: "personal"), vault: id.uuidString, offline: false)
    for name in ["Alpha", "Beta"] {
        let catalog = try await service.execute(.catalog, vault: id.uuidString, offline: true).requireCatalog()
        let attachment = try Attachment(fileName: "fixture.bin", data: Data([0, 255, 42]))
        let item = VaultItem(name: name, type: .login, fields: [ItemField(path: "password", type: .password, value: name), ItemField(path: "document", type: .attachment, value: try attachment.encodedValue())])
        _ = try await service.execute(.save(ItemEdit(revision: catalog.revision, item: item, create: true)), vault: id.uuidString, offline: true)
    }
    let original = try await service.execute(.catalog, vault: id.uuidString, offline: true).requireCatalog()
    var alpha = try #require(original.items.first { $0.name == "Alpha" })
    var beta = try #require(original.items.first { $0.name == "Beta" })
    let session = try await backend.open(id)
    let alphaID = try #require(alpha.storageID.flatMap(UUID.init(uuidString:)))
    let before = try #require(try await repository.item(session.binding.item(alphaID)))
    let oldEnvelope = try JSONDecoder().decode(ItemEnvelope.self, from: before.ciphertext)
    alpha.metadata = ItemMetadata(favorite: true)
    let saved = try await service.execute(.save(ItemEdit(revision: original.revision, item: alpha, create: false)), vault: id.uuidString, offline: true)
    #expect(saved.message.contains("Saved on this device"))
    let after = try #require(try await repository.item(session.binding.item(alphaID)))
    let newEnvelope = try JSONDecoder().decode(ItemEnvelope.self, from: after.ciphertext)
    #expect(newEnvelope.encryptedRecords == oldEnvelope.encryptedRecords)
    beta.metadata = ItemMetadata(tags: ["independent"])
    _ = try await service.execute(.save(ItemEdit(revision: original.revision, item: beta, create: false)), vault: id.uuidString, offline: true)
    await #expect(throws: MopError.vaultConflict) {
        try await service.execute(.save(ItemEdit(revision: original.revision, item: alpha, create: false)), vault: id.uuidString, offline: true)
    }
    let reference = try SecretReference("sp://personal/Alpha/password")
    #expect(try await service.readLocal(reference, vault: id.uuidString).value == SecretBytes(utf8: "Alpha"))
    let pending = try await repository.pendingMutations(account: "service")
    #expect(!pending.isEmpty)
    for value in pending { #expect(try await repository.mutationReceipt(id: value.id, account: "service")?.status == .queued) }
    let first = try #require(pending.first)
    try await repository.acknowledge(mutationID: first.id, account: "service", serverSystemFields: Data([1]))
    #expect(try await repository.mutationReceipt(id: first.id, account: "service")?.status == .cloudConfirmed)
    service.lock()
    await #expect(throws: MopError.authentication) { try await service.readLocal(reference, vault: id.uuidString) }
}

@Test func itemServiceRestoreAndExportUsePortableLocalSnapshotAndUnsupportedManagementIsExplicit() async throws {
    let directory = try serviceLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let backend = try SoftwareItemBackend(repository: repository), service = ItemVaultService(backend: backend), id = UUID()
    let original = try sessionArchive(), archive = try PortableArchive.seal(original)
    _ = try await service.execute(.restorePortable(document: archive.data, key: archive.recoveryKey, name: "restored"), vault: id.uuidString, offline: false)
    let catalog = try await service.execute(.catalog, vault: id.uuidString, offline: true).requireCatalog()
    #expect(catalog.items.count == original.items.count)
    let exportURL = directory.appendingPathComponent("snapshot.moparchive")
    let result = try await service.execute(.exportPortable(exportURL), vault: id.uuidString, offline: true)
    let key = try #require(result.value)
    let reopened = try PortableArchive.open(Data(contentsOf: exportURL), recoveryKey: key)
    #expect(reopened.records == original.records)
    #expect(result.message.contains("local snapshot"))
    #expect(service.capabilities == [.portableBackup, .enrollment, .passwordCheckCache])
    await #expect(throws: ItemVaultServiceFailure.unavailable) {
        try await service.execute(.manage(.requestEnrollment(name: "old")), vault: id.uuidString, offline: false)
    }
}

@Test func itemServiceTrashAllowsReusedNameWithoutDroppingEitherPortableRecordGraph() async throws {
    let directory = try serviceLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let backend = try SoftwareItemBackend(repository: repository), service = ItemVaultService(backend: backend), id = UUID()
    let archive = try PortableArchive.seal(sessionArchive())
    _ = try await service.execute(.restorePortable(document: archive.data, key: archive.recoveryKey, name: "trash"), vault: id.uuidString, offline: false)
    let before = try await service.execute(.catalog, vault: id.uuidString, offline: true).requireCatalog()
    let trashed = try await service.execute(.trashItem(name: "Login", revision: before.revision), vault: id.uuidString, offline: true)
    #expect(trashed.catalog?.items.isEmpty == true)
    #expect(trashed.deletedCatalog?.items.count == 1)
    let deletion = try #require(trashed.deletedCatalog?.items.first?.deletion)
    #expect(deletion.originalName == "Login")
    _ = try await service.execute(.write(SecretReference("sp://trash/Login/password"), "replacement-secret", replace: false), vault: id.uuidString, offline: true)
    let current = try await service.execute(.catalog, vault: id.uuidString, offline: true)
    #expect(current.catalog?.items.count == 1 && current.deletedCatalog?.items.count == 1)
    await #expect(throws: MopError.duplicate) {
        try await service.execute(.restoreItem(id: deletion.id, revision: #require(current.catalog).revision), vault: id.uuidString, offline: true)
    }
    let document = try await backend.open(id).exportPortableLocalSnapshot()
    #expect(document.items.count == 2 && document.records.count == 2)
    #expect(Set(document.items.map(\.name)).count == 2)
    #expect(document.records.values.contains { $0.bytes == SecretBytes(utf8: "session-secret") })
    #expect(document.records.values.contains { $0.bytes == SecretBytes(utf8: "replacement-secret") })
}

@Test func itemServiceOfflineInitializationRejectsBeforeAnyDurableMutation() async throws {
    let directory = try serviceLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let backend = try SoftwareItemBackend(repository: repository), service = ItemVaultService(backend: backend), id = UUID()
    await #expect(throws: MopError.offlineWrite) {
        try await service.execute(.create(name: "offline"), vault: id.uuidString, offline: true)
    }
    #expect(try await backend.inventory().isEmpty)
    #expect(try await repository.pendingMutations(account: "service").isEmpty)
    #expect(try await repository.vaultInitialization(VaultScope(account: "service", vaultID: id)) == nil)
}

@Test(arguments: [1, 40])
func itemServiceCatalogAndWarmRevealHaveBoundedKeyUnwraps(itemCount: Int) async throws {
    let directory = try serviceLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let backend = try SoftwareItemBackend(repository: repository), id = UUID()
    let document = performanceDocument(itemCount: itemCount)
    let backup = try PortableArchive.seal(document)
    _ = try await backend.create(name: "performance", id: id, archiveData: backup.data, recoveryKey: backup.recoveryKey)
    let service = ItemVaultService(backend: backend)
    let projectionSession = try await backend.open(id)
    let versions = try await projectionSession.revisionIndex().filter { $0.key != ItemVaultSession.metadataRecordID }
    let selected = try #require(versions.first)
    let beforeBatch = backend.unwrapCount
    let batch = try await projectionSession.displayCatalogBatch(expectedVersions: [selected.key: selected.value])
    #expect(batch.count == 1 && batch[0].entry.itemID == selected.key)
    #expect(batch[0].item.fields.first(where: { $0.path == "password" })?.value == nil)
    #expect(backend.unwrapCount - beforeBatch == 1)
    let beforeRejected = backend.unwrapCount
    await #expect(throws: ItemRepositoryError.staleLocalVersion) {
        try await projectionSession.displayCatalogBatch(expectedVersions: [selected.key: UUID()])
    }
    let oversized = Dictionary(uniqueKeysWithValues: (0..<65).map { _ in (UUID(), UUID()) })
    await #expect(throws: ItemVaultSessionFailure.invalidBinding) {
        try await projectionSession.displayCatalogBatch(expectedVersions: oversized)
    }
    #expect(backend.unwrapCount == beforeRejected)
    let beforeCatalog = backend.unwrapCount
    let catalog = try await service.execute(.catalog, vault: id.uuidString, offline: true).requireCatalog()
    #expect(catalog.items.count == itemCount)
    #expect(catalog.items.allSatisfy { $0.fields.first(where: { $0.path == "username" })?.value == "alice" })
    #expect(catalog.items.allSatisfy { $0.fields.first(where: { $0.path == "password" })?.value == nil })
    // One wrapped item key per item; one separate wrapped vault metadata key.
    #expect(backend.unwrapCount - beforeCatalog <= itemCount + 1)
    let beforeWarm = backend.unwrapCount
    _ = try await service.execute(.catalog, vault: id.uuidString, offline: true)
    #expect(backend.unwrapCount == beforeWarm)
    let reference = try SecretReference("sp://performance/Login0/password")
    let revealed = try await service.readLocal(reference, vault: id.uuidString)
    #expect(revealed.value == SecretBytes(utf8: "target-secret"))
    #expect(backend.unwrapCount - beforeWarm <= 2)
    let session = try await backend.open(id)
    let targetID = try #require(catalog.items.first(where: { $0.name == "Login0" })?.storageID.flatMap(UUID.init(uuidString:)))
    let entry = try await session.catalog(itemID: targetID)
    var edited = entry.catalog
    edited.item.metadata = ItemMetadata(favorite: true)
    _ = try await session.edit(itemID: targetID, expectedBase: entry.versionID, catalog: edited)
    let beforeIncremental = backend.unwrapCount
    let refreshed = try await service.execute(.catalog, vault: id.uuidString, offline: true).requireCatalog()
    #expect(refreshed.items.first(where: { $0.name == "Login0" })?.metadata?.favorite == true)
    #expect(backend.unwrapCount - beforeIncremental <= 1)
    service.lock()
    let beforeLocked = backend.unwrapCount
    await #expect(throws: MopError.authentication) { try await service.readLocal(reference, vault: id.uuidString) }
    #expect(backend.unwrapCount == beforeLocked)
}

private func performanceDocument(itemCount: Int) -> PortableVaultArchive {
    var document = PortableVaultArchive(name: "performance", items: [], itemIDs: [:], references: [:], records: [:])
    for index in 0..<itemCount {
        let name = "Login\(index)", itemID = UUID().uuidString
        let fields = [ItemField(path: "username", type: .username, value: "alice"),
                      ItemField(path: "website", type: .website, value: "https://example.com"),
                      ItemField(path: "notes", type: .notes, value: "visible notes"),
                      ItemField(path: "password", type: .password)]
        document.items.append(VaultItem(name: name, type: .login, fields: fields)); document.itemIDs[name] = itemID
        for field in fields {
            let record = UUID().uuidString
            document.references[name + "/" + field.path] = record
            document.records[record] = PortableArchiveRecord(itemID: itemID, bytes: SecretBytes(utf8: field.value ?? "target-secret"))
        }
    }
    return document
}

private actor CatalogPublicationRecorder: AutoFillPublishing {
    private(set) var itemCounts: [Int] = []
    func status() async -> AutoFillPublicationStatus { AutoFillPublicationStatus() }
    func publish(catalog: ItemCatalog, vaultID: String) async throws { itemCounts.append(catalog.items.count) }
    func refresh() async throws {}
}

@Test func progressiveCatalogReturnsPartialThenNotifiesCompleteAndNeverPublishesPartialAutoFill() async throws {
    let directory = try serviceLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let backend = try SoftwareItemBackend(repository: repository), id = UUID(), total = 64
    let archive = try PortableArchive.seal(performanceDocument(itemCount: total))
    _ = try await backend.create(name: "performance", id: id, archiveData: archive.data, recoveryKey: archive.recoveryKey)
    let publisher = CatalogPublicationRecorder()
    let service = ItemVaultService(backend: backend, publisher: publisher, displayBatchSize: 1)
    let events = await service.changes()
    let initial = try await service.displayCatalog(vault: id.uuidString)
    #expect(initial.catalogLoadedCount == 1 && initial.catalogTotalCount == total)
    let loaded = try #require(initial.catalog?.items.first), itemID = try #require(loaded.storageID)
    let reference = try SecretReference(vault: "performance", relativePath: loaded.name + "/password")
    let revealed = try await service.readLocal(reference, vault: id.uuidString, itemID: itemID)
    #expect(revealed.value == SecretBytes(utf8: "target-secret"))
    let session = try await backend.open(id)
    let entry = try await session.catalog(itemID: #require(UUID(uuidString: itemID)))
    var updated = entry.catalog
    updated.item.metadata = ItemMetadata(favorite: true)
    _ = try await session.edit(itemID: entry.itemID, expectedBase: entry.versionID, catalog: updated)
    let complete = try await DeliveryConfirmationWaiter.wait(timeout: .seconds(5), request: {}, observe: {
        for await _ in events {
            let result = try await service.displayCatalog(vault: id.uuidString)
            if result.catalogLoadedCount == nil {
                #expect(result.catalog?.items.count == total)
                #expect(Set(result.catalog?.items.map(\.name) ?? []).count == total)
                #expect(result.catalog?.items.first(where: { $0.storageID == itemID })?.metadata?.favorite == true)
                return true
            }
        }
        return false
    })
    #expect(complete)
    #expect(await publisher.itemCounts.allSatisfy { $0 == total })
    let full = try await service.execute(.catalog, vault: id.uuidString, offline: true)
    #expect(full.catalogLoadedCount == nil && full.catalog?.items.count == total)
    service.lock()
    #expect(try await service.cachedCatalog(vault: id.uuidString) == nil)
    await #expect(throws: MopError.authentication) {
        try await service.readLocal(reference, vault: id.uuidString, itemID: itemID)
    }
}

@Test func lockDuringProgressiveOpeningDiscardsRemainingPlaintextAndPublication() async throws {
    let directory = try serviceLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let backend = try SoftwareItemBackend(repository: repository), id = UUID()
    let archive = try PortableArchive.seal(performanceDocument(itemCount: 64))
    _ = try await backend.create(name: "performance", id: id, archiveData: archive.data, recoveryKey: archive.recoveryKey)
    let publisher = CatalogPublicationRecorder()
    let service = ItemVaultService(backend: backend, publisher: publisher, displayBatchSize: 1)
    let initial = try await service.displayCatalog(vault: id.uuidString)
    #expect(initial.catalogLoadedCount == 1)
    service.lock()
    #expect(service.authenticatedAt == nil)
    #expect(try await service.cachedCatalog(vault: id.uuidString) == nil)
    #expect(await publisher.itemCounts.isEmpty)
}

@Test(arguments: [1, 40])
func reopenedNamedReadUsesDurableIndexWithoutOpeningEveryItem(itemCount: Int) async throws {
    let directory = try serviceLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let location = directory.appendingPathComponent("items.sqlite")
    let repository = try EncryptedItemRepository(storeURL: location)
    let backend = try SoftwareItemBackend(repository: repository), id = UUID()
    let archive = try PortableArchive.seal(performanceDocument(itemCount: itemCount))
    _ = try await backend.create(name: "performance", id: id, archiveData: archive.data, recoveryKey: archive.recoveryKey)
    let initial = ItemVaultService(backend: backend)
    _ = try await initial.execute(.catalog, vault: id.uuidString, offline: true)
    initial.lock()
    let reopened = try EncryptedItemRepository(storeURL: location)
    let freshBackend = try await backend.reopened(repository: reopened)
    let freshService = ItemVaultService(backend: freshBackend)
    let before = freshBackend.unwrapCount
    let value = try await freshService.execute(.read(SecretReference("sp://performance/Login0/password")), vault: id.uuidString, offline: true)
    #expect(value.value == SecretBytes(utf8: "target-secret"))
    // Index key + exact item's metadata key + requested secret key only.
    #expect(freshBackend.unwrapCount - before <= 3)
    freshService.lock()
}

@Test func durableNameLookupRepairsTamperAndRejectsExternallyIntroducedDuplicates() async throws {
    let directory = try serviceLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let backend = try SoftwareItemBackend(repository: repository), id = UUID()
    let archive = try PortableArchive.seal(performanceDocument(itemCount: 2))
    _ = try await backend.create(name: "performance", id: id, archiveData: archive.data, recoveryKey: archive.recoveryKey)
    let service = ItemVaultService(backend: backend)
    _ = try await service.execute(.catalog, vault: id.uuidString, offline: true)
    let session = try await backend.open(id), scope = VaultScope(account: "service", vaultID: id)
    let originalBytes = try #require(try await repository.localNameIndex(scope: scope))
    let versions = try await session.revisionIndex()
    try await repository.saveLocalNameIndex(scope: scope, bytes: Data("untrusted-cache".utf8), expectedVersions: versions, authorization: DomainAccountAuthorization())
    let fresh = ItemVaultService(backend: backend)
    let value = try await fresh.execute(.read(SecretReference("sp://performance/Login0/password")), vault: id.uuidString, offline: true)
    #expect(value.value == SecretBytes(utf8: "target-secret"))
    #expect(try await repository.localNameIndex(scope: scope) != Data("untrusted-cache".utf8))
    let other = try await session.catalog(named: "Login1")
    var changed = other.catalog
    changed.item.name = "Login0"
    changed.references = Dictionary(uniqueKeysWithValues: changed.references.map { key, value in
        (key.replacingOccurrences(of: "Login1/", with: "Login0/"), value)
    })
    _ = try await session.edit(itemID: other.itemID, expectedBase: other.versionID, catalog: changed)
    // Replaying an older authentic cache is insufficient to hide the duplicate.
    try await repository.saveLocalNameIndex(scope: scope, bytes: originalBytes, expectedVersions: session.revisionIndex(), authorization: DomainAccountAuthorization())
    await #expect(throws: MopError.duplicate) { try await session.catalog(named: "Login0") }
    await #expect(throws: MopError.notFound) { try await session.catalog(named: "Login1") }
    for current in try await session.catalog() {
        var deleted = current.catalog
        deleted.item.deletion = ItemDeletion(originalName: deleted.item.name, deletedAt: Date())
        _ = try await session.edit(itemID: current.itemID, expectedBase: current.versionID, catalog: deleted)
    }
    await #expect(throws: MopError.notFound) { try await session.catalog(named: "Login0") }
}

@Test(arguments: [1, 40, 1200])
func persistentDisplayCatalogOpensWholeListWithConstantHardwareWork(itemCount: Int) async throws {
    let directory = try serviceLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("items.sqlite")
    let repository = try EncryptedItemRepository(storeURL: url)
    let backend = try SoftwareItemBackend(repository: repository), id = UUID()
    let archive = try PortableArchive.seal(performanceDocument(itemCount: itemCount))
    _ = try await backend.create(name: "performance", id: id, archiveData: archive.data, recoveryKey: archive.recoveryKey)
    let original = ItemVaultService(backend: backend)
    let first = try await original.execute(.catalog, vault: id.uuidString, offline: true).requireCatalog()
    let pending = try await repository.pendingMutations(account: "service")
    original.lock()
    let reopened = try EncryptedItemRepository(storeURL: url)
    let fresh = try await backend.reopened(repository: reopened)
    let service = ItemVaultService(backend: fresh, displayBatchSize: 1)
    let before = fresh.unwrapCount
    let result = try await service.displayCatalog(vault: id.uuidString)
    #expect(result.catalog?.items.count == itemCount)
    #expect(result.catalogTotalCount == nil) // No old progressive rebuild UI.
    #expect(fresh.unwrapCount - before <= 2) // One catalog key, one vault metadata key.
    #expect(result.catalog?.items.map(\.name) == first.items.map(\.name))
    #expect(result.catalog?.items.allSatisfy { $0.fields.first(where: { $0.path == "notes" })?.value == "visible notes" } == true)
    #expect(result.catalog?.items.allSatisfy { $0.fields.first(where: { $0.path == "password" })?.value == nil } == true)
    #expect(try await reopened.pendingMutations(account: "service").map(\.id) == pending.map(\.id))
    let session = try await fresh.open(id)
    let index = try await session.revisionIndex()
    service.lock()
    await #expect(throws: MopError.authentication) { try await session.cachedDisplayRows(expectedVersions: index) }
}

@Test func persistentDisplayCatalogReconcilesOneChangedItemAfterRestart() async throws {
    let directory = try serviceLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("items.sqlite"), id = UUID()
    let repository = try EncryptedItemRepository(storeURL: url)
    let backend = try SoftwareItemBackend(repository: repository)
    let archive = try PortableArchive.seal(performanceDocument(itemCount: 40))
    let session = try await backend.create(name: "performance", id: id, archiveData: archive.data, recoveryKey: archive.recoveryKey)
    let original = ItemVaultService(backend: backend)
    let catalog = try await original.execute(.catalog, vault: id.uuidString, offline: true).requireCatalog()
    let item = try #require(catalog.items.first), itemID = try #require(item.storageID.flatMap(UUID.init(uuidString:)))
    let entry = try await session.catalog(itemID: itemID)
    var changed = entry.catalog; changed.item.metadata = ItemMetadata(favorite: true)
    _ = try await session.edit(itemID: itemID, expectedBase: entry.versionID, catalog: changed)
    // Simulates a source commit followed by termination before projection work.
    original.lock()
    let reopened = try EncryptedItemRepository(storeURL: url), fresh = try await backend.reopened(repository: reopened)
    let service = ItemVaultService(backend: fresh)
    let before = fresh.unwrapCount
    let result = try await service.displayCatalog(vault: id.uuidString)
    #expect(result.catalog?.items.count == 40 && result.catalogTotalCount == nil)
    #expect(result.catalog?.items.first(where: { $0.storageID == item.storageID })?.metadata?.favorite == true)
    #expect(fresh.unwrapCount - before <= 3) // Only the changed item needs a hardware unwrap.
    service.lock()
}

@Test func damagedDisplayRowsRebuildIndividuallyAndKeyDamageRebuildsWithoutChangingItems() async throws {
    let directory = try serviceLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("items.sqlite"), id = UUID()
    let repository = try EncryptedItemRepository(storeURL: url)
    let backend = try SoftwareItemBackend(repository: repository)
    let archive = try PortableArchive.seal(performanceDocument(itemCount: 40))
    let session = try await backend.create(name: "performance", id: id, archiveData: archive.data, recoveryKey: archive.recoveryKey)
    let original = ItemVaultService(backend: backend)
    _ = try await original.execute(.catalog, vault: id.uuidString, offline: true)
    let scope = VaultScope(account: "service", vaultID: id, database: "private", zoneOwner: "__defaultOwner__")
    let key = try #require(try await repository.displayCatalogKey(scope: scope))
    let row = try #require(try await repository.displayCatalogRows(scope: scope).first)
    var damaged = row.ciphertext; damaged[damaged.startIndex] ^= 1
    let authorization = ClosureRepositoryWritePermit { try #require(session.isUnlocked) }
    try await repository.saveDisplayCatalogRows(scope: scope,
        rows: [.init(itemID: row.itemID, versionID: row.versionID, keyID: row.keyID, ciphertext: damaged)],
        keyEnvelope: key, authorization: authorization)
    let sourceVersions = try await session.revisionIndex()
    let pending = try await repository.pendingMutations(account: "service").map(\.id)
    original.lock()
    let reopened = try EncryptedItemRepository(storeURL: url), fresh = try await backend.reopened(repository: reopened)
    let service = ItemVaultService(backend: fresh)
    let before = fresh.unwrapCount
    let result = try await service.displayCatalog(vault: id.uuidString)
    #expect(result.catalog?.items.count == 40 && result.catalogTotalCount == nil)
    #expect(fresh.unwrapCount - before <= 3)
    let active = try await fresh.open(id)
    let permit = ClosureRepositoryWritePermit { try #require(active.isUnlocked) }
    _ = try await reopened.reserveDisplayCatalogKey(scope: scope, candidate: Data([0]), replacing: key, authorization: permit)
    service.lock()
    let nextRepository = try EncryptedItemRepository(storeURL: url), nextBackend = try await fresh.reopened(repository: nextRepository)
    let next = ItemVaultService(backend: nextBackend)
    let rebuilt = try await next.execute(.catalog, vault: id.uuidString, offline: true).requireCatalog()
    #expect(rebuilt.items.count == 40)
    #expect(try await nextRepository.itemRevisionIndex(account: "service", vaultID: id) == sourceVersions)
    #expect(try await nextRepository.pendingMutations(account: "service").map(\.id) == pending)
    next.lock()
}

private struct ClosureRepositoryWritePermit: RepositoryWritePermit {
    let check: @Sendable () throws -> Void
    init(_ check: @escaping @Sendable () throws -> Void) { self.check = check }
    func withWritePermission<T>(_ body: () throws -> T) throws -> T { try check(); return try body() }
}

@MainActor @Test func itemServiceStoresHealthSeparatelyWithoutRewritingItems() async throws {
    let directory = try serviceLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let backend = try SoftwareItemBackend(repository: repository), id = UUID()
    let service = ItemVaultService(backend: backend)
    #expect(service.capabilities.contains(.passwordCheckCache))
    _ = try await service.execute(.create(name: "health"), vault: id.uuidString, offline: false)
    let empty = try await service.execute(.catalog, vault: id.uuidString, offline: true).requireCatalog()
    let item = VaultItem(name: "login", fields: [ItemField(path: "password", type: .password, value: "password")])
    _ = try await service.execute(.save(ItemEdit(revision: empty.revision, item: item, create: true)), vault: id.uuidString, offline: true)
    let before = try await service.execute(.catalog, vault: id.uuidString, offline: true).requireCatalog()
    let session = try await backend.open(id), itemID = try #require(before.items[0].storageID.flatMap(UUID.init(uuidString:)))
    let original = try #require(try await repository.item(session.binding.item(itemID)))
    let metadataBefore = try await session.vaultMetadata().versionID
    let report = try await PasswordHealthSession().scan(catalogs: [id.uuidString: before], service: service, breach: UnusedHealthBreach(), enabled: false)
    let checks = try #require(report.cachedChecks[id.uuidString])
    _ = try await service.execute(.savePasswordChecks(checks, revision: before.revision), vault: id.uuidString, offline: true)
    let saved = try await service.execute(.catalog, vault: id.uuidString, offline: true).requireCatalog()
    #expect(saved.security?.passwordChecks == checks)
    #expect(saved.items[0].fields[0].passwordQuality == checks.first?.strengthResult?.quality)
    #expect(saved.items[0].fields[0].passwordQuality != nil)
    #expect(try await session.vaultMetadata().versionID == metadataBefore)
    let health = try await repository.healthItems(account: session.binding.account, vaultID: id)
    #expect(health.count == 1 && health.first?.healthItemID == itemID)
    #expect(try await session.catalog().count == 1)
    #expect(try await session.revisionIndex().count == 2)
    #expect(try await session.exportPortableLocalSnapshot().items.count == 1)
    let restarted = ItemVaultService(backend: backend)
    #expect(try await restarted.execute(.catalog, vault: id.uuidString, offline: true).requireCatalog().items[0].fields[0].passwordQuality == saved.items[0].fields[0].passwordQuality)
    #expect(try await restarted.execute(.catalog, vault: id.uuidString, offline: true).requireCatalog().security?.passwordChecks == checks)
    let check = try #require(checks.first)
    var newer = check
    newer.breachResult = CachedBreachResult(exposed: true, checkedAt: Date())
    _ = try await session.saveHealthChecks([newer], itemID: itemID, expectedItemVersion: original.versionID)
    _ = try await session.saveHealthChecks([check], itemID: itemID, expectedItemVersion: original.versionID)
    #expect(try await session.healthChecks().first?.breachResult == newer.breachResult)
    #expect(saved.revision == before.revision)
    #expect(try await repository.item(session.binding.item(itemID))?.ciphertext == original.ciphertext)
    await #expect(throws: MopError.vaultConflict) {
        try await service.execute(.savePasswordChecks(checks, revision: "stale"), vault: id.uuidString, offline: true)
    }
}
private struct UnusedHealthBreach: BreachChecking {
    func contains(_ password: Data, force: Bool) async throws -> Bool { Issue.record("Disabled breach check called"); return false }
    func clear() async {}
}
