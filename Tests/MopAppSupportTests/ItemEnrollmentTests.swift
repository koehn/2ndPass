import Foundation
import Testing
import MopCore
import MopSync
@testable import MopVaultNext
@testable import MopAppSupport

private struct JoinedDisplayBackend: ItemVaultServiceBackend {
    let session: ItemVaultSession
    func inventory() async throws -> [VaultDescriptor] {
        [VaultDescriptor(id: session.binding.vaultID.uuidString, name: "existing", format: "mop-items-v2", enrolled: true)]
    }
    func open(_ vaultID: UUID) async throws -> ItemVaultSession { session }
    func create(name: String, id: UUID, archiveData: Data?, recoveryKey: SecretBytes?) async throws -> ItemVaultSession { throw MopError.invalidVault }
    func requestSync() async throws {}
    func lock() { session.lock() }
}

@Test func enrollmentRequestSurvivesRestartAndRetainsIdentityAcrossRetry() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-enrollment-request-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let device = try SessionDevice()
    let scope = EnrollmentScope(container: "iCloud.test", environment: "Development", account: "account", vault: UUID(), member: device.identity.member)
    let original = try DeviceEnrollmentRequest.create(scope: scope, device: device)
    let store = ItemEnrollmentRequestStore(directory: directory, scope: scope)
    #expect(try store.reserve(original) == original)
    let reopened = ItemEnrollmentRequestStore(directory: directory, scope: scope)
    #expect(try reopened.load() == original)
    let retry = try DeviceEnrollmentRequest.create(scope: scope, device: device)
    #expect(retry.id != original.id)
    #expect(try reopened.reserve(retry) == original)
    let foreignScope = EnrollmentScope(container: scope.container, environment: "Production", account: scope.account, vault: scope.vault, member: scope.member)
    #expect(throws: DeviceEnrollmentFailure.invalidRequest) {
        try ItemEnrollmentRequestStore(directory: directory, scope: foreignScope).load()
    }
    let otherAccount = EnrollmentScope(container: scope.container, environment: scope.environment, account: "other", vault: scope.vault, member: scope.member)
    #expect(try ItemEnrollmentRequestStore(directory: directory, scope: otherAccount).load() == nil)
    try reopened.clear()
    #expect(try reopened.load() == nil)
}

@Test func privateAccountApprovalBootstrapsExistingVaultWithoutNewOutboxAndSurvivesRestart() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-enrollment-join-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let owner = try SessionDevice(), joining = try SessionDevice(member: owner.identity.member)
    let restartJoining = SessionDevice(copying: joining)
    let scope = ItemVaultSetupScope(container: "iCloud.test", environment: "Development",
        binding: ItemVaultBinding(account: "same-account", database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
    let ownerRepository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("owner.sqlite"))
    let archive = try PortableArchive.seal(sessionArchive())
    let ownerSession = try await ItemVaultBootstrap(repository: ownerRepository, trustStore: MemoryItemInventory(), scope: scope,
        device: SessionDevice(copying: owner)).restore(archiveData: archive.data, recoveryKey: archive.recoveryKey, name: "existing")
    let requestScope = EnrollmentScope(container: scope.container, environment: scope.environment, account: scope.binding.account,
        vault: scope.binding.vaultID, member: owner.identity.member)
    let request = try DeviceEnrollmentRequest.create(scope: requestScope, device: joining)
    let prepared = try await ownerSession.prepareAdmission(request: request)
    let metadata = try #require(prepared.versions.first { $0.scope.itemID == ItemVaultSession.metadataRecordID })
    let joiningURL = directory.appendingPathComponent("joining.sqlite")
    let joiningRepository = try EncryptedItemRepository(storeURL: joiningURL), trust = MemoryItemInventory()
    let wrongScope = ItemVaultSetupScope(container: scope.container, environment: scope.environment,
        binding: ItemVaultBinding(account: "other-account", database: "private", zoneOwner: "__defaultOwner__", vaultID: scope.binding.vaultID))
    let wrongBootstrap = try ItemVaultBootstrap(repository: joiningRepository, trustStore: trust, scope: wrongScope, device: SessionDevice(copying: joining))
    await #expect(throws: (any Error).self) {
        try await wrongBootstrap.acceptFromAuthenticatedPrivateCloudKit(approval: prepared.approval, request: request, metadata: metadata)
    }
    #expect(try trust.load(scope: wrongScope) == nil)
    wrongBootstrap.lock()
    let bootstrap = try ItemVaultBootstrap(repository: joiningRepository, trustStore: trust, scope: scope, device: joining)
    let corrupt = EncryptedItemVersion(scope: metadata.scope, versionID: metadata.versionID,
        baseVersionID: metadata.baseVersionID, ciphertext: Data([0]), generation: metadata.generation)
    await #expect(throws: (any Error).self) {
        try await bootstrap.acceptFromAuthenticatedPrivateCloudKit(approval: prepared.approval, request: request, metadata: corrupt)
    }
    #expect(try trust.load(scope: scope) == nil)
    #expect(try await joiningRepository.vaultInitialization(scope.repositoryScope) == nil)
    let admitted = try await bootstrap.acceptFromAuthenticatedPrivateCloudKit(approval: prepared.approval, request: request, metadata: metadata)
    let again = try await bootstrap.acceptFromAuthenticatedPrivateCloudKit(approval: prepared.approval, request: request, metadata: metadata)
    #expect(admitted === again)
    // Reinstall: retain Keychain-like pins/keys but lose the entire local store.
    let reconnectRequest = try DeviceEnrollmentRequest.create(scope: requestScope, device: restartJoining)
    let admittedHistory = try prepared.approval.verifiedHistory()
    let reconnect = try DeviceEnrollmentApproval.reconnect(request: reconnectRequest, history: admittedHistory,
        owner: owner, expectedItemCount: prepared.versions.count - 1)
    let originalPin = try trust.load(scope: scope)
    let reinstalledRepository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("reinstalled.sqlite"))
    let reinstalled = try ItemVaultBootstrap(repository: reinstalledRepository, trustStore: trust, scope: scope,
        device: SessionDevice(copying: restartJoining))
    let restored = try await reinstalled.acceptFromAuthenticatedPrivateCloudKit(approval: reconnect,
        request: reconnectRequest, metadata: metadata)
    #expect(try await restored.vaultMetadata().value.name == "existing")
    #expect(try trust.load(scope: scope) == originalPin)
    #expect(try await reinstalledRepository.pendingMutations(account: scope.binding.account).isEmpty)
    #expect(try await reinstalledRepository.vaultInitialization(scope.repositoryScope) != nil)
    let reissued = try await restored.reconnectApproval(reconnectRequest)
    #expect(reissued?.isReconnect == true)
    #expect(reissued?.successor == reconnect.successor)
    restored.lock()
    // Metadata-only bootstrap must not present the cloud vault as empty, and
    // the hint must survive a process/store restart before any items arrive.
    #expect(prepared.approval.expectedItemCount == prepared.versions.count - 1)
    let suggestions = directory.appendingPathComponent("suggestions")
    let publisher = AutoFillPublisher(directory: suggestions, publish: { _ in })
    let prior = VaultItem(name: "Still downloading", type: .login, fields: [
        ItemField(path: "username", type: .username, value: "retained-user"),
        ItemField(path: "website", type: .website, value: "https://example.test"),
        ItemField(path: "password", type: .password)
    ])
    try await publisher.publish(catalog: ItemCatalog(vault: "existing", revision: "", items: [prior]), vaultID: scope.binding.vaultID.uuidString)
    let firstService = ItemVaultService(backend: JoinedDisplayBackend(session: admitted), publisher: publisher)
    let firstDisplay = try await firstService.displayCatalog(vault: scope.binding.vaultID.uuidString)
    #expect(firstDisplay.catalogDownloading)
    #expect(firstDisplay.catalogLoadedCount == 0)
    #expect(firstDisplay.catalogTotalCount == prepared.versions.count - 1)
    // Both explicit catalog reads and repair must retain suggestions while
    // only the metadata bootstrap has arrived, even though local rows are complete.
    _ = try await firstService.execute(.catalog, vault: scope.binding.vaultID.uuidString)
    #expect(try AutoFillIndex(directory: suggestions).load().map(\.username) == ["retained-user"])
    _ = try await firstService.refreshAutoFillSuggestions(offline: true)
    #expect(try AutoFillIndex(directory: suggestions).load().map(\.username) == ["retained-user"])
    let progressRepository = try EncryptedItemRepository(storeURL: joiningURL)
    #expect(try await progressRepository.initialDownloadExpectedCount(scope: scope.repositoryScope) == prepared.versions.count - 1)
    // Native change delivery may include historical ciphertext before the owner
    // uploads recipient rewrites. This is progress, not vault corruption.
    let historical = try await ownerRepository.items(account: scope.binding.account, vaultID: scope.binding.vaultID,
        database: scope.binding.database, zoneOwner: scope.binding.zoneOwner).filter { $0.scope.itemID != ItemVaultSession.metadataRecordID }
    for version in historical { try await joiningRepository.applyRemote(version, serverSystemFields: Data([1])) }
    let pendingVersions = Dictionary(uniqueKeysWithValues: historical.map { ($0.scope.itemID, $0.versionID) })
    let waiting = try await admitted.admissionAwareDisplayCatalogBatch(expectedVersions: pendingVersions)
    #expect(waiting.rows.isEmpty)
    #expect(waiting.waiting == pendingVersions)
    await #expect(throws: ItemVaultSessionFailure.pendingAdmission) { try await admitted.catalog() }
    await #expect(throws: ItemVaultSessionFailure.pendingAdmission) { try await admitted.exportPortableLocalSnapshot() }
    #expect(try await admitted.prepareMembershipCatchUp().isEmpty)
    let displayService = ItemVaultService(backend: JoinedDisplayBackend(session: admitted), idleDelay: .milliseconds(100), idleSpacing: .zero)
    let pendingDisplay = try await waitForDisplay(displayService, vault: scope.binding.vaultID) { $0.catalogWaitingCount == historical.count }
    #expect(pendingDisplay.catalog?.items.isEmpty == true)
    #expect(pendingDisplay.catalogLoadedCount == 0)
    #expect(pendingDisplay.catalogTotalCount == historical.count)
    #expect(pendingDisplay.catalogWaitingCount == historical.count)
    // A second refresh with no rewrite must remain settled waiting, not loop or
    // turn the partial projection into a complete catalog.
    let stillWaiting = try await displayService.displayCatalog(vault: scope.binding.vaultID.uuidString)
    #expect(stillWaiting.catalogWaitingCount == historical.count)
    await #expect(throws: ItemVaultServiceFailure.awaitingAdmission) {
        try await displayService.execute(.catalog, vault: scope.binding.vaultID.uuidString)
    }
    for version in prepared.versions where version.scope.itemID != ItemVaultSession.metadataRecordID {
        try admitted.validate(version, direction: .receiving)
        try await joiningRepository.applyRemote(version, serverSystemFields: Data([1]))
    }
    let availableDisplay = try await waitForDisplay(displayService, vault: scope.binding.vaultID) { $0.catalogTotalCount == nil }
    #expect(!availableDisplay.catalogDownloading)
    #expect(try await progressRepository.initialDownloadExpectedCount(scope: scope.repositoryScope) == nil)
    #expect(availableDisplay.catalogTotalCount == nil)
    #expect(availableDisplay.catalogWaitingCount == nil)
    #expect(availableDisplay.catalog?.items.count == historical.count)
    _ = try await firstService.execute(.catalog, vault: scope.binding.vaultID.uuidString)
    #expect(try !AutoFillIndex(directory: suggestions).load().contains { $0.username == "retained-user" })
    let entry = try #require(try await admitted.catalog().first)
    let record = try #require(entry.catalog.references["Login/password"])
    #expect(try await admitted.reveal(itemID: entry.itemID, recordID: record) == SecretBytes(utf8: "session-secret"))
    #expect(try await joiningRepository.pendingMutations(account: scope.binding.account).isEmpty)
    admitted.lock()
    let reopened = try EncryptedItemRepository(storeURL: joiningURL)
    let restarted = try await ItemVaultBootstrap(repository: reopened, trustStore: trust, scope: scope, device: restartJoining).open()
    #expect(try await restarted.reveal(itemID: entry.itemID, recordID: record) == SecretBytes(utf8: "session-secret"))
    #expect(try trust.records(container: scope.container, environment: scope.environment, account: scope.binding.account).count == 1)
    ownerSession.lock(); restarted.lock()
}
