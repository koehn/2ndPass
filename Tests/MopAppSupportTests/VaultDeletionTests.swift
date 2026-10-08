import Foundation
import Synchronization
import Testing
import MopCore
import MopVaultNext
@testable import MopSync
@testable import MopAppSupport

private actor DeletionServer: VaultDeletionTransport {
    var notices: [UUID: Data] = [:]
    var deleted: Set<UUID> = []
    var loseResponse = false
    var failDelete = false
    func configure(loseResponse: Bool = false, failDelete: Bool = false) { self.loseResponse = loseResponse; self.failDelete = failDelete }
    func read(vaultID: UUID) async throws -> Data? { notices[vaultID] }
    func publish(vaultID: UUID, notice: Data) async throws -> Data {
        notices[vaultID] = notices[vaultID] ?? notice
        if loseResponse { throw MopError.cloudUnavailable }
        return notices[vaultID]!
    }
    func deleteZone(address: VaultCloudAddress) async throws {
        if failDelete { throw MopError.cloudUnavailable }
        deleted.insert(address.vaultID)
    }
    func install(_ bytes: Data, vault: UUID) { notices[vault] = bytes }
}
private actor DeletionDriver: ItemVaultRuntimeDriver {
    private(set) var stops = 0
    func start(automaticallySync: Bool) async throws {}
    func stop() async { stops += 1 }
    func setUploadsAllowed(_ allowed: Bool) async {}
    func requestForegroundSync() async throws -> DurableSyncRequest {
        .init(account: "deletion-test", database: "private", generation: 1, reason: .manual)
    }
}

private final class DeletionFixture: @unchecked Sendable {
    let directory: URL
    let repository: EncryptedItemRepository
    let inventory = MemoryItemInventory()
    let owner: SessionDevice
    let server = DeletionServer()
    let cleanupFails = Mutex(false)
    let cleanups = Mutex<[UUID]>([])
    let validAccount = Mutex(true)
    let drivers = Mutex<[DeletionDriver]>([])
    let context: ItemVaultRuntimeContext
    init() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("deletion-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
        owner = try SessionDevice()
        context = ItemVaultRuntimeContext(container: "iCloud.test", environment: "Development", account: "deletion-test",
            memberID: owner.identity.member, leaseURL: directory.appendingPathComponent("lease"))
    }
    func runtime() throws -> ItemVaultSyncRuntime {
        return try ItemVaultSyncRuntime(context: context, repository: repository, trustStore: inventory,
            transport: DomainProvisionServer(), accountValidator: { [self] in validAccount.withLock { $0 } },
            accountAuthorization: DomainAccountAuthorization(), deletionTransport: server,
            deletionCleanup: { [self] state in
                if cleanupFails.withLock({ $0 }) { throw MopError.inputOutput }
                cleanups.withLock { $0.append(state.scope.vaultID) }
            }) { [self] _, _, _, _ in
                let driver = DeletionDriver(); drivers.withLock { $0.append(driver) }; return driver
            }
    }
    func create(_ runtime: ItemVaultSyncRuntime) async throws -> (ItemVaultSetupScope, ItemVaultSession) {
        let scope = ItemVaultSetupScope(container: context.container, environment: context.environment,
            binding: ItemVaultBinding(account: context.account, database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
        let bootstrap = try ItemVaultBootstrap(repository: repository, trustStore: inventory, scope: scope, device: SessionDevice(copying: owner))
        let session = try await bootstrap.create(name: "test")
        try await runtime.register(session: session)
        return (scope, session)
    }
}

@Test func vaultDeletionCompletesAndCannotResurrectAcrossRepositoryInstances() async throws {
    let f = try DeletionFixture(); defer { try? FileManager.default.removeItem(at: f.directory) }
    let runtime = try f.runtime(), (scope, _) = try await f.create(runtime), (other, _) = try await f.create(runtime)
    let before = try await f.repository.items(account: scope.binding.account, vaultID: scope.binding.vaultID)
    #expect(!before.isEmpty)
    #expect(try await runtime.deleteVault(scope.binding.vaultID) == .complete)
    #expect(try await f.repository.items(account: scope.binding.account, vaultID: scope.binding.vaultID).isEmpty)
    #expect(try await f.repository.pendingMutations(account: scope.binding.account).allSatisfy { $0.version.scope.vaultID != scope.binding.vaultID })
    #expect(try await f.repository.vaultInitialization(other.repositoryScope) != nil)
    let reopened = try EncryptedItemRepository(storeURL: f.directory.appendingPathComponent("items.sqlite"))
    #expect(try await reopened.deletion(scope.repositoryScope)?.phase == .complete)
    await #expect(throws: VaultDeletionFailure.deleted) { try await reopened.commitLocalMutation(before[0], authorization: DomainAccountAuthorization()) }
    await #expect(throws: (any Error).self) { _ = try await runtime.session(vaultID: scope.binding.vaultID) }
    #expect(await f.server.deleted == [scope.binding.vaultID])
    #expect(f.cleanups.withLock { $0 } == [scope.binding.vaultID])
    await runtime.stop()
}

@Test func vaultDeletionLostPublicationResponseResumesWithoutNewNotice() async throws {
    let f = try DeletionFixture(); defer { try? FileManager.default.removeItem(at: f.directory) }
    let runtime = try f.runtime(), (scope, _) = try await f.create(runtime)
    await f.server.configure(loseResponse: true)
    #expect(try await runtime.deleteVault(scope.binding.vaultID) == .publishing)
    let published = try #require(try await f.server.read(vaultID: scope.binding.vaultID))
    await runtime.stop()
    let resumed = try f.runtime()
    try await resumed.reconcileDeletions()
    #expect(try await f.repository.deletion(scope.repositoryScope)?.phase == .complete)
    #expect(try await f.server.read(vaultID: scope.binding.vaultID) == published)
    await resumed.stop()
}

@Test func vaultDeletionRetriesCloudAndCleanupFailures() async throws {
    let f = try DeletionFixture(); defer { try? FileManager.default.removeItem(at: f.directory) }
    let runtime = try f.runtime(), (scope, _) = try await f.create(runtime)
    await f.server.configure(failDelete: true)
    #expect(try await runtime.deleteVault(scope.binding.vaultID) == .committed)
    #expect(try await f.repository.items(account: scope.binding.account, vaultID: scope.binding.vaultID).isEmpty)
    await f.server.configure()
    f.cleanupFails.withLock { $0 = true }
    await #expect(throws: (any Error).self) { try await runtime.reconcileDeletions() }
    #expect(try await f.repository.deletion(scope.repositoryScope)?.phase == .cloudDeleted)
    f.cleanupFails.withLock { $0 = false }
    try await runtime.reconcileDeletions()
    #expect(try await f.repository.deletion(scope.repositoryScope)?.phase == .complete)
    await runtime.stop()
}

@Test func vaultDeletionVerifiesRemoteNoticeAndPreservesUnrelatedVault() async throws {
    let f = try DeletionFixture(); defer { try? FileManager.default.removeItem(at: f.directory) }
    let runtime = try f.runtime(), (scope, session) = try await f.create(runtime), (other, _) = try await f.create(runtime)
    let notice = try await session.deletionNotice(scope: scope)
    await f.server.install(try notice.encoded(), vault: scope.binding.vaultID)
    try await runtime.reconcileDeletions()
    #expect(try await f.repository.deletion(scope.repositoryScope)?.phase == .complete)
    #expect(try await f.repository.deletion(other.repositoryScope) == nil)
    #expect(try await f.repository.vaultInitialization(other.repositoryScope) != nil)
    await runtime.stop()
}

@Test func vaultDeletionRejectsWrongBindingAndAccountWithoutErasure() async throws {
    let f = try DeletionFixture(); defer { try? FileManager.default.removeItem(at: f.directory) }
    let runtime = try f.runtime(), (scope, session) = try await f.create(runtime), (other, _) = try await f.create(runtime)
    let notice = try await session.deletionNotice(scope: scope)
    await f.server.install(try notice.encoded(), vault: other.binding.vaultID)
    await #expect(throws: (any Error).self) { try await runtime.reconcileDeletions() }
    #expect(try await f.repository.deletion(other.repositoryScope) == nil)
    f.validAccount.withLock { $0 = false }
    await #expect(throws: MopError.cloudAccount) { _ = try await runtime.deleteVault(scope.binding.vaultID) }
    #expect(try await f.repository.deletion(scope.repositoryScope) == nil)
    await runtime.stop()
}

@Test func vaultDeletionAssetCleanupUsesReceiptIDsAndPreservesOtherAccounts() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("deletion-assets-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let assets = root.appendingPathComponent("EncryptedAssets")
    try LocalFile.privateDirectory(assets)
    let removed = UUID(), retained = UUID(), vault = UUID()
    let deletedFile = assets.appendingPathComponent(removed.uuidString + "-chunk.ciphertext")
    let retainedFile = assets.appendingPathComponent(retained.uuidString + "-chunk.ciphertext")
    try LocalFile.write(Data("deleted ciphertext".utf8), to: deletedFile)
    try LocalFile.write(Data("unrelated ciphertext".utf8), to: retainedFile)
    try ItemVaultDeletionCleanup.removeAssets(directory: root, account: "one", vaultID: vault, assetVersions: [removed])
    #expect(!FileManager.default.fileExists(atPath: deletedFile.path))
    #expect(try LocalFile.read(retainedFile, privateFile: true) == Data("unrelated ciphertext".utf8))
    try ItemVaultDeletionCleanup.removeAssets(directory: root, account: "one", vaultID: vault, assetVersions: [removed])
}

@Test func vaultDeletionRespectsAnotherProcessesSynchronizationLease() async throws {
    let f = try DeletionFixture(); defer { try? FileManager.default.removeItem(at: f.directory) }
    let runtime = try f.runtime(), (scope, _) = try await f.create(runtime)
    let lease = try SynchronizationLease(url: f.context.leaseURL)
    await #expect(throws: CloudSyncAdapterError.engineAlreadyOwned) { _ = try await runtime.deleteVault(scope.binding.vaultID) }
    #expect(try await f.repository.deletion(scope.repositoryScope) == nil)
    #expect(try await f.repository.vaultInitialization(scope.repositoryScope) != nil)
    withExtendedLifetime(lease) {}
    await runtime.stop()
}

@Test func vaultDeletionRetainsHistoricalAssetIDsUntilCleanupCompletes() async throws {
    let f = try DeletionFixture(); defer { try? FileManager.default.removeItem(at: f.directory) }
    let runtime = try f.runtime(), (scope, _) = try await f.create(runtime)
    let initial = try #require(try await f.repository.pendingMutations(account: scope.binding.account).first)
    try await f.repository.acknowledge(mutationID: initial.id, account: scope.binding.account, serverSystemFields: Data([1]))
    f.cleanupFails.withLock { $0 = true }
    #expect(try await runtime.deleteVault(scope.binding.vaultID) == .cloudDeleted)
    #expect(try await f.repository.deletion(scope.repositoryScope)?.assetVersions.contains(initial.version.versionID) == true)
    f.cleanupFails.withLock { $0 = false }
    try await runtime.reconcileDeletions()
    let marker = try #require(try await f.repository.deletion(scope.repositoryScope))
    #expect(marker.assetVersions.isEmpty && marker.notice.count == 32)
    await runtime.stop()
}

@Test func vaultDeletionDiscoveryPreservesSynchronizationOfRemainingVaults() async throws {
    let f = try DeletionFixture(); defer { try? FileManager.default.removeItem(at: f.directory) }
    let runtime = try f.runtime(), (scope, session) = try await f.create(runtime), (other, _) = try await f.create(runtime)
    try await runtime.start()
    let initial = try #require(f.drivers.withLock { $0.first })
    try await runtime.reconcileDeletions()
    #expect(await initial.stops == 0)
    #expect(f.drivers.withLock { $0.count } == 1)
    await f.server.install(try await session.deletionNotice(scope: scope).encoded(), vault: scope.binding.vaultID)
    try await runtime.reconcileDeletions()
    #expect(await initial.stops == 1)
    #expect(f.drivers.withLock { $0.count } >= 2)
    #expect(try await runtime.session(vaultID: other.binding.vaultID).isUnlocked)
    await runtime.stop()
}
