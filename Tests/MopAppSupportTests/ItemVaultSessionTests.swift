import CloudKit
import CryptoKit
import Foundation
import Synchronization
import Testing
import MopCore
@testable import MopSync
@testable import MopVaultNext
@testable import MopAppSupport

final class SessionUnwrapCounter: Sendable {
    let value = Mutex(0)
    let failure = Mutex<MopError?>(nil)
}

final class SessionDevice: DeviceOperations {
    let identity: DevicePublicKey
    private var encryption: P256.KeyAgreement.PrivateKey?
    private var signing: P256.Signing.PrivateKey?
    private let unwraps: SessionUnwrapCounter
    var unwrapCount: Int { unwraps.value.withLock { $0 } }
    init(member: UUID = UUID()) throws {
        unwraps = SessionUnwrapCounter()
        let encryption = P256.KeyAgreement.PrivateKey(), signing = P256.Signing.PrivateKey()
        identity = try DevicePublicKey(member: member, encryption: encryption.publicKey.x963Representation, signing: signing.publicKey.x963Representation)
        self.encryption = encryption; self.signing = signing
    }
    init(copying source: SessionDevice, unwrapCounter: SessionUnwrapCounter = SessionUnwrapCounter()) {
        unwraps = unwrapCounter
        identity = source.identity
        encryption = source.encryption
        signing = source.signing
    }
    func sign(_ bytes: Data) throws -> Data {
        guard let signing else { throw MopError.authentication }
        return try signing.signature(for: bytes).rawRepresentation
    }
    func unwrap(_ envelope: KeyEnvelope, context: Data) throws -> SymmetricKey {
        guard let encryption else { throw MopError.authentication }
        unwraps.value.withLock { $0 += 1 }
        if let failure = unwraps.failure.withLock({ $0 }) { throw failure }
        return try envelope.open(using: encryption, context: context)
    }
    func close() { encryption = nil; signing = nil }
}

@MainActor private func awaitItemView(_ predicate: () -> Bool) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(3))
    while !predicate() {
        guard ContinuousClock.now < deadline else { throw CocoaError(.coderInvalidValue) }
        await Task.yield()
    }
}

@MainActor @Test func itemVaultObservationUpdatesCommittedItemsWithoutDecryptingStatusOnlyChanges() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-observation-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite/ContentPreview3/Content3.sqlite"))
    let owner = try SessionDevice()
    let vault = try sessionAuthority(owner: owner)
    let authority = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
    let history = try TrustedMembershipHistory(genesis: authority, vault: vault.id, pinnedDigest: authority.digest())
    let archive = try sessionArchive()
    let components = try ContentItemArchive.components(archive)
    let competing = try ContentEnvelope.seal(components.values, vault: vault.id, item: components.item, history: history, signer: owner)
    let binding = ItemVaultBinding(account: "observation", database: "private", zoneOwner: "__defaultOwner__", vaultID: vault.id)
    let session = try await currentTestSession(repository: repository, binding: binding, history: history, device: owner)
    let first = try await session.save(archive, expectedBase: nil)
    let state = ItemVaultViewState(repository: repository, session: session)
    state.start()
    try await awaitItemView { state.status == .ready && state.entries.count == 1 }
    #expect(state.entries.first?.versionID == first.version.versionID)
    #expect(state.pendingItems.contains(first.version.scope.itemID))
    let beforeAcknowledgement = owner.unwrapCount
    try await confirmCurrentMutation(first, repository: repository)
    try await awaitItemView { state.pendingItems.isEmpty }
    #expect(owner.unwrapCount == beforeAcknowledgement)
    var catalog = try #require(state.entries.first?.catalog)
    catalog.item.metadata = ItemMetadata(favorite: true)
    let next = try await state.edit(itemID: first.version.scope.itemID, expectedBase: first.version.versionID, catalog: catalog)
    try await awaitItemView { state.entries.first?.versionID == next.version.versionID }
    #expect(state.entries.first?.catalog.item.metadata?.favorite == true)
    let beforeStatusChanges = owner.unwrapCount
    try await repository.saveEngineState(Data([1]), account: binding.account, database: "private")
    _ = try await branchCurrentPublication(competing, repository: repository, scope: first.version.scope, history: history, fields: Data([9]))
    try await awaitItemView { state.conflictedItems.contains(first.version.scope.itemID) }
    #expect(owner.unwrapCount == beforeStatusChanges)
    state.lock()
    #expect(state.entries.isEmpty && state.conflictedItems.isEmpty && state.pendingItems.isEmpty && state.savingItems.isEmpty && state.status == .locked)
    state.start()
    #expect(state.status == .locked)
    let initiallyLocked = ItemVaultViewState(repository: repository, session: session)
    initiallyLocked.start()
    #expect(initiallyLocked.status == .locked && initiallyLocked.entries.isEmpty)
    await #expect(throws: MopError.authentication) { try await session.catalog() }
}

func sessionAuthority(owner: SessionDevice) throws -> (id: UUID, membership: Membership) {
    (UUID(), try Membership(accounts: [AccountMember(id: owner.identity.member, role: .owner, devices: [owner.identity])]))
}
func sessionArchive() throws -> PortableVaultArchive {
    let itemID = UUID().uuidString, recordID = UUID().uuidString
    return PortableVaultArchive(name: "source", items: [VaultItem(name: "Login", type: .login, fields: [ItemField(path: "password", type: .password)])],
        itemIDs: ["Login": itemID], references: ["Login/password": recordID],
        records: [recordID: PortableArchiveRecord(itemID: itemID, bytes: SecretBytes(utf8: "session-secret"))])
}

private enum SetupTestFailure: Error { case interruptedAfterPin, trustUnavailable }
private final class TestItemTrustStore: ItemVaultTrustStore {
    private struct State { var record: ItemVaultSetupRecord?; var interrupt = false; var failReads = false }
    private let state = Mutex(State())
    func load(scope: ItemVaultSetupScope) throws -> ItemVaultSetupRecord? {
        try state.withLock {
            if $0.failReads { throw SetupTestFailure.trustUnavailable }
            return $0.record
        }
    }
    func reserve(_ candidate: ItemVaultSetupRecord) throws -> ItemVaultSetupRecord {
        try state.withLock {
            if $0.record == nil { $0.record = candidate }
            if $0.interrupt { $0.interrupt = false; throw SetupTestFailure.interruptedAfterPin }
            return $0.record!
        }
    }
    func interruptAfterPin() { state.withLock { $0.interrupt = true } }
    func failReads(_ value: Bool) { state.withLock { $0.failReads = value } }
}

actor DomainProvisionServer: VaultProvisioningTransport {
    private var zones: Set<UUID> = []
    private var genesis: [UUID: ProvisioningCloudRecord] = [:]
    private var head: [UUID: ProvisioningCloudRecord] = [:]
    private(set) var creates = 0
    func zoneExists(binding: VaultProvisioningBinding) async throws -> Bool { zones.contains(binding.scope.vaultID) }
    func createZone(binding: VaultProvisioningBinding) async throws { zones.insert(binding.scope.vaultID); creates += 1 }
    func readControl(_ kind: VaultControlRecordKind, binding: VaultProvisioningBinding) async throws -> ProvisioningCloudRecord? {
        switch kind { case .genesis: genesis[binding.scope.vaultID]; case .head: head[binding.scope.vaultID] }
    }
    func createControl(_ kind: VaultControlRecordKind, binding: VaultProvisioningBinding, bytes: Data) async throws -> ProvisioningCloudRecord {
        let value = ProvisioningCloudRecord(bytes: bytes, systemFields: Data([1]))
        switch kind { case .genesis: genesis[binding.scope.vaultID] = value; case .head: head[binding.scope.vaultID] = value }
        return value
    }
}
struct DomainAccountAuthorization: RepositoryWritePermit {
    func withWritePermission<T>(_ body: () throws -> T) throws -> T { try body() }
}

@Test func itemBootstrapResumesPinnedArchiveAfterInterruptionAndPreservesLaterEditsOnRetry() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-bootstrap-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("items.sqlite/ContentPreview3/Content3.sqlite")
    let repository = try EncryptedItemRepository(storeURL: url)
    let archive = try sessionArchive()
    let backup = try PortableArchive.seal(archive)
    let owner = try SessionDevice(), restartOwner = SessionDevice(copying: owner), secondRestartOwner = SessionDevice(copying: owner)
    let scope = ItemVaultSetupScope(container: "iCloud.example.test", environment: "Development",
        binding: ItemVaultBinding(account: "restorer", database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
    let trust = TestItemTrustStore()
    trust.interruptAfterPin()
    let interrupted = try ItemVaultBootstrap(repository: repository, trustStore: trust, scope: scope, device: owner)
    await #expect(throws: SetupTestFailure.interruptedAfterPin) {
        try await interrupted.restore(archiveData: backup.data, recoveryKey: backup.recoveryKey, name: "restored")
    }
    let pin = try #require(try trust.load(scope: scope))
    #expect(try await repository.vaultInitialization(scope.repositoryScope) == nil)
    interrupted.lock()
    let reopened = try EncryptedItemRepository(storeURL: url)
    let resumed = try ItemVaultBootstrap(repository: reopened, trustStore: trust, scope: scope, device: restartOwner)
    let session = try await resumed.restore(archiveData: backup.data, recoveryKey: backup.recoveryKey, name: "restored")
    #expect(try trust.load(scope: scope) == pin)
    let restored = try await session.exportPortableLocalSnapshot()
    #expect(restored.records == archive.records)
    let entry = try #require(try await session.catalog().first)
    _ = try await session.replaceField(itemID: entry.itemID, expectedBase: entry.versionID, path: "password", value: SecretBytes(utf8: "after-import"))
    let latest = try #require(try await session.catalog().first)
    let mutationCount = try await reopened.pendingMutations(account: scope.binding.account).count
    resumed.lock()
    let lostResponseRestart = try ItemVaultBootstrap(repository: EncryptedItemRepository(storeURL: url), trustStore: trust, scope: scope, device: secondRestartOwner)
    let retried = try await lostResponseRestart.restore(archiveData: backup.data, recoveryKey: backup.recoveryKey, name: "restored")
    #expect(try await retried.catalog().first?.versionID == latest.versionID)
    #expect(try await reopened.pendingMutations(account: scope.binding.account).count == mutationCount)
    let currentRecord = try #require(latest.catalog.references["Login/password"])
    #expect(try await retried.reveal(itemID: latest.itemID, recordID: currentRecord) == SecretBytes(utf8: "after-import"))
    await #expect(throws: ItemVaultBootstrapFailure.sourceMismatch) {
        try await lostResponseRestart.restore(archiveData: backup.data, recoveryKey: backup.recoveryKey, name: "other-name")
    }
    let otherBackup = try PortableArchive.seal(archive)
    await #expect(throws: ItemVaultBootstrapFailure.sourceMismatch) {
        try await lostResponseRestart.restore(archiveData: otherBackup.data, recoveryKey: otherBackup.recoveryKey, name: "restored")
    }
    let wrongDevice = try ItemVaultBootstrap(repository: reopened, trustStore: trust, scope: scope, device: SessionDevice())
    await #expect(throws: ItemVaultBootstrapFailure.invalidTrust) { try await wrongDevice.open() }
    let wrongScope = ItemVaultSetupScope(container: scope.container, environment: "Production", binding: scope.binding)
    let wrongNamespace = try ItemVaultBootstrap(repository: reopened, trustStore: trust, scope: wrongScope, device: SessionDevice())
    await #expect(throws: ItemVaultBootstrapFailure.invalidTrust) { try await wrongNamespace.open() }
}

@Test func concurrentIdenticalBootstrapUsesOneAuthorityAndOneCompleteVault() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-bootstrap-race-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("items.sqlite/ContentPreview3/Content3.sqlite")
    let repository = try EncryptedItemRepository(storeURL: url)
    let backup = try PortableArchive.seal(sessionArchive())
    let owner = try SessionDevice(), otherOwner = SessionDevice(copying: owner)
    let scope = ItemVaultSetupScope(container: "iCloud.example.test", environment: "Development",
        binding: ItemVaultBinding(account: "same-restorer", database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
    let trust = TestItemTrustStore()
    let first = try ItemVaultBootstrap(repository: repository, trustStore: trust, scope: scope, device: owner)
    let second = try ItemVaultBootstrap(repository: EncryptedItemRepository(storeURL: url), trustStore: trust, scope: scope, device: otherOwner)
    async let a = first.restore(archiveData: backup.data, recoveryKey: backup.recoveryKey, name: "same")
    async let b = second.restore(archiveData: backup.data, recoveryKey: backup.recoveryKey, name: "same")
    let sessions = try await [a, b]
    let firstEntry = try #require(try await sessions[0].catalog().first)
    let secondEntry = try #require(try await sessions[1].catalog().first)
    #expect(firstEntry.versionID == secondEntry.versionID)
    #expect(try await repository.pendingMutations(account: scope.binding.account).count == 2)
    let pin = try #require(try trust.load(scope: scope))
    #expect(try await repository.vaultInitialization(scope.repositoryScope)?.membershipState == pin.genesis)
    #expect(try await sessions[0].exportPortableLocalSnapshot().records == sessions[1].exportPortableLocalSnapshot().records)
}

@Test func emptyBootstrapCreatesAndReopensOneCachedSessionAndWrongKeyCreatesNoPin() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-bootstrap-empty-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite/ContentPreview3/Content3.sqlite"))
    let scope = ItemVaultSetupScope(container: "iCloud.example.test", environment: "Development",
        binding: ItemVaultBinding(account: "empty", database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
    let trust = TestItemTrustStore()
    let bootstrap = try ItemVaultBootstrap(repository: repository, trustStore: trust, scope: scope, device: SessionDevice())
    let backup = try PortableArchive.seal(sessionArchive())
    await #expect(throws: (any Error).self) {
        try await bootstrap.restore(archiveData: backup.data, recoveryKey: SecretBytes(copying: Data(repeating: 0, count: 32)), name: "empty")
    }
    #expect(try trust.load(scope: scope) == nil)
    #expect(try await repository.vaultInitialization(scope.repositoryScope) == nil)
    var initial: ItemVaultSession? = try await bootstrap.create(name: "empty")
    let same = try await bootstrap.create(name: "empty")
    #expect(initial === same)
    initial = nil
    #expect(same.isUnlocked)
    #expect(try await same.catalog().isEmpty)
    let opened = try await bootstrap.open()
    #expect(opened === same)
    let exported = try await opened.exportPortableLocalSnapshot()
    #expect(exported.name == "empty" && exported.items.isEmpty && exported.records.isEmpty)
    #expect(try await repository.pendingMutations(account: scope.binding.account).count == 1)
}

@Test func conflictPreviewKeepsValuesHiddenAndRequiresCurrentUnlockedReviewToReveal() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-conflict-preview-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite/ContentPreview3/Content3.sqlite"))
    let owner = try SessionDevice()
    let root = try sessionAuthority(owner: owner)
    let authority = try MembershipEnvelope.genesis(vault: root.id, membership: root.membership, owner: owner)
    let digest = try authority.digest()
    let history = try TrustedMembershipHistory(genesis: authority, vault: root.id, pinnedDigest: digest)
    let archive = try sessionArchive()
    var remoteArchive = archive
    let recordID = try #require(archive.references["Login/password"])
    let original = try #require(remoteArchive.records[recordID])
    remoteArchive.records[recordID] = PortableArchiveRecord(itemID: original.itemID, bytes: SecretBytes(utf8: "remote-secret"))
    let components = try ContentItemArchive.components(remoteArchive)
    let remoteEnvelope = try ContentEnvelope.seal(components.values, vault: root.id, item: components.item, history: history, signer: owner)
    let binding = ItemVaultBinding(account: "review", database: "private", zoneOwner: "__defaultOwner__", vaultID: root.id)
    let session = try await currentTestSession(repository: repository, binding: binding, history: history, device: owner)
    let local = try await session.save(archive, expectedBase: nil)
    let conflict = try await branchCurrentPublication(remoteEnvelope, repository: repository, scope: local.version.scope, history: history, fields: Data([1]))
    let preview = try await session.conflictPreview(conflict)
    #expect(preview.local.editOrigin != nil)
    #expect(preview.remote.editOrigin == nil) // Existing envelopes remain readable.
    #expect(preview.localDeviceName == preview.remoteDeviceName) // Same known author.
    #expect(preview.localUpdatedAt != nil)
    #expect(preview.remoteUpdatedAt == nil) // Never fabricate a time for older items.
    #expect(preview.local.item.fields.allSatisfy { $0.value == nil })
    #expect(preview.remote.item.fields.allSatisfy { $0.value == nil })
    #expect(try await session.revealConflict(conflict, side: .local, recordID: recordID) == SecretBytes(utf8: "session-secret"))
    #expect(try await session.revealConflict(conflict, side: .remote, recordID: recordID) == SecretBytes(utf8: "remote-secret"))
    let changed = try await branchCurrentPublication(remoteEnvelope, repository: repository, scope: local.version.scope, history: history, fields: Data([2]))
    let unwraps = owner.unwrapCount
    await #expect(throws: ItemRepositoryError.staleConflict) { try await session.conflictPreview(conflict) }
    await #expect(throws: ItemRepositoryError.staleConflict) { try await session.revealConflict(conflict, side: .remote, recordID: recordID) }
    #expect(owner.unwrapCount == unwraps)
    _ = try await session.replaceField(itemID: local.version.scope.itemID, expectedBase: local.version.versionID,
        path: "password", value: SecretBytes(utf8: "new-local-secret"))
    let afterLocalEdit = owner.unwrapCount
    await #expect(throws: ItemRepositoryError.staleConflict) { try await session.conflictPreview(changed) }
    await #expect(throws: ItemRepositoryError.staleConflict) { try await session.revealConflict(changed, side: .remote, recordID: recordID) }
    #expect(owner.unwrapCount == afterLocalEdit)
    session.lock()
    await #expect(throws: MopError.authentication) { try await session.conflictPreview(changed) }
    await #expect(throws: MopError.authentication) { try await session.revealConflict(changed, side: .remote, recordID: recordID) }
}

@Test func itemVaultSessionDurablySavesRevealsExportsAndLocks() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-session-test-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite/ContentPreview3/Content3.sqlite"))
    let owner = try SessionDevice()
    let root = try sessionAuthority(owner: owner)
    let authority = try MembershipEnvelope.genesis(vault: root.id, membership: root.membership, owner: owner)
    let history = try TrustedMembershipHistory(genesis: authority, vault: root.id, pinnedDigest: authority.digest())
    let binding = ItemVaultBinding(account: "session-account", database: "private", zoneOwner: "__defaultOwner__", vaultID: root.id)
    let archive = try sessionArchive()
    let components = try ContentItemArchive.components(archive)
    let remoteEnvelope = try ContentEnvelope.seal(components.values, vault: root.id, item: components.item, history: history, signer: owner)
    let session = try await currentTestSession(repository: repository, binding: binding, history: history, device: owner)
    _ = try await session.saveMetadata(VaultMetadata(name: "session"), expectedBase: nil)
    let receipt = try await session.save(archive, expectedBase: nil)
    let itemID = try #require(archive.itemIDs.values.first.flatMap(UUID.init(uuidString:)))
    let recordID = try #require(archive.references["Login/password"])
    let catalog = try await session.catalog()
    #expect(catalog.count == 1)
    #expect(catalog.first?.itemID == itemID)
    #expect(catalog.first?.versionID == receipt.version.versionID)
    #expect(try await session.reveal(itemID: itemID, recordID: recordID) == SecretBytes(utf8: "session-secret"))
    let pending = try await repository.pendingMutations(account: "session-account")
    #expect(pending.count == 2)
    let exported = try await session.exportPortableLocalSnapshot()
    #expect(exported.records == archive.records)
    #expect(exported.name == "session")
    let secondSave = try await session.save(archive, expectedBase: receipt.version.versionID)
    #expect(secondSave.version.generation == 2)
    #expect(secondSave.version.baseVersionID == receipt.version.versionID)
    _ = try await branchCurrentPublication(remoteEnvelope, repository: repository, scope: receipt.version.scope, history: history, fields: Data([9]))
    await #expect(throws: (any Error).self) { try await session.exportPortableLocalSnapshot() }
    await #expect(throws: (any Error).self) { try await session.save(archive, expectedBase: nil) }
    session.lock()
    await #expect(throws: (any Error).self) { try await session.reveal(itemID: itemID, recordID: recordID) }
    await #expect(throws: (any Error).self) { try await session.exportPortableLocalSnapshot() }
    await #expect(throws: (any Error).self) { try await session.save(archive, expectedBase: receipt.version.versionID) }
    #expect(try await repository.pendingMutations(account: "session-account").count == 3)
    session.invalidate()
}

@Test func localHealthCacheAuthenticatesButDoesNotTransferDuringEnrollment() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-health-sync-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("owner.sqlite/ContentPreview3/Content3.sqlite"))
    let owner = try SessionDevice(), joining = try SessionDevice(member: owner.identity.member)
    let root = try sessionAuthority(owner: owner)
    let genesis = try MembershipEnvelope.genesis(vault: root.id, membership: root.membership, owner: owner)
    let history = try TrustedMembershipHistory(genesis: genesis, vault: root.id, pinnedDigest: genesis.digest())
    let binding = ItemVaultBinding(account: "health-sync", database: "private", zoneOwner: "__defaultOwner__", vaultID: root.id)
    let session = try await currentTestSession(repository: repository, binding: binding, history: history, device: SessionDevice(copying: owner))
    _ = try await session.saveMetadata(VaultMetadata(name: "test"), expectedBase: nil)
    let archive = try sessionArchive()
    let item = try await session.save(archive, expectedBase: nil)
    let record = try #require(archive.references.values.first), now = Date()
    var check = CachedPasswordCheck(record: record, context: ["Login", ""], weak: false, exposed: true,
        checkedAt: now, breachCheckedAt: now, reuseGroup: nil, scope: String(repeating: "a", count: 64), batch: UUID())
    check.breachResult = CachedBreachResult(exposed: true, checkedAt: now)
    check.strengthResult?.quality = .veryStrong
    let saved = try #require(try await session.saveHealthChecks([check], itemID: item.version.scope.itemID, expectedItemVersion: item.version.versionID))
    await #expect(throws: ItemRepositoryError.staleLocalVersion) {
        try await session.saveHealthChecks([check], itemID: item.version.scope.itemID, expectedItemVersion: UUID())
    }
    #expect(try await session.healthChecks() == [check])
    let unwraps = SessionUnwrapCounter()
    let reopened = try await currentTestSession(repository: repository, binding: binding, history: history,
        device: SessionDevice(copying: owner, unwrapCounter: unwraps))
    #expect(try await reopened.healthChecks() == [check])
    #expect(unwraps.value.withLock { $0 } == 1) // One local index key, no companion-key unwrap.
    #expect(try await reopened.healthChecks() == [check])
    #expect(unwraps.value.withLock { $0 } == 1)
    reopened.lock()
    // A damaged derived cache is unknown and replaceable, never a secret failure.
    let damaged = EncryptedItemVersion(scope: saved.scope, baseVersionID: saved.versionID,
        ciphertext: Data([0]), generation: saved.generation + 1, healthItemID: saved.healthItemID)
    try await repository.saveLocalHealth(damaged, expectedParent: item.version.versionID,
                                        authorization: DomainAccountAuthorization())
    #expect(try await session.healthChecks().isEmpty)
    _ = try await session.saveHealthChecks([check], itemID: item.version.scope.itemID, expectedItemVersion: item.version.versionID)
    #expect(try await session.healthChecks() == [check])
    #expect(try await repository.pendingMutations(account: binding.account).allSatisfy { $0.version.healthItemID == nil })
    #expect(try await repository.item(item.version.scope) == item.version)
}

private struct SyncedHealthBackend: ItemVaultServiceBackend {
    let session: ItemVaultSession
    func inventory() async throws -> [VaultDescriptor] { [] }
    func open(_ vaultID: UUID) async throws -> ItemVaultSession { session }
    func create(name: String, id: UUID, archiveData: Data?, recoveryKey: SecretBytes?) async throws -> ItemVaultSession { throw MopError.invalidVault }
    func requestSync() async throws {}
    func lock() { session.lock() }
}

private struct ContentStorageTestPermit: RepositoryWritePermit {
    func withWritePermission<T>(_ body: () throws -> T) throws -> T { try body() }
}

@MainActor @Test func grantBackedStorageAuthenticatesBeforeAtomicCommitAndKeepsEnrollmentIndependent() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-content-adapter-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let repository = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
    let storage = GrantBackedContentStorage(repository: repository)
    let owner = try SessionDevice(), joining = try SessionDevice(member: owner.identity.member)
    let membership = try Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity])])
    let genesis = try MembershipEnvelope.genesis(membership: membership, owner: owner)
    let original = try TrustedMembershipHistory(genesis: genesis, vault: genesis.header.vault, pinnedDigest: genesis.digest())
    var history = original
    let scope = ItemScope(account: "a", vaultID: history.vault, itemID: UUID())
    let vaultScope = VaultScope(account: "a", vaultID: history.vault)
    try await storage.setAuthority(scope: vaultScope, expected: nil, history: history, authorization: ContentStorageTestPermit())
    let first = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let ownerGrant = try #require(first.grants.first)
    let successor = try MembershipEnvelope.successor(of: history.current,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])]), owner: owner)
    try history.append(successor)
    try await storage.setAuthority(scope: vaultScope, expected: original, history: history, authorization: ContentStorageTestPermit())
    // Prepared before admission, still valid under additive current authority.
    let saved = try await storage.commit(first.content, grants: first.grants, scope: scope, history: history, authorization: ContentStorageTestPermit())
    let joiningGrant = try ContentKeyGrant.extendingAccess(to: joining.identity, content: first.content,
        existingGrant: ownerGrant, history: history, decryptor: owner, signer: owner)
    try await storage.commitGrant(joiningGrant, for: first.content, scope: scope, history: history, authorization: ContentStorageTestPermit())
    #expect(try await repository.pendingMutations(account: "a") == [saved])
    #expect(try await repository.missingContentGrants(scope: vaultScope).isEmpty)
    let differentScope = ItemScope(account: "a", vaultID: history.vault, itemID: UUID())
    await #expect(throws: MopError.vaultUntrusted) {
        try await storage.commit(first.content, grants: first.grants, scope: differentScope, history: history, authorization: ContentStorageTestPermit())
    }
    #expect(try await repository.contentState(scope: differentScope) == nil)
    let removed = try MembershipEnvelope.successor(of: history.current,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity])],
            removedDevices: [joining.identity.device]), owner: owner)
    let beforeRemoval = history
    try history.append(removed)
    try await storage.setAuthority(scope: vaultScope, expected: beforeRemoval, history: history, authorization: ContentStorageTestPermit())
    #expect(try GrantBackedContentStorage.recipientPolicy(history: history).keyAuthority == removed.digest())
    await #expect(throws: MopError.vaultUntrusted) {
        try await storage.commitGrant(joiningGrant, for: first.content, scope: scope, history: history, authorization: ContentStorageTestPermit())
    }
    let rotated = try first.content.rotateKey(grant: ownerGrant, history: history, decryptor: owner, signer: owner)
    _ = try await storage.commit(rotated.content, grants: rotated.grants, scope: scope, history: history, authorization: ContentStorageTestPermit())
    #expect(try await repository.contentState(scope: scope)?.keyGeneration == rotated.content.header.keyGeneration)
}

@MainActor private func previewInboxFixture() async throws -> (URL, EncryptedItemRepository, SessionDevice, TrustedMembershipHistory, ItemScope) {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-inbox-" + UUID().uuidString)
    let repository = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
    let owner = try SessionDevice()
    let membership = try Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity])])
    let genesis = try MembershipEnvelope.genesis(membership: membership, owner: owner)
    let history = try TrustedMembershipHistory(genesis: genesis, vault: genesis.header.vault, pinnedDigest: genesis.digest())
    let scope = ItemScope(account: "a", vaultID: history.vault, itemID: UUID())
    try await GrantBackedContentStorage(repository: repository).setAuthority(scope: VaultScope(account: "a", vaultID: history.vault),
        expected: nil, history: history, authorization: ContentStorageTestPermit())
    return (root, repository, owner, history, scope)
}

private func preparedInboxContent(_ content: ContentEnvelope, scope: ItemScope, history: TrustedMembershipHistory) throws -> PreparedContentVersion {
    try PreparedContentVersion(version: EncryptedItemVersion(scope: scope, versionID: content.header.version, baseVersionID: content.header.base,
        ciphertext: content.encoded(), isTombstone: content.header.isTombstone, generation: content.header.generation),
        keyGeneration: content.header.keyGeneration, contentRevision: content.header.contentRevision, membership: content.header.membership,
        keyAuthority: GrantBackedContentStorage.keyAuthority(history: history, at: content.header.keyMembership))
}
private func preparedInboxGrant(_ grant: ContentKeyGrant, scope: ItemScope) throws -> PreparedContentGrant {
    try PreparedContentGrant(scope: scope, keyGeneration: grant.keyGeneration, recipient: grant.recipient, identifier: grant.identifier, bytes: grant.encoded())
}

@MainActor @Test func previewInboxReceivesGrantBeforeContentAndAppliesWhileLocked() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let publication = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let content = try preparedInboxContent(publication.content, scope: scope, history: history)
    let grant = try preparedInboxGrant(#require(publication.grants.first), scope: scope)
    let incomingGrant = try ContentRecordTransport.materialize(ContentRecordTransport.grant(grant), account: "a")
    let version = try ContentRecordTransport.materialize(ContentRecordTransport.content(content, kind: .version), account: "a")
    let head = try ContentRecordTransport.materialize(ContentRecordTransport.content(content, kind: .head), account: "a")
    let inbox = GrantBackedContentInbox(repository: repository, account: "a")
    owner.close()
    try await repository.stageIncomingBatch([incomingGrant], checkpoint: Data([1]), account: "a", database: "private", permit: ContentStorageTestPermit())
    guard case .waiting(let dependencies) = try await inbox.process(id: incomingGrant.id, history: history, permit: ContentStorageTestPermit()) else {
        Issue.record("A grant must wait for content with its key generation"); return
    }
    #expect(dependencies.first?.kind == .content)
    _ = try await repository.stageIncoming(version)
    _ = try await inbox.process(id: version.id, history: history, permit: ContentStorageTestPermit())
    #expect(try await repository.item(scope) == nil)
    _ = try await inbox.process(id: incomingGrant.id, history: history, permit: ContentStorageTestPermit())
    #expect(try await repository.contentGrantDelivery(grant) == .cloudConfirmed)
    _ = try await repository.stageIncoming(head)
    _ = try await inbox.process(id: head.id, history: history, permit: ContentStorageTestPermit())
    #expect(try await repository.item(scope) == content.version)
    #expect(owner.unwrapCount == 0)
    _ = try await repository.stageIncoming(head) // token rollback replays safely
    _ = try await inbox.process(id: head.id, history: history, permit: ContentStorageTestPermit())
    #expect(try await repository.contentVersions(scope: scope).count == 1)
}

@MainActor @Test func previewInboxWaitsForSkippedAncestorAndNeverInstallsAnOldHead() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try ContentEnvelope.seal(["password": "one"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let grant = try #require(first.grants.first)
    let second = try first.content.editing(["password": "two"], grant: grant, history: history, device: owner)
    let third = try second.editing(["password": "three"], grant: grant, history: history, device: owner)
    let inbox = GrantBackedContentInbox(repository: repository, account: "a")
    func event(_ content: ContentEnvelope, _ kind: ContentRecordKind = .head) throws -> IncomingRecord {
        try ContentRecordTransport.materialize(ContentRecordTransport.content(preparedInboxContent(content, scope: scope, history: history), kind: kind), account: "a")
    }
    let old = try event(first.content), newest = try event(third), missing = try event(second, .version)
    _ = try await repository.stageIncoming(old)
    _ = try await inbox.process(id: old.id, history: history, permit: ContentStorageTestPermit())
    _ = try await repository.stageIncoming(newest)
    guard case .waiting = try await inbox.process(id: newest.id, history: history, permit: ContentStorageTestPermit()) else { Issue.record("Missing ancestry must wait"); return }
    #expect(try await repository.item(scope)?.versionID == first.content.header.version)
    _ = try await repository.stageIncoming(missing)
    _ = try await inbox.process(id: missing.id, history: history, permit: ContentStorageTestPermit())
    _ = try await inbox.process(id: newest.id, history: history, permit: ContentStorageTestPermit())
    #expect(try await repository.item(scope)?.versionID == third.header.version)
    _ = try await repository.stageIncoming(old)
    _ = try await inbox.process(id: old.id, history: history, permit: ContentStorageTestPermit())
    #expect(try await repository.item(scope)?.versionID == third.header.version)
}

@MainActor @Test func previewInboxSupersedesIdenticalEditsButPreservesDifferentBranches() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try ContentEnvelope.seal(["password": "base"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let grant = try #require(first.grants.first)
    let storage = GrantBackedContentStorage(repository: repository), inbox = GrantBackedContentInbox(repository: repository, account: "a")
    _ = try await storage.commit(first.content, grants: first.grants, scope: scope, history: history, authorization: ContentStorageTestPermit())
    let local = try first.content.editing(["password": "same"], grant: grant, history: history, device: owner)
    let saved = try await storage.commit(local, scope: scope, history: history, authorization: ContentStorageTestPermit())
    let remote = try first.content.editing(["password": "same"], grant: grant, history: history, device: owner)
    let incoming = try ContentRecordTransport.materialize(ContentRecordTransport.content(preparedInboxContent(remote, scope: scope, history: history), kind: .head), account: "a")
    _ = try await repository.stageIncoming(incoming)
    guard case .authorization = try await inbox.process(id: incoming.id, history: history, permit: ContentStorageTestPermit()) else { Issue.record("Comparison requires authorization"); return }
    let comparison = ContentComparisonSession(authorization: ContentStorageTestPermit()) { @MainActor lhs, rhs in
        try lhs.hasIdenticalContents(to: rhs, grant: grant, otherGrant: grant, history: history, device: owner)
    }
    _ = try await inbox.process(id: incoming.id, history: history, permit: ContentStorageTestPermit(), comparison: comparison)
    #expect(try await repository.item(scope)?.versionID == remote.header.version)
    #expect(try await repository.mutationReceipt(id: saved.id, account: "a")?.status == .superseded)
    let competing = try first.content.editing(["password": "different"], grant: grant, history: history, device: owner)
    let conflict = try ContentRecordTransport.materialize(ContentRecordTransport.content(preparedInboxContent(competing, scope: scope, history: history), kind: .head), account: "a")
    _ = try await repository.stageIncoming(conflict)
    guard case .attention(.conflict) = try await inbox.process(id: conflict.id, history: history, permit: ContentStorageTestPermit(), comparison: comparison) else {
        Issue.record("Different branches must survive"); return
    }
    #expect(try await repository.contentBranches(scope: scope).map(\.version.versionID) == [competing.header.version])
    #expect(try await repository.item(scope)?.versionID == remote.header.version)
}

@MainActor @Test func previewInboxMissingMembershipDefersAndInvalidPayloadDoesNotBlockOtherItems() async throws {
    let (root, repository, owner, original, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    var history = original
    let joining = try SessionDevice(member: owner.identity.member)
    try history.append(MembershipEnvelope.successor(of: history.current,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])]), owner: owner))
    let publication = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: scope.itemID, history: history, signer: joining)
    let record = try ContentRecordTransport.content(preparedInboxContent(publication.content, scope: scope, history: history), kind: .head)
    let incoming = try ContentRecordTransport.materialize(record, account: "a")
    let inbox = GrantBackedContentInbox(repository: repository, account: "a")
    _ = try await repository.stageIncoming(incoming)
    guard case .waiting(let dependencies) = try await inbox.process(id: incoming.id, history: original, permit: ContentStorageTestPermit()) else { Issue.record("Missing authority must defer"); return }
    #expect(dependencies.first?.kind == .membership)
    try await GrantBackedContentStorage(repository: repository).setAuthority(scope: VaultScope(account: "a", vaultID: history.vault),
        expected: original, history: history, authorization: ContentStorageTestPermit())
    _ = try await inbox.process(id: incoming.id, history: history, permit: ContentStorageTestPermit())
    #expect(try await repository.item(scope)?.versionID == publication.content.header.version)
    record["payload"] = Data("invalid signature and payload".utf8) as CKRecordValue
    let invalid = try ContentRecordTransport.materialize(record, account: "a")
    _ = try await repository.stageIncoming(invalid)
    guard case .attention(.invalidAuthority) = try await inbox.process(id: invalid.id, history: history, permit: ContentStorageTestPermit()) else { Issue.record("Invalid bytes must quarantine"); return }
    #expect(try await repository.quarantineSummary(account: "a").records == 1)
    #expect(try await repository.item(scope)?.versionID == publication.content.header.version)
    _ = try await repository.stageIncoming(invalid)
    #expect(try await repository.operations(account: "a", database: "private").first { $0.id == invalid.operationID }?.state == .ready)
    _ = try await inbox.process(id: invalid.id, history: history, permit: ContentStorageTestPermit())
    #expect(try await repository.quarantineSummary(account: "a").records == 1)
    let otherScope = ItemScope(account: "a", vaultID: history.vault, itemID: UUID())
    let other = try ContentEnvelope.seal(["password": "other"], vault: history.vault, item: otherScope.itemID, history: history, signer: owner)
    let otherEvent = try ContentRecordTransport.materialize(ContentRecordTransport.content(preparedInboxContent(other.content, scope: otherScope, history: history), kind: .head), account: "a")
    _ = try await repository.stageIncoming(otherEvent)
    _ = try await inbox.process(id: otherEvent.id, history: history, permit: ContentStorageTestPermit())
    #expect(try await repository.item(otherScope)?.versionID == other.content.header.version)
}

@MainActor @Test func previewInboxOwnsDownloadedAssetBytesBeforeCheckpointAndReopen() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let publication = try ContentEnvelope.seal(["attachment": SecretBytes(copying: Data(repeating: 7, count: 600_000))],
        vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let content = try preparedInboxContent(publication.content, scope: scope, history: history)
    let asset = root.appendingPathComponent("downloaded-asset")
    try content.version.ciphertext.write(to: asset)
    let record = try ContentRecordTransport.content(content, kind: .head, assetURL: asset)
    let incoming = try ContentRecordTransport.materialize(record, account: "a")
    try await repository.stageIncomingBatch([incoming], checkpoint: Data([8]), account: "a", database: "private", permit: ContentStorageTestPermit())
    try FileManager.default.removeItem(at: asset)
    let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
    _ = try await GrantBackedContentInbox(repository: reopened, account: "a").process(id: incoming.id, history: history, permit: ContentStorageTestPermit())
    #expect(try await reopened.item(scope)?.ciphertext == content.version.ciphertext)
    #expect(try await reopened.engineState(account: "a", database: "private") == Data([8]))
}

@MainActor @Test func previewInboxLateComparisonCannotReplaceANewLocalEdit() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try ContentEnvelope.seal(["password": "base"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let grant = try #require(first.grants.first)
    let storage = GrantBackedContentStorage(repository: repository)
    _ = try await storage.commit(first.content, grants: first.grants, scope: scope, history: history, authorization: ContentStorageTestPermit())
    let local = try first.content.editing(["password": "same"], grant: grant, history: history, device: owner)
    let saved = try await storage.commit(local, scope: scope, history: history, authorization: ContentStorageTestPermit())
    let remote = try first.content.editing(["password": "same"], grant: grant, history: history, device: owner)
    let latest = try local.editing(["password": "new edit"], grant: grant, history: history, device: owner)
    let incoming = try ContentRecordTransport.materialize(ContentRecordTransport.content(preparedInboxContent(remote, scope: scope, history: history), kind: .head), account: "a")
    _ = try await repository.stageIncoming(incoming)
    let comparison = ContentComparisonSession(authorization: ContentStorageTestPermit()) { @MainActor lhs, rhs in
        let same = try lhs.hasIdenticalContents(to: rhs, grant: grant, otherGrant: grant, history: history, device: owner)
        _ = try await storage.commit(latest, scope: scope, history: history, authorization: ContentStorageTestPermit())
        return same
    }
    await #expect(throws: ItemRepositoryError.staleLocalVersion) {
        try await GrantBackedContentInbox(repository: repository, account: "a").process(id: incoming.id, history: history,
            permit: ContentStorageTestPermit(), comparison: comparison)
    }
    #expect(try await repository.item(scope)?.versionID == latest.header.version)
    #expect(try await repository.mutationReceipt(id: saved.id, account: "a")?.status == .queued)
    #expect(try await repository.incomingRecord(id: incoming.id, account: "a", database: "private") != nil)
}

@MainActor @Test func previewInboxCoordinatorResumesGrantOnContentCommitWithoutManualWake() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let publication = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let prepared = try preparedInboxContent(publication.content, scope: scope, history: history)
    let grant = try preparedInboxGrant(#require(publication.grants.first), scope: scope)
    let incoming = try ContentRecordTransport.materialize(ContentRecordTransport.grant(grant), account: "a")
    let version = try ContentRecordTransport.materialize(ContentRecordTransport.content(prepared, kind: .version), account: "a")
    _ = try await repository.stageIncoming(incoming)
    let inbox = GrantBackedContentInbox(repository: repository, account: "a")
    let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.applyIncoming],
        dependencyAvailable: { try await inbox.dependencyAvailable($0, history: history) },
        handler: { await inbox.handle($0, history: history, permit: ContentStorageTestPermit()) })
    await coordinator.start()
    await coordinator.waitUntilIdle()
    #expect(try await repository.operations(account: "a", database: "private").first { $0.id == incoming.operationID }?.state == .waitingForDependency)
    let changes = await repository.changes()
    let delivered = Task {
        for await _ in changes {
            if try await repository.contentGrantDelivery(grant) == .cloudConfirmed { return }
        }
    }
    _ = try await repository.stageIncoming(version)
    try await delivered.value
    await coordinator.stop()
    await coordinator.waitUntilIdle()
    #expect(try await repository.operations(account: "a", database: "private").filter { $0.kind == .applyIncoming }.allSatisfy { $0.state == .completed })
}

@MainActor @Test func previewTransportKeepsImmutableVersionAndHeadDistinctAndRejectsForeignSystemFields() async throws {
    let (root, _, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let publication = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let prepared = try preparedInboxContent(publication.content, scope: scope, history: history)
    let records = try ContentRecordTransport.publication(prepared)
    let version = try ContentRecordTransport.materialize(records.version, account: "a")
    let head = try ContentRecordTransport.materialize(records.head, account: "a")
    #expect(version.recordName != head.recordName)
    #expect(version.bytes == head.bytes)
    let restored = try ContentRecordTransport.publication(prepared, headSystemFields: head.systemFields)
    #expect(restored.head.recordID == records.head.recordID)
    #expect(throws: CloudSyncAdapterError.malformedRecord) {
        try ContentRecordTransport.publication(prepared, headSystemFields: version.systemFields)
    }
    records.head["asset"] = CKAsset(fileURL: root.appendingPathComponent("nonexistent"))
    #expect(throws: CloudSyncAdapterError.malformedRecord) { try ContentRecordTransport.materialize(records.head, account: "a") }
}

@MainActor @Test func previewInboxObsoleteAuthorityCannotAdvanceAnExistingHead() async throws {
    let (root, repository, owner, original, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    var history = original
    let joining = try SessionDevice(member: owner.identity.member)
    try history.append(MembershipEnvelope.successor(of: history.current,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])]), owner: owner))
    let storage = GrantBackedContentStorage(repository: repository)
    let vault = VaultScope(account: "a", vaultID: history.vault)
    try await storage.setAuthority(scope: vault, expected: original, history: history, authorization: ContentStorageTestPermit())
    let first = try ContentEnvelope.seal(["password": "base"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let grant = try #require(first.grants.first { $0.recipient == owner.identity.fingerprint })
    _ = try await storage.commit(first.content, grants: first.grants, scope: scope, history: history, authorization: ContentStorageTestPermit())
    let oldEdit = try first.content.editing(["password": "offline"], grant: grant, history: history, device: owner)
    let beforeRemoval = history
    try history.append(MembershipEnvelope.successor(of: history.current,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity])], removedDevices: [joining.identity.device]), owner: owner))
    try await storage.setAuthority(scope: vault, expected: beforeRemoval, history: history, authorization: ContentStorageTestPermit())
    let incoming = try ContentRecordTransport.materialize(ContentRecordTransport.content(preparedInboxContent(oldEdit, scope: scope, history: history), kind: .head), account: "a")
    _ = try await repository.stageIncoming(incoming)
    guard case .attention(.conflict) = try await GrantBackedContentInbox(repository: repository, account: "a").process(id: incoming.id,
        history: history, permit: ContentStorageTestPermit()) else { Issue.record("Obsolete authority must not advance the head"); return }
    #expect(try await repository.item(scope)?.versionID == first.content.header.version)
    #expect(try await repository.contentBranches(scope: scope).map(\.version.versionID) == [oldEdit.header.version])
}

@MainActor @Test func previewInboxExactEchoConfirmsOnlyExactReceiptAndRetirementBlocksApplication() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try ContentEnvelope.seal(["password": "base"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let grant = try #require(first.grants.first)
    let storage = GrantBackedContentStorage(repository: repository)
    let earlier = try await storage.commit(first.content, grants: first.grants, scope: scope, history: history, authorization: ContentStorageTestPermit())
    let edited = try first.content.editing(["password": "new"], grant: grant, history: history, device: owner)
    let latest = try await storage.commit(edited, scope: scope, history: history, authorization: ContentStorageTestPermit())
    let incoming = try ContentRecordTransport.materialize(ContentRecordTransport.content(preparedInboxContent(edited, scope: scope, history: history), kind: .head), account: "a")
    _ = try await repository.stageIncoming(incoming)
    let lease = try SynchronizationLease(url: root.appendingPathComponent("lease"))
    let permit = ConflictPublicationPermit(lease: lease, authorization: ContentStorageTestPermit())
    permit.invalidate()
    let inbox = GrantBackedContentInbox(repository: repository, account: "a")
    await #expect(throws: CloudSyncAdapterError.operationInterrupted) { try await inbox.process(id: incoming.id, history: history, permit: permit) }
    #expect(try await repository.pendingMutations(account: "a").count == 2)
    _ = try await inbox.process(id: incoming.id, history: history, permit: ContentStorageTestPermit())
    #expect(try await repository.mutationReceipt(id: latest.id, account: "a")?.status == .cloudConfirmed)
    #expect(try await repository.mutationReceipt(id: earlier.id, account: "a")?.status == .superseded)
    #expect(try await repository.pendingMutations(account: "a").isEmpty)
}

@MainActor @Test func previewInboxFetchesMissingAncestorAfterRestartWithoutNotification() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try ContentEnvelope.seal(["password": "one"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let grant = try #require(first.grants.first)
    let second = try first.content.editing(["password": "two"], grant: grant, history: history, device: owner)
    let third = try second.editing(["password": "three"], grant: grant, history: history, device: owner)
    let ancestor = try preparedInboxContent(second, scope: scope, history: history)
    let inbox = GrantBackedContentInbox(repository: repository, account: "a")
    for content in [first.content, third] {
        let record = try ContentRecordTransport.materialize(ContentRecordTransport.content(
            preparedInboxContent(content, scope: scope, history: history), kind: .head), account: "a")
        _ = try await repository.stageIncoming(record)
        _ = try await inbox.process(id: record.id, history: history, permit: ContentStorageTestPermit())
    }
    let persisted = try await repository.operations(account: "a", database: "private").filter { $0.kind == .fetchContentVersion }
    #expect(persisted.count == 1)
    let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
    let resumedInbox = GrantBackedContentInbox(repository: reopened, account: "a")
    let fetched = AsyncStream<CKRecord.ID>.makeStream()
    let fetcher = ContentVersionFetcher(repository: reopened, account: "a") { id in
        fetched.continuation.yield(id)
        return try ContentRecordTransport.content(ancestor, kind: .version)
    }
    let unwrapsBeforeSync = owner.unwrapCount
    owner.close()
    let changes = await reopened.changes()
    let converged = Task {
        for await _ in changes {
            if try await reopened.item(scope)?.versionID == third.header.version { return }
        }
    }
    let coordinator = DurableSyncCoordinator(repository: reopened, account: "a", kinds: [.applyIncoming, .fetchContentVersion],
        dependencyAvailable: { try await resumedInbox.dependencyAvailable($0, history: history) }) { operation in
            if operation.kind == .fetchContentVersion { return await fetcher.handle(operation, permit: ContentStorageTestPermit()) }
            return await resumedInbox.handle(operation, history: history, permit: ContentStorageTestPermit())
        }
    await coordinator.start()
    try await converged.value
    await coordinator.stop(); await coordinator.waitUntilIdle()
    fetched.continuation.finish()
    var ids: [CKRecord.ID] = []
    for await id in fetched.stream { ids.append(id) }
    #expect(ids.count == 1)
    #expect(ids.first?.recordName == scope.itemID.uuidString + ":" + second.header.version.uuidString)
    #expect(try await reopened.incomingRecords(account: "a", database: "private").isEmpty)
    #expect(owner.unwrapCount == unwrapsBeforeSync)
}

@MainActor @Test func previewFetchRejectsWrongRecordAndPreservesRequestAcrossRetirement() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let publication = try ContentEnvelope.seal(["password": "one"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let prepared = try preparedInboxContent(publication.content, scope: scope, history: history)
    let request = try #require(ContentVersionFetch(dependency: SyncDependency(.content,
        identifier: history.vault.uuidString + ":" + scope.itemID.uuidString + ":" + publication.content.header.version.uuidString)))
    let operation = try await repository.enqueue(request.operation(account: "a", owner: scope.zoneOwner))
    let wrong = ContentVersionFetcher(repository: repository, account: "a") { _ in
        try ContentRecordTransport.content(prepared, kind: .head)
    }
    guard case .attention(.invalidAuthority) = await wrong.handle(operation, permit: ContentStorageTestPermit()) else {
        Issue.record("A mutable head cannot satisfy an immutable version fetch"); return
    }
    let lease = try SynchronizationLease(url: root.appendingPathComponent("fetch.lock"))
    let permit = ConflictPublicationPermit(lease: lease, authorization: ContentStorageTestPermit())
    let entered = AsyncStream<Void>.makeStream(), release = AsyncStream<Void>.makeStream()
    let delayed = ContentVersionFetcher(repository: repository, account: "a") { _ in
        entered.continuation.yield(())
        for await _ in release.stream { break }
        return try ContentRecordTransport.content(prepared, kind: .version)
    }
    let transfer = Task { await delayed.handle(operation, permit: permit) }
    for await _ in entered.stream { break }
    permit.invalidate(); release.continuation.yield(())
    guard case .retry(.authorization, _) = await transfer.value else { Issue.record("Retired fetch must not commit"); return }
    #expect(try await repository.operations(account: "a", database: "private").first?.state == .ready)
    entered.continuation.finish(); release.continuation.finish()
    let retry = ContentVersionFetcher(repository: repository, account: "a") { _ in
        try ContentRecordTransport.content(prepared, kind: .version)
    }
    _ = await retry.handle(operation, permit: ContentStorageTestPermit())
    #expect(try await repository.incomingRecords(account: "a", database: "private").count == 1)
    #expect(try await repository.operations(account: "a", database: "private").first { $0.id == operation.id }?.state == .completed)
    #expect(try await repository.item(scope) == nil) // transport does not install trust
}

@MainActor @Test func previewFetchHonorsServerThrottleAndNeverFetchesKeyGenerationAsVersion() async throws {
    let (root, repository, _, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let identity = history.vault.uuidString + ":" + scope.itemID.uuidString + ":" + UUID().uuidString
    #expect(ContentVersionFetch(dependency: SyncDependency(.contentKeyGeneration, identifier: identity)) == nil)
    #expect(ContentVersionFetch(dependency: SyncDependency(.content, identifier: identity.lowercased())) == nil)
    let request = try #require(ContentVersionFetch(dependency: SyncDependency(.content, identifier: identity)))
    let operation = try await repository.enqueue(request.operation(account: "a", owner: scope.zoneOwner))
    let fetcher = ContentVersionFetcher(repository: repository, account: "a") { _ in
        throw CKError(.requestRateLimited, userInfo: [CKErrorRetryAfterKey: 900])
    }
    guard case .retry(.transport, let delay) = await fetcher.handle(operation, permit: ContentStorageTestPermit()) else {
        Issue.record("Throttle must remain retryable"); return
    }
    #expect(delay == 900)
    #expect(try await repository.operations(account: "a", database: "private").first?.state == .ready)
}

@MainActor @Test func previewPublicationSendsImmutableBeforeHeadAndAcknowledgesEachQueuedEditWhileLocked() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let session = try GrantBackedContentSession(repository: repository,
        binding: ItemVaultBinding(account: "a", database: "private", zoneOwner: scope.zoneOwner, vaultID: scope.vaultID), history: history, device: owner)
    let first = try await session.create(item: scope.itemID, components: ["password": "one"])
    let second = try await session.edit(item: scope.itemID, expected: first.version.versionID, components: ["password": "two"])
    let unwraps = owner.unwrapCount
    session.lock()
    let inbox = GrantBackedContentInbox(repository: repository, account: "a")
    for mutation in [first, second] {
        for kind in [ContentRecordKind.version, .head] {
            let candidates = try await repository.contentPublications(account: "a")
            let upload = try #require(candidates.first { $0.operationID == mutation.id })
            #expect(upload.kind == kind)
            try GrantBackedContentStorage.validatePublication(upload, history: history)
            let record = try upload.record(assetDirectory: root.appendingPathComponent("assets"))
            let incoming = try ContentRecordTransport.materialize(record, account: "a")
            _ = try await repository.stageIncoming(incoming)
            _ = try await inbox.process(id: incoming.id, history: history, permit: ContentStorageTestPermit())
            if kind == .version { #expect(try await repository.mutationReceipt(id: mutation.id, account: "a")?.status == .queued) }
            #expect(try await repository.item(scope)?.versionID == second.version.versionID)
        }
        #expect(try await repository.mutationReceipt(id: mutation.id, account: "a")?.status == .cloudConfirmed)
    }
    #expect(try await repository.pendingMutations(account: "a").isEmpty)
    #expect(owner.unwrapCount == unwraps)
}

@MainActor @Test func previewGrantWorkerAddsCoverageWithoutReplacingOfflineEditAndReusesSignedBytes() async throws {
    let (root, repository, owner, original, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let binding = ItemVaultBinding(account: "a", database: "private", zoneOwner: scope.zoneOwner, vaultID: scope.vaultID)
    let session = try GrantBackedContentSession(repository: repository, binding: binding, history: original, device: SessionDevice(copying: owner))
    let first = try await session.create(item: scope.itemID, components: ["password": "one"])
    let edit = try await session.edit(item: scope.itemID, expected: first.version.versionID, components: ["password": "offline"])
    let joining = try SessionDevice(member: owner.identity.member)
    let successor = try MembershipEnvelope.successor(of: original.current,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])]), owner: owner)
    var history = original; try history.append(successor)
    try await GrantBackedContentStorage(repository: repository).setAuthority(scope: VaultScope(account: "a", vaultID: scope.vaultID),
        expected: original, history: history, authorization: ContentStorageTestPermit())
    let authorized = try GrantBackedContentSession(repository: repository, binding: binding, history: history, device: SessionDevice(copying: owner))
    let work = try #require(await repository.operations(account: "a", database: "private").first { $0.kind == .prepareGrant && $0.state != .completed })
    guard case .completed = await authorized.handle(work, owner: ContentStorageTestPermit()) else { Issue.record("Grant preparation failed"); return }
    let state = try #require(await repository.contentState(scope: scope))
    let grants = try await repository.contentGrants(scope: scope, keyGeneration: state.keyGeneration)
    let newGrant = try #require(grants.first { $0.recipient == joining.identity.fingerprint })
    #expect(try await repository.contentGrantDelivery(newGrant) == .queued)
    _ = await authorized.handle(work, owner: ContentStorageTestPermit())
    #expect(try await repository.contentGrants(scope: scope, keyGeneration: state.keyGeneration) == grants)
    #expect(try await repository.pendingMutations(account: "a") == [first, edit])
    let joined = try GrantBackedContentSession(repository: repository, binding: binding, history: history, device: joining)
    #expect(try await joined.open(item: scope.itemID, component: "password", expected: edit.version.versionID) == SecretBytes("offline"))
    authorized.lock()
    for upload in try await repository.contentPublications(account: "a") { try GrantBackedContentStorage.validatePublication(upload, history: history) }
}

@MainActor @Test(arguments: [false, true]) func previewRotationPreservesOfflinePlaintextWithoutPublishingRevokedAncestors(accepted: Bool) async throws {
    let (root, repository, owner, original, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let joining = try SessionDevice(member: owner.identity.member)
    var enrolled = original
    try enrolled.append(MembershipEnvelope.successor(of: original.current,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])]), owner: owner))
    let storage = GrantBackedContentStorage(repository: repository), vault = VaultScope(account: "a", vaultID: scope.vaultID)
    try await storage.setAuthority(scope: vault, expected: original, history: enrolled, authorization: ContentStorageTestPermit())
    let binding = ItemVaultBinding(account: "a", database: "private", zoneOwner: scope.zoneOwner, vaultID: scope.vaultID)
    let session = try GrantBackedContentSession(repository: repository, binding: binding, history: enrolled, device: SessionDevice(copying: owner))
    let first = try await session.create(item: scope.itemID, components: ["password": "first"])
    if accepted {
        let inbox = GrantBackedContentInbox(repository: repository, account: "a")
        for _ in 0..<2 {
            let upload = try #require(await repository.contentPublications(account: "a").first { $0.operationID == first.id })
            let incoming = try ContentRecordTransport.materialize(upload.record(assetDirectory: root), account: "a")
            _ = try await repository.stageIncoming(incoming)
            _ = try await inbox.process(id: incoming.id, history: enrolled, permit: ContentStorageTestPermit())
        }
    }
    let edit = try await session.edit(item: scope.itemID, expected: first.version.versionID, components: ["password": "offline"])
    let before = try #require(await repository.contentState(scope: scope))
    var revoked = enrolled
    try revoked.append(MembershipEnvelope.successor(of: enrolled.current,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity])], removedDevices: [joining.identity.device]), owner: owner))
    try await storage.setAuthority(scope: vault, expected: enrolled, history: revoked, authorization: ContentStorageTestPermit())
    #expect(try await repository.contentPublications(account: "a").isEmpty)
    let authorized = try GrantBackedContentSession(repository: repository, binding: binding, history: revoked, device: SessionDevice(copying: owner))
    let rotation = try #require(await repository.operations(account: "a", database: "private").first { $0.kind == .rotateContent && $0.state != .completed })
    guard case .completed = await authorized.handle(rotation, owner: ContentStorageTestPermit()) else { Issue.record("Rotation failed"); return }
    let current = try #require(await repository.item(scope))
    let after = try #require(await repository.contentState(scope: scope))
    #expect(after.contentRevision == before.contentRevision)
    #expect(after.keyGeneration != before.keyGeneration)
    #expect(current.baseVersionID == (accepted ? first.version.versionID : nil))
    #expect(current.generation == (accepted ? 2 : 1))
    #expect(try await authorized.open(item: scope.itemID, component: "password", expected: current.versionID) == SecretBytes("offline"))
    #expect(try await repository.mutationReceipt(id: edit.id, account: "a")?.status == .superseded)
    #expect(try await repository.mutationReceipt(id: first.id, account: "a")?.status == (accepted ? .cloudConfirmed : .superseded))
    let publications = try await repository.contentPublications(account: "a")
    #expect(!publications.isEmpty)
    #expect(publications.allSatisfy { $0.content.keyGeneration == after.keyGeneration })
    for upload in publications { try GrantBackedContentStorage.validatePublication(upload, history: revoked) }
}

@MainActor @Test(arguments: [true, false]) func previewIncomingRotationRebasesOnlyAccessChangesAfterUnlock(accessOnly: Bool) async throws {
    let (root, repository, owner, original, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let joining = try SessionDevice(member: owner.identity.member)
    var enrolled = original
    try enrolled.append(MembershipEnvelope.successor(of: original.current,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])]), owner: owner))
    let storage = GrantBackedContentStorage(repository: repository), vault = VaultScope(account: "a", vaultID: scope.vaultID)
    try await storage.setAuthority(scope: vault, expected: original, history: enrolled, authorization: ContentStorageTestPermit())
    let base = try ContentEnvelope.seal(["password": "base"], vault: scope.vaultID, item: scope.itemID, history: enrolled, signer: owner)
    let receipt = try await storage.commit(base.content, grants: base.grants, scope: scope, history: enrolled, authorization: ContentStorageTestPermit())
    let inbox = GrantBackedContentInbox(repository: repository, account: "a")
    for _ in 0..<2 {
        let upload = try #require(await repository.contentPublications(account: "a").first { $0.operationID == receipt.id })
        let incoming = try ContentRecordTransport.materialize(upload.record(assetDirectory: root), account: "a")
        _ = try await repository.stageIncoming(incoming)
        _ = try await inbox.process(id: incoming.id, history: enrolled, permit: ContentStorageTestPermit())
    }
    let binding = ItemVaultBinding(account: "a", database: "private", zoneOwner: scope.zoneOwner, vaultID: scope.vaultID)
    let offlineSession = try GrantBackedContentSession(repository: repository, binding: binding, history: enrolled, device: SessionDevice(copying: owner))
    let edit = try await offlineSession.edit(item: scope.itemID, expected: base.content.header.version, components: ["password": "offline"])
    let before = try #require(await repository.contentState(scope: scope))
    var revoked = enrolled
    try revoked.append(MembershipEnvelope.successor(of: enrolled.current,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity])], removedDevices: [joining.identity.device]), owner: owner))
    try await storage.setAuthority(scope: vault, expected: enrolled, history: revoked, authorization: ContentStorageTestPermit())
    let ownerGrant = try #require(base.grants.first { $0.recipient == owner.identity.fingerprint })
    let remoteBase = accessOnly ? base.content : try base.content.editing(["password": "different remote edit"], grant: ownerGrant, history: enrolled, device: owner)
    if !accessOnly {
        let predecessor = try ContentRecordTransport.materialize(ContentRecordTransport.content(
            preparedInboxContent(remoteBase, scope: scope, history: revoked), kind: .version), account: "a")
        _ = try await repository.stageIncoming(predecessor)
        _ = try await inbox.process(id: predecessor.id, history: revoked, permit: ContentStorageTestPermit())
    }
    let rotated = try remoteBase.rotateKey(grant: ownerGrant, history: revoked, decryptor: owner, signer: owner)
    let prepared = try preparedInboxContent(rotated.content, scope: scope, history: revoked)
    let remote = try ContentRecordTransport.materialize(ContentRecordTransport.content(prepared, kind: .head), account: "a")
    let version = try ContentRecordTransport.materialize(ContentRecordTransport.content(prepared, kind: .version), account: "a")
    let grant = try ContentRecordTransport.materialize(ContentRecordTransport.grant(preparedInboxGrant(#require(rotated.grants.first), scope: scope)), account: "a")
    for incoming in [version, grant, remote] {
        _ = try await repository.stageIncoming(incoming)
        _ = try await inbox.process(id: incoming.id, history: revoked, permit: ContentStorageTestPermit())
    }
    #expect(try await repository.item(scope)?.versionID == edit.version.versionID)
    let unlocked = try GrantBackedContentSession(repository: repository, binding: binding, history: revoked, device: SessionDevice(copying: owner))
    let outcome = try await inbox.process(id: remote.id, history: revoked, permit: ContentStorageTestPermit(), comparison: unlocked.comparison())
    if !accessOnly {
        guard case .attention(.conflict) = outcome else { Issue.record("Different remote content must stay a conflict"); return }
        #expect(try await repository.item(scope)?.versionID == edit.version.versionID)
        #expect(try await repository.contentBranches(scope: scope).count == 1)
        #expect(try await repository.mutationReceipt(id: edit.id, account: "a")?.status == .queued)
        return
    }
    guard case .completed = outcome else {
        Issue.record("Access-only rotation should preserve the offline edit without conflict"); return
    }
    let after = try #require(await repository.contentState(scope: scope))
    let working = try #require(await repository.item(scope))
    #expect(after.keyGeneration == rotated.content.header.keyGeneration)
    #expect(after.contentRevision == before.contentRevision)
    #expect(working.baseVersionID == rotated.content.header.version)
    #expect(try await repository.contentBranches(scope: scope).isEmpty)
    #expect(try await repository.mutationReceipt(id: edit.id, account: "a")?.status == .superseded)
    #expect(try await unlocked.open(item: scope.itemID, component: "password", expected: working.versionID) == SecretBytes("offline"))
    #expect(try await repository.operations(account: "a", database: "private").filter { $0.kind == .rotateContent }.allSatisfy { $0.state == .completed })
}

@MainActor @Test func previewRotationReadbackRecoversLostAcknowledgmentAndRejectsDisappearedHead() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let session = try GrantBackedContentSession(repository: repository,
        binding: ItemVaultBinding(account: "a", database: "private", zoneOwner: scope.zoneOwner, vaultID: scope.vaultID),
        history: history, device: owner)
    let first = try await session.create(item: scope.itemID, components: ["password": "first"])
    let edit = try await session.edit(item: scope.itemID, expected: first.version.versionID, components: ["password": "offline"])
    let prepared = try #require(await repository.contentVersion(scope: scope, version: first.version.versionID))
    let inbox = GrantBackedContentInbox(repository: repository, account: "a")
    let readback = ContentRotationReadback(repository: repository, account: "a") { _ in
        try ContentRecordTransport.content(prepared, kind: .head)
    }
    let result = try await readback.perform(scope: scope, permit: ContentStorageTestPermit(), check: {},
        apply: { await inbox.handle($0, history: history, permit: $1) }, rotate: { () async throws -> SyncOperationOutcome in
            #expect(try await repository.acceptedVersion(scope)?.versionID == first.version.versionID)
            #expect(try await repository.mutationReceipt(id: first.id, account: "a")?.status == .cloudConfirmed)
            #expect(try await repository.item(scope)?.versionID == edit.version.versionID)
            return .completed
        })
    guard case .completed = result else { Issue.record("Exact readback must precede rotation"); return }
    let missing = ContentRotationReadback(repository: repository, account: "a") { _ in throw CKError(.unknownItem) }
    let blocked = try await missing.perform(scope: scope, permit: ContentStorageTestPermit(), check: {},
        apply: { await inbox.handle($0, history: history, permit: $1) }, rotate: {
            Issue.record("A disappeared head must not be recreated by rotation"); return .completed
        })
    guard case .attention(.conflict) = blocked else { Issue.record("Missing accepted record must retain conflict"); return }
    #expect(try await repository.item(scope)?.versionID == edit.version.versionID)
}

@MainActor @Test func rotationBatchReadbackIsolatesFailuresAndPreservesCheckpoint() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let session = try GrantBackedContentSession(repository: repository,
        binding: ItemVaultBinding(account: "a", database: "private", zoneOwner: scope.zoneOwner, vaultID: scope.vaultID),
        history: history, device: owner)
    let scopes = (0..<5).map { _ in ItemScope(account: "a", vaultID: scope.vaultID, itemID: UUID()) }
    var prepared: [PreparedContentVersion] = []
    for item in scopes {
        let saved = try await session.create(item: item.itemID, components: ["password": "fixture"])
        prepared.append(try #require(await repository.contentVersion(scope: item, version: saved.version.versionID)))
    }
    let inbox = GrantBackedContentInbox(repository: repository, account: "a")
    // Item 1 was accepted earlier; its disappearance must remain a conflict.
    let accepted = try ContentRecordTransport.materialize(ContentRecordTransport.content(prepared[1], kind: .head), account: "a")
    _ = try await repository.stageIncoming(accepted)
    _ = await inbox.handle(SyncOperation(id: accepted.operationID, account: "a", vaultID: scope.vaultID,
        zoneOwner: scope.zoneOwner, kind: .applyIncoming, payload: Data(accepted.id.utf8)),
        history: history, permit: ContentStorageTestPermit())
    try await repository.saveEngineState(Data([44]), account: "a", database: "private")
    let valid = prepared[0], invalid = prepared[4]
    let fetchCalls = Mutex(0), rotated = Mutex<[UUID]>([])
    let batch = ContentRotationBatchReadback(repository: repository, account: "a") { ids in
        fetchCalls.withLock { $0 += 1 }
        #expect(ids.count == 5)
        let bad = try ContentRecordTransport.content(invalid, kind: .head)
        bad["payload"] = Data([0]) as CKRecordValue
        return [
            ids[0]: .success(try ContentRecordTransport.content(valid, kind: .head)),
            ids[1]: .failure(CKError(.unknownItem)),
            // Deliberately omit ids[2]: omission is NOT proof of absence.
            ids[3]: .failure(CKError(.requestRateLimited, userInfo: [CKErrorRetryAfterKey: 120.0])),
            ids[4]: .success(bad)
        ]
    }
    let results = try await batch.perform(scopes: scopes, permit: ContentStorageTestPermit(), check: {},
        apply: { await inbox.handle($0, history: history, permit: $1) }, rotate: { item async throws -> SyncOperationOutcome in
            #expect(try await repository.acceptedVersion(item) != nil)
            rotated.withLock { $0.append(item.itemID) }
            return .completed
        })
    #expect(fetchCalls.withLock { $0 } == 1)
    #expect(rotated.withLock { $0 } == [scopes[0].itemID])
    guard case .completed = results[0], case .attention(.conflict) = results[1],
          case .retry(.transport, _) = results[2], case .retry(.transport, let delay) = results[3] else {
        Issue.record("Partial failures must remain item-specific"); return
    }
    #expect(delay == 120)
    #expect(try await repository.engineState(account: "a", database: "private") == Data([44]))
}

@MainActor @Test func rotationBatchRechecksAuthorityBetweenItems() async throws {
    let (root, repository, _, _, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let second = ItemScope(account: "a", vaultID: scope.vaultID, itemID: UUID())
    let valid = Mutex(true), completed = Mutex<[UUID]>([])
    let batch = ContentRotationBatchReadback(repository: repository, account: "a") { ids in
        Dictionary(uniqueKeysWithValues: ids.map { ($0, .failure(CKError(.unknownItem))) })
    }
    let result = try await batch.perform(scopes: [scope, second], permit: ContentStorageTestPermit(),
        check: { if !valid.withLock({ $0 }) { throw CloudSyncAdapterError.operationInterrupted } },
        apply: { _, _ in Issue.record("Absent heads have nothing to apply"); return .completed },
        rotate: { item in
            completed.withLock { $0.append(item.itemID) }
            valid.withLock { $0 = false }
            return .completed
        })
    #expect(completed.withLock { $0 } == [scope.itemID])
    guard case .completed = result[0], case .retry(.authorization, _) = result[1] else {
        Issue.record("Retain the completed prefix and defer interrupted work"); return
    }
}

@MainActor @Test func rotationBatchCannotApplyAfterAccountInvalidationDuringFetch() async throws {
    let (root, repository, _, _, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let valid = Mutex(true)
    let batch = ContentRotationBatchReadback(repository: repository, account: "a") { ids in
        valid.withLock { $0 = false }
        return Dictionary(uniqueKeysWithValues: ids.map { ($0, .failure(CKError(.unknownItem))) })
    }
    await #expect(throws: CloudSyncAdapterError.operationInterrupted) {
        try await batch.perform(scopes: [scope], permit: ContentStorageTestPermit(),
            check: { if !valid.withLock({ $0 }) { throw CloudSyncAdapterError.operationInterrupted } },
            apply: { _, _ in Issue.record("Invalid account cannot apply"); return .completed },
            rotate: { _ in Issue.record("Invalid account cannot rotate"); return .completed })
    }
}

@MainActor @Test func contentClientFacadeRoundTripsPendingEditsAndPortableHistory() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let binding = ItemVaultBinding(account: scope.account, database: scope.database, zoneOwner: scope.zoneOwner, vaultID: scope.vaultID)
    let session = try await currentTestSession(repository: repository, binding: binding, history: history, device: owner)
    _ = try await session.saveMetadata(VaultMetadata(name: "preview", exclusions: ["temporary"]), expectedBase: nil)
    let archive = try sessionArchive()
    let saved = try await session.save(archive, expectedBase: nil)
    let id = saved.version.scope.itemID
    let first = try ContentEnvelope.decode(saved.version.ciphertext, history: history, item: id)
    let entry = try await session.catalog(named: "Login")
    #expect(entry.versionID == saved.version.versionID)
    #expect(entry.catalog.item.fields.first?.value == nil)
    let record = try #require(entry.catalog.references["Login/password"])
    #expect(try await session.reveal(itemID: id, recordID: record) == SecretBytes(utf8: "session-secret"))
    let edited = try await session.replaceField(itemID: id, expectedBase: saved.version.versionID, path: "password", value: SecretBytes(utf8: "replacement"))
    let next = try ContentEnvelope.decode(edited.version.ciphertext, history: history, item: id)
    #expect(next.header.keyGeneration == first.header.keyGeneration)
    #expect(next.header.contentRevision != first.header.contentRevision)
    let exported = try await session.exportPortableLocalSnapshot()
    #expect(exported.exclusions == ["temporary"])
    #expect(exported.security?.histories.first?.entries.first?.id == record)
    #expect(exported.records[record]?.bytes == SecretBytes(utf8: "session-secret"))
    let newRecord = try #require(exported.references["Login/password"])
    #expect(exported.records[newRecord]?.bytes == SecretBytes(utf8: "replacement"))
    #expect(try await repository.pendingMutations(account: scope.account).count == 3)
    session.lock()
    await #expect(throws: MopError.authentication) { try await session.exportPortableLocalSnapshot() }
}

@MainActor @Test func contentBootstrapImportsAtomicallyAndRetryPreservesEditsAndLegacyStore() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-content-import-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let legacy = root.appendingPathComponent("Items.sqlite")
    let sentinel = Data("existing preview store must remain untouched".utf8)
    try sentinel.write(to: legacy)
    let repository = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
    let owner = try SessionDevice(), store = TestItemTrustStore()
    let binding = ItemVaultBinding(account: "content-import", database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID())
    let scope = ItemVaultSetupScope(container: "iCloud.test", environment: "Development", binding: binding)
    let bootstrap = try ItemVaultBootstrap(repository: repository, trustStore: store, scope: scope, device: owner)
    let archive = try sessionArchive()
    let sealed = try PortableArchive.seal(archive)
    let data = sealed.data, key = sealed.recoveryKey
    let session = try await bootstrap.restore(archiveData: data, recoveryKey: key, name: "imported")
    let receipt = try #require(await repository.vaultInitialization(scope.repositoryScope))
    #expect(receipt.mutationIDs.count == 2)
    let operations = try await repository.operations(account: binding.account, database: binding.database)
    let provision = try #require(operations.first { $0.kind == .provision })
    #expect(operations.filter { $0.kind == .publishItem }.allSatisfy { $0.dependencies.contains(SyncDependency(.operation, identifier: provision.id.uuidString)) })
    #expect(try await repository.contentPublications(account: binding.account).isEmpty)
    let entry = try await session.catalog(named: "Login")
    _ = try await session.replaceField(itemID: entry.itemID, expectedBase: entry.versionID, path: "password", value: SecretBytes(utf8: "edited after import"))
    let retried = try await bootstrap.restore(archiveData: data, recoveryKey: key, name: "imported")
    let exported = try await retried.exportPortableLocalSnapshot()
    let id = try #require(exported.references["Login/password"])
    #expect(exported.records[id]?.bytes == SecretBytes(utf8: "edited after import"))
    #expect(try await repository.vaultInitialization(scope.repositoryScope) == receipt)
    #expect(try Data(contentsOf: legacy) == sentinel)
}

@MainActor @Test func contentProvisioningUsesSignedJournalWhileLocked() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-content-provision-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let repository = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
    let owner = try SessionDevice(), trust = TestItemTrustStore(), server = DomainProvisionServer()
    let binding = ItemVaultBinding(account: "content-provision", database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID())
    let scope = ItemVaultSetupScope(container: "iCloud.test", environment: "Development", binding: binding)
    let bootstrap = try ItemVaultBootstrap(repository: repository, trustStore: trust, scope: scope, device: owner)
    let session = try await bootstrap.create(name: "provisioned")
    session.lock()
    let operation = try #require(await repository.operations(account: binding.account, database: "private").first { $0.kind == .provision })
    let provisioner = JournaledContentProvisioner(repository: repository, trustStore: trust, transport: server, accountValidator: { true })
    let outcome = await provisioner.handle(operation, permit: ContentStorageTestPermit())
    guard case .completed = outcome else { Issue.record("Prepared commissioning did not complete while locked"); return }
    #expect(try await repository.operationIsDelivered(operation.id, account: binding.account))
    #expect(try await repository.contentPublications(account: binding.account).count == 2) // metadata immutable version and independent grant
    #expect(await server.creates == 1)
    let receipt = try #require(await repository.vaultInitialization(scope.repositoryScope))
    try await repository.pruneCompletedOperations(account: binding.account, database: "private", now: Date().addingTimeInterval(31 * 24 * 60 * 60))
    #expect(try await repository.operationIsDelivered(operation.id, account: binding.account))
    #expect(try await repository.contentPublications(account: binding.account).count == 2)
    #expect(try await repository.vaultInitialization(scope.repositoryScope) == receipt)
}

@MainActor @Test func coordinationReplayAcknowledgesOnlyExactPayloadAndNeverInstallsDiscoveryTrust() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let inbox = GrantBackedCoordinationInbox(repository: repository, container: "iCloud.test", environment: "Development", account: scope.account, member: owner.identity.member)
    let statement = try CoordinationEnvelope.sign(kind: .discovery, scope: inbox.scope(vault: scope.vaultID), identity: scope.vaultID,
        payload: Data(scope.vaultID.uuidString.utf8), history: history, device: owner)
    let record = try PreparedCoordinationRecord(account: scope.account, vault: scope.vaultID, kind: .discovery, identity: scope.vaultID, bytes: statement.encoded())
    let operation = try await repository.enqueueCoordination(record, authorization: ContentStorageTestPermit())
    try await repository.setContentUploadBlocked(operation.id, account: scope.account, blocked: true, permit: ContentStorageTestPermit())
    #expect(try await repository.operations(account: scope.account, database: "private").first { $0.id == operation.id }?.state == .waitingForAuthorization)
    try await repository.setContentUploadBlocked(operation.id, account: scope.account, blocked: false, permit: ContentStorageTestPermit())
    #expect(try await repository.operations(account: scope.account, database: "private").first { $0.id == operation.id }?.state == .ready)
    #expect(try await repository.coordinationPublications(account: scope.account) == [record])
    let incoming = try PreparedCoordinationRecord.materialize(record.record(), account: scope.account)
    try await repository.stageIncoming(incoming, permit: ContentStorageTestPermit())
    let applied = await inbox.handle(SyncOperation(id: incoming.operationID, account: scope.account, vaultID: scope.vaultID, kind: .applyIncoming,
        payload: Data(incoming.id.utf8)), history: nil, permit: ContentStorageTestPermit())
    guard case .completed = applied else { Issue.record("Valid discovery hint did not apply"); return }
    #expect(try await repository.coordinationRecords(account: scope.account, kind: .discovery) == [record])
    #expect(try await repository.operationIsDelivered(operation.id, account: scope.account))
    #expect(try await repository.vaultInitialization(VaultScope(account: scope.account, vaultID: scope.vaultID, database: scope.database, zoneOwner: scope.zoneOwner)) == nil)
    let changed = try CoordinationEnvelope.sign(kind: .discovery, scope: inbox.scope(vault: scope.vaultID), identity: scope.vaultID,
        payload: Data("different immutable payload".utf8), history: history, device: owner)
    let collision = try PreparedCoordinationRecord(account: scope.account, vault: scope.vaultID, kind: .discovery, identity: scope.vaultID, bytes: changed.encoded())
    let collisionIncoming = try PreparedCoordinationRecord.materialize(collision.record(), account: scope.account)
    try await repository.stageIncoming(collisionIncoming, permit: ContentStorageTestPermit())
    let refused = await inbox.handle(SyncOperation(id: collisionIncoming.operationID, account: scope.account, vaultID: scope.vaultID,
        kind: .applyIncoming, payload: Data(collisionIncoming.id.utf8)), history: history, permit: ContentStorageTestPermit())
    guard case .attention(.invalidAuthority) = refused else { Issue.record("Immutable collision was accepted"); return }
    #expect(try await repository.quarantineSummary(account: scope.account).records == 1)
    #expect(try await repository.coordinationRecords(account: scope.account, kind: .discovery) == [record])
}

@MainActor @Test func contentEnrollmentJournalsApprovalBehindMembershipWithoutReplacingPendingEdits() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let binding = ItemVaultBinding(account: scope.account, database: "private", zoneOwner: scope.zoneOwner, vaultID: scope.vaultID)
    let session = try GrantBackedContentSession(repository: repository, binding: binding, history: history, device: owner)
    let item = try await session.create(item: scope.itemID, components: ["body": SecretBytes(utf8: "pending user edit")])
    let newcomer = try SessionDevice(member: owner.identity.member)
    let enrollmentScope = EnrollmentScope(container: "iCloud.test", environment: "Development", account: scope.account, vault: scope.vaultID, member: owner.identity.member)
    let request = try DeviceEnrollmentRequest.create(scope: enrollmentScope, device: newcomer)
    let first = try await session.prepareEnrollment(request, scope: enrollmentScope, owner: ContentStorageTestPermit())
    let retry = try await session.prepareEnrollment(request, scope: enrollmentScope, owner: ContentStorageTestPermit())
    #expect(first == retry)
    #expect(try await repository.item(scope) == item.version)
    #expect(try await repository.pendingMutations(account: scope.account).map(\.id) == [item.id])
    #expect(try await repository.coordinationPublications(account: scope.account).isEmpty)
    let membership = try #require(await repository.operations(account: scope.account, database: "private").first { $0.kind == .membership })
    try await repository.confirmOperation(membership, permit: ContentStorageTestPermit())
    #expect(try await repository.coordinationPublications(account: scope.account) == [first])
    let wrapper = try CoordinationEnvelope.decode(first.bytes, scope: enrollmentScope)
    let approval = try DeviceEnrollmentApproval.decode(wrapper.payload)
    #expect(approval.request == request)
    #expect(approval.successor.membership.devices.contains(newcomer.identity))
    #expect(try await repository.contentRecipients(scope: VaultScope(account: scope.account, vaultID: scope.vaultID)) == GrantBackedContentStorage.recipientPolicy(history: history))
}

@MainActor @Test func contentMembershipFetchWaitsForPinnedApplicationAndRetriesMissedHeads() async throws {
    let (root, repository, _, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let digest = try history.current.digest()
    let dependency = SyncDependency(.membership, identifier: scope.vaultID.uuidString + ":" + digest)
    let request = try #require(ContentMembershipFetch(dependency: dependency))
    let operation = try await repository.enqueue(request.operation(account: scope.account, owner: scope.zoneOwner))
    let available = Mutex(false), requests = Mutex<[String]>([])
    let bytes = try history.current.encoded()
    let fetcher = ContentMembershipFetcher(repository: repository, account: scope.account, fetch: { id in
        requests.withLock { $0.append(id.recordName) }
        let record = CKRecord(recordType: NativeVaultProvisioningTransport.recordType, recordID: id)
        record["membership"] = bytes as CKRecordValue
        return record
    }, available: { candidate in candidate == dependency && available.withLock { $0 } })
    guard case .retry(.dependency, _) = await fetcher.handle(operation, permit: ContentStorageTestPermit()) else { Issue.record("Fetch incorrectly treated immutable membership as committed authority"); return }
    #expect(requests.withLock { $0 } == ["membership-" + digest, "membership-head"])
    #expect(try await repository.incomingRecords(account: scope.account, database: "private").count == 2)
    available.withLock { $0 = true }
    guard case .completed = await fetcher.handle(operation, permit: ContentStorageTestPermit()) else { Issue.record("Pinned membership did not release fetch"); return }
    #expect(requests.withLock { $0.count } == 2)
}

@MainActor @Test func contentAdmissionCompletesBeforeDownloadAndReopensAfterGrantReception() async throws {
    let (root, _, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let repository = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root.appendingPathComponent("joining")))
    let joining = try SessionDevice(member: owner.identity.member), restarted = SessionDevice(copying: joining), trust = MemoryItemInventory()
    let setup = ItemVaultSetupScope(container: "iCloud.test", environment: "Development",
        binding: ItemVaultBinding(account: scope.account, database: "private", zoneOwner: scope.zoneOwner, vaultID: scope.vaultID))
    let enrollment = EnrollmentScope(container: setup.container, environment: setup.environment, account: scope.account, vault: scope.vaultID, member: owner.identity.member)
    let request = try DeviceEnrollmentRequest.create(scope: enrollment, device: joining)
    let approval = try DeviceEnrollmentApproval.create(request: request, history: history, owner: owner, expectedItemCount: 1)
    let admitted = try approval.verifiedHistory()
    let session = try await ItemVaultBootstrap(repository: repository, trustStore: trust, scope: setup, device: joining).acceptContentEnrollment(approval: approval, request: request)
    #expect(try await repository.vaultInitialization(setup.repositoryScope) != nil)
    await #expect(throws: ItemVaultSessionFailure.missingVaultMetadata) { try await session.vaultMetadata() }
    let metadata = try ContentEnvelope.seal([ContentItemArchive.metadataComponent: ContentItemArchive.encode(VaultMetadata(name: "admitted"))],
        vault: scope.vaultID, item: ItemVaultSession.metadataRecordID, history: history, signer: owner)
    let grant = try ContentKeyGrant.extendingAccess(to: restarted.identity, content: metadata.content,
        existingGrant: #require(metadata.grants.first), history: admitted, decryptor: owner, signer: owner)
    let metadataScope = setup.binding.item(ItemVaultSession.metadataRecordID)
    let prepared = try preparedInboxContent(metadata.content, scope: metadataScope, history: admitted)
    let inbox = GrantBackedContentInbox(repository: repository, account: scope.account)
    for record in [try ContentRecordTransport.content(prepared, kind: .head), try ContentRecordTransport.grant(preparedInboxGrant(grant, scope: metadataScope))] {
        let incoming = try ContentRecordTransport.materialize(record, account: scope.account)
        try await repository.stageIncoming(incoming, permit: ContentStorageTestPermit())
        guard case .completed = try await inbox.process(id: incoming.id, history: admitted, permit: ContentStorageTestPermit()) else { Issue.record("Admission content did not apply"); return }
    }
    #expect(try await session.vaultMetadata().value.name == "admitted")
    #expect(try await repository.pendingMutations(account: scope.account).isEmpty)
    session.lock()
    let reopened = try await ItemVaultBootstrap(repository: repository, trustStore: trust, scope: setup, device: restarted).open()
    #expect(try await reopened.vaultMetadata().value.name == "admitted")
}

@MainActor @Test func contentRecoveryRotatesKeysPreservingLogicalContentAndCreatesReplacementGrants() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("recovery-grants-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let recoveryScope = try RecoveryScope(container: "iCloud.test", environment: "Development", account: "account")
    let owner = try SessionDevice(member: recoveryScope.member), joining = try SessionDevice(member: recoveryScope.member), recovery = try OfflineRecoveryKey(scope: recoveryScope)
    let repository = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
    let trust = MemoryItemInventory(), setup = ItemVaultSetupScope(container: recoveryScope.container, environment: recoveryScope.environment,
        binding: ItemVaultBinding(account: "account", database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
    let original = try await ItemVaultBootstrap(repository: repository, trustStore: trust, scope: setup, device: SessionDevice(copying: owner), recovery: recovery.identity).create(name: "recovered")
    let pin = try #require(try trust.load(scope: setup)), before = try ItemVaultMembershipAuthority.history(record: pin, trustStore: trust)
    let request = try DeviceEnrollmentRequest.create(scope: EnrollmentScope(container: setup.container, environment: setup.environment, account: "account", vault: setup.binding.vaultID, member: owner.identity.member), device: joining)
    let approval = try DeviceEnrollmentApproval.create(request: request, history: before, owner: recovery), history = try approval.verifiedHistory()
    let oldContent = try #require(await repository.item(setup.binding.item(ItemVaultSession.metadataRecordID)))
    try await GrantBackedContentStorage(repository: repository).setAuthority(scope: setup.repositoryScope, expected: before, history: history, authorization: ContentStorageTestPermit())
    let session = try GrantBackedContentSession(repository: repository, binding: setup.binding, history: history, device: joining)
    let operations = try await repository.operations(account: "account", database: "private").filter { $0.kind == .rotateContent && $0.state != .completed }
    original.lock(); owner.close()
    #expect(operations.count == 1)
    for operation in operations {
        guard case .completed = await session.handle(operation, owner: ContentStorageTestPermit(), recovery: recovery) else { Issue.record("Recovery rotation failed"); return }
    }
    recovery.close()
    #expect(try await session.vaultMetadata().value.name == "recovered")
    let after = try ContentEnvelope.decode(#require(await repository.item(oldContent.scope)).ciphertext, history: history, item: oldContent.scope.itemID)
    let beforeContent = try ContentEnvelope.decode(oldContent.ciphertext, history: before, item: oldContent.scope.itemID)
    #expect(after.header.contentRevision == beforeContent.header.contentRevision)
    #expect(after.header.keyGeneration != beforeContent.header.keyGeneration)
    #expect(try await repository.missingContentGrants(scope: setup.repositoryScope).isEmpty)
}

@MainActor @Test func contentEnrollmentCleanupRetainsCompactAcknowledgmentAndDeletionNotices() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let receipt = CompletedEnrollmentReceipt(request: UUID(), vault: scope.vaultID, approvalDigest: String(repeating: "a", count: 64))
    let relay = try PreparedCoordinationRecord(account: scope.account, vault: scope.vaultID, kind: .enrollmentRequest, identity: receipt.request, bytes: Data([1]))
    _ = try await repository.enqueue(SyncOperation(account: scope.account, vaultID: scope.vaultID, kind: .enrollment, payload: JSONEncoder().encode(relay)))
    try await repository.completeContentEnrollment(receipt, account: scope.account, permit: ContentStorageTestPermit())
    try await repository.completeContentEnrollment(receipt, account: scope.account, permit: ContentStorageTestPermit())
    #expect(try await repository.operations(account: scope.account, database: "private").allSatisfy { $0.kind != .enrollment })
    let removals = try await repository.coordinationRemovals(account: scope.account)
    #expect(removals.count == 3)
    #expect(try await repository.enrollmentReceipt(account: scope.account, vault: scope.vaultID, request: receipt.request) != nil)
    #expect(try await repository.enrollmentReceipt(account: scope.account, vault: scope.vaultID, request: receipt.request, now: Date().addingTimeInterval(31 * 86400)) == nil)
    let bound = EnrollmentScope(container: "iCloud.test", environment: "Development", account: scope.account, vault: scope.vaultID, member: owner.identity.member)
    let notice = try CoordinationEnvelope.sign(kind: .deletion, scope: bound, identity: scope.vaultID, payload: VaultDeletionNotice.create(binding: .init(container: bound.container, environment: bound.environment, account: bound.account, vault: bound.vault, database: "private", zone: SyncStoreLayout.contentZone(vault: bound.vault), owner: "__defaultOwner__", genesis: history.orderedStates[0].digest()), history: history, owner: owner).encoded(), history: history, device: owner).encoded()
    let vault = VaultScope(account: scope.account, vaultID: scope.vaultID)
    for phase: VaultDeletionPhase in [.committed, .cloudDeleted, .complete] { _ = try await repository.saveDeletion(scope: vault, notice: notice, phase: phase, authorization: ContentStorageTestPermit()) }
    #expect(try await repository.deletion(vault)?.notice == notice)
}

@MainActor @Test func contentConcurrentAdmissionsRebaseOnlyUncommittedAuthorityAndKeepEdits() async throws {
    let (root, repository, owner, original, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let binding = ItemVaultBinding(account: scope.account, database: "private", zoneOwner: scope.zoneOwner, vaultID: scope.vaultID)
    let session = try GrantBackedContentSession(repository: repository, binding: binding, history: original, device: SessionDevice(copying: owner))
    let item = try await session.create(item: scope.itemID, components: ["password": "offline edit"])
    let first = try SessionDevice(member: owner.identity.member), second = try SessionDevice(member: owner.identity.member)
    let enrollmentScope = EnrollmentScope(container: "iCloud.test", environment: "Development", account: scope.account, vault: scope.vaultID, member: owner.identity.member)
    let request = try DeviceEnrollmentRequest.create(scope: enrollmentScope, device: first)
    _ = try await session.prepareEnrollment(request, scope: enrollmentScope, owner: ContentStorageTestPermit())
    let proposed = try #require(await repository.operations(account: scope.account, database: "private").first { $0.kind == .membership })
    let otherRequest = try DeviceEnrollmentRequest.create(scope: enrollmentScope, device: second)
    await #expect(throws: ContentStoreError.staleAuthority) {
        try await session.prepareEnrollment(otherRequest, scope: enrollmentScope, owner: ContentStorageTestPermit())
    }
    let accepted = try DeviceEnrollmentApproval.create(request: otherRequest, history: original, owner: owner).verifiedHistory()
    try await GrantBackedContentStorage(repository: repository).setAuthority(scope: VaultScope(account: scope.account, vaultID: scope.vaultID, database: scope.database, zoneOwner: scope.zoneOwner), expected: original, history: accepted, authorization: ContentStorageTestPermit())
    let current = try GrantBackedContentSession(repository: repository, binding: binding, history: accepted, device: SessionDevice(copying: owner))
    #expect(try await current.reconcileMembership(proposed, scope: enrollmentScope, owner: ContentStorageTestPermit()))
    let rebased = try #require(await repository.operations(account: scope.account, database: "private").first { $0.id == proposed.id })
    #expect(rebased.revision != proposed.revision && rebased.deliveredAt == nil)
    let approval = try DeviceEnrollmentApproval.decode(rebased.payload)
    #expect(approval.history.last == accepted.current)
    #expect(approval.successor.membership.devices.contains(first.identity))
    #expect(approval.successor.membership.devices.contains(second.identity))
    #expect(try await repository.item(scope) == item.version)
    #expect(try await repository.coordinationPublications(account: scope.account).isEmpty)
    await #expect(throws: SyncJournalError.staleOperation) { try await repository.confirmOperation(proposed, permit: ContentStorageTestPermit()) }
    try await repository.confirmOperation(rebased, permit: ContentStorageTestPermit())
    #expect(try await repository.coordinationPublications(account: scope.account).count == 1)
}

@MainActor @Test func contentEquivalentApprovalEchoSupersedesWithoutFalseLocalDelivery() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let binding = ItemVaultBinding(account: scope.account, database: "private", zoneOwner: scope.zoneOwner, vaultID: scope.vaultID)
    let session = try GrantBackedContentSession(repository: repository, binding: binding, history: history, device: SessionDevice(copying: owner))
    let joining = try SessionDevice(member: owner.identity.member)
    let enrollment = EnrollmentScope(container: "iCloud.test", environment: "Development", account: scope.account, vault: scope.vaultID, member: owner.identity.member)
    let request = try DeviceEnrollmentRequest.create(scope: enrollment, device: joining)
    let local = try await session.prepareEnrollment(request, scope: enrollment, owner: ContentStorageTestPermit())
    let proposal = try #require(await repository.operations(account: scope.account, database: "private").first { $0.kind == .membership })
    try await repository.confirmOperation(proposal, permit: ContentStorageTestPermit())
    let approval = try DeviceEnrollmentApproval.decode(proposal.payload)
    let accepted = try approval.verifiedHistory()
    let reconnect = try DeviceEnrollmentApproval.reconnect(request: request, history: accepted, owner: owner)
    let envelope = try CoordinationEnvelope.sign(kind: .enrollmentApproval, scope: enrollment, identity: request.id, payload: reconnect.encoded(), history: accepted, device: owner)
    let remote = try PreparedCoordinationRecord(account: scope.account, vault: scope.vaultID, kind: .enrollmentApproval, identity: request.id, bytes: envelope.encoded())
    #expect(remote.bytes != local.bytes)
    let incoming = try PreparedCoordinationRecord.materialize(remote.record(), account: scope.account)
    try await repository.stageIncoming(incoming, permit: ContentStorageTestPermit())
    let operation = try #require(await repository.operations(account: scope.account, database: "private").first { $0.id == incoming.operationID })
    let handler = GrantBackedCoordinationInbox(repository: repository, container: enrollment.container, environment: enrollment.environment, account: enrollment.account, member: enrollment.member)
    guard case .completed = await handler.handle(operation, history: accepted, permit: ContentStorageTestPermit()) else { Issue.record("Equivalent server approval did not converge"); return }
    #expect(try await repository.preparedCoordination(account: scope.account, vault: scope.vaultID, kind: .enrollmentApproval, identity: request.id) == remote)
    #expect(try await !repository.operationIsDelivered(local.operationID, account: scope.account))
    #expect(try await repository.quarantineSummary(account: scope.account).records == 0)
}

@MainActor @Test func contentMissingOwnGrantPublishesOneDurableScopedRequest() async throws {
    let (root, repository, owner, original, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let binding = ItemVaultBinding(account: scope.account, database: "private", zoneOwner: scope.zoneOwner, vaultID: scope.vaultID)
    let first = try GrantBackedContentSession(repository: repository, binding: binding, history: original, device: SessionDevice(copying: owner))
    let item = try await first.create(item: scope.itemID, components: ["password": "secret"])
    let joining = try SessionDevice(member: owner.identity.member)
    let enrollment = EnrollmentScope(container: "iCloud.test", environment: "Development", account: scope.account, vault: scope.vaultID, member: owner.identity.member)
    let request = try DeviceEnrollmentRequest.create(scope: enrollment, device: joining)
    let history = try DeviceEnrollmentApproval.create(request: request, history: original, owner: owner).verifiedHistory()
    try await GrantBackedContentStorage(repository: repository).setAuthority(scope: VaultScope(account: scope.account, vaultID: scope.vaultID), expected: original, history: history, authorization: ContentStorageTestPermit())
    let session = try GrantBackedContentSession(repository: repository, binding: binding, history: history, device: joining)
    let operation = try #require(await repository.operations(account: scope.account, database: "private").first { $0.kind == .prepareGrant })
    #expect(try await session.requestOwnGrant(for: operation, scope: enrollment, owner: ContentStorageTestPermit()))
    let originalRequest = try #require(await repository.coordinationPublications(account: scope.account).first { $0.kind == .grantRequest })
    #expect(try await session.requestOwnGrant(for: operation, scope: enrollment, owner: ContentStorageTestPermit()))
    #expect(try await repository.coordinationPublications(account: scope.account) == [originalRequest])
    let inbox = GrantBackedCoordinationInbox(repository: repository, container: enrollment.container, environment: enrollment.environment, account: enrollment.account, member: enrollment.member)
    let payload = try JSONDecoder().decode(ContentGrantRequest.self, from: inbox.verify(originalRequest, history: history).payload)
    #expect(payload.item == scope.itemID && payload.recipient == joining.identity.fingerprint)
    #expect(try await repository.item(scope) == item.version)
}

@MainActor @Test func contentGrantRequestWaitsForMembershipBeforeVerification() async throws {
    let (root, repository, owner, original, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let joining = try SessionDevice(member: owner.identity.member)
    let enrollment = EnrollmentScope(container: "iCloud.test", environment: "Development", account: scope.account,
        vault: scope.vaultID, member: owner.identity.member)
    let request = try DeviceEnrollmentRequest.create(scope: enrollment, device: joining)
    let history = try DeviceEnrollmentApproval.create(request: request, history: original, owner: owner).verifiedHistory()
    let payload = try JSONEncoder().encode(ContentGrantRequest(item: scope.itemID, keyGeneration: UUID(), recipient: joining.identity.fingerprint))
    let envelope = try CoordinationEnvelope.sign(kind: .grantRequest, scope: enrollment, identity: UUID(),
        payload: payload, history: history, device: joining)
    let record = try PreparedCoordinationRecord(account: scope.account, vault: scope.vaultID, kind: .grantRequest,
        identity: envelope.identity, bytes: envelope.encoded())
    let incoming = try PreparedCoordinationRecord.materialize(record.record(), account: scope.account)
    try await repository.stageIncoming(incoming, permit: ContentStorageTestPermit())
    let operation = try #require(await repository.operations(account: scope.account, database: "private").first { $0.id == incoming.operationID })
    let inbox = GrantBackedCoordinationInbox(repository: repository, container: enrollment.container,
        environment: enrollment.environment, account: enrollment.account, member: enrollment.member)
    guard case .waiting(let dependencies) = await inbox.handle(operation, history: original, permit: ContentStorageTestPermit()) else {
        Issue.record("A request arriving before membership must wait, not quarantine"); return
    }
    #expect(dependencies == [.init(.membership, identifier: scope.vaultID.uuidString + ":" + (try history.current.digest()))])
    #expect(try await repository.operations(account: scope.account, database: "private").contains { $0.kind == .fetchMembership })
    #expect(try await repository.coordinationRecords(account: scope.account, kind: .grantRequest).isEmpty)
    #expect(try await repository.quarantineSummary(account: scope.account).records == 0)
    guard case .completed = await inbox.handle(operation, history: history, permit: ContentStorageTestPermit()) else {
        Issue.record("Request did not resume after trusted membership arrived"); return
    }
    #expect(try await repository.coordinationRecords(account: scope.account, kind: .grantRequest) == [record])
    #expect(try await repository.incomingRecord(id: incoming.id, account: scope.account, database: "private") == nil)

    var revoked = history
    try revoked.append(MembershipEnvelope.successor(of: history.current,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity])],
            removedDevices: [joining.identity.device]), owner: owner))
    try await repository.stageIncoming(incoming, permit: ContentStorageTestPermit())
    // Strict verification must still reject the removed author for access.
    #expect(throws: MopError.vaultUntrusted) { try inbox.verify(record, history: revoked) }
    #expect(try inbox.obsoleteGrantRequest(record, history: revoked))
    guard case .completed = await inbox.handle(operation, history: revoked, permit: ContentStorageTestPermit()) else {
        Issue.record("Verified obsolete work must terminate without granting access"); return
    }
    #expect(try await repository.incomingRecord(id: incoming.id, account: scope.account, database: "private") == nil)
    #expect(try await repository.quarantineSummary(account: scope.account).records == 0)
    let wrongRecipient = try CoordinationEnvelope.sign(kind: .grantRequest, scope: enrollment, identity: UUID(),
        payload: JSONEncoder().encode(ContentGrantRequest(item: scope.itemID, keyGeneration: UUID(), recipient: owner.identity.fingerprint)),
        history: history, device: joining)
    let mismatched = try PreparedCoordinationRecord(account: scope.account, vault: scope.vaultID, kind: .grantRequest,
        identity: wrongRecipient.identity, bytes: wrongRecipient.encoded())
    #expect(throws: MopError.vaultUntrusted) { try inbox.obsoleteGrantRequest(mismatched, history: revoked) }
    var corrupted = try #require(JSONSerialization.jsonObject(with: record.bytes) as? [String: Any])
    corrupted["signature"] = Data(repeating: 0, count: 64).base64EncodedString()
    let invalid = try PreparedCoordinationRecord(account: scope.account, vault: scope.vaultID, kind: .grantRequest,
        identity: record.identity, bytes: JSONSerialization.data(withJSONObject: corrupted, options: [.sortedKeys]))
    #expect(throws: (any Error).self) { try inbox.obsoleteGrantRequest(invalid, history: revoked) }
    // Previously terminal work is re-evaluated without rearming it or issuing grants.
    for candidate in [record, mismatched, invalid] {
        let queued = try await repository.enqueue(SyncOperation(account: scope.account, vaultID: scope.vaultID,
            kind: .enrollment, payload: JSONEncoder().encode(candidate)))
        let failed = try await repository.transition(queued, to: .needsAttention, failure: .invalidAuthority, attempted: true)
        #expect(try await !inbox.retireObsoleteFailure(failed, history: nil, permit: ContentStorageTestPermit()))
        #expect(try await !inbox.retireObsoleteFailure(failed, history: original, permit: ContentStorageTestPermit()))
        #expect(try await !inbox.retireObsoleteFailure(failed, history: history, permit: ContentStorageTestPermit()))
        let retired = try await inbox.retireObsoleteFailure(failed, history: revoked, permit: ContentStorageTestPermit())
        #expect(retired == (candidate == record))
        let saved = try #require(await repository.operations(account: scope.account, database: "private").first { $0.id == failed.id })
        #expect(saved.state == (retired ? .completed : .needsAttention))
        #expect(saved.failure == (retired ? nil : .invalidAuthority))
        #expect(saved.attempts == 1 && saved.deliveredAt == nil)
        if retired {
            await #expect(throws: SyncJournalError.staleOperation) {
                _ = try await inbox.retireObsoleteFailure(failed, history: revoked, permit: ContentStorageTestPermit())
            }
        }
    }
    let badIncoming = try PreparedCoordinationRecord.materialize(invalid.record(), account: scope.account)
    try await repository.stageIncoming(badIncoming, permit: ContentStorageTestPermit())
    let badOperation = try #require(await repository.operations(account: scope.account, database: "private").first { $0.id == badIncoming.operationID })
    guard case .attention(.invalidAuthority) = await inbox.handle(badOperation, history: revoked, permit: ContentStorageTestPermit()) else {
        Issue.record("Invalid signatures cannot be retired as obsolete"); return
    }
    #expect(try await repository.quarantineSummary(account: scope.account).records == 1)
    let badCandidate = try #require(await repository.quarantinedRecords(account: scope.account).first)
    #expect(try await !inbox.retireQuarantinedRequest(badCandidate, history: revoked, permit: ContentStorageTestPermit()))
    // Exercise the old rejection path with a valid, now-obsolete signed request.
    try await repository.stageIncoming(incoming, permit: ContentStorageTestPermit())
    try await repository.quarantineIncoming(incoming, permit: ContentStorageTestPermit())
    let candidate = try #require(await repository.quarantinedRecords(account: scope.account).first { $0.payload == record.bytes })
    #expect(try await !inbox.retireQuarantinedRequest(candidate, history: nil, permit: ContentStorageTestPermit()))
    #expect(try await !inbox.retireQuarantinedRequest(candidate, history: history, permit: ContentStorageTestPermit()))
    var legacy = candidate; legacy.operations = nil
    #expect(try await !inbox.retireQuarantinedRequest(legacy, history: revoked, permit: ContentStorageTestPermit()))
    var evicted = candidate; evicted.payload = nil
    #expect(try await !inbox.retireQuarantinedRequest(evicted, history: revoked, permit: ContentStorageTestPermit()))
    #expect(try await inbox.retireQuarantinedRequest(candidate, history: revoked, permit: ContentStorageTestPermit()))
    let retiredIncoming = try #require(await repository.operations(account: scope.account, database: "private").first { $0.id == incoming.operationID })
    #expect(retiredIncoming.state == .completed && retiredIncoming.failure == nil && retiredIncoming.deliveredAt == nil)
    #expect(try await repository.quarantinedRecords(account: scope.account) == [badCandidate])
    #expect(try await repository.quarantineSummary(account: scope.account).records == 2) // evidence retained
    await #expect(throws: SyncJournalError.staleOperation) {
        _ = try await inbox.retireQuarantinedRequest(candidate, history: revoked, permit: ContentStorageTestPermit())
    }

}

@MainActor @Test func contentDeletionCarriesAuthorityForReturningDevicesAndReusesPreparedBytes() async throws {
    let (root, repository, owner, original, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let joining = try SessionDevice(member: owner.identity.member)
    var history = original
    try history.append(MembershipEnvelope.successor(of: history.current,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])]), owner: owner))
    let binding = ItemVaultBinding(account: scope.account, database: "private", zoneOwner: scope.zoneOwner, vaultID: scope.vaultID)
    let session = try GrantBackedContentSession(repository: repository, binding: binding, history: history, device: joining)
    let enrollment = EnrollmentScope(container: "iCloud.test", environment: "Development", account: scope.account, vault: scope.vaultID, member: owner.identity.member)
    try await session.prepareDeletion(scope: enrollment, owner: ContentStorageTestPermit())
    let prepared = try #require(await repository.preparedCoordination(account: scope.account, vault: scope.vaultID, kind: .deletion, identity: scope.vaultID))
    try await session.prepareDeletion(scope: enrollment, owner: ContentStorageTestPermit())
    #expect(try await repository.preparedCoordination(account: scope.account, vault: scope.vaultID, kind: .deletion, identity: scope.vaultID) == prepared)
    #expect(try await repository.deletion(VaultScope(account: scope.account, vaultID: scope.vaultID))?.notice == prepared.bytes)
    session.lock(); owner.close()
    let handler = GrantBackedCoordinationInbox(repository: repository, container: enrollment.container, environment: enrollment.environment, account: enrollment.account, member: enrollment.member)
    // Only the old independently pinned history is available; no zone fetch or secret key is needed.
    _ = try handler.verify(prepared, history: original)
    #expect(throws: CloudSyncAdapterError.membershipUnavailable) { try handler.verify(prepared, history: nil) }
    let other = GrantBackedCoordinationInbox(repository: repository, container: "iCloud.other", environment: enrollment.environment, account: enrollment.account, member: enrollment.member)
    #expect(throws: (any Error).self) { try other.verify(prepared, history: original) }
    let incoming = try PreparedCoordinationRecord.materialize(prepared.record(), account: scope.account)
    _ = try await repository.stageIncoming(incoming)
    let operation = try #require(await repository.operations(account: scope.account, database: "private").first { $0.id == incoming.operationID })
    guard case .completed = await handler.handle(operation, history: original, permit: ContentStorageTestPermit()) else { Issue.record("Returning device could not authenticate terminal notice"); return }
    #expect(try await repository.operations(account: scope.account, database: "private").contains { $0.kind == .deletion })
    #expect(try await repository.quarantineSummary(account: scope.account).records == 0)
}

@MainActor @Test func contentConcurrentDeletionSupersedesLocalNoticeWithoutFalseDelivery() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let binding = ItemVaultBinding(account: scope.account, database: "private", zoneOwner: scope.zoneOwner, vaultID: scope.vaultID)
    let session = try GrantBackedContentSession(repository: repository, binding: binding, history: history, device: SessionDevice(copying: owner))
    let enrollment = EnrollmentScope(container: "iCloud.test", environment: "Development", account: scope.account, vault: scope.vaultID, member: owner.identity.member)
    try await session.prepareDeletion(scope: enrollment, owner: ContentStorageTestPermit())
    let local = try #require(await repository.preparedCoordination(account: scope.account, vault: scope.vaultID, kind: .deletion, identity: scope.vaultID))
    let handler = GrantBackedCoordinationInbox(repository: repository, container: enrollment.container, environment: enrollment.environment, account: enrollment.account, member: enrollment.member)
    let notice = try VaultDeletionNotice.create(binding: handler.deletionBinding(vault: scope.vaultID, genesis: history.orderedStates[0].digest()), history: history, owner: owner)
    let remote = try PreparedCoordinationRecord(account: scope.account, vault: scope.vaultID, kind: .deletion, identity: scope.vaultID,
        bytes: CoordinationEnvelope.sign(kind: .deletion, scope: enrollment, identity: scope.vaultID, payload: notice.encoded(), history: history, device: owner).encoded())
    #expect(local != remote)
    let incoming = try PreparedCoordinationRecord.materialize(remote.record(), account: scope.account)
    _ = try await repository.stageIncoming(incoming)
    let operation = try #require(await repository.operations(account: scope.account, database: "private").first { $0.id == incoming.operationID })
    guard case .completed = await handler.handle(operation, history: history, permit: ContentStorageTestPermit()) else { Issue.record("Concurrent terminal notices failed to converge"); return }
    #expect(try await repository.preparedCoordination(account: scope.account, vault: scope.vaultID, kind: .deletion, identity: scope.vaultID) == remote)
    #expect(try await !repository.operationIsDelivered(local.operationID, account: scope.account))
    #expect(try await repository.quarantineSummary(account: scope.account).records == 0)
}

@MainActor @Test(arguments: [false, true])
func contentConflictChoiceSurvivesNonOwnerExitAndCommitsWhileLocked(keepLocal: Bool) async throws {
    let (root, repository, owner, history, originalScope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let scope = ItemScope(account: originalScope.account, vaultID: originalScope.vaultID, itemID: ItemVaultSession.metadataRecordID)
    let binding = ItemVaultBinding(account: scope.account, database: "private", zoneOwner: scope.zoneOwner, vaultID: scope.vaultID)
    let session = try GrantBackedContentSession(repository: repository, binding: binding, history: history, device: SessionDevice(copying: owner))
    let local = try await session.create(item: scope.itemID, components: [ContentItemArchive.metadataComponent: ContentItemArchive.encode(VaultMetadata(name: "local"))])
    let remote = try ContentEnvelope.seal([ContentItemArchive.metadataComponent: ContentItemArchive.encode(VaultMetadata(name: "remote"))], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let prepared = try GrantBackedContentStorage.prepare(remote, scope: scope, history: history)
    let inbox = GrantBackedContentInbox(repository: repository, account: scope.account)
    let records = try [ContentRecordTransport.content(prepared.content, kind: .version)] + prepared.grants.map { try ContentRecordTransport.grant($0) } + [ContentRecordTransport.content(prepared.content, kind: .head)]
    for record in records {
        let incoming = try ContentRecordTransport.materialize(record, account: scope.account)
        _ = try await repository.stageIncoming(incoming)
        _ = try await inbox.process(id: incoming.id, history: history, permit: ContentStorageTestPermit(), comparison: session.comparison())
    }
    let expected = try #require(await repository.contentConflicts(account: scope.account).first)
    let catalog = keepLocal ? ItemContentCatalog(item: VaultItem(name: "settings", fields: []), references: [:]) : nil
    try await session.queueConflictChoice(expected, catalog: catalog)
    let decision = try #require(await repository.operations(account: scope.account, database: "private").first { $0.kind == .resolveConflict })
    try await session.queueConflictChoice(expected, catalog: catalog)
    #expect(try await repository.operations(account: scope.account, database: "private").filter { $0.kind == .resolveConflict } == [decision])
    #expect(try await repository.contentConflicts(account: scope.account).isEmpty)
    #expect(try await repository.contentConflicts(account: scope.account, includePendingDecisions: true) == [expected])
    #expect(try await !repository.syncHealth(account: scope.account, database: "private").blockedReasons.contains(.conflict))
    #expect(try await repository.item(scope) == local.version)
    session.lock(); owner.close()
    let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
    let (reviewed, replacement) = try await reopened.contentConflictDecision(decision)
    if let replacement {
        for grant in replacement.grants {
            try GrantBackedContentStorage.validatePublication(ContentUpload(operationID: decision.id, content: replacement.content,
                grant: grant, kind: .grant, systemFields: nil), history: history)
        }
    }
    _ = try await reopened.resolveContentConflict(reviewed, replacement: replacement, serverSystemFields: Data([9]),
        policy: GrantBackedContentStorage.recipientPolicy(history: history), decision: decision, permit: ContentStorageTestPermit())
    #expect(try await reopened.operations(account: scope.account, database: "private").first { $0.id == decision.id }?.state == .completed)
    #expect(try await !reopened.operationIsDelivered(decision.id, account: scope.account))
    #expect(try await reopened.item(scope)?.versionID == (replacement?.content.version.versionID ?? expected.remote.versionID))
    if let replacement {
        let publications = try await reopened.contentPublications(account: scope.account)
        #expect(publications.filter { $0.grant?.keyGeneration == replacement.content.keyGeneration }.count == replacement.grants.count)
    }
    await #expect(throws: SyncJournalError.staleOperation) { try await reopened.contentConflictDecision(decision) }
}

@Test(arguments: [MopError.vaultUntrusted, .cloudPermission, .invalidVault, .signing, .notVaultMember, .invalidIdentity])
func permanentCoordinationFailuresDoNotRetryOnWake(failure: MopError) async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let repository = try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite/ContentPreview3/Content3.sqlite"))
    let operation = try await repository.enqueue(SyncOperation(account: "test", kind: .enrollment))
    let coordinator = DurableSyncCoordinator(repository: repository, account: "test", kinds: [.enrollment],
        dependencyAvailable: { _ in true }, handler: { _ in ItemVaultSyncRuntime.workFailureOutcome(failure) })
    await coordinator.start()
    await coordinator.wake(reason: .unlocked)
    await coordinator.wake(reason: .dependenciesChanged)
    await coordinator.wake(reason: .foreground)
    await coordinator.waitUntilIdle()
    await coordinator.stop()
    let result = try #require(await repository.operations(account: "test", database: "private").first { $0.id == operation.id })
    #expect(result.state == .needsAttention && result.failure == .invalidAuthority && result.attempts == 1)
    guard case .retry(.dependency, _) = ItemVaultSyncRuntime.workFailureOutcome(CloudSyncAdapterError.membershipUnavailable) else {
        Issue.record("Unknown membership must remain retryable"); return
    }
}

@Test func permanentRuntimeFailuresRemainStoppedAcrossWakes() async throws {
    let failures: [any Error] = [
        DeviceEnrollmentFailure.invalidRequest, DeviceEnrollmentFailure.invalidApproval,
        CloudSyncAdapterError.invalidBinding, CloudSyncAdapterError.malformedRecord,
        CloudSyncAdapterError.untrustedRecord, ContentStoreError.invalidRecord,
        ContentStoreError.identityCollision, SyncJournalError.invalidOperation,
        SyncJournalError.identityCollision, ItemContentFailure.invalidRecordMutation,
        ItemRepositoryError.invalidScope, ItemRepositoryError.invalidGeneration,
        ItemRepositoryError.emptyCiphertext, ItemRepositoryError.oversizedCiphertext,
        MopError.invalidRecovery, MopError.deviceRemoved,
        DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "test"))
    ]
    for failure in failures {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite/ContentPreview3/Content3.sqlite"))
        let operation = try await repository.enqueue(SyncOperation(account: "test", kind: .enrollment))
        let coordinator = DurableSyncCoordinator(repository: repository, account: "test", kinds: [.enrollment],
            dependencyAvailable: { _ in true }, handler: { _ in ItemVaultSyncRuntime.workFailureOutcome(failure) })
        await coordinator.start()
        await coordinator.waitUntilIdle()
        for reason: SyncWakeReason in [.unlocked, .dependenciesChanged, .foreground] {
            await coordinator.wake(reason: reason)
            await coordinator.waitUntilIdle()
        }
        await coordinator.stop()
        let result = try #require(await repository.operations(account: "test", database: "private").first { $0.id == operation.id })
        #expect(result.state == .needsAttention && result.failure == .invalidAuthority && result.attempts == 1)
    }
}

@Test func runtimeTransientFailuresRetainTheirRetryReason() {
    let dependencies: [any Error] = [CloudSyncAdapterError.membershipUnavailable,
        ContentStoreError.staleAuthority, SyncJournalError.staleOperation, ItemRepositoryError.staleLocalVersion]
    for failure in dependencies {
        guard case .retry(.dependency, _) = ItemVaultSyncRuntime.workFailureOutcome(failure) else {
            Issue.record("Temporary dependency incorrectly classified: \(failure)"); continue
        }
    }
    guard case .attention(.processing) = ItemVaultSyncRuntime.workFailureOutcome(ContentStoreError.wrongLayout),
          case .attention(.processing) = ItemVaultSyncRuntime.workFailureOutcome(ItemRepositoryError.corruptStore),
          case .attention(.processing) = ItemVaultSyncRuntime.workFailureOutcome(MopError.cloudInvalidRequest),
          case .attention(.accountChanged) = ItemVaultSyncRuntime.workFailureOutcome(CloudSyncAdapterError.accountChanged),
          case .attention(.conflict) = ItemVaultSyncRuntime.workFailureOutcome(MopError.vaultConflict),
          case .retry(.inboxFull, _) = ItemVaultSyncRuntime.workFailureOutcome(SyncJournalError.inboxFull),
          case .retry(.inboxFull, _) = ItemVaultSyncRuntime.workFailureOutcome(CloudSyncAdapterError.inboxFull),
          case .authorization = ItemVaultSyncRuntime.workFailureOutcome(MopError.authentication),
          case .retry(.transport, _) = ItemVaultSyncRuntime.workFailureOutcome(MopError.cloudUnavailable),
          case .retry(.processing, _) = ItemVaultSyncRuntime.workFailureOutcome(NSError(domain: "test", code: 1)) else {
        Issue.record("Transient failures lost their retry classification"); return
    }
}

@MainActor @Test func grantPrerequisitesFetchMissingHeadAndWakeOnlyForRelevantState() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let publication = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let request = ContentGrantRequest(item: scope.itemID, keyGeneration: publication.content.header.keyGeneration, recipient: owner.identity.fingerprint)
    let worker = GrantRequestPrerequisites(repository: repository), permit = ContentStorageTestPermit()
    guard case .waiting(let dependencies) = try await worker.reconcile(request: request, scope: scope, history: history, permit: permit) else {
        Issue.record("Missing head must wait"); return
    }
    let dependency = try #require(dependencies.first)
    let wait = try #require(GrantRequestWait(dependency: dependency))
    #expect(try await !wait.available(repository: repository, scope: scope, history: history))
    _ = try await worker.reconcile(request: request, scope: scope, history: history, permit: permit)
    let fetches = try await repository.operations(account: "a", database: "private").filter { $0.kind == .fetchContentHead }
    #expect(fetches.count == 1)
    let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
    #expect(try await reopened.operations(account: "a", database: "private").contains { $0.id == fetches.first?.id })
    let otherScope = ItemScope(account: "a", vaultID: history.vault, itemID: UUID())
    let other = try ContentEnvelope.seal(["password": "other"], vault: history.vault, item: otherScope.itemID, history: history, signer: owner)
    let storage = GrantBackedContentStorage(repository: repository)
    _ = try await storage.commit(other.content, grants: other.grants, scope: otherScope, history: history, authorization: permit)
    #expect(try await !wait.available(repository: repository, scope: scope, history: history))
    _ = try await storage.commit(publication.content, grants: publication.grants, scope: scope, history: history, authorization: permit)
    #expect(try await wait.available(repository: repository, scope: scope, history: history))
    guard case .completed = try await worker.reconcile(request: request, scope: scope, history: history, permit: permit) else { Issue.record("Expected completion"); return }
}

@MainActor @Test func grantPrerequisiteWaitObservesMembershipAndPreservesUnknownGeneration() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    _ = try await GrantBackedContentStorage(repository: repository).commit(first.content, grants: first.grants, scope: scope, history: history, authorization: ContentStorageTestPermit())
    let request = ContentGrantRequest(item: scope.itemID, keyGeneration: UUID(), recipient: owner.identity.fingerprint)
    guard case .waiting(let dependencies) = try await GrantRequestPrerequisites(repository: repository).reconcile(request: request, scope: scope, history: history, permit: ContentStorageTestPermit()) else {
        Issue.record("Unrelated generation is not obsolete proof"); return
    }
    let dependency = try #require(dependencies.first)
    let wait = try #require(GrantRequestWait(dependency: dependency))
    #expect(try await !wait.available(repository: repository, scope: scope, history: history))
    let joining = try SessionDevice(member: owner.identity.member)
    var updated = history
    try updated.append(MembershipEnvelope.successor(of: history.current, membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])]), owner: owner))
    #expect(try await wait.available(repository: repository, scope: scope, history: updated))
    #expect(GrantRequestWait(dependency: try wait.dependency()) == wait)
}

@MainActor @Test func grantPrerequisitesRetireOnlyVerifiedAncestorGeneration() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let storage = GrantBackedContentStorage(repository: repository), permit = ContentStorageTestPermit()
    _ = try await storage.commit(first.content, grants: first.grants, scope: scope, history: history, authorization: permit)
    let rotated = try first.content.rotateKey(grant: #require(first.grants.first), history: history, decryptor: owner, signer: owner)
    _ = try await storage.commit(rotated.content, grants: rotated.grants, scope: scope, history: history, authorization: permit)
    let worker = GrantRequestPrerequisites(repository: repository)
    let obsolete = ContentGrantRequest(item: scope.itemID, keyGeneration: first.content.header.keyGeneration, recipient: owner.identity.fingerprint)
    guard case .completed = try await worker.reconcile(request: obsolete, scope: scope, history: history, permit: permit) else { Issue.record("Verified ancestor should retire"); return }
    let unrelated = ContentGrantRequest(item: scope.itemID, keyGeneration: UUID(), recipient: owner.identity.fingerprint)
    guard case .waiting = try await worker.reconcile(request: unrelated, scope: scope, history: history, permit: permit) else {
        Issue.record("Unproven generation must remain waiting"); return
    }
    let wrongRecipient = ContentGrantRequest(item: scope.itemID, keyGeneration: first.content.header.keyGeneration, recipient: String(repeating: "f", count: 64))
    await #expect(throws: ContentStoreError.staleAuthority) {
        try await worker.reconcile(request: wrongRecipient, scope: scope, history: history, permit: permit)
    }
}

@MainActor @Test func grantPrerequisiteHeadFetchStagesWithoutTrustOrCheckpointAndRejectsWrongRoute() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let prepared = try preparedInboxContent(first.content, scope: scope, history: history)
    let dependency = SyncDependency(.contentHead, identifier: scope.vaultID.uuidString + ":" + scope.itemID.uuidString)
    let request = try #require(ContentHeadFetch(dependency: dependency))
    let operation = try await repository.enqueuePrerequisite(request.operation(account: "a", owner: scope.zoneOwner), permit: ContentStorageTestPermit())
    try await repository.saveEngineState(Data([7]), account: "a", database: "private")
    let wrong = ContentHeadFetcher(repository: repository, account: "a") { _ in
        try ContentRecordTransport.content(prepared, kind: .version)
    }
    guard case .attention(.invalidAuthority) = await wrong.handle(operation, permit: ContentStorageTestPermit()) else { Issue.record("Wrong route must fail"); return }
    let missing = ContentHeadFetcher(repository: repository, account: "a") { _ in throw CKError(.unknownItem) }
    guard case .retry(.transport, _) = await missing.handle(operation, permit: ContentStorageTestPermit()) else {
        Issue.record("Missing cloud record must not retire request"); return
    }
    let fetcher = ContentHeadFetcher(repository: repository, account: "a") { id in
        #expect(id == request.recordID(owner: scope.zoneOwner))
        return try ContentRecordTransport.content(prepared, kind: .head)
    }
    guard case .completed = await fetcher.handle(operation, permit: ContentStorageTestPermit()) else { Issue.record("Head fetch must complete"); return }
    #expect(try await repository.item(scope) == nil)
    #expect(try await repository.engineState(account: "a", database: "private") == Data([7]))
    #expect(try await repository.incomingRecords(account: "a", database: "private").count == 1)
    let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
    #expect(try await reopened.operations(account: "a", database: "private").first { $0.id == operation.id }?.state == .completed)
    let incoming = try #require(await reopened.incomingRecords(account: "a", database: "private").first)
    _ = try await GrantBackedContentInbox(repository: reopened, account: "a").process(id: incoming.id, history: history, permit: ContentStorageTestPermit())
    #expect(try await reopened.contentState(scope: scope)?.keyGeneration == first.content.header.keyGeneration)
}

@MainActor @Test func grantPrerequisitesFetchMissingAncestryBeforeRetirement() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let rotated = try first.content.rotateKey(grant: #require(first.grants.first), history: history, decryptor: owner, signer: owner)
    let current = try ContentRecordTransport.materialize(ContentRecordTransport.content(preparedInboxContent(rotated.content, scope: scope, history: history), kind: .head), account: "a")
    let inbox = GrantBackedContentInbox(repository: repository, account: "a"), permit = ContentStorageTestPermit()
    _ = try await repository.stageIncoming(current)
    _ = try await inbox.process(id: current.id, history: history, permit: permit)
    let request = ContentGrantRequest(item: scope.itemID, keyGeneration: first.content.header.keyGeneration, recipient: owner.identity.fingerprint)
    let worker = GrantRequestPrerequisites(repository: repository)
    guard case .waiting(let dependencies) = try await worker.reconcile(request: request, scope: scope, history: history, permit: permit) else {
        Issue.record("Missing ancestry cannot prove obsolescence"); return
    }
    let dependency = try #require(dependencies.first)
    let wait = try #require(GrantRequestWait(dependency: dependency))
    #expect(wait.missingVersion == first.content.header.version)
    #expect(try await !wait.available(repository: repository, scope: scope, history: history))
    let fetch = try #require(await repository.operations(account: "a", database: "private").first { $0.kind == .fetchContentVersion })
    let decoded = try JSONDecoder().decode(ContentVersionFetch.self, from: fetch.payload)
    #expect(decoded.version == first.content.header.version)
    let ancestor = try ContentRecordTransport.materialize(ContentRecordTransport.content(preparedInboxContent(first.content, scope: scope, history: history), kind: .version), account: "a")
    _ = try await repository.stageIncoming(ancestor)
    _ = try await inbox.process(id: ancestor.id, history: history, permit: permit)
    #expect(try await wait.available(repository: repository, scope: scope, history: history))
    guard case .completed = try await worker.reconcile(request: request, scope: scope, history: history, permit: permit) else {
        Issue.record("Verified ancestor should retire"); return
    }
    #expect(try await repository.item(scope)?.versionID == rotated.content.header.version)
}

@MainActor @Test func grantPrerequisitesRefreshStaleHeadOnceAndResumeNewGeneration() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: scope.itemID, history: history, signer: owner)
    let rotated = try first.content.rotateKey(grant: #require(first.grants.first), history: history, decryptor: owner, signer: owner)
    let inbox = GrantBackedContentInbox(repository: repository, account: "a"), permit = ContentStorageTestPermit()
    let head = try ContentRecordTransport.materialize(ContentRecordTransport.content(preparedInboxContent(first.content, scope: scope, history: history), kind: .head), account: "a")
    _ = try await repository.stageIncoming(head)
    _ = try await inbox.process(id: head.id, history: history, permit: permit)
    let worker = GrantRequestPrerequisites(repository: repository)
    let request = ContentGrantRequest(item: scope.itemID, keyGeneration: rotated.content.header.keyGeneration, recipient: owner.identity.fingerprint)
    guard case .waiting(let dependencies) = try await worker.reconcile(request: request, scope: scope, history: history, permit: permit) else {
        Issue.record("Newer generation must fetch its head"); return
    }
    let dependency = try #require(dependencies.first)
    let wait = try #require(GrantRequestWait(dependency: dependency))
    let fetch = try #require(await repository.operations(account: "a", database: "private").first { $0.kind == .fetchContentHead })
    let prepared = try preparedInboxContent(rotated.content, scope: scope, history: history)
    let fetcher = ContentHeadFetcher(repository: repository, account: "a") { _ in try ContentRecordTransport.content(prepared, kind: .head) }
    guard case .completed = await fetcher.handle(fetch, permit: permit) else { Issue.record("Fetch failed"); return }
    // Reception alone is not readiness and duplicate work cannot re-fetch it.
    #expect(try await !wait.available(repository: repository, scope: scope, history: history))
    _ = try await worker.reconcile(request: request, scope: scope, history: history, permit: permit)
    let fetches = try await repository.operations(account: "a", database: "private").filter { $0.kind == .fetchContentHead }
    #expect(fetches.count == 1)
    #expect(fetches.first?.state == .completed)
    let incoming = try #require(await repository.incomingRecords(account: "a", database: "private").first)
    _ = try await inbox.process(id: incoming.id, history: history, permit: permit)
    #expect(try await wait.available(repository: repository, scope: scope, history: history))
    guard case .completed = try await worker.reconcile(request: request, scope: scope, history: history, permit: permit) else {
        Issue.record("Verified newer head should resolve request"); return
    }
    let oldFetch = ContentHeadFetch(vault: scope.vaultID, item: scope.itemID, observedVersion: first.content.header.version, membership: try history.current.digest())
    let newFetch = ContentHeadFetch(vault: scope.vaultID, item: scope.itemID, observedVersion: rotated.content.header.version, membership: try history.current.digest())
    #expect(try oldFetch.operation(account: "a", owner: scope.zoneOwner).id != newFetch.operation(account: "a", owner: scope.zoneOwner).id)
}

@MainActor @Test(arguments: [false, true]) func rotationPrerequisitesRecoverAfterRestart(missingAncestor: Bool) async throws {
    let (root, repository, owner, original, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let peer = try SessionDevice(member: owner.identity.member), permit = ContentStorageTestPermit()
    var admitted = original
    try admitted.append(MembershipEnvelope.successor(of: original.current,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, peer.identity])]), owner: owner))
    let storage = GrantBackedContentStorage(repository: repository)
    let vaultScope = VaultScope(account: scope.account, vaultID: scope.vaultID)
    try await storage.setAuthority(scope: vaultScope, expected: original, history: admitted, authorization: permit)
    let first = try ContentEnvelope.seal(["password": "first"], vault: scope.vaultID, item: scope.itemID, history: admitted, signer: owner)
    let ownGrant = try #require(first.grants.first { $0.recipient == owner.identity.fingerprint })
    let edited = try first.content.editing(["password": "offline edit"], grant: ownGrant, history: admitted, device: owner)
    let content = missingAncestor ? edited : first.content
    // Commit an unpublished edit whose parent is absent, or a head without its
    // source grant. Both are recoverable without deleting or trusting cloud data.
    if missingAncestor {
        _ = try await storage.commit(first.content, grants: first.grants, scope: scope, history: admitted, authorization: permit)
    }
    _ = try await storage.commit(content, grants: missingAncestor ? [ownGrant] : [], scope: scope, history: admitted, authorization: permit)
    if missingAncestor { try await repository.removePrerequisiteFixtureVersion(scope: scope, version: first.content.header.version) }
    var revoked = admitted
    try revoked.append(MembershipEnvelope.successor(of: admitted.current,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity])], removedDevices: [peer.identity.device]), owner: owner))
    try await storage.setAuthority(scope: vaultScope, expected: admitted, history: revoked, authorization: permit)
    let binding = ItemVaultBinding(account: scope.account, database: scope.database, zoneOwner: scope.zoneOwner, vaultID: scope.vaultID)
    let enrollment = EnrollmentScope(container: "iCloud.test", environment: "Development", account: scope.account, vault: scope.vaultID, member: owner.identity.member)
    let session = try GrantBackedContentSession(repository: repository, binding: binding, history: revoked, device: SessionDevice(copying: owner))
    let operation = try #require(await repository.activeOperations(account: scope.account, database: scope.database).first { $0.kind == .rotateContent })
    try await repository.saveEngineState(Data([42]), account: scope.account, database: scope.database)
    guard case .waiting(let dependencies) = await session.handle(operation, owner: permit, grantRequestScope: enrollment) else {
        Issue.record("Missing prerequisite must create durable recovery and wait"); return
    }
    let waiting = try await repository.transition(operation, to: .waitingForDependency, dependencies: dependencies, failure: .dependency)
    let before = try await repository.coordinationPublications(account: scope.account)
    _ = await session.handle(waiting, owner: permit, grantRequestScope: enrollment)
    #expect(try await repository.coordinationPublications(account: scope.account) == before)
    #expect(before.filter { $0.kind == .grantRequest }.count == (missingAncestor ? 0 : 1))
    let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
    let fetches = try await reopened.activeOperations(account: scope.account, database: scope.database).filter { [.fetchContentVersion, .fetchContentHead].contains($0.kind) }
    #expect(fetches.count == 1)
    let inbox = GrantBackedContentInbox(repository: reopened, account: scope.account)
    let dependency = try #require(dependencies.first)
    func ready() async throws -> Bool {
        if let wait = GrantRequestWait(dependency: dependency) { return try await wait.available(repository: reopened, scope: scope, history: revoked) }
        return try await inbox.dependencyAvailable(dependency, history: revoked)
    }
    #expect(try await !ready())
    let record = missingAncestor
        ? try ContentRecordTransport.content(preparedInboxContent(first.content, scope: scope, history: revoked), kind: .version)
        : try ContentRecordTransport.grant(preparedInboxGrant(ownGrant, scope: scope))
    let malformed = record.copy() as! CKRecord
    malformed["payload"] = Data("invalid signed payload".utf8)
    let rejected = try ContentRecordTransport.materialize(malformed, account: scope.account)
    try await reopened.stageIncoming(rejected, permit: permit)
    guard case .attention(.invalidAuthority) = try await inbox.process(id: rejected.id, history: revoked, permit: permit) else {
        Issue.record("Invalid prerequisite must remain untrusted"); return
    }
    #expect(try await !ready())
    let incoming = try ContentRecordTransport.materialize(record, account: scope.account)
    try await reopened.stageIncoming(incoming, permit: permit)
    #expect(try await !ready()) // Reception is never verification.
    guard case .completed = try await inbox.process(id: incoming.id, history: revoked, permit: permit) else {
        Issue.record("Authentic prerequisite must apply"); return
    }
    #expect(try await ready())
    let resumed = try GrantBackedContentSession(repository: reopened, binding: binding, history: revoked, device: SessionDevice(copying: owner))
    guard case .completed = await resumed.handle(waiting, owner: permit, grantRequestScope: enrollment) else {
        Issue.record("Rotation must resume with verified prerequisite"); return
    }
    #expect(try await reopened.contentState(scope: scope)?.keyGeneration != first.content.header.keyGeneration)
    #expect(try await reopened.engineState(account: scope.account, database: scope.database) == Data([42]))
}

private extension EncryptedItemRepository {
    func removePrerequisiteFixtureVersion(scope: ItemScope, version: UUID) throws {
        try transaction {
            if let row = try fetchOne("ContentVersion", key: scope.storageKey + ":" + version.uuidString) { context.delete(row) }
        }
    }
}

@MainActor @Test func manualPrerequisiteRefreshPreservesVerificationAndServerDeadline() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let permit = ContentStorageTestPermit(), inbox = GrantBackedContentInbox(repository: repository, account: scope.account)
    let publication = try ContentEnvelope.seal(["password": "secret"], vault: scope.vaultID, item: scope.itemID, history: history, signer: owner)
    let prepared = try preparedInboxContent(publication.content, scope: scope, history: history)
    let initial = try ContentRecordTransport.materialize(ContentRecordTransport.content(prepared, kind: .head), account: scope.account)
    try await repository.stageIncoming(initial, permit: permit)
    _ = try await inbox.process(id: initial.id, history: history, permit: permit)
    let worker = GrantRequestPrerequisites(repository: repository)
    let request = ContentGrantRequest(item: scope.itemID, keyGeneration: UUID(), recipient: owner.identity.fingerprint)
    guard case .waiting(let dependencies) = try await worker.reconcile(request: request, scope: scope, history: history, permit: permit) else {
        Issue.record("Unknown generation must remain waiting"); return
    }
    _ = try await repository.enqueue(SyncOperation(account: scope.account, vaultID: scope.vaultID, kind: .enrollment, dependencies: dependencies))
    let fetch = try #require(await repository.activeOperations(account: scope.account, database: scope.database).first { $0.kind == .fetchContentHead })
    let fetcher = ContentHeadFetcher(repository: repository, account: scope.account) { _ in try ContentRecordTransport.content(prepared, kind: .head) }
    _ = await fetcher.handle(fetch, permit: permit)
    try await worker.refreshWaitingHeads(account: scope.account, owner: scope.zoneOwner, permit: permit)
    #expect(try await repository.operations(account: scope.account, database: scope.database).first { $0.id == fetch.id }?.state == .completed)
    // A staged response must be verified before another manual fetch is useful.
    _ = try await inbox.process(id: initial.id, history: history, permit: permit)
    let dependency = try #require(dependencies.first)
    let wait = try #require(GrantRequestWait(dependency: dependency))
    #expect(try await !wait.available(repository: repository, scope: scope, history: history))
    try await repository.saveEngineState(Data([17]), account: scope.account, database: scope.database)
    try await worker.refreshWaitingHeads(account: scope.account, owner: scope.zoneOwner, permit: permit)
    let refreshed = try #require(await repository.operations(account: scope.account, database: scope.database).first { $0.id == fetch.id })
    #expect(refreshed.state == .ready)
    let deadline = Date().addingTimeInterval(300)
    _ = try await repository.transition(refreshed, to: .retryScheduled, failure: .transport, nextAttempt: deadline, retryNotBefore: deadline)
    try await worker.refreshWaitingHeads(account: scope.account, owner: scope.zoneOwner, permit: permit)
    let retained = try #require(await repository.operations(account: scope.account, database: scope.database).first { $0.id == fetch.id })
    #expect(retained.state == .retryScheduled && retained.retryNotBefore == deadline)
    #expect(try await !wait.available(repository: repository, scope: scope, history: history))
    #expect(try await repository.engineState(account: scope.account, database: scope.database) == Data([17]))
}

private extension EncryptedItemRepository {
    func markEnrollmentRecipientForGrantTest(scope: VaultScope, recipient: String) throws {
        try transaction { try writeJournal(recipient, entity: "StateBlob", key: "enrollment-progress-recipient:" + scope.storageKey) }
    }
}

@MainActor @Test(arguments: [false, true])
func enrollmentWaitsForAutomaticGrantsThenRepairsOnlyIfStillMissing(grantArrives: Bool) async throws {
    let (root, repository, owner, original, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let permit = ContentStorageTestPermit()
    let binding = ItemVaultBinding(account: scope.account, database: scope.database, zoneOwner: scope.zoneOwner, vaultID: scope.vaultID)
    let source = try GrantBackedContentSession(repository: repository, binding: binding, history: original, device: SessionDevice(copying: owner))
    _ = try await source.create(item: scope.itemID, components: ["password": "secret"])
    let joining = try SessionDevice(member: owner.identity.member)
    let enrollment = EnrollmentScope(container: "iCloud.test", environment: "Development", account: scope.account, vault: scope.vaultID, member: owner.identity.member)
    let request = try DeviceEnrollmentRequest.create(scope: enrollment, device: joining)
    let history = try DeviceEnrollmentApproval.create(request: request, history: original, owner: owner).verifiedHistory()
    try await GrantBackedContentStorage(repository: repository).setAuthority(scope: VaultScope(scope), expected: original, history: history, authorization: permit)
    try await repository.markEnrollmentRecipientForGrantTest(scope: VaultScope(scope), recipient: joining.identity.fingerprint)
    let session = try GrantBackedContentSession(repository: repository, binding: binding, history: history, device: SessionDevice(copying: joining))
    let operation = try #require(await repository.activeOperations(account: scope.account, database: scope.database).first { $0.kind == .prepareGrant })
    let now = operation.createdAt
    guard case .waitingUntil(let dependencies, let deadline) = await session.handle(operation, owner: permit, grantRequestScope: enrollment, now: now) else {
        Issue.record("Fresh enrollment must wait for the automatic grant"); return
    }
    #expect(deadline == now.addingTimeInterval(GrantBackedContentSession.initialGrantRepairDelay))
    let waiting = try await repository.transition(operation, to: .waitingForDependency, dependencies: dependencies, failure: .dependency, nextAttempt: deadline)
    let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
    let resumed = try GrantBackedContentSession(repository: reopened, binding: binding, history: history, device: SessionDevice(copying: joining))
    for _ in 0..<3 {
        guard case .waitingUntil(_, let sameDeadline) = await resumed.handle(waiting, owner: permit, grantRequestScope: enrollment, now: now.addingTimeInterval(1)) else {
            Issue.record("Reopening must preserve the enrollment grace period"); return
        }
        #expect(sameDeadline == deadline)
    }
    #expect(try await reopened.coordinationPublications(account: scope.account).isEmpty)
    #expect(try await reopened.activeOperations(account: scope.account, database: scope.database).allSatisfy { ![.fetchContentHead, .fetchContentVersion].contains($0.kind) })
    let dependency = try #require(dependencies.first)
    let wait = try #require(GrantRequestWait(dependency: dependency))
    #expect(try await !wait.available(repository: reopened, scope: scope, history: history))
    if grantArrives {
        let sender = try GrantBackedContentSession(repository: repository, binding: binding, history: history, device: SessionDevice(copying: owner))
        guard case .completed = await sender.handle(waiting, owner: permit, grantRequestScope: enrollment, now: now) else {
            Issue.record("Owner must prepare the grant immediately despite the recipient's wait"); return
        }
        #expect(try await wait.available(repository: reopened, scope: scope, history: history))
        guard case .completed = await resumed.handle(waiting, owner: permit, grantRequestScope: enrollment, now: now.addingTimeInterval(1)) else {
            Issue.record("Verified grant must release the work before its deadline"); return
        }
        #expect(try await reopened.coordinationPublications(account: scope.account).isEmpty)
    } else {
        for _ in 0..<3 {
            guard case .waiting = await resumed.handle(waiting, owner: permit, grantRequestScope: enrollment, now: deadline) else {
                Issue.record("Expired grace period must create repair work and wait for evidence"); return
            }
        }
        #expect(try await reopened.coordinationPublications(account: scope.account).filter { $0.kind == .grantRequest }.count == 1)
        #expect(try await reopened.activeOperations(account: scope.account, database: scope.database).filter { $0.kind == .fetchContentHead }.count == 1)
        #expect(try await !wait.available(repository: reopened, scope: scope, history: history))
    }
}

@MainActor @Test func ownGrantRequestEchoDoesNotCreateAnotherHeadFetch() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let request = ContentGrantRequest(item: scope.itemID, keyGeneration: UUID(), recipient: owner.identity.fingerprint)
    let repair = GrantRequestPrerequisites(repository: repository)
    guard case .completed = try await repair.reconcile(request: request, scope: scope, history: history,
        permit: ContentStorageTestPermit(), localRecipient: owner.identity.fingerprint) else {
        Issue.record("Own authenticated request echo must not initiate repair work"); return
    }
    #expect(try await repository.activeOperations(account: scope.account, database: scope.database).isEmpty)
    guard case .waiting = try await repair.reconcile(request: request, scope: scope, history: history,
        permit: ContentStorageTestPermit(), localRecipient: "another device") else {
        Issue.record("Other devices must still reconcile a request with missing content"); return
    }
    #expect(try await repository.activeOperations(account: scope.account, database: scope.database).contains { $0.kind == .fetchContentHead })
}

private final class GrantSigningBarrier: @unchecked Sendable {
    private let arrived = Mutex(0)
    private let gate = DispatchSemaphore(value: 0)
    func meet() throws {
        let count = arrived.withLock { $0 += 1; return $0 }
        if count == 2 { gate.signal() }
        else if gate.wait(timeout: .now() + 5) != .success { throw MopError.cloudUnavailable }
    }
    var count: Int { arrived.withLock { $0 } }
}

private final class SimultaneousGrantSigner: DeviceOperations {
    let underlying: SessionDevice
    let barrier: GrantSigningBarrier
    var identity: DevicePublicKey { underlying.identity }
    init(owner: SessionDevice, barrier: GrantSigningBarrier) { underlying = SessionDevice(copying: owner); self.barrier = barrier }
    func sign(_ bytes: Data) throws -> Data { try barrier.meet(); return try underlying.sign(bytes) }
    func unwrap(_ envelope: KeyEnvelope, context: Data) throws -> SymmetricKey { try underlying.unwrap(envelope, context: context) }
    func close() { underlying.close() }
}

@MainActor @Test func concurrentGrantRequestsReuseAuthenticatedDurableWinner() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let barrier = GrantSigningBarrier()
    let binding = ItemVaultBinding(account: scope.account, database: scope.database, zoneOwner: scope.zoneOwner, vaultID: scope.vaultID)
    let first = try GrantBackedContentSession(repository: repository, binding: binding, history: history,
        device: SimultaneousGrantSigner(owner: owner, barrier: barrier))
    let second = try GrantBackedContentSession(repository: repository, binding: binding, history: history,
        device: SimultaneousGrantSigner(owner: owner, barrier: barrier))
    let enrollment = EnrollmentScope(container: "iCloud.test", environment: "Development", account: scope.account, vault: scope.vaultID, member: owner.identity.member)
    let id = UUID()
    let payload = try setupEncode(ContentGrantRequest(item: scope.itemID, keyGeneration: UUID(), recipient: owner.identity.fingerprint))
    let left = Task.detached { try await first.coordination(kind: .grantRequest, scope: enrollment, identity: id, payload: payload, owner: ContentStorageTestPermit()) }
    let right = Task.detached { try await second.coordination(kind: .grantRequest, scope: enrollment, identity: id, payload: payload, owner: ContentStorageTestPermit()) }
    let results = try await (left.value, right.value)
    #expect(barrier.count == 2) // Both signed before either could commit.
    #expect(results.0 == results.1)
    #expect(try await repository.coordinationPublications(account: scope.account) == [results.0])
    // Reusing an address never authorizes a different request payload.
    await #expect(throws: MopError.vaultUntrusted) {
        try await first.coordination(kind: .grantRequest, scope: enrollment, identity: id, payload: Data([1]), owner: ContentStorageTestPermit())
    }
}

@MainActor @Test func deletionPreflightVerifiesBeforeRetiringAndSurvivesRestart() async throws {
    let (root, repository, owner, history, scope) = try await previewInboxFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let permit = ContentStorageTestPermit()
    let session = try GrantBackedContentSession(repository: repository,
        binding: ItemVaultBinding(account: scope.account, database: "private", zoneOwner: scope.zoneOwner, vaultID: scope.vaultID), history: history, device: SessionDevice(copying: owner))
    _ = try await session.create(item: scope.itemID, components: ["data": SecretBytes(utf8: "retained until cleanup")])
    let original = try await repository.item(scope)
    let enrollment = EnrollmentScope(container: "iCloud.test", environment: "Development", account: scope.account, vault: scope.vaultID, member: owner.identity.member)
    let inbox = GrantBackedCoordinationInbox(repository: repository, container: enrollment.container,
        environment: enrollment.environment, account: scope.account, member: owner.identity.member)
    let notice = try VaultDeletionNotice.create(binding: inbox.deletionBinding(vault: scope.vaultID,
        genesis: history.orderedStates[0].digest()), history: history, owner: owner)
    let record = try PreparedCoordinationRecord(account: scope.account, vault: scope.vaultID, kind: .deletion, identity: scope.vaultID,
        bytes: CoordinationEnvelope.sign(kind: .deletion, scope: enrollment, identity: scope.vaultID,
            payload: notice.encoded(), history: history, device: owner).encoded())
    let wrong = try PreparedCoordinationRecord(account: scope.account, vault: scope.vaultID, kind: .deletion,
        identity: scope.vaultID, bytes: Data([1, 2]))
    await #expect(throws: (any Error).self) {
        try await inbox.acceptDeletionBeforeRouting(PreparedCoordinationRecord.materialize(wrong.record(), account: scope.account), history: history, permit: permit)
    }
    #expect(try await repository.deletion(VaultScope(scope)) == nil)
    let incoming = try PreparedCoordinationRecord.materialize(record.record(), account: scope.account)
    let wrongAccount = try PreparedCoordinationRecord.materialize(record.record(), account: "another-account")
    await #expect(throws: (any Error).self) {
        try await inbox.acceptDeletionBeforeRouting(wrongAccount, history: history, permit: permit)
    }
    #expect(try await repository.deletion(VaultScope(scope)) == nil)
    let otherGenesis = try MembershipEnvelope.genesis(membership: history.current.membership, owner: owner)
    let otherHistory = try TrustedMembershipHistory(genesis: otherGenesis, vault: otherGenesis.header.vault, pinnedDigest: otherGenesis.digest())
    try await GrantBackedContentStorage(repository: repository).setAuthority(scope: VaultScope(account: scope.account, vaultID: otherHistory.vault), expected: nil, history: otherHistory, authorization: permit)
    let otherSession = try GrantBackedContentSession(repository: repository,
        binding: ItemVaultBinding(account: scope.account, database: "private", zoneOwner: scope.zoneOwner, vaultID: otherHistory.vault), history: otherHistory, device: SessionDevice(copying: owner))
    _ = try await otherSession.create(item: UUID(), components: ["data": SecretBytes(utf8: "live vault")])
    try await repository.saveEngineState(Data([8]), account: scope.account, database: "test-checkpoint")
    try await inbox.acceptDeletionBeforeRouting(incoming, history: history, permit: permit)
    try await inbox.acceptDeletionBeforeRouting(incoming, history: history, permit: permit)
    #expect(try await repository.deletion(VaultScope(scope))?.phase == .prepared)
    #expect(try await repository.item(scope) == original)
    let uploads = try await repository.contentPublications(account: scope.account)
    #expect(!uploads.isEmpty)
    #expect(uploads.allSatisfy { $0.scope.vaultID == otherHistory.vault })
    #expect(try await repository.operations(account: scope.account, database: "private").filter { $0.kind == .deletion }.count == 1)
    let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
    #expect(try await reopened.deletion(VaultScope(scope))?.notice == record.bytes)
    #expect(try await reopened.engineState(account: scope.account, database: "test-checkpoint") == Data([8]))

}
