import CryptoKit
import Foundation
import Synchronization
import Testing
import MopCore
import MopSync
@testable import MopVaultNext
@testable import MopAppSupport

final class SessionUnwrapCounter: Sendable { let value = Mutex(0) }

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
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let owner = try SessionDevice()
    let vault = try sessionAuthority(owner: owner)
    let authority = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
    let history = try TrustedMembershipHistory(genesis: authority, vault: vault.id, pinnedDigest: authority.digest())
    let archive = try sessionArchive()
    let competing = try ItemEnvelope.seal(archive, vault: vault.id, generation: 1,
        membership: vault.membership, membershipStateDigest: authority.digest(), signer: owner)
    let binding = ItemVaultBinding(account: "observation", database: "private", zoneOwner: "__defaultOwner__", vaultID: vault.id)
    let session = try ItemVaultSession(repository: repository, binding: binding, history: history, device: owner)
    let first = try await session.save(archive, expectedBase: nil)
    let state = ItemVaultViewState(repository: repository, session: session)
    state.start()
    try await awaitItemView { state.status == .ready && state.entries.count == 1 }
    #expect(state.entries.first?.versionID == first.version.versionID)
    #expect(state.pendingItems.contains(first.version.scope.itemID))
    let beforeAcknowledgement = owner.unwrapCount
    try await repository.acknowledge(mutationID: first.id, account: binding.account, serverSystemFields: Data([1]))
    try await awaitItemView { state.pendingItems.isEmpty }
    #expect(owner.unwrapCount == beforeAcknowledgement)
    var catalog = try #require(state.entries.first?.catalog)
    catalog.item.metadata = ItemMetadata(favorite: true)
    let next = try await state.edit(itemID: first.version.scope.itemID, expectedBase: first.version.versionID, catalog: catalog)
    try await awaitItemView { state.entries.first?.versionID == next.version.versionID }
    #expect(state.entries.first?.catalog.item.metadata?.favorite == true)
    let beforeStatusChanges = owner.unwrapCount
    try await repository.saveEngineState(Data([1]), account: binding.account, database: "private")
    let remote = EncryptedItemVersion(scope: first.version.scope, versionID: competing.header.version,
        baseVersionID: competing.header.base, ciphertext: try competing.encoded(), generation: competing.header.generation)
    try await repository.recordConflict(remote: remote, serverSystemFields: Data([9]))
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

@Test func itemProvisionerBindsIndependentPinAndPublicControlValidationSurvivesOnlyOrdinaryLock() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-domain-provision-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let scope = ItemVaultSetupScope(container: "iCloud.example.test", environment: "Development",
        binding: ItemVaultBinding(account: "owner", database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
    let trust = TestItemTrustStore()
    let bootstrap = try ItemVaultBootstrap(repository: repository, trustStore: trust, scope: scope, device: SessionDevice())
    let session = try await bootstrap.create(name: "provisioned")
    let server = DomainProvisionServer()
    let coordinator = VaultProvisioningCoordinator(repository: repository, transport: server,
        leaseURL: directory.appendingPathComponent("lease.lock"), accountValidator: { true }, accountAuthorization: DomainAccountAuthorization())
    let provisioner = try ItemVaultProvisioner(repository: repository, trustStore: trust, scope: scope, session: session, coordinator: coordinator)
    let wrongAddress = VaultCloudAddress(vaultID: scope.binding.vaultID, zoneName: "zone", ownerName: "different-owner")
    await #expect(throws: ItemVaultBootstrapFailure.invalidScope) { try await provisioner.provision(address: wrongAddress) }
    #expect(await server.creates == 0)
    let address = VaultCloudAddress(vaultID: scope.binding.vaultID, zoneName: "zone", ownerName: scope.binding.zoneOwner)
    let result = try await provisioner.provision(address: address)
    #expect(result.phase == .controlConfirmed)
    let record = try #require(try trust.load(scope: scope))
    #expect(result.controlBytes == record.genesis && result.binding.controlDigest == record.pinnedDigest)
    try await provisioner.controlValidator(result.binding, result.controlBytes)
    trust.failReads(true)
    await #expect(throws: CloudSyncAdapterError.storageFailure) { try await provisioner.controlValidator(result.binding, result.controlBytes) }
    #expect(try await repository.provisioning(scope.repositoryScope)?.phase == .controlConfirmed)
    trust.failReads(false)
    try await provisioner.controlValidator(result.binding, result.controlBytes)
    await #expect(throws: (any Error).self) { try await provisioner.controlValidator(result.binding, Data([99])) }
    session.lock()
    try await provisioner.controlValidator(result.binding, result.controlBytes)
    await #expect(throws: (any Error).self) { try await provisioner.provision(address: address) }
    session.invalidate()
    await #expect(throws: (any Error).self) { try await provisioner.controlValidator(result.binding, result.controlBytes) }
}

@Test func itemBootstrapResumesPinnedArchiveAfterInterruptionAndPreservesLaterEditsOnRetry() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-bootstrap-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("items.sqlite")
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
    let url = directory.appendingPathComponent("items.sqlite")
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
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
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
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
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
    let remoteEnvelope = try ItemEnvelope.seal(remoteArchive, vault: root.id, generation: 1,
        membership: root.membership, membershipStateDigest: digest, signer: owner)
    let binding = ItemVaultBinding(account: "review", database: "private", zoneOwner: "__defaultOwner__", vaultID: root.id)
    let session = try ItemVaultSession(repository: repository, binding: binding, history: history, device: owner)
    let local = try await session.save(archive, expectedBase: nil)
    let remote = EncryptedItemVersion(scope: local.version.scope, versionID: remoteEnvelope.header.version,
        baseVersionID: nil, ciphertext: try remoteEnvelope.encoded())
    let conflict = try await repository.recordConflict(remote: remote, serverSystemFields: Data([1]))
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
    let changed = try await repository.recordConflict(remote: remote, serverSystemFields: Data([2]))
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
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let owner = try SessionDevice()
    let root = try sessionAuthority(owner: owner)
    let authority = try MembershipEnvelope.genesis(vault: root.id, membership: root.membership, owner: owner)
    let history = try TrustedMembershipHistory(genesis: authority, vault: root.id, pinnedDigest: authority.digest())
    let binding = ItemVaultBinding(account: "session-account", database: "private", zoneOwner: "__defaultOwner__", vaultID: root.id)
    let archive = try sessionArchive()
    let remoteEnvelope = try ItemEnvelope.seal(archive, vault: root.id, generation: 1, membership: root.membership,
        membershipStateDigest: authority.digest(), signer: owner)
    let session = try ItemVaultSession(repository: repository, binding: binding, history: history, device: owner)
    _ = try await session.saveMetadata(VaultEnvelopeMetadata(name: "session"), expectedBase: nil)
    let receipt = try await session.save(archive, expectedBase: nil)
    try session.validate(receipt.version, direction: .sending)
    let rebound = EncryptedItemVersion(scope: ItemScope(account: "other-account", vaultID: root.id, itemID: receipt.version.scope.itemID),
        versionID: receipt.version.versionID, baseVersionID: receipt.version.baseVersionID, ciphertext: receipt.version.ciphertext)
    #expect(throws: (any Error).self) { try session.validate(rebound, direction: .receiving) }
    let forgedVersion = EncryptedItemVersion(scope: receipt.version.scope, versionID: UUID(),
        baseVersionID: receipt.version.baseVersionID, ciphertext: receipt.version.ciphertext)
    #expect(throws: (any Error).self) { try session.validate(forgedVersion, direction: .receiving) }
    let forgedGeneration = EncryptedItemVersion(scope: receipt.version.scope, versionID: receipt.version.versionID,
        baseVersionID: receipt.version.baseVersionID, ciphertext: receipt.version.ciphertext, generation: 2)
    #expect(throws: (any Error).self) { try session.validate(forgedGeneration, direction: .receiving) }
    let forgedBase = EncryptedItemVersion(scope: receipt.version.scope, versionID: receipt.version.versionID,
        baseVersionID: UUID(), ciphertext: receipt.version.ciphertext)
    #expect(throws: (any Error).self) { try session.validate(forgedBase, direction: .receiving) }
    for alteredScope in [
        ItemScope(account: "session-account", vaultID: root.id, itemID: receipt.version.scope.itemID, database: "shared"),
        ItemScope(account: "session-account", vaultID: root.id, itemID: receipt.version.scope.itemID, zoneOwner: "other-owner")
    ] {
        let forgedScope = EncryptedItemVersion(scope: alteredScope, versionID: receipt.version.versionID,
            baseVersionID: receipt.version.baseVersionID, ciphertext: receipt.version.ciphertext)
        #expect(throws: (any Error).self) { try session.validate(forgedScope, direction: .receiving) }
    }
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
    let remote = EncryptedItemVersion(scope: receipt.version.scope, versionID: remoteEnvelope.header.version,
        baseVersionID: remoteEnvelope.header.base, ciphertext: try remoteEnvelope.encoded())
    try session.validate(remote, direction: .receiving)
    try await repository.recordConflict(remote: remote, serverSystemFields: Data([9]))
    await #expect(throws: (any Error).self) { try await session.exportPortableLocalSnapshot() }
    await #expect(throws: (any Error).self) { try await session.save(archive, expectedBase: nil) }
    session.lock()
    #expect(throws: (any Error).self) { try session.validate(receipt.version, direction: .sending) }
    try session.validate(receipt.version, direction: .receiving)
    await #expect(throws: (any Error).self) { try await session.reveal(itemID: itemID, recordID: recordID) }
    await #expect(throws: (any Error).self) { try await session.exportPortableLocalSnapshot() }
    await #expect(throws: (any Error).self) { try await session.save(archive, expectedBase: receipt.version.versionID) }
    #expect(try await repository.pendingMutations(account: "session-account").count == 3)
    session.invalidate()
    #expect(throws: (any Error).self) { try session.validate(receipt.version, direction: .receiving) }
}

@Test func itemVaultSessionViewerReadsButCannotQueueMutations() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-session-viewer-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let owner = try SessionDevice(), viewer = try SessionDevice()
    var vault = try sessionAuthority(owner: owner)
    vault.membership = try Membership(accounts: vault.membership.accounts + [AccountMember(id: viewer.identity.member, role: .viewer, devices: [viewer.identity])])
    let authority = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
    let history = try TrustedMembershipHistory(genesis: authority, vault: vault.id, pinnedDigest: authority.digest())
    let binding = ItemVaultBinding(account: "session-account", database: "shared", zoneOwner: "owner", vaultID: vault.id)
    let ownerSession = try ItemVaultSession(repository: repository, binding: binding, history: history, device: owner)
    let archive = try sessionArchive()
    let pending = try await ownerSession.save(archive, expectedBase: nil)
    let session = try ItemVaultSession(repository: repository, binding: binding, history: history, device: viewer)
    let recordID = try #require(archive.references["Login/password"])
    #expect(try await session.reveal(itemID: pending.version.scope.itemID, recordID: recordID) == SecretBytes(utf8: "session-secret"))
    await #expect(throws: MopError.cloudPermission) { try await session.save(archive, expectedBase: pending.version.versionID) }
    await #expect(throws: MopError.cloudPermission) { try await session.saveMetadata(VaultEnvelopeMetadata(name: "renamed"), expectedBase: nil) }
    #expect(throws: MopError.cloudPermission) { try session.validate(pending.version, direction: .sending) }
    #expect(try await repository.pendingMutations(account: "session-account").count == 1)
}

@Test func healthCompanionsAuthenticateSyncAndRewrapWithoutEnteringItemCatalog() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-health-sync-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("owner.sqlite"))
    let owner = try SessionDevice(), joining = try SessionDevice(member: owner.identity.member)
    let root = try sessionAuthority(owner: owner)
    let genesis = try MembershipEnvelope.genesis(vault: root.id, membership: root.membership, owner: owner)
    let history = try TrustedMembershipHistory(genesis: genesis, vault: root.id, pinnedDigest: genesis.digest())
    let binding = ItemVaultBinding(account: "health-sync", database: "private", zoneOwner: "__defaultOwner__", vaultID: root.id)
    let session = try ItemVaultSession(repository: repository, binding: binding, history: history, device: SessionDevice(copying: owner))
    _ = try await session.saveMetadata(VaultEnvelopeMetadata(name: "test"), expectedBase: nil)
    let archive = try sessionArchive()
    let item = try await session.save(archive, expectedBase: nil)
    let record = try #require(archive.references.values.first), now = Date()
    var check = CachedPasswordCheck(record: record, context: ["Login", ""], weak: false, exposed: true,
        checkedAt: now, breachCheckedAt: now, reuseGroup: nil, scope: String(repeating: "a", count: 64), batch: UUID())
    check.breachResult = CachedBreachResult(exposed: true, checkedAt: now)
    check.strengthResult?.quality = .veryStrong
    let saved = try #require(try await session.saveHealthChecks([check], itemID: item.version.scope.itemID, expectedItemVersion: item.version.versionID))
    try session.validate(saved.version, direction: .receiving)
    let wrongParent = EncryptedItemVersion(scope: saved.version.scope, versionID: saved.version.versionID,
        baseVersionID: saved.version.baseVersionID, ciphertext: saved.version.ciphertext, generation: saved.version.generation, healthItemID: UUID())
    #expect(throws: (any Error).self) { try session.validate(wrongParent, direction: .receiving) }
    let wrongKind = EncryptedItemVersion(scope: saved.version.scope, versionID: saved.version.versionID, baseVersionID: nil,
        ciphertext: saved.version.ciphertext, generation: saved.version.generation)
    #expect(throws: (any Error).self) { try session.validate(wrongKind, direction: .receiving) }
    await #expect(throws: ItemRepositoryError.staleLocalVersion) {
        try await session.saveHealthChecks([check], itemID: item.version.scope.itemID, expectedItemVersion: UUID())
    }
    #expect(try await session.healthChecks() == [check])
    let unwraps = SessionUnwrapCounter()
    let reopened = try ItemVaultSession(repository: repository, binding: binding, history: history,
        device: SessionDevice(copying: owner, unwrapCounter: unwraps))
    #expect(try await reopened.healthChecks() == [check])
    #expect(unwraps.value.withLock { $0 } == 1) // One local index key, no companion-key unwrap.
    #expect(try await reopened.healthChecks() == [check])
    #expect(unwraps.value.withLock { $0 } == 1)
    reopened.lock()
    let address = VaultCloudAddress(vaultID: root.id, zoneName: "health", ownerName: binding.zoneOwner)
    let cloud = try CloudKitSyncAdapter.makeRecord(saved.version, address: address)
    #expect(try CloudKitSyncAdapter.unverifiedVersion(from: cloud, account: binding.account, database: binding.database, address: address) == saved.version)
    let request = try DeviceEnrollmentRequest.create(scope: EnrollmentScope(container: "iCloud.test", environment: "Development",
        account: binding.account, vault: root.id, member: owner.identity.member), device: joining)
    let prepared = try await session.prepareAdmission(request: request)
    #expect(prepared.approval.expectedItemCount == 1)
    #expect(prepared.versions.count == 3)
    let joinedHistory = try prepared.approval.verifiedHistory()
    let target = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("joining.sqlite"))
    let joined = try ItemVaultSession(repository: target, binding: binding, history: joinedHistory, device: joining)
    for version in prepared.versions {
        try joined.validate(version, direction: .receiving)
        try await target.applyRemote(version, serverSystemFields: Data([1]))
    }
    #expect(try await joined.catalog().count == 1)
    #expect(try await joined.revisionIndex().count == 2)
    #expect(try await joined.healthChecks() == [check])
    let receiver = ItemVaultService(backend: SyncedHealthBackend(session: joined))
    let received = try await receiver.execute(.catalog, vault: root.id.uuidString, offline: true).requireCatalog()
    #expect(received.items.first?.fields.first?.passwordQuality == .veryStrong)
    #expect(try await joined.exportPortableLocalSnapshot().items.count == 1)
    joined.lock()
    await #expect(throws: MopError.authentication) { try await joined.healthChecks() }
}

private struct SyncedHealthBackend: ItemVaultServiceBackend {
    let session: ItemVaultSession
    func inventory() async throws -> [VaultDescriptor] { [] }
    func open(_ vaultID: UUID) async throws -> ItemVaultSession { session }
    func create(name: String, id: UUID, archiveData: Data?, recoveryKey: SecretBytes?) async throws -> ItemVaultSession { throw MopError.invalidVault }
    func requestSync() async throws {}
    func lock() { session.lock() }
}
