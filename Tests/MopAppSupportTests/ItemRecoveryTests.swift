@preconcurrency import CloudKit
import Foundation
import Synchronization
import Testing
import MopCore
import MopSync
@testable import MopVaultNext
@testable import MopAppSupport

@Test func itemRecoveryRestoresFreshDeviceAndReopensWithoutRecoverySecret() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-recovery-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let recoveryScope = try RecoveryScope(container: "iCloud.test", environment: "Development", account: "account")
    let owner = try SessionDevice(member: recoveryScope.member), joining = try SessionDevice(member: recoveryScope.member)
    let restart = SessionDevice(copying: joining), recovery = try OfflineRecoveryKey(scope: recoveryScope)
    let scope = ItemVaultSetupScope(container: recoveryScope.container, environment: recoveryScope.environment,
        binding: ItemVaultBinding(account: "namespace", database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
    let originalRepository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("owner.sqlite"))
    let ownerTrust = MemoryItemInventory()
    let backup = try PortableArchive.seal(sessionArchive())
    let original = try await ItemVaultBootstrap(repository: originalRepository, trustStore: ownerTrust, scope: scope,
        device: SessionDevice(copying: owner), recovery: recovery.identity).restore(archiveData: backup.data, recoveryKey: backup.recoveryKey, name: "recovered")
    let setup = try #require(try ownerTrust.load(scope: scope))
    let history = try ItemVaultMembershipAuthority.history(record: setup, trustStore: ownerTrust)
    let requestScope = EnrollmentScope(container: scope.container, environment: scope.environment, account: scope.binding.account,
        vault: scope.binding.vaultID, member: owner.identity.member)
    let request = try DeviceEnrollmentRequest.create(scope: requestScope, device: joining)
    let approval = try DeviceEnrollmentApproval.create(request: request, history: history, owner: recovery)
    let admitted = try approval.acceptFromAuthenticatedPrivateCloudKit(request: request, scope: requestScope)
    let records = try await originalRepository.items(account: scope.binding.account, vaultID: scope.binding.vaultID)
    original.lock(); owner.close()
    let transformed = try records.map { try ItemEnvelopeTransition.rewrite($0, history: admitted, decryptor: recovery, signer: joining) }
    let metadata = try #require(transformed.first { $0.scope.itemID == ItemVaultSession.metadataRecordID })
    recovery.close()
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("joining.sqlite")), trust = MemoryItemInventory()
    let session = try await ItemVaultBootstrap(repository: repository, trustStore: trust, scope: scope, device: joining)
        .acceptFromAuthenticatedPrivateCloudKit(approval: approval, request: request, metadata: metadata)
    for record in transformed { try await repository.applyRemote(record, serverSystemFields: Data([1])) }
    #expect(try await session.vaultMetadata().value.name == "recovered")
    session.lock()
    let reopened = try await ItemVaultBootstrap(repository: repository, trustStore: trust, scope: scope, device: restart).open()
    #expect(try reopened.enrolledDevices.count == 2)
    #expect(try await reopened.vaultMetadata().value.name == "recovered")
    for record in transformed { try ItemEnvelopeTransition.verifyReadable(record, history: admitted, device: SessionDevice(copying: restart)) }
}

@Test func recoveryRecipientRotationReencryptsAllRecordKindsAndRetainsDevices() throws {
    let scope = try RecoveryScope(container: "iCloud.test", environment: "Development", account: "account")
    let owner = try SessionDevice(member: scope.member), oldKey = try OfflineRecoveryKey(scope: scope), newKey = try OfflineRecoveryKey(scope: scope)
    let membership = try Membership(accounts: [.init(id: scope.member, role: .owner, devices: [owner.identity])], offlineRecovery: oldKey.identity)
    let genesis = try MembershipEnvelope.genesis(membership: membership, owner: owner)
    var history = try TrustedMembershipHistory(genesis: genesis, vault: genesis.header.vault, pinnedDigest: genesis.digest())
    let binding = ItemVaultBinding(account: "account", database: "private", zoneOwner: "__defaultOwner__", vaultID: history.vault)
    let item = try ItemEnvelope.seal(sessionArchive(), vault: history.vault, generation: 1, membership: membership, membershipStateDigest: genesis.digest(), signer: owner)
    let metadata = try VaultMetadataEnvelope.seal(.init(name: "vault"), vault: history.vault, generation: 1, membership: membership, membershipStateDigest: genesis.digest(), signer: owner)
    let health = try ItemHealthEnvelope.seal([], vault: history.vault, item: item.header.item, generation: 1, membership: membership, membershipStateDigest: genesis.digest(), signer: owner)
    let records = [
        EncryptedItemVersion(scope: binding.item(item.header.item), versionID: item.header.version, baseVersionID: nil, ciphertext: try item.encoded()),
        EncryptedItemVersion(scope: binding.item(ItemVaultSession.metadataRecordID), versionID: metadata.header.version, baseVersionID: nil, ciphertext: try metadata.encoded()),
        EncryptedItemVersion(scope: binding.item(ItemHealthEnvelope.recordID(for: item.header.item)), versionID: health.header.version, baseVersionID: nil, ciphertext: try health.encoded(), healthItemID: item.header.item)
    ]
    let target = try Membership(accounts: membership.accounts, offlineRecovery: newKey.identity)
    let successor = try MembershipEnvelope.successor(of: genesis, membership: target, owner: owner)
    try history.append(successor)
    let rotated = try records.map { try ItemEnvelopeTransition.rewrite($0, history: history, decryptor: owner, signer: owner) }
    for record in rotated {
        try ItemEnvelopeTransition.verifyReadable(record, history: history, device: owner)
        try ItemEnvelopeTransition.verifyReadable(record, history: history, device: newKey)
        #expect(throws: (any Error).self) { try ItemEnvelopeTransition.verifyReadable(record, history: history, device: oldKey) }
    }
    let changedItem = try #require(rotated.first)
    let decoded = try ItemEnvelope.decode(changedItem.ciphertext, vault: history.vault, item: item.header.item, membership: target, membershipStateDigest: successor.digest())
    #expect(decoded.header.keyGeneration != item.header.keyGeneration)
    #expect(decoded.encryptedRecords != item.encryptedRecords)
    let revoked = try MembershipEnvelope.successor(of: successor, membership: Membership(accounts: membership.accounts), owner: owner)
    try history.append(revoked)
    for record in rotated {
        let removed = try ItemEnvelopeTransition.rewrite(record, history: history, decryptor: owner, signer: owner)
        try ItemEnvelopeTransition.verifyReadable(removed, history: history, device: owner)
        #expect(throws: (any Error).self) { try ItemEnvelopeTransition.verifyReadable(removed, history: history, device: newKey) }
    }
}

@Test func recoveryStateSurvivesRestartAndRemainsAccountScoped() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-recovery-state-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = ItemRecoveryStateStore(directory: directory, account: "a")
    let vault = UUID()
    var progress = ItemRecoveryState(account: "a", vaults: [vault])
    for phase: ItemRecoveryPhase in [.preview, .enrolling, .repairing, .verifying] {
        progress.phase = phase; try store.save(progress)
        let reopened = try #require(try ItemRecoveryStateStore(directory: directory, account: "a").load())
        #expect(reopened == progress && reopened.blocksRegularAccess)
        #expect(try ItemRecoveryStateStore(directory: directory, account: "b").load() == nil)
    }
    progress.completed = [vault]; progress.phase = .complete; try store.save(progress)
    #expect(try store.load()?.blocksRegularAccess == false)
}

private struct RecoveryTestAccount: ItemRecoveryAccount {
    let directory: URL
    let recoveryScope: RecoveryScope
    var containerIdentifier: String { recoveryScope.container }
    var environment: String { recoveryScope.environment }
    var accountNamespace: String { "test-account" }
    var memberID: UUID { recoveryScope.member }
    func setupScope(vaultID: UUID) throws -> ItemVaultSetupScope {
        ItemVaultSetupScope(container: containerIdentifier, environment: environment,
            binding: ItemVaultBinding(account: accountNamespace, database: "private", zoneOwner: "__defaultOwner__", vaultID: vaultID))
    }
}

// This fixture never exposes its source; copying the CryptoKit value keys is
// serialized, and each caller gets independent closeable handles.
private final class RecoveryDeviceSource: @unchecked Sendable {
    private let value: SessionDevice
    private let lock = NSLock()
    init(_ device: SessionDevice) { value = SessionDevice(copying: device) }
    func copy() -> SessionDevice { lock.lock(); defer { lock.unlock() }; return SessionDevice(copying: value) }
}

private enum RecoveryInjectedFailure: Error { case interrupted }
private actor RecoveryTestTransport: ItemRecoveryTransport {
    var histories: [UUID: TrustedMembershipHistory]
    var values: [UUID: [EncryptedItemVersion]]
    var config: RecoveryConfiguration
    var failAfterHead = false
    var failAfterRecord = false
    init(history: TrustedMembershipHistory, records: [EncryptedItemVersion], scope: RecoveryScope) {
        histories = [history.vault: history]; values = [history.vault: records]
        config = RecoveryConfiguration(scope: scope, active: history.current.membership.offlineRecovery)
    }
    func appendLate(_ value: EncryptedItemVersion) { values[value.scope.vaultID, default: []].append(value) }
    func interruptAfterHead() { failAfterHead = true }
    func interruptAfterRecord() { failAfterRecord = true }
    private var checkFailure = false
    private var saveFailure: CKError.Code?
    private(set) var saveAttempts = 0
    private var failOnSave: Int?
    func interruptBeforeSave(_ attempt: Int) { failOnSave = attempt }
    func failChecks() { checkFailure = true }
    func failSaves(_ code: CKError.Code) { saveFailure = code }
    func check() async throws { if checkFailure { throw MopError.cloudUnavailable } }
    func discover() async throws -> [VaultDescriptor] {
        histories.keys.map { VaultDescriptor(id: $0.uuidString, name: "vault", format: "mop-items-v2", enrolled: false) }
    }
    func history(_ vault: UUID) async throws -> (TrustedMembershipHistory, ProvisioningCloudRecord) {
        guard let history = histories[vault] else { throw MopError.notFound }
        return (history, ProvisioningCloudRecord(bytes: try history.current.encoded(), systemFields: Data()))
    }
    func publish(_ successor: MembershipEnvelope, expected: ProvisioningCloudRecord) async throws {
        guard var history = histories[successor.header.vault], try history.current.encoded() == expected.bytes else { throw MopError.vaultConflict }
        try successor.verifyAccountTransition(of: history.current); try history.append(successor); histories[history.vault] = history
        if failAfterHead { failAfterHead = false; throw RecoveryInjectedFailure.interrupted }
    }
    func records(_ vault: UUID) async throws -> [(EncryptedItemVersion, Data)] {
        (values[vault] ?? []).map { ($0, Data($0.versionID.uuidString.utf8)) }
    }
    @discardableResult func save(_ version: EncryptedItemVersion, expected: Data) async throws -> Data {
        saveAttempts += 1
        if saveAttempts == failOnSave { throw RecoveryInjectedFailure.interrupted }
        if let saveFailure { throw CKError(saveFailure) }
        guard let index = values[version.scope.vaultID]?.firstIndex(where: { $0.scope == version.scope }),
              let old = values[version.scope.vaultID]?[index], Data(old.versionID.uuidString.utf8) == expected,
              old.versionID == version.baseVersionID else { throw MopError.vaultConflict }
        values[version.scope.vaultID]?[index] = version
        if failAfterRecord { failAfterRecord = false; throw RecoveryInjectedFailure.interrupted }
        return Data(version.versionID.uuidString.utf8)
    }
    func configuration() async throws -> (RecoveryConfiguration, CKRecord?) { (config, nil) }
    func saveConfiguration(_ value: RecoveryConfiguration, expected: CKRecord?) async throws { config = value }
}

private func coordinatorFixture() throws -> (RecoveryTestAccount, SessionDevice, SessionDevice, OfflineRecoveryKey, RecoveryTestTransport, UUID) {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-coordinator-" + UUID().uuidString)
    let scope = try RecoveryScope(container: "iCloud.test", environment: "Development", account: "account")
    let account = RecoveryTestAccount(directory: directory, recoveryScope: scope)
    let owner = try SessionDevice(member: scope.member), joining = try SessionDevice(member: scope.member), key = try OfflineRecoveryKey(scope: scope)
    let membership = try Membership(accounts: [.init(id: scope.member, role: .owner, devices: [owner.identity])], offlineRecovery: key.identity)
    let genesis = try MembershipEnvelope.genesis(membership: membership, owner: owner)
    let history = try TrustedMembershipHistory(genesis: genesis, vault: genesis.header.vault, pinnedDigest: genesis.digest())
    let binding = try account.setupScope(vaultID: history.vault).binding
    let item = try ItemEnvelope.seal(sessionArchive(), vault: history.vault, generation: 1, membership: membership, membershipStateDigest: genesis.digest(), signer: owner)
    let metadata = try VaultMetadataEnvelope.seal(.init(name: "vault"), vault: history.vault, generation: 1, membership: membership, membershipStateDigest: genesis.digest(), signer: owner)
    let records = [
        EncryptedItemVersion(scope: binding.item(item.header.item), versionID: item.header.version, baseVersionID: nil, ciphertext: try item.encoded()),
        EncryptedItemVersion(scope: binding.item(ItemVaultSession.metadataRecordID), versionID: metadata.header.version, baseVersionID: nil, ciphertext: try metadata.encoded())
    ]
    return (account, owner, joining, key, RecoveryTestTransport(history: history, records: records, scope: scope), history.vault)
}

@Test(arguments: [true, false]) func recoveryCoordinatorResumesAfterCommittedCloudWriteWithoutPersistingCode(afterHead: Bool) async throws {
    let (account, owner, joining, key, cloud, vault) = try coordinatorFixture()
    defer { try? FileManager.default.removeItem(at: account.directory) }
    let repository = try EncryptedItemRepository(storeURL: account.directory.appendingPathComponent("items.sqlite")), trust = MemoryItemInventory()
    let source = RecoveryDeviceSource(joining)
    let loader: ItemRecoveryCoordinator.DeviceLoader = { _, _ in source.copy() }
    let first = ItemRecoveryCoordinator(account: account, repository: repository, transport: cloud, trust: trust)
    _ = try await first.execute(.recoveryOpen(copy: key.code()), device: loader, check: {})
    if afterHead { await cloud.interruptAfterHead() } else { await cloud.interruptAfterRecord() }
    await #expect(throws: RecoveryInjectedFailure.interrupted) {
        try await first.execute(.recoveryComplete(vault), device: loader, check: {})
    }
    #expect(try first.store.load()?.blocksRegularAccess == true)
    first.lock(); key.close(); owner.close()
    let resumed = ItemRecoveryCoordinator(account: account, repository: repository, transport: cloud, trust: trust)
    // Every not-yet-uploaded record was staged for the joining device before the
    // authority update. Neither old devices nor the recovery code are needed.
    let result = try await resumed.execute(afterHead ? .recoveryEligibility : .recoveryComplete(vault), device: loader, check: {})
    #expect(!result.recoveryInProgress)
    if !afterHead { #expect(result.recoveryVaults.first?.complete == true) }
    #expect(try resumed.store.load()?.phase == .complete)
    let (history, _) = try await cloud.history(vault)
    #expect(history.current.membership.devices.count == 2)
    for (record, _) in try await cloud.records(vault) { try ItemEnvelopeTransition.verifyReadable(record, history: history, device: joining) }
}

@Test func recoveryCoordinatorReplacesAndRevokesKeyWithResumableConfiguration() async throws {
    let (account, owner, _, oldKey, cloud, vault) = try coordinatorFixture()
    defer { try? FileManager.default.removeItem(at: account.directory) }
    let repository = try EncryptedItemRepository(storeURL: account.directory.appendingPathComponent("items.sqlite"))
    let coordinator = ItemRecoveryCoordinator(account: account, repository: repository, transport: cloud, trust: MemoryItemInventory())
    let source = RecoveryDeviceSource(owner)
    let loader: ItemRecoveryCoordinator.DeviceLoader = { _, _ in source.copy() }
    let replacement = try OfflineRecoveryKey(scope: account.recoveryScope)
    await cloud.interruptAfterHead()
    await #expect(throws: RecoveryInjectedFailure.interrupted) {
        try await coordinator.execute(.recoveryActivate(copy: replacement.code(), fingerprint: replacement.identity.fingerprint), device: loader, check: {})
    }
    #expect(try await cloud.configuration().0.incomplete)
    let resumed = try await coordinator.execute(.recoveryResume, device: loader, check: {})
    #expect(resumed.recoveryConfiguration?.active == replacement.identity)
    #expect(resumed.recoveryConfiguration?.incomplete == false)
    let (history, _) = try await cloud.history(vault)
    for (record, _) in try await cloud.records(vault) {
        try ItemEnvelopeTransition.verifyReadable(record, history: history, device: replacement)
        #expect(throws: (any Error).self) { try ItemEnvelopeTransition.verifyReadable(record, history: history, device: oldKey) }
    }
    let revoked = try await coordinator.execute(.recoveryRevoke, device: loader, check: {})
    #expect(revoked.recoveryConfiguration?.active == nil)
    #expect(revoked.recoveryConfiguration?.incomplete == false)
}

@Test func recoveryRequestsCodeAgainForALateRecordWithoutDiscardingProgress() async throws {
    let (account, owner, joining, key, cloud, vault) = try coordinatorFixture()
    defer { try? FileManager.default.removeItem(at: account.directory) }
    let copy = try key.code()
    let repository = try EncryptedItemRepository(storeURL: account.directory.appendingPathComponent("items.sqlite")), trust = MemoryItemInventory()
    let source = RecoveryDeviceSource(joining)
    let loader: ItemRecoveryCoordinator.DeviceLoader = { _, _ in source.copy() }
    let first = ItemRecoveryCoordinator(account: account, repository: repository, transport: cloud, trust: trust)
    _ = try await first.execute(.recoveryOpen(copy: copy), device: loader, check: {})
    let (before, _) = try await cloud.history(vault)
    await cloud.interruptAfterHead()
    await #expect(throws: RecoveryInjectedFailure.interrupted) {
        try await first.execute(.recoveryComplete(vault), device: loader, check: {})
    }
    // An original device's delayed upload was not present in the staged snapshot.
    let late = try ItemEnvelope.seal(sessionArchive(), vault: vault, generation: 1,
        membership: before.current.membership, membershipStateDigest: before.current.digest(), signer: owner)
    await cloud.appendLate(EncryptedItemVersion(scope: try account.setupScope(vaultID: vault).binding.item(late.header.item),
        versionID: late.header.version, baseVersionID: nil, ciphertext: try late.encoded()))
    first.lock(); key.close(); owner.close()
    let resumed = ItemRecoveryCoordinator(account: account, repository: repository, transport: cloud, trust: trust)
    let pending = try await resumed.execute(.recoveryEligibility, device: loader, check: {})
    #expect(pending.recoveryInProgress)
    #expect(pending.message == ItemRecoveryFailure.codeRequired.localizedDescription)
    #expect(try resumed.store.load()?.blocksRegularAccess == true)
    _ = try await resumed.execute(.recoveryOpen(copy: copy), device: loader, check: {})
    _ = try await resumed.execute(.recoveryComplete(vault), device: loader, check: {})
    #expect(try resumed.store.load()?.phase == .complete)
    let (history, _) = try await cloud.history(vault)
    for (record, _) in try await cloud.records(vault) { try ItemEnvelopeTransition.verifyReadable(record, history: history, device: joining) }
}

@Test func recoveryGenerationDoesNotRequireCloudAvailability() async throws {
    let (account, _, _, _, cloud, _) = try coordinatorFixture()
    defer { try? FileManager.default.removeItem(at: account.directory) }
    let repository = try EncryptedItemRepository(storeURL: account.directory.appendingPathComponent("items.sqlite"))
    let coordinator = ItemRecoveryCoordinator(account: account, repository: repository, transport: cloud, trust: MemoryItemInventory())
    await cloud.failChecks()
    let result = try await coordinator.execute(.recoveryGenerate, device: { _, _ in throw MopError.authentication }, check: {})
    #expect(result.recoveryCode != nil)
    #expect(result.recoveryFile != nil)
}

@Test func recoveryActivationRetryResumesSameCodeAndSurfacesPermanentCloudFailure() async throws {
    let (account, owner, _, _, cloud, _) = try coordinatorFixture()
    defer { try? FileManager.default.removeItem(at: account.directory) }
    let repository = try EncryptedItemRepository(storeURL: account.directory.appendingPathComponent("items.sqlite"))
    let coordinator = ItemRecoveryCoordinator(account: account, repository: repository, transport: cloud, trust: MemoryItemInventory())
    let source = RecoveryDeviceSource(owner)
    let loader: ItemRecoveryCoordinator.DeviceLoader = { _, _ in source.copy() }
    let replacement = try OfflineRecoveryKey(scope: account.recoveryScope)
    await cloud.interruptAfterHead()
    await #expect(throws: RecoveryInjectedFailure.interrupted) {
        try await coordinator.execute(.recoveryActivate(copy: replacement.code(), fingerprint: ""), device: loader, check: {})
    }
    let operation = try await cloud.configuration().0.operation
    await cloud.failSaves(.permissionFailure)
    do {
        _ = try await coordinator.execute(.recoveryActivate(copy: replacement.code(), fingerprint: ""), device: loader, check: {})
        Issue.record("Expected the original CloudKit permission failure")
    } catch let error as CKError { #expect(error.code == .permissionFailure) }
    #expect(await cloud.saveAttempts == 1)
    #expect(try await cloud.configuration().0.operation == operation)
}

@Test func recoveryRetriesOnlyCloudRecordConflicts() {
    #expect(ItemRecoveryCoordinator.isRecordConflict(CKError(.serverRecordChanged)))
    for code: CKError.Code in [.networkFailure, .permissionFailure, .quotaExceeded, .requestRateLimited] {
        #expect(!ItemRecoveryCoordinator.isRecordConflict(CKError(code)))
    }
}

@Test func recoveryExplainsExpiredDeviceAuthorization() {
    let error = NSError(domain: "com.apple.LocalAuthentication", code: -1004)
    let message = ItemRecoveryFailure.message(for: error)
    #expect(message.contains("authenticate again"))
    #expect(message.contains("progress is saved"))
    #expect(message.contains("Resume Recovery Setup"))
    let unrelated = NSError(domain: "unrelated", code: -1004)
    #expect(!ItemRecoveryFailure.message(for: unrelated).contains("authenticate again"))
}

@Test func recoveryCoveragePropagatesAuthenticationRenewal() async throws {
    let (account, _, _, _, cloud, _) = try coordinatorFixture()
    defer { try? FileManager.default.removeItem(at: account.directory) }
    let repository = try EncryptedItemRepository(storeURL: account.directory.appendingPathComponent("items.sqlite"))
    let coordinator = ItemRecoveryCoordinator(account: account, repository: repository, transport: cloud, trust: MemoryItemInventory())
    do {
        _ = try await coordinator.execute(.recoveryStatus, device: { _, _ in
            throw NSError(domain: "com.apple.LocalAuthentication", code: -1004)
        }, check: {})
        Issue.record("Coverage must not swallow the request for fresh authentication")
    } catch {
        #expect((error as NSError).domain == "com.apple.LocalAuthentication")
        #expect((error as NSError).code == -1004)
    }
}

@Test(arguments: [false, true], [false, true])
func recoveryConflictResolutionHandlesHistoricalRecipients(localOld: Bool, remoteOld: Bool) async throws {
    let (account, owner, _, _, cloud, vault) = try coordinatorFixture()
    defer { try? FileManager.default.removeItem(at: account.directory) }
    let (initial, _) = try await cloud.history(vault)
    let original = try #require(try await cloud.records(vault).first { $0.0.scope.itemID != ItemVaultSession.metadataRecordID }).0
    let replacement = try OfflineRecoveryKey(scope: account.recoveryScope)
    let next = try MembershipEnvelope.successor(of: initial.current,
        membership: Membership(accounts: initial.current.membership.accounts, offlineRecovery: replacement.identity), owner: owner)
    var history = initial; try history.append(next)
    let local = localOld ? original : try ItemEnvelopeTransition.rewrite(original, history: history, decryptor: owner, signer: owner)
    let remote = remoteOld ? original : try ItemEnvelopeTransition.rewrite(original, history: history, decryptor: owner, signer: owner)
    let repository = try EncryptedItemRepository(storeURL: account.directory.appendingPathComponent("conflicts.sqlite"))
    try await repository.applyRemote(local, serverSystemFields: Data([1]))
    let conflict = try await repository.recordConflict(remote: remote, serverSystemFields: Data([2]))
    let session = try ItemVaultSession(repository: repository, binding: account.setupScope(vaultID: vault).binding,
        history: history, device: SessionDevice(copying: owner))
    #expect(try await session.isDuplicateConflict(conflict))
    #expect(try await session.prepareMembershipCatchUp().isEmpty)
    #expect(try await repository.conflict(local.scope) == conflict)
    for selected in [local, remote] {
        let state = try history.state(forDigest: ItemEnvelopeTransition.membershipDigest(selected))
        let envelope = try ItemEnvelope.decode(selected.ciphertext, vault: vault, item: selected.scope.itemID,
            membership: state.membership, membershipStateDigest: state.digest())
        let remoteState = try history.state(forDigest: ItemEnvelopeTransition.membershipDigest(remote))
        let other = try ItemEnvelope.decode(remote.ciphertext, vault: vault, item: remote.scope.itemID,
            membership: remoteState.membership, membershipStateDigest: remoteState.digest())
        let catalog = try envelope.catalog(device: owner, membership: state.membership, membershipStateDigest: state.digest())
        let resolved = try envelope.resolvingConflict(with: other, catalog: catalog, history: history,
            signer: owner, localGeneration: local.generation)
        #expect(resolved.header.base == remote.versionID)
        #expect(resolved.header.generation == max(local.generation, remote.generation) + 1)
        #expect(resolved.header.membership == (try history.current.digest()))
        let recovered = try resolved.portableArchive(name: "conflict", device: replacement,
            membership: history.current.membership, membershipStateDigest: history.current.digest())
        #expect(try recovered == envelope.portableArchive(name: "conflict", device: owner,
            membership: state.membership, membershipStateDigest: state.digest()))
    }
}

@Test func recoveryRotationAdoptsAcknowledgedRecordsLocally() async throws {
    let (account, owner, _, _, cloud, vault) = try coordinatorFixture()
    defer { try? FileManager.default.removeItem(at: account.directory) }
    let repository = try EncryptedItemRepository(storeURL: account.directory.appendingPathComponent("items.sqlite"))
    for (value, fields) in try await cloud.records(vault) { try await repository.applyRemote(value, serverSystemFields: fields) }
    let coordinator = ItemRecoveryCoordinator(account: account, repository: repository, transport: cloud, trust: MemoryItemInventory())
    let source = RecoveryDeviceSource(owner), replacement = try OfflineRecoveryKey(scope: account.recoveryScope)
    _ = try await coordinator.execute(.recoveryActivate(copy: replacement.code(), fingerprint: ""), device: { _, _ in source.copy() }, check: {})
    for (value, _) in try await cloud.records(vault) { #expect(try await repository.item(value.scope) == value) }
    #expect(try await repository.pendingScopes(account: account.accountNamespace).isEmpty)
    #expect(try await repository.conflicts(account: account.accountNamespace).isEmpty)
}

@Test func conflictDuplicateDetectionComparesConcealedRecordBytes() async throws {
    let (account, owner, _, _, cloud, vault) = try coordinatorFixture()
    defer { try? FileManager.default.removeItem(at: account.directory) }
    let (history, _) = try await cloud.history(vault)
    let local = try #require(try await cloud.records(vault).first { $0.0.scope.itemID != ItemVaultSession.metadataRecordID }).0
    let envelope = try ItemEnvelope.decode(local.ciphertext, vault: vault, item: local.scope.itemID,
        membership: history.current.membership, membershipStateDigest: history.current.digest())
    var archive = try envelope.portableArchive(name: "conflict", device: owner,
        membership: history.current.membership, membershipStateDigest: history.current.digest())
    let record = try #require(archive.records.keys.first)
    archive.records[record] = PortableArchiveRecord(itemID: local.scope.itemID.uuidString, bytes: SecretBytes(utf8: "different secret"))
    let changed = try ItemEnvelope.seal(archive, vault: vault, generation: local.generation + 1,
        base: local.versionID, membership: history.current.membership, membershipStateDigest: history.current.digest(), signer: owner)
    let remote = EncryptedItemVersion(scope: local.scope, versionID: changed.header.version,
        baseVersionID: changed.header.base, ciphertext: try changed.encoded(), generation: changed.header.generation)
    let repository = try EncryptedItemRepository(storeURL: account.directory.appendingPathComponent("conflict.sqlite"))
    try await repository.applyRemote(local, serverSystemFields: Data([1]))
    let conflict = try await repository.recordConflict(remote: remote, serverSystemFields: Data([2]))
    let session = try ItemVaultSession(repository: repository, binding: account.setupScope(vaultID: vault).binding,
        history: history, device: SessionDevice(copying: owner))
    #expect(try await !session.isDuplicateConflict(conflict))
    #expect(try await repository.conflict(local.scope) == conflict)
}

@Test func interruptedRecoveryRotationKeepsAcknowledgedLocalRecordsCurrent() async throws {
    let (account, owner, _, _, cloud, vault) = try coordinatorFixture()
    defer { try? FileManager.default.removeItem(at: account.directory) }
    let repository = try EncryptedItemRepository(storeURL: account.directory.appendingPathComponent("items.sqlite"))
    for (value, fields) in try await cloud.records(vault) { try await repository.applyRemote(value, serverSystemFields: fields) }
    let coordinator = ItemRecoveryCoordinator(account: account, repository: repository, transport: cloud, trust: MemoryItemInventory())
    let source = RecoveryDeviceSource(owner), replacement = try OfflineRecoveryKey(scope: account.recoveryScope)
    await cloud.interruptBeforeSave(2)
    await #expect(throws: RecoveryInjectedFailure.interrupted) {
        try await coordinator.execute(.recoveryActivate(copy: replacement.code(), fingerprint: ""), device: { _, _ in source.copy() }, check: {})
    }
    #expect(await cloud.saveAttempts == 2)
    for (value, _) in try await cloud.records(vault) { #expect(try await repository.item(value.scope) == value) }
    #expect(try await cloud.configuration().0.incomplete)
}
