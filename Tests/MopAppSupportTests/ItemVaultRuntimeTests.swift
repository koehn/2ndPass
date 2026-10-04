import Foundation
import Synchronization
import Testing
import MopCore
import MopVaultNext
@testable import MopSync
@testable import MopAppSupport

final class MemoryItemInventory: ItemVaultInventoryStore, ItemVaultMembershipTrustStore {
    private let successors = Mutex<[String: [Data]]>([:])
    func membershipHistory(scope: ItemVaultSetupScope) throws -> [Data] {
        let key = try setupHash(setupEncode(scope)); return successors.withLock { $0[key] ?? [] }
    }
    func reserveMembership(scope: ItemVaultSetupScope, successors next: [Data]) throws {
        let key = try setupHash(setupEncode(scope))
        try successors.withLock { values in
            let existing = values[key] ?? []
            guard next.count >= existing.count, Array(next.prefix(existing.count)) == existing else { throw ItemVaultBootstrapFailure.invalidTrust }
            values[key] = next
        }
    }
    private let values = Mutex<[ItemVaultSetupRecord]>([])
    func load(scope: ItemVaultSetupScope) throws -> ItemVaultSetupRecord? { values.withLock { $0.first { $0.scope == scope } } }
    func reserve(_ candidate: ItemVaultSetupRecord) throws -> ItemVaultSetupRecord {
        values.withLock { records in
            if let existing = records.first(where: { $0.scope == candidate.scope }) { return existing }
            records.append(candidate); return candidate
        }
    }
    func records(container: String, environment: String, account: String) throws -> [ItemVaultSetupRecord] {
        values.withLock { $0.filter { $0.scope.container == container && $0.scope.environment == environment && $0.scope.binding.account == account } }
    }
}

private actor RuntimeDriver: ItemVaultRuntimeDriver {
    let addresses: [VaultCloudAddress]
    let items: CloudItemValidator
    let controls: CloudControlValidator
    let eligible: CloudVaultUploadEligibility
    private(set) var starts = 0
    private(set) var stops = 0
    private(set) var uploadAllowed = false
    let startGate: RuntimeBarrier?
    init(_ addresses: [VaultCloudAddress], _ items: @escaping CloudItemValidator, _ controls: @escaping CloudControlValidator, _ eligible: @escaping CloudVaultUploadEligibility, startGate: RuntimeBarrier? = nil) {
        self.addresses = addresses; self.items = items; self.controls = controls; self.eligible = eligible
        self.startGate = startGate
    }
    func start(automaticallySync: Bool) async throws { starts += 1; if starts == 1 { await startGate?.wait() } }
    func stop() async { stops += 1 }
    func setUploadsAllowed(_ allowed: Bool) async { uploadAllowed = allowed }
    func requestForegroundSync() async throws -> DurableSyncRequest { DurableSyncRequest(account: "runtime", database: "private", generation: 1, reason: .manual) }
    func verify(_ version: EncryptedItemVersion, direction: CloudRecordDirection) async throws { try await items(version, direction) }
    func canUpload(_ scope: VaultScope) async -> Bool { await eligible(scope) }
}

private actor RuntimeBarrier {
    private var blocked: CheckedContinuation<Void, Never>?
    private var observer: CheckedContinuation<Void, Never>?
    func wait() async { await withCheckedContinuation { blocked = $0; observer?.resume(); observer = nil } }
    func entered() async { if blocked == nil { await withCheckedContinuation { observer = $0 } } }
    func release() { blocked?.resume(); blocked = nil }
}

@Test func multiVaultOwnerObservesAlreadyHandledWakeAndRebuildsForNewVault() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-runtime-growth-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let inventory = MemoryItemInventory(), owner = try SessionDevice()
    let context = ItemVaultRuntimeContext(container: "iCloud.test", environment: "Development", account: "runtime", memberID: owner.identity.member, leaseURL: directory.appendingPathComponent("lease.lock"))
    let gate = RuntimeBarrier(), drivers = Mutex<[RuntimeDriver]>([])
    let runtime = try ItemVaultSyncRuntime(context: context, repository: repository, trustStore: inventory, transport: DomainProvisionServer(),
        accountValidator: { true }, accountAuthorization: DomainAccountAuthorization()) { addresses, items, controls, eligible in
            drivers.withLock { values in
                let driver = RuntimeDriver(addresses, items, controls, eligible, startGate: values.isEmpty ? gate : nil)
                values.append(driver); return driver
            }
        }
    func create(_ name: String) async throws -> ItemVaultSession {
        let scope = ItemVaultSetupScope(container: context.container, environment: context.environment,
            binding: ItemVaultBinding(account: context.account, database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
        return try await ItemVaultBootstrap(repository: repository, trustStore: inventory, scope: scope, device: SessionDevice(copying: owner)).create(name: name)
    }
    let first = try await create("first")
    try await runtime.register(session: first)
    let started = Task { try await runtime.start() }
    await gate.entered()
    let second = try await create("second")
    let pending = try #require(try await repository.pendingSyncRequests(account: context.account, database: "private").first)
    try await repository.markSyncRequestHandled(pending)
    try await runtime.setSessionLoader { record in record.scope.binding == second.binding ? second : nil }
    await gate.release()
    try await started.value
    let deadline = ContinuousClock.now.advanced(by: .seconds(3))
    while drivers.withLock({ $0.count }) < 2, ContinuousClock.now < deadline { await Task.yield() }
    let all = drivers.withLock { $0 }
    #expect(all.count == 2)
    if all.count == 2 {
        #expect(await all[0].stops > 0)
        #expect(await all[1].addresses.count == 2)
        #expect(await all[1].canUpload(VaultScope(second.binding.item(UUID()))))
    }
    await runtime.stop()
}

private actor ElsewhereOwnedDriver: ItemVaultRuntimeDriver {
    func start(automaticallySync: Bool) async throws { throw CloudSyncAdapterError.engineAlreadyOwned }
    func stop() async {}
    func setUploadsAllowed(_ allowed: Bool) async {}
    func requestForegroundSync() async throws -> DurableSyncRequest { throw CloudSyncAdapterError.engineNotStarted }
}

@Test func multiVaultRuntimePersistsWakeForAnotherProcessLeaseOwner() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-runtime-wake-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("items.sqlite")
    let repository = try EncryptedItemRepository(storeURL: url)
    let context = ItemVaultRuntimeContext(container: "iCloud.test", environment: "Development", account: "runtime", memberID: UUID(), leaseURL: directory.appendingPathComponent("lease.lock"))
    let runtime = try ItemVaultSyncRuntime(context: context, repository: repository, trustStore: MemoryItemInventory(), transport: DomainProvisionServer(),
        accountValidator: { true }, accountAuthorization: DomainAccountAuthorization()) { _, _, _, _ in ElsewhereOwnedDriver() }
    let receipt = try await runtime.requestSync()
    let reopened = try EncryptedItemRepository(storeURL: url)
    #expect(try await reopened.pendingSyncRequests(account: "runtime", database: "private") == [receipt])
    await runtime.stop()
}

@Test func multiVaultRuntimeUsesOneDriverAndRoutesLockedVaultsIndependently() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-runtime-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let inventory = MemoryItemInventory()
    let owner = try SessionDevice()
    let context = ItemVaultRuntimeContext(container: "iCloud.test", environment: "Development", account: "runtime", memberID: owner.identity.member,
        leaseURL: directory.appendingPathComponent("lease.lock"))
    let drivers = Mutex<[RuntimeDriver]>([])
    let runtime = try ItemVaultSyncRuntime(context: context, repository: repository, trustStore: inventory,
        transport: DomainProvisionServer(), accountValidator: { true }, accountAuthorization: DomainAccountAuthorization()) { addresses, items, controls, eligible in
            let driver = RuntimeDriver(addresses, items, controls, eligible)
            drivers.withLock { $0.append(driver) }; return driver
        }
    let backup = try PortableArchive.seal(sessionArchive())
    var sessions: [ItemVaultSession] = []
    var scopes: [ItemVaultSetupScope] = []
    for name in ["first", "second"] {
        let scope = ItemVaultSetupScope(container: context.container, environment: context.environment,
            binding: ItemVaultBinding(account: context.account, database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
        let bootstrap = try ItemVaultBootstrap(repository: repository, trustStore: inventory, scope: scope, device: SessionDevice(copying: owner))
        sessions.append(try await bootstrap.restore(archiveData: backup.data, recoveryKey: backup.recoveryKey, name: name)); scopes.append(scope)
    }
    try await runtime.register(session: sessions[0])
    try await runtime.register(session: sessions[1])
    try await runtime.start()
    #expect(drivers.withLock { $0.count } == 1)
    let driver = try #require(drivers.withLock { $0.first })
    #expect(await driver.addresses.count == 2)
    #expect(await driver.canUpload(scopes[0].repositoryScope))
    #expect(await driver.canUpload(scopes[1].repositoryScope))
    let item = try #require(try await repository.pendingMutations(account: context.account).first { $0.version.scope.vaultID == scopes[0].binding.vaultID })
    runtime.lock(vaultID: scopes[0].binding.vaultID)
    #expect(!sessions[0].isUnlocked && sessions[1].isUnlocked)
    #expect(await !driver.canUpload(scopes[0].repositoryScope))
    #expect(await driver.canUpload(scopes[1].repositoryScope))
    try await driver.verify(item.version, direction: .receiving)
    await #expect(throws: (any Error).self) { try await driver.verify(item.version, direction: .sending) }
    _ = try await runtime.requestSync()
    #expect(drivers.withLock { $0.count } == 1)
    await runtime.pauseNetwork()
    try await runtime.register(session: sessions[1], synchronize: true)
    let resumedDeadline = ContinuousClock.now.advanced(by: .seconds(3))
    while drivers.withLock({ $0.count }) < 2, ContinuousClock.now < resumedDeadline { await Task.yield() }
    #expect(drivers.withLock { $0.count } == 2)
    #expect(await driver.stops > 0)
    runtime.invalidate()
    #expect(!sessions[1].isUnlocked)
    #expect(await !driver.canUpload(scopes[1].repositoryScope))
    await #expect(throws: (any Error).self) { try await driver.verify(item.version, direction: .receiving) }
    await runtime.stop()
}

@Test func localInventoryAndRegistrationDoNotWaitForBlockedCloudStartup() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-runtime-local-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let inventory = MemoryItemInventory(), owner = try SessionDevice()
    let context = ItemVaultRuntimeContext(container: "iCloud.test", environment: "Development", account: "runtime", memberID: owner.identity.member, leaseURL: directory.appendingPathComponent("lease.lock"))
    let gate = RuntimeBarrier(), drivers = Mutex<[RuntimeDriver]>([])
    let runtime = try ItemVaultSyncRuntime(context: context, repository: repository, trustStore: inventory, transport: DomainProvisionServer(),
        accountValidator: { true }, accountAuthorization: DomainAccountAuthorization()) { addresses, items, controls, eligible in
            drivers.withLock { values in
                let driver = RuntimeDriver(addresses, items, controls, eligible, startGate: values.isEmpty ? gate : nil)
                values.append(driver); return driver
            }
        }
    let scope = ItemVaultSetupScope(container: context.container, environment: context.environment,
        binding: ItemVaultBinding(account: context.account, database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
    let session = try await ItemVaultBootstrap(repository: repository, trustStore: inventory, scope: scope, device: SessionDevice(copying: owner)).create(name: "local")
    try await runtime.register(session: session)
    let startup = Task { try await runtime.start() }
    await gate.entered()
    // Cloud startup remains suspended while both local operations complete.
    let localCompleted = try await DeliveryConfirmationWaiter.wait(timeout: .seconds(2), request: {}, observe: {
        let records = try await runtime.inventory()
        #expect(records.count == 1 && records[0].scope == scope)
        try await runtime.register(session: session)
        return true
    })
    #expect(localCompleted)
    #expect(session.isUnlocked)
    await gate.release()
    try await startup.value
    await runtime.stop()
}

private actor AdmissionHeadServer: VaultMembershipTransport {
    private var head: ProvisioningCloudRecord
    private var history: [String: Data] = [:]
    private(set) var headWrites = 0
    init(head: Data) { self.head = ProvisioningCloudRecord(bytes: head, systemFields: Data([1])) }
    func readHead(binding: VaultProvisioningBinding) async throws -> ProvisioningCloudRecord { head }
    func readMembership(binding: VaultProvisioningBinding, digest: String) async throws -> Data {
        guard let value = history[digest] else { throw VaultProvisioningError.controlMismatch }; return value
    }
    func createMembership(binding: VaultProvisioningBinding, digest: String, bytes: Data) async throws {
        if let existing = history[digest], existing != bytes { throw VaultProvisioningError.controlMismatch }
        history[digest] = bytes
    }
    func compareAndSwapHead(binding: VaultProvisioningBinding, bytes: Data, expected: ProvisioningCloudRecord) async throws -> ProvisioningCloudRecord {
        guard expected.bytes == head.bytes, expected.systemFields == head.systemFields else { throw VaultProvisioningError.controlMismatch }
        headWrites += 1
        head = ProvisioningCloudRecord(bytes: bytes, systemFields: Data([2]))
        throw URLError(.networkConnectionLost) // Cloud committed, response was lost.
    }
}

@Test func runtimeAdmissionRecoversLostHeadAcknowledgementWithoutDuplicateMembership() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-runtime-admission-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let inventory = MemoryItemInventory(), provider = Mutex(try SessionDevice())
    let member = provider.withLock { $0.identity.member }
    let context = ItemVaultRuntimeContext(container: "iCloud.test", environment: "Development", account: "runtime", memberID: member, leaseURL: directory.appendingPathComponent("lease.lock"))
    let scope = ItemVaultSetupScope(container: context.container, environment: context.environment,
        binding: ItemVaultBinding(account: context.account, database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
    let initialDevice = provider.withLock { SessionDevice(copying: $0) }
    let session = try await ItemVaultBootstrap(repository: repository, trustStore: inventory, scope: scope, device: initialDevice).create(name: "admitted")
    let record = try #require(try inventory.load(scope: scope)), head = AdmissionHeadServer(head: record.genesis)
    let runtime = try ItemVaultSyncRuntime(context: context, repository: repository, trustStore: inventory, transport: DomainProvisionServer(),
        accountValidator: { true }, accountAuthorization: DomainAccountAuthorization(), membershipTransport: head) { addresses, items, controls, eligible in
            RuntimeDriver(addresses, items, controls, eligible)
        }
    try await runtime.setSessionLoader { record in
        let device = provider.withLock { SessionDevice(copying: $0) }
        return try await ItemVaultBootstrap(repository: repository, trustStore: inventory, scope: record.scope, device: device).open()
    }
    try await runtime.register(session: session)
    try await runtime.start()
    for pending in try await repository.pendingMutations(account: context.account) {
        try await repository.acknowledge(mutationID: pending.id, account: context.account, serverSystemFields: Data([7]))
    }
    let joining = try SessionDevice(member: member)
    let request = try DeviceEnrollmentRequest.create(scope: EnrollmentScope(container: context.container, environment: context.environment,
        account: context.account, vault: scope.binding.vaultID, member: member), device: joining)
    let approval = try await runtime.approveEnrollment(request)
    #expect(await head.headWrites == 1)
    #expect(try await runtime.approveEnrollment(request) == approval)
    #expect(await head.headWrites == 1)
    #expect(try inventory.membershipHistory(scope: scope).count == 1)
    #expect(try await repository.admission(scope: scope.repositoryScope)?.phase == .complete)
    #expect(try await repository.pendingMutations(account: context.account).count == 1)
    #expect(!session.isUnlocked)
    let beforeReconnect = try await repository.pendingMutations(account: context.account).map(\.version)
    let reconnectRequest = try DeviceEnrollmentRequest.create(scope: request.scope, device: joining)
    let reconnect = try await runtime.approveEnrollment(reconnectRequest)
    #expect(reconnect.isReconnect)
    #expect(reconnect.successor == approval.successor)
    #expect(await head.headWrites == 1)
    #expect(try inventory.membershipHistory(scope: scope).count == 1)
    #expect(try await repository.pendingMutations(account: context.account).map(\.version) == beforeReconnect)
    #expect(try await repository.admission(scope: scope.repositoryScope)?.requestID == request.id)
    await runtime.stop()
}

@Test func runtimeRewrapsOfflinePendingItemsAfterAdditiveMembershipAdvance() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-runtime-offline-admission-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let inventory = MemoryItemInventory(), owner = try SessionDevice(), joining = try SessionDevice(member: owner.identity.member)
    let context = ItemVaultRuntimeContext(container: "iCloud.test", environment: "Development", account: "runtime",
        memberID: owner.identity.member, leaseURL: directory.appendingPathComponent("lease.lock"))
    let scope = ItemVaultSetupScope(container: context.container, environment: context.environment,
        binding: ItemVaultBinding(account: context.account, database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
    let archive = try PortableArchive.seal(sessionArchive())
    let originalSession = try await ItemVaultBootstrap(repository: repository, trustStore: inventory, scope: scope,
        device: SessionDevice(copying: owner)).restore(archiveData: archive.data, recoveryKey: archive.recoveryKey, name: "offline")
    let originalPending = try await repository.pendingMutations(account: context.account)
    let originalItem = try #require(originalPending.first { $0.version.scope.itemID != ItemVaultSession.metadataRecordID })
    #expect(originalItem.version.generation == 1)
    let record = try #require(try inventory.load(scope: scope))
    let history = try ItemVaultMembershipAuthority.history(record: record, trustStore: inventory)
    let request = try DeviceEnrollmentRequest.create(scope: EnrollmentScope(container: context.container,
        environment: context.environment, account: context.account, vault: scope.binding.vaultID, member: owner.identity.member), device: joining)
    let approval = try DeviceEnrollmentApproval.create(request: request, history: history, owner: owner)
    let permission = DomainAccountAuthorization()
    let binding = VaultProvisioningBinding(scope: scope.repositoryScope,
        address: VaultCloudAddress(vaultID: scope.binding.vaultID, zoneName: "MopItems-" + scope.binding.vaultID.uuidString,
            ownerName: scope.binding.zoneOwner), setupID: try record.setupID, controlDigest: record.pinnedDigest)
    let prepared = try await repository.prepareProvisioning(binding: binding, controlBytes: record.genesis, authorization: permission)
    let commissioning = try await repository.advanceProvisioning(prepared, to: .commissioningStarted, authorization: permission)
    _ = try await repository.advanceProvisioning(commissioning, to: .controlConfirmed, headSystemFields: Data([1]), authorization: permission)
    try inventory.reserveMembership(scope: scope, successors: [approval.successor.encoded()])
    try await repository.acceptMembershipHead(scope: scope.repositoryScope, expectedControl: record.genesis,
        control: approval.successor.encoded(), headSystemFields: Data([2]), authorization: permission)
    originalSession.lock()
    let refreshed = try await ItemVaultBootstrap(repository: repository, trustStore: inventory, scope: scope,
        device: SessionDevice(copying: owner)).open()
    let drivers = Mutex<[RuntimeDriver]>([])
    let runtime = try ItemVaultSyncRuntime(context: context, repository: repository, trustStore: inventory,
        transport: DomainProvisionServer(), accountValidator: { true }, accountAuthorization: permission,
        membershipTransport: AdmissionHeadServer(head: try approval.successor.encoded())) { addresses, items, controls, eligible in
            let driver = RuntimeDriver(addresses, items, controls, eligible)
            drivers.withLock { $0.append(driver) }
            return driver
        }
    try await runtime.register(session: refreshed)
    try await runtime.start()
    let replacement = try #require(try await repository.item(originalItem.version.scope))
    #expect(replacement.baseVersionID == originalItem.version.versionID)
    #expect(replacement.generation == 2)
    for previous in originalPending {
        #expect(try await repository.mutationReceipt(id: previous.id, account: context.account)?.status == .superseded)
    }
    let pending = try await repository.pendingMutations(account: context.account)
    #expect(pending.count == originalPending.count)
    #expect(pending.allSatisfy { $0.version.generation == 2 })
    let adopted = try ItemEnvelope.decode(replacement.ciphertext, vault: scope.binding.vaultID,
        item: replacement.scope.itemID, membership: approval.successor.membership, membershipStateDigest: approval.successor.digest())
    let original = try ItemEnvelope.decode(originalItem.version.ciphertext, vault: scope.binding.vaultID,
        item: originalItem.version.scope.itemID, membership: history.current.membership, membershipStateDigest: history.current.digest())
    #expect(adopted.encryptedRecords == original.encryptedRecords)
    let catalog = try adopted.catalog(device: joining, membership: approval.successor.membership,
        membershipStateDigest: approval.successor.digest())
    let password = try #require(catalog.references["Login/password"])
    #expect(try adopted.read(record: password, device: joining, membership: approval.successor.membership,
        membershipStateDigest: approval.successor.digest()) == SecretBytes(utf8: "session-secret"))
    // Historical enrollment must not tear down and recreate the engine on
    // every foreground/manual wake once all item envelopes have caught up.
    _ = try await runtime.requestSync()
    _ = try await runtime.requestSync()
    #expect(drivers.withLock { $0.count } == 1)
    let activeDriver = try #require(drivers.withLock { $0.first })
    #expect(await activeDriver.stops == 0)
    await runtime.stop()
}

private actor SuspendedRuntimeDriver: ItemVaultRuntimeDriver {
    let repository: EncryptedItemRepository
    var suspended = false
    private(set) var starts = 0
    private(set) var recoveries = 0
    init(repository: EncryptedItemRepository) { self.repository = repository }
    func suspend() { suspended = true }
    func start(automaticallySync: Bool) async throws {
        guard !suspended else { throw CloudSyncAdapterError.accountChanged }
        starts += 1
    }
    func stop() async {}
    func setUploadsAllowed(_ allowed: Bool) async {}
    func requestForegroundSync() async throws -> DurableSyncRequest {
        if suspended { suspended = false; recoveries += 1 }
        return try await repository.requestSync(account: "runtime", database: "private", reason: .foreground)
    }
}

@Test func foregroundRequestUsesSuspendedDriversRecoveryEntryPoint() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-runtime-resume-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let driver = SuspendedRuntimeDriver(repository: repository)
    let context = ItemVaultRuntimeContext(container: "iCloud.test", environment: "Development", account: "runtime", memberID: UUID(),
        leaseURL: directory.appendingPathComponent("lease.lock"))
    let runtime = try ItemVaultSyncRuntime(context: context, repository: repository, trustStore: MemoryItemInventory(),
        transport: DomainProvisionServer(), accountValidator: { true }, accountAuthorization: DomainAccountAuthorization()) { _, _, _, _ in driver }
    try await runtime.start()
    await driver.suspend()
    _ = try await runtime.requestSync()
    #expect(await driver.recoveries == 1)
    #expect(await driver.starts == 1)
    await runtime.stop()
}
