import CryptoKit
import Foundation
import Synchronization
import Testing
import MopCore
import MopVault
import MopCloudKit
@testable import MopAppSupport

private final class TestDevice: SessionDevice, @unchecked Sendable {
    let key: P256.KeyAgreement.PrivateKey
    let closed = Mutex(false)
    let strictBiometrics = false
    let observedUnwrap: @Sendable (String) -> Void
    init(key: P256.KeyAgreement.PrivateKey, observedUnwrap: @escaping @Sendable (String) -> Void = { _ in }) {
        self.key = key; self.observedUnwrap = observedUnwrap
    }
    var publicKey: Data { key.publicKey.x963Representation }
    var request: DeviceRequest { try! DeviceRequest(name: "Test Mac", publicKey: publicKey) }
    func unwrap(_ recipient: VaultRecipient, vaultID: UUID) throws -> SymmetricKey {
        guard !closed.withLock({ $0 }) else { throw MopError.authentication }
        observedUnwrap(recipient.purpose)
        return try VaultDocument.unwrap(recipient, vaultID: vaultID, privateKey: key)
    }
    func close() { closed.withLock { $0 = true } }
}
private actor TestCloud: CloudTransport {
    nonisolated let container = "iCloud.test.session"
    nonisolated let environment = "Development"
    var user = "user"
    var data: [UUID: [String: CloudObject]] = [:]
    var loseResponse = false
    var holdHead = false
    var waiting: CheckedContinuation<Void, Never>?
    func account() -> String { user }
    func changeAccount() { user = "other" }
    func zones() -> [UUID] { Array(data.keys) }
    func createZone(_ id: UUID) { data[id] = data[id] ?? [:] }
    func deleteZone(_ id: UUID) { data[id] = nil }
    func fetch(_ id: String, vault: UUID) throws -> CloudObject? {
        guard let zone = data[vault] else { throw MopError.vaultMissing }; return zone[id]
    }
    func save(_ id: String, kind: CloudKind, data bytes: Data, vault: UUID, expected: Data?) async throws -> CloudObject {
        if kind == .head && holdHead { await withCheckedContinuation { waiting = $0 }; holdHead = false }
        guard data[vault]?[id]?.version == expected else { throw MopError.vaultConflict }
        let object = CloudObject(data: bytes, version: Data(UUID().uuidString.utf8))
        data[vault, default: [:]][id] = object
        if kind == .head && loseResponse { loseResponse = false; throw MopError.cloudUnavailable }
        return object
    }
    func requests(vault: UUID) -> [String] { data[vault]?.keys.filter { $0.hasPrefix("q-") } ?? [] }
    func pauseHead() { holdHead = true }
    func releaseHead() { waiting?.resume(); waiting = nil }
    var isWaiting: Bool { waiting != nil }
    func loseNextResponse() { loseResponse = true }
}
private final class Counter: Sendable {
    let value = Mutex(0)
}
private struct Fixture {
    let directory: URL
    let cloud: TestCloud
    let key: P256.KeyAgreement.PrivateKey
    let vaults: [CloudVault]
    let service: NativeVaultService
    let authentications: Counter
    let indexUnwraps: Counter
    let recordUnwraps: Counter
    func cleanup() { service.lock(); try? FileManager.default.removeItem(at: directory) }
}
private func fixture() async throws -> Fixture {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-native-session-" + UUID().uuidString)
    let cloud = TestCloud(), key = P256.KeyAgreement.PrivateKey()
    let device = TestDevice(key: key)
    let repo = try await CloudRepository.open(transport: cloud, state: directory)
    var vaults: [CloudVault] = []
    for name in ["personal", "work"] {
        let bytes = try VaultSession.createSnapshot(name: name, device: device.request, recovery: RecoveryKey())
        let document = try VaultDocument.decode(bytes)
        let slot = try #require(document.header.recipients.first { $0.publicKey == device.publicKey })
        let fingerprint = try VaultTrust.fingerprint(document: document, key: device.unwrap(slot, vaultID: document.header.vaultID))
        let vault = try await repo.create(bytes, fingerprint: fingerprint)
        let store = try CloudSecretStore(vault: vault, snapshot: bytes, opener: device)
        try await store.write(SecretReference(vault: name, item: "item", field: "token"), value: "value", replace: false)
        store.close(); vaults.append(vault)
    }
    let count = Counter(), indexUnwraps = Counter(), recordUnwraps = Counter()
    let service = NativeVaultService(state: directory, transport: { cloud }, device: { _, _, _, _, register in
        count.value.withLock { $0 += 1 }
        let device = TestDevice(key: key) { purpose in
            if purpose == "index" { indexUnwraps.value.withLock { $0 += 1 } }
            else if purpose.hasPrefix("record:") { recordUnwraps.value.withLock { $0 += 1 } }
        }
        // The only concurrent operation on the fake device is its mutex-backed close flag.
        try register { device.close() }
        return device
    })
    return Fixture(directory: directory, cloud: cloud, key: key, vaults: vaults, service: service, authentications: count, indexUnwraps: indexUnwraps, recordUnwraps: recordUnwraps)
}
private func operation(_ f: Fixture, _ op: VaultOperation, index: Int = 0, offline: Bool = false) async throws -> VaultResult {
    try await f.service.execute(op, vault: f.vaults[index].id.uuidString, offline: offline)
}

@Test func nativeSessionReusesAuthenticationAcrossReadsEditsAndVaults() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    _ = try await operation(f, .catalog)
    let ref = try SecretReference("mop://personal/item/token")
    #expect(try await operation(f, .read(ref)).value == "value")
    _ = try await operation(f, .write(ref, "updated", replace: true))
    _ = try await operation(f, .catalog, index: 1)
    #expect(try await operation(f, .read(ref)).value == "updated")
    #expect(f.authentications.value.withLock { $0 } == 1)
    f.service.lock(); #expect(!f.service.isAuthenticated)
    _ = try await operation(f, .read(ref))
    #expect(f.authentications.value.withLock { $0 } == 2)
}
@Test func staleEditsConflictButSharedAuthorizationSurvives() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let catalog = try await operation(f, .catalog).requireCatalog()
    let ref = try SecretReference("mop://personal/item/token")
    let remote = try CloudSecretStore(vault: f.vaults[0], snapshot: await f.vaults[0].sync(), opener: TestDevice(key: f.key))
    defer { remote.close() }
    try await remote.write(ref, value: "remote", replace: true)
    let edit = ItemEdit(revision: catalog.revision, item: catalog.items[0], create: false)
    await #expect(throws: MopError.vaultConflict) { _ = try await operation(f, .save(edit)) }
    #expect(try await operation(f, .read(ref)).value == "remote")
    #expect(f.authentications.value.withLock { $0 } == 1)
}
@Test func accountChangeInvalidatesEntireSession() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    _ = try await operation(f, .catalog)
    await f.cloud.changeAccount()
    await #expect(throws: MopError.cloudAccount) { _ = try await operation(f, .catalog) }
    #expect(!f.service.isAuthenticated)
}
@Test func onlineRefreshRejectsRemoteRevocation() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    _ = try await operation(f, .catalog)
    let current = TestDevice(key: f.key), other = TestDevice(key: P256.KeyAgreement.PrivateKey())
    let store = try CloudSecretStore(vault: f.vaults[0], snapshot: await f.vaults[0].sync(), opener: current)
    try await store.enroll(other.request, fingerprint: other.request.fingerprint)
    store.close()
    let revoker = try CloudSecretStore(vault: f.vaults[0], snapshot: await f.vaults[0].sync(), opener: other)
    defer { revoker.close() }
    try await revoker.revoke(current.request.fingerprint, currentDevice: other.publicKey)
    await #expect(throws: MopError.deviceNotEnrolled) {
        _ = try await operation(f, .read(SecretReference("mop://personal/item/token")))
    }
    #expect(!f.service.isAuthenticated)
}
@Test func offlineRequiresSeparateSessionAndRejectsWrites() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    _ = try await operation(f, .catalog)
    await #expect(throws: MopError.cloudAccount) { _ = try await operation(f, .catalog, offline: true) }
    let result = try await operation(f, .catalog, offline: true)
    #expect(result.offlineDate != nil)
    await #expect(throws: MopError.offlineWrite) {
        _ = try await operation(f, .write(SecretReference("mop://personal/item/token"), "forbidden", replace: true), offline: true)
    }
}
@Test func uncertainCommitReconcilesBeforeNextMutation() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let ref = try SecretReference("mop://personal/item/token")
    _ = try await operation(f, .catalog)
    await f.cloud.loseNextResponse()
    await #expect(throws: MopError.cloudUncertain) { _ = try await operation(f, .write(ref, "committed", replace: true)) }
    #expect(try await operation(f, .read(ref)).value == "committed")
    _ = try await operation(f, .write(ref, "next", replace: true))
    #expect(f.authentications.value.withLock { $0 } == 1)
}
@Test func lockWhilePublishingRejectsResultAndNextUnlockAuthenticates() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let ref = try SecretReference("mop://personal/item/token")
    _ = try await operation(f, .catalog)
    await f.cloud.pauseHead()
    let service = f.service, id = f.vaults[0].id.uuidString
    let pending = Task { try await service.execute(.write(ref, "submitted", replace: true), vault: id, offline: false) }
    for _ in 0..<500 {
        if await f.cloud.isWaiting { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(await f.cloud.isWaiting)
    service.lock(); #expect(!service.isAuthenticated)
    await f.cloud.releaseHead()
    await #expect(throws: MopError.authentication) { _ = try await pending.value }
    #expect(try await operation(f, .read(ref)).value == "submitted")
    #expect(f.authentications.value.withLock { $0 } == 2)
}

private final class AuthenticationBarrier: Sendable {
    let entered = Mutex(false)
    let invalidated = Mutex(false)
    let release = DispatchSemaphore(value: 0)
}
@Test func lockCancelsPendingAuthenticationWithoutInstallingItsDevice() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let barrier = AuthenticationBarrier()
    let cloud = f.cloud, key = f.key
    let service = NativeVaultService(state: f.directory, transport: { cloud }, device: { _, _, _, _, register in
        let device = TestDevice(key: key)
        try register { barrier.invalidated.withLock { $0 = true }; device.close() }
        barrier.entered.withLock { $0 = true }
        guard barrier.release.wait(timeout: .now() + 5) == .success else { throw MopError.authentication }
        return device
    })
    let id = f.vaults[0].id.uuidString
    let pending = Task { try await service.execute(.catalog, vault: id, offline: false) }
    for _ in 0..<500 {
        if barrier.entered.withLock({ $0 }) { break }
        try await Task.sleep(for: .milliseconds(5))
    }
    #expect(barrier.entered.withLock { $0 })
    service.lock()
    #expect(barrier.invalidated.withLock { $0 })
    barrier.release.signal()
    await #expect(throws: MopError.authentication) { _ = try await pending.value }
    #expect(!service.isAuthenticated)
}
@Test func nativeExportPreservesNoOverwriteAndStateDirectoryProtection() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let output = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".mopfile")
    defer { try? FileManager.default.removeItem(at: output) }
    _ = try await operation(f, .export(output))
    let exported = try Data(contentsOf: output)
    #expect(try VaultDocument.decode(exported).header.vaultID == f.vaults[0].id)
    await #expect(throws: (any Error).self) { _ = try await operation(f, .export(output)) }
    #expect(try Data(contentsOf: output) == exported)
    await #expect(throws: (any Error).self) { _ = try await operation(f, .export(f.directory.appendingPathComponent("backup"))) }
}

@Test func nativeCreationEnrollmentTrustAndDeletionUseSharedSession() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let id = UUID().uuidString
    let recovery = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".key")
    defer { try? FileManager.default.removeItem(at: recovery) }
    let created = try await f.service.execute(.create(name: "new", deviceName: "Mac", strict: false, recovery: recovery), vault: id, offline: false)
    #expect(try created.requireCatalog().vault == "new")
    #expect(FileManager.default.fileExists(atPath: recovery.path))
    let otherKey = P256.KeyAgreement.PrivateKey(), cloud = f.cloud
    let otherDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-other-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: otherDirectory) }
    let other = NativeVaultService(state: otherDirectory, transport: { cloud }, device: { _, _, _, _, register in
        let device = TestDevice(key: otherKey); try register { device.close() }; return device
    })
    defer { other.lock() }
    _ = try await other.execute(.manage(.request(name: "Other", strict: false)), vault: id, offline: false)
    let requests = try await f.service.execute(.requests, vault: id, offline: false).requests
    let request = try #require(requests.first)
    let approved = try await f.service.execute(.manage(.approve(request: request.id, fingerprint: request.fingerprint)), vault: id, offline: false)
    #expect(approved.catalog != nil)
    let fingerprint = try await f.service.execute(.manage(.fingerprint), vault: id, offline: false).message
    _ = try await other.execute(.manage(.trust(fingerprint: fingerprint)), vault: id, offline: false)
    #expect(try await other.execute(.catalog, vault: id, offline: false).requireCatalog().vault == "new")
    #expect(f.authentications.value.withLock { $0 } == 1)
    _ = try await f.service.execute(.deleteVault, vault: id, offline: false)
    #expect(!(await cloud.zones()).contains(UUID(uuidString: id)!))
    _ = try await operation(f, .catalog)
    #expect(f.authentications.value.withLock { $0 } == 1)
}

@Test func recoveryEnrollsNewDeviceWithoutChangingOtherSessions() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let id = UUID().uuidString
    let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".key")
    defer { try? FileManager.default.removeItem(at: file) }
    _ = try await f.service.execute(.create(name: "recoverable", deviceName: "Mac", strict: false, recovery: file), vault: id, offline: false)
    let fingerprint = try await f.service.execute(.manage(.fingerprint), vault: id, offline: false).message
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-recovery-test-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let cloud = f.cloud, key = P256.KeyAgreement.PrivateKey()
    let recovered = NativeVaultService(state: directory, transport: { cloud }, device: { _, _, _, _, register in
        let device = TestDevice(key: key); try register { device.close() }; return device
    })
    defer { recovered.lock() }
    _ = try await recovered.execute(.manage(.recover(file: file, name: "Recovered", fingerprint: fingerprint)), vault: id, offline: false)
    #expect(try await recovered.execute(.catalog, vault: id, offline: false).requireCatalog().vault == "recoverable")
}

@Test func concurrentMutationsHoldPermitAcrossCloudSuspensions() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    _ = try await operation(f, .catalog)
    let service = f.service, id = f.vaults[0].id.uuidString
    let ref = try SecretReference("mop://personal/item/token")
    await f.cloud.pauseHead()
    let first = Task { try await service.execute(.write(ref, "first", replace: true), vault: id, offline: false) }
    for _ in 0..<500 {
        if await f.cloud.isWaiting { break }
        try await Task.sleep(for: .milliseconds(5))
    }
    #expect(await f.cloud.isWaiting)
    let second = Task { try await service.execute(.write(ref, "second", replace: true), vault: id, offline: false) }
    // Give the second operation an opportunity to enter while the first is
    // suspended; without the permit it would collide with the live writer lease.
    try await Task.sleep(for: .milliseconds(30))
    await f.cloud.releaseHead()
    _ = try await first.value
    _ = try await second.value
    #expect(try await operation(f, .read(ref)).value == "second")
    #expect(f.authentications.value.withLock { $0 } == 1)
}

@Test func passwordScoresReturnNoPlaintextAndNeverOpenALockedSession() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    var catalog = try await operation(f, .catalog).requireCatalog()
    catalog.items[0].fields[0].type = .password
    catalog.items[0].fields[0].value = "password"
    _ = try await operation(f, .save(ItemEdit(revision: catalog.revision, item: catalog.items[0], create: false)))
    let result = try await operation(f, .passwordQuality(item: "item"))
    #expect(result.passwordQuality["token"] != nil)
    #expect(result.value == nil && result.catalog == nil && result.message.isEmpty)
    #expect(f.authentications.value.withLock { $0 } == 1)
    f.service.lock()
    await #expect(throws: MopError.authentication) { _ = try await operation(f, .passwordQuality(item: "item")) }
    #expect(f.authentications.value.withLock { $0 } == 1)
}

@Test func nativeTrashRestoreAndOfflineRestrictions() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let initial = try await operation(f, .catalog).requireCatalog()
    let deleted = try await operation(f, .trashItem(name: "item", revision: initial.revision))
    #expect(try deleted.requireCatalog().items.isEmpty)
    let archived = try #require(deleted.deletedCatalog?.items.first)
    let deletion = try #require(archived.deletion)
    #expect(deletion.originalName == "item")
    #expect(try await operation(f, .recentlyDeleted).deletedCatalog?.items.count == 1)
    let restored = try await operation(f, .restoreItem(id: deletion.id, revision: deleted.requireCatalog().revision))
    #expect(try restored.requireCatalog().items.map(\.name) == ["item"])
    #expect(restored.deletedCatalog?.items.isEmpty == true)
    #expect(f.authentications.value.withLock { $0 } == 1)
    f.service.lock()
    _ = try await operation(f, .catalog, offline: true)
    await #expect(throws: MopError.offlineWrite) {
        _ = try await operation(f, .trashItem(name: "item", revision: restored.requireCatalog().revision), offline: true)
    }
}

@Test func uncertainTrashCommitReconcilesWithoutDuplicatingDeletedItem() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let catalog = try await operation(f, .catalog).requireCatalog()
    await f.cloud.loseNextResponse()
    // The cloud layer may reconcile a committed head immediately, or surface uncertainty.
    do { _ = try await operation(f, .trashItem(name: "item", revision: catalog.revision)) } catch {}
    let reconciled = try await operation(f, .catalog)
    #expect(try reconciled.requireCatalog().items.isEmpty)
    #expect(reconciled.deletedCatalog?.items.count == 1)
    await #expect(throws: MopError.vaultConflict) {
        _ = try await operation(f, .trashItem(name: "item", revision: catalog.revision))
    }
}

@Test func onlineCatalogPurgesExpiredTrashFromCloudSnapshot() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let vault = f.vaults[0]
    let remote = try CloudSecretStore(vault: vault, snapshot: await vault.sync(), opener: TestDevice(key: f.key))
    defer { remote.close() }
    try await remote.trashItem(name: "item", revision: remote.catalog().revision,
                               at: Date().addingTimeInterval(-ItemDeletion.retention - 10))
    #expect(try VaultDocument.decode(remote.snapshot).records.count == 1)
    let result = try await operation(f, .catalog)
    #expect(try result.requireCatalog().items.isEmpty && result.deletedCatalog?.items.isEmpty == true)
    #expect(try VaultDocument.decode(await vault.sync()).records.isEmpty)
}

@Test func readsReportCurrentFieldConcealmentForClipboardPolicy() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let ref = try SecretReference("mop://personal/item/token")
    #expect(try await operation(f, .read(ref)).valueIsConcealed)
    var catalog = try await operation(f, .catalog).requireCatalog()
    catalog.items[0].fields[0].type = .text
    _ = try await operation(f, .save(ItemEdit(revision: catalog.revision, item: catalog.items[0], create: false)))
    #expect(try await !operation(f, .read(ref)).valueIsConcealed)
}

@Test func unchangedUnlockedVaultsNeverReopenIndexWhenReadingValuesOrSwitching() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    _ = try await operation(f, .catalog)
    _ = try await operation(f, .catalog, index: 1)
    let indexCount = f.indexUnwraps.value.withLock { $0 }
    let recordCount = f.recordUnwraps.value.withLock { $0 }
    #expect(indexCount >= 2 && recordCount == 0)
    for _ in 0..<3 {
        for (index, name) in ["personal", "work"].enumerated() {
            _ = try await operation(f, .catalog, index: index)
            #expect(try await operation(f, .read(SecretReference("mop://" + name + "/item/token")), index: index).value == "value")
        }
    }
    #expect(f.indexUnwraps.value.withLock { $0 } == indexCount)
    #expect(f.recordUnwraps.value.withLock { $0 } == recordCount + 6)
    #expect(f.authentications.value.withLock { $0 } == 1)
}
