import CryptoKit
import Foundation
import Synchronization
import Testing
import MopCore
import MopKeychain
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
    var failure: MopError?
    func fail(with error: MopError?) { failure = error }
    var data: [UUID: [String: CloudObject]] = [:]
    var loseResponse = false
    var losePairingResponse = false
    var rejectHead = false
    var holdManifest = false
    var holdHead = false
    var holdFetch = false
    var waiting: CheckedContinuation<Void, Never>?
    var readRequests = 0
    func account() throws -> String { readRequests += 1; if let failure { throw failure }; return user }
    func changeAccount() { user = "other" }
    func zones() -> [UUID] { Array(data.keys) }
    func createZone(_ id: UUID) { data[id] = data[id] ?? [:] }
    func deleteZone(_ id: UUID) { data[id] = nil }
    func fetch(_ id: String, vault: UUID) async throws -> CloudObject? {
        if holdFetch { holdFetch = false; await withCheckedContinuation { waiting = $0 } }
        readRequests += 1
        guard let zone = data[vault] else { throw MopError.vaultMissing }; return zone[id]
    }
    func save(_ id: String, kind: CloudKind, data bytes: Data, vault: UUID, expected: Data?) async throws -> CloudObject {
        if id.hasPrefix("m-") && holdManifest { await withCheckedContinuation { waiting = $0 }; holdManifest = false }
        if kind == .head && holdHead { await withCheckedContinuation { waiting = $0 }; holdHead = false }
        if kind == .head && rejectHead { rejectHead = false; throw MopError.vaultConflict }
        guard data[vault]?[id]?.version == expected else { throw MopError.vaultConflict }
        let object = CloudObject(data: bytes, version: Data(UUID().uuidString.utf8))
        data[vault, default: [:]][id] = object
        if id.hasPrefix("p-") && losePairingResponse { losePairingResponse = false; throw MopError.cloudUnavailable }
        if kind == .head && loseResponse { loseResponse = false; throw MopError.cloudUnavailable }
        return object
    }
    func requests(vault: UUID) -> [String] { data[vault]?.keys.filter { $0.hasPrefix("q-") } ?? [] }
    func pauseManifest() { holdManifest = true }
    func pauseHead() { holdHead = true }
    func pauseFetch() { holdFetch = true }
    func releaseHead() { waiting?.resume(); waiting = nil }
    var isWaiting: Bool { waiting != nil }
    func loseNextResponse() { loseResponse = true }
    func loseNextPairingResponse() { losePairingResponse = true }
    func rejectNextHead() { rejectHead = true }
    func replacePairing(_ invitation: PairingInvitation, bytes: Data, direction: PairingInvitation.Direction) {
        data[invitation.vault]?["p-\(invitation.session.uuidString)-\(direction.rawValue)"] = CloudObject(data: bytes, version: Data("tampered".utf8))
    }
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
@Test func authenticatedReadsAndStrengthUseSnapshotWithoutCloudRequests() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    _ = try await operation(f, .catalog)
    let count = await f.cloud.readRequests
    await f.cloud.fail(with: .cloudUnavailable)
    let ref = try SecretReference("mop://personal/item/token")
    for _ in 0..<3 {
        #expect(try await operation(f, .read(ref)).value == "value")
        _ = try await operation(f, .passwordQuality(item: "item"))
    }
    #expect(await f.cloud.readRequests == count)
    #expect(f.authentications.value.withLock { $0 } == 1)
}

@Test func authenticatedSnapshotChangesOnlyAfterRefresh() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    _ = try await operation(f, .catalog)
    let ref = try SecretReference("mop://personal/item/token")
    let remote = try CloudSecretStore(vault: f.vaults[0], snapshot: await f.vaults[0].sync(), opener: TestDevice(key: f.key))
    defer { remote.close() }
    try await remote.write(ref, value: "remote", replace: true)
    #expect(try await operation(f, .read(ref)).value == "value")
    _ = try await operation(f, .catalog)
    let count = await f.cloud.readRequests
    #expect(try await operation(f, .read(ref)).value == "remote")
    #expect(await f.cloud.readRequests == count)
}

@Test func snapshotReadDoesNotWaitForCloudRefresh() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    _ = try await operation(f, .catalog)
    let service = f.service, id = f.vaults[0].id.uuidString
    await f.cloud.pauseFetch()
    let refresh = Task { try await service.execute(.catalog, vault: id, offline: false) }
    for _ in 0..<500 {
        if await f.cloud.isWaiting { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(await f.cloud.isWaiting)
    let completed = Mutex(false)
    let read = Task {
        let result = try await service.execute(.read(SecretReference("mop://personal/item/token")), vault: id, offline: false)
        completed.withLock { $0 = true }; return result
    }
    for _ in 0..<100 {
        if completed.withLock({ $0 }) { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(completed.withLock { $0 })
    await f.cloud.releaseHead()
    #expect(try await read.value.value == "value")
    _ = try await refresh.value
}

@Test func snapshotReadDoesNotWaitForOrExposePendingWrite() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    _ = try await operation(f, .catalog)
    let ref = try SecretReference("mop://personal/item/token")
    await f.cloud.pauseHead()
    let service = f.service, id = f.vaults[0].id.uuidString
    let write = Task { try await service.execute(.write(ref, "new", replace: true), vault: id, offline: false) }
    for _ in 0..<500 {
        if await f.cloud.isWaiting { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(await f.cloud.isWaiting)
    let completed = Mutex(false)
    let read = Task {
        let result = try await service.execute(.read(ref), vault: id, offline: false)
        completed.withLock { $0 = true }; return result
    }
    for _ in 0..<100 {
        if completed.withLock({ $0 }) { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(completed.withLock { $0 })
    await f.cloud.releaseHead()
    #expect(try await read.value.value == "value")
    _ = try await write.value
    #expect(try await operation(f, .read(ref)).value == "new")
}

@Test func nativeOTPReadsReturnCodesAndInvalidateCachedKeysAfterReplacement() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let catalog = try await operation(f, .catalog).requireCatalog()
    let secret = "JBSWY3DPEHPK3PXP"
    let item = VaultItem(name: "otp-login", type: .login, fields: [
        ItemField(path: "otp", type: .otp, value: secret),
        ItemField(path: "otp-url", type: .otp, value: "otpauth://totp/Mop:test@example.com?secret=\(secret)&issuer=Mop")
    ])
    _ = try await operation(f, .save(ItemEdit(revision: catalog.revision, item: item, create: true)))
    let ref = try SecretReference("mop://personal/otp-login/otp")
    let start = Date()
    let result = try await operation(f, .read(ref))
    let otp = try TimeBasedOTP(secret)
    #expect(result.value != SecretBytes(utf8: secret))
    #expect(result.valueIsConcealed)
    let Expected = try [SecretBytes(utf8: otp.code(at: start)), SecretBytes(utf8: otp.code())]
    #expect(Expected.contains { $0 == result.value })
    let urlStart = Date()
    let urlResult = try await operation(f, .read(SecretReference("mop://personal/otp-login/otp-url")))
    let urlExpected = try [SecretBytes(utf8: otp.code(at: urlStart)), SecretBytes(utf8: otp.code())]
    #expect(urlExpected.contains { $0 == urlResult.value })
    let unwraps = f.recordUnwraps.value.withLock { $0 }
    _ = try await operation(f, .read(ref))
    #expect(f.recordUnwraps.value.withLock { $0 } == unwraps)
    let replacement = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    _ = try await operation(f, .write(ref, SecretBytes(utf8: replacement), replace: true))
    let nextStart = Date(), next = try await operation(f, .read(ref))
    let nextOTP = try TimeBasedOTP(replacement)
    let nextExpected = try [SecretBytes(utf8: nextOTP.code(at: nextStart)), SecretBytes(utf8: nextOTP.code())]
    #expect(nextExpected.contains { $0 == next.value })
    f.service.lock()
    let coldStart = Date(), cold = try await operation(f, .read(ref))
    let coldExpected = try [SecretBytes(utf8: nextOTP.code(at: coldStart)), SecretBytes(utf8: nextOTP.code())]
    #expect(coldExpected.contains { $0 == cold.value })
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
        _ = try await operation(f, .catalog)
    }
    #expect(!f.service.isAuthenticated)
}
@Test func cacheTransitionPreservesSessionAndRejectsOfflineWrites() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    _ = try await operation(f, .catalog)
    let result = try await operation(f, .catalog, offline: true)
    #expect(result.offlineDate != nil)
    #expect(f.authentications.value.withLock { $0 } == 1)
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

@Test func preparedCreationRequiresExportAndRetainsIdentity() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    var intent = try PendingVaultCreation.prepare(name: "prepared", deviceName: "Phone", strict: false, state: f.directory)
    let reloaded = try PendingVaultCreation.prepare(name: "prepared", deviceName: "Phone", strict: false, state: f.directory)
    #expect(intent.id == reloaded.id)
    let key = try RecoveryKey(file: PendingVaultCreation.recoveryURL(state: f.directory)).publicKey
    await #expect(throws: MopError.invalidRecovery) {
        try await f.service.execute(.createPrepared, vault: intent.id.uuidString, offline: false)
    }
    #expect(!(await f.cloud.zones()).contains(intent.id))
    let output = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".key")
    defer { try? FileManager.default.removeItem(at: output) }
    try intent.export(to: output, state: f.directory)
    #expect(try RecoveryKey(file: output).publicKey == key)
    #expect(throws: MopError.outputExists) { try intent.export(to: output, state: f.directory) }
    #expect(try RecoveryKey(file: output).publicKey == key)
    let result = try await f.service.execute(.createPrepared, vault: intent.id.uuidString, offline: false)
    #expect(try result.requireCatalog().vault == "prepared")
    #expect(try PendingVaultCreation.load(state: f.directory) == nil)
    #expect(FileManager.default.fileExists(atPath: output.path))
}

@Test func preparedCreationReconcilesLostResponseWithoutNewKeyOrVault() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    var intent = try PendingVaultCreation.prepare(name: "interrupted", deviceName: "Tablet", strict: false, state: f.directory)
    let output = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".key")
    defer { try? FileManager.default.removeItem(at: output) }
    try intent.export(to: output, state: f.directory)
    await f.cloud.loseNextResponse()
    await #expect(throws: MopError.cloudUncertain) {
        try await f.service.execute(.createPrepared, vault: intent.id.uuidString, offline: false)
    }
    let pending = try #require(try PendingVaultCreation.load(state: f.directory))
    #expect(pending.id == intent.id && pending.submitted)
    let snapshot = try #require(pending.snapshot)
    f.service.lock()
    let result = try await f.service.execute(.createPrepared, vault: intent.id.uuidString, offline: false)
    #expect(try result.requireCatalog().vault == "interrupted")
    let repo = try await CloudRepository.open(transport: f.cloud, state: f.directory)
    #expect(try await repo.vault(intent.id).sync() == snapshot)
    #expect(try PendingVaultCreation.load(state: f.directory) == nil)
}

@Test func submittedCreationCannotResurrectDeletedVault() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    var intent = try PendingVaultCreation.prepare(name: "removed", deviceName: "Phone", strict: false, state: f.directory)
    let output = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".key")
    defer { try? FileManager.default.removeItem(at: output) }
    try intent.export(to: output, state: f.directory)
    await f.cloud.loseNextResponse()
    await #expect(throws: MopError.cloudUncertain) {
        try await f.service.execute(.createPrepared, vault: intent.id.uuidString, offline: false)
    }
    await f.cloud.deleteZone(intent.id)
    await #expect(throws: MopError.cloudUncertain) {
        try await f.service.execute(.createPrepared, vault: intent.id.uuidString, offline: false)
    }
    #expect(!(await f.cloud.zones()).contains(intent.id))
    #expect(try PendingVaultCreation.load(state: f.directory)?.id == intent.id)
}

@Test func recoveryImportStagesBoundedPrivateCopyWithoutChangingSource() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try SafeFile.privateDirectory(directory)
    defer { try? FileManager.default.removeItem(at: directory) }
    let source = directory.appendingPathComponent("source.key")
    let recovery = RecoveryKey()
    try recovery.save(to: source)
    let staged = try DocumentAccess.importRecovery(source, state: directory.appendingPathComponent("state"))
    #expect(staged != source)
    #expect(try RecoveryKey(file: staged).publicKey == recovery.publicKey)
    #expect(try RecoveryKey(file: source).publicKey == recovery.publicKey)
    let large = directory.appendingPathComponent("large.key")
    try SafeFile.write(Data(repeating: 65, count: 1025), to: large)
    #expect(throws: MopError.invalidVault) { try DocumentAccess.importRecovery(large, state: directory.appendingPathComponent("state")) }
}

private func phoneService(_ f: Fixture, key: P256.KeyAgreement.PrivateKey = P256.KeyAgreement.PrivateKey()) -> NativeVaultService {
    NativeVaultService(state: f.directory.appendingPathComponent("phone-" + UUID().uuidString), transport: { f.cloud }, device: { _, _, _, _, register in
        let device = TestDevice(key: key)
        try register { device.close() }
        return device
    })
}
private func pairingStep(_ service: NativeVaultService, _ operation: PairingOperation, vault: String? = nil) async throws -> PairingProgress {
    try #require(await service.execute(.pairing(operation), vault: vault, offline: false).pairing)
}
private func pairSetup(_ f: Fixture, phone: NativeVaultService) async throws -> PairingProgress {
    let start = try await pairingStep(f.service, .start, vault: f.vaults[0].id.uuidString)
    let join = try await pairingStep(phone, .join(qr: #require(start.qr), name: "Phone", strict: false))
    let compare = try await pairingStep(f.service, .poll(start.session))
    #expect(compare.phase == .comparing)
    #expect(compare.qr == nil)
    #expect(compare.code == join.code)
    return compare
}

struct NativePairingTests {
    @Test func enrollmentAndTrust() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let phone = phoneService(f); defer { phone.lock() }
        let compare = try await pairSetup(f, phone: phone)
        #expect(try await pairingStep(f.service, .approve(compare.session)).phase == .awaitingTrust)
        #expect(try await pairingStep(phone, .poll(compare.session)).phase == .complete)
        let result = try await phone.execute(.read(SecretReference(vault: "personal", item: "item", field: "token")), vault: compare.vault.uuidString, offline: false)
        #expect(result.value == "value")
        #expect(await f.cloud.requests(vault: compare.vault).isEmpty)
        #expect(try await pairingStep(f.service, .poll(compare.session)).phase == .complete)
        // Consumed sessions cannot publish another approval.
        await #expect(throws: PairingError.self) { try await pairingStep(f.service, .approve(compare.session)) }
    }
    @Test func competingPhonesAndCancel() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let first = phoneService(f), second = phoneService(f)
        defer { first.lock(); second.lock() }
        let start = try await pairingStep(f.service, .start, vault: f.vaults[0].id.uuidString)
        let qr = try #require(start.qr)
        _ = try await pairingStep(first, .join(qr: qr, name: "One", strict: false))
        await #expect(throws: PairingError.self) { try await pairingStep(second, .join(qr: qr, name: "Two", strict: false)) }
        _ = try await f.service.execute(.pairing(.cancel(start.session)), vault: nil, offline: false)
        await #expect(throws: PairingError.self) { try await pairingStep(f.service, .approve(start.session)) }
        let devices = try await f.service.execute(.devices, vault: start.vault.uuidString, offline: false)
        #expect(devices.devices.count == 1)
    }
    @Test func uncertainCommitReconcilesWithoutDuplicate() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let phone = phoneService(f); defer { phone.lock() }
        let compare = try await pairSetup(f, phone: phone)
        await f.cloud.loseNextResponse()
        await #expect(throws: MopError.self) { try await pairingStep(f.service, .approve(compare.session)) }
        #expect(try await pairingStep(phone, .poll(compare.session)).phase == .waiting)
        #expect(try await pairingStep(f.service, .approve(compare.session)).phase == .awaitingTrust)
        #expect(try await pairingStep(phone, .poll(compare.session)).phase == .complete)
        let devices = try await f.service.execute(.devices, vault: compare.vault.uuidString, offline: false)
        #expect(devices.devices.count == 2)
    }
    @Test func freshPairingAfterCommittedInterruption() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let phone = phoneService(f); defer { phone.lock() }
        let first = try await pairSetup(f, phone: phone)
        _ = try await pairingStep(f.service, .approve(first.session))
        _ = try await phone.execute(.pairing(.cancel(first.session)), vault: nil, offline: false)
        let second = try await pairSetup(f, phone: phone)
        _ = try await pairingStep(f.service, .approve(second.session))
        #expect(try await pairingStep(phone, .poll(second.session)).phase == .complete)
        let devices = try await f.service.execute(.devices, vault: second.vault.uuidString, offline: false)
        #expect(devices.devices.count == 2)
    }
    @Test func lockWhileEnrollmentIsSubmitted() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let phone = phoneService(f); defer { phone.lock() }
        let compare = try await pairSetup(f, phone: phone)
        await f.cloud.pauseHead()
        let service = f.service
        let approval = Task { try await pairingStep(service, .approve(compare.session)) }
        for _ in 0..<500 {
            if await f.cloud.isWaiting { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(await f.cloud.isWaiting)
        f.service.lock()
        await f.cloud.releaseHead()
        await #expect(throws: (any Error).self) { try await approval.value }
        #expect(try await pairingStep(phone, .poll(compare.session)).phase == .waiting)
        // An uncertain submitted enrollment is finished by a fresh explicit pairing.
        let retry = try await pairSetup(f, phone: phone)
        _ = try await pairingStep(f.service, .approve(retry.session))
        #expect(try await pairingStep(phone, .poll(retry.session)).phase == .complete)
    }
    @Test func accountChangeAndMissingZone() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let start = try await pairingStep(f.service, .start, vault: f.vaults[0].id.uuidString)
        await f.cloud.changeAccount()
        await #expect(throws: MopError.cloudAccount) { try await pairingStep(f.service, .poll(start.session)) }
        let other = try await fixture(); defer { other.cleanup() }
        let invitation = try await pairingStep(other.service, .start, vault: other.vaults[0].id.uuidString)
        await other.cloud.deleteZone(invitation.vault)
        let phone = phoneService(other); defer { phone.lock() }
        await #expect(throws: MopError.vaultMissing) { try await pairingStep(phone, .join(qr: #require(invitation.qr), name: "Phone", strict: false)) }
        #expect(await other.cloud.zones().contains(invitation.vault) == false)
    }
    @Test func revocationBeforePhoneFinishes() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let key = P256.KeyAgreement.PrivateKey()
        let phone = phoneService(f, key: key); defer { phone.lock() }
        let compare = try await pairSetup(f, phone: phone)
        _ = try await pairingStep(f.service, .approve(compare.session))
        let fingerprint = VaultCoding.digest(key.publicKey.x963Representation)
        _ = try await f.service.execute(.manage(.revoke(fingerprint: fingerprint)), vault: compare.vault.uuidString, offline: false)
        await #expect(throws: MopError.deviceNotEnrolled) { try await pairingStep(phone, .poll(compare.session)) }
    }
}

extension NativePairingTests {
    @Test func droppedPairingResponsesAreReconciled() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let phone = phoneService(f); defer { phone.lock() }
        await f.cloud.loseNextPairingResponse()
        let compare = try await pairSetup(f, phone: phone)
        await f.cloud.loseNextPairingResponse()
        _ = try await pairingStep(f.service, .approve(compare.session))
        #expect(try await pairingStep(phone, .poll(compare.session)).phase == .complete)
    }
    @Test func conflictDoesNotRepeatMutation() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let phone = phoneService(f); defer { phone.lock() }
        let compare = try await pairSetup(f, phone: phone)
        await f.cloud.rejectNextHead()
        await #expect(throws: MopError.self) { try await pairingStep(f.service, .approve(compare.session)) }
        await #expect(throws: MopError.vaultConflict) { try await pairingStep(f.service, .approve(compare.session)) }
        let devices = try await f.service.execute(.devices, vault: compare.vault.uuidString, offline: false)
        #expect(devices.devices.count == 1)
        let retry = try await pairSetup(f, phone: phone)
        _ = try await pairingStep(f.service, .approve(retry.session))
        #expect(try await pairingStep(phone, .poll(retry.session)).phase == .complete)
    }
    @Test func substitutedRequestCannotChangeApproval() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let key = P256.KeyAgreement.PrivateKey()
        let phone = phoneService(f, key: key); defer { phone.lock() }
        let start = try await pairingStep(f.service, .start, vault: f.vaults[0].id.uuidString)
        let qr = try #require(start.qr), invitation = try PairingInvitation.parse(qr)
        _ = try await pairingStep(phone, .join(qr: qr, name: "Phone", strict: false))
        let compare = try await pairingStep(f.service, .poll(start.session))
        let other = PairingRequest(device: try DeviceRequest(name: "Other", publicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation))
        await f.cloud.replacePairing(invitation, bytes: try invitation.seal(other, direction: .request), direction: .request)
        let unchanged = try await pairingStep(f.service, .poll(start.session))
        #expect(unchanged.code == compare.code)
        _ = try await pairingStep(f.service, .approve(start.session))
        #expect(try await pairingStep(phone, .poll(start.session)).phase == .complete)
        let devices = try await f.service.execute(.devices, vault: start.vault.uuidString, offline: false)
        #expect(devices.devices.contains { $0.fingerprint == VaultCoding.digest(key.publicKey.x963Representation) })
        #expect(!devices.devices.contains { $0.fingerprint == other.device.fingerprint })
    }
    @Test func malformedCloudRequestAndReceiptAreRejected() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let start = try await pairingStep(f.service, .start, vault: f.vaults[0].id.uuidString)
        let invitation = try PairingInvitation.parse(#require(start.qr))
        await f.cloud.replacePairing(invitation, bytes: Data(count: 8193), direction: .request)
        await #expect(throws: PairingError.self) { try await pairingStep(f.service, .poll(start.session)) }
        let phone = phoneService(f); defer { phone.lock() }
        let next = try await pairingStep(f.service, .start, vault: start.vault.uuidString)
        let qr = try #require(next.qr), nextInvitation = try PairingInvitation.parse(qr)
        _ = try await pairingStep(phone, .join(qr: qr, name: "Phone", strict: false))
        await f.cloud.replacePairing(nextInvitation, bytes: Data("not authenticated".utf8), direction: .response)
        await #expect(throws: PairingError.self) { try await pairingStep(phone, .poll(next.session)) }
    }
}

extension NativePairingTests {
    @Test func cancellationWhileStagingPreventsEnrollment() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let phone = phoneService(f); defer { phone.lock() }
        let compare = try await pairSetup(f, phone: phone)
        await f.cloud.pauseManifest()
        let service = f.service
        let approval = Task { try await pairingStep(service, .approve(compare.session)) }
        for _ in 0..<500 {
            if await f.cloud.isWaiting { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(await f.cloud.isWaiting)
        approval.cancel()
        await f.cloud.releaseHead()
        await #expect(throws: (any Error).self) { try await approval.value }
        let devices = try await f.service.execute(.devices, vault: compare.vault.uuidString, offline: false)
        #expect(devices.devices.count == 1)
        #expect(try await pairingStep(phone, .poll(compare.session)).phase == .waiting)
    }
    @Test func rotationInvalidatesPendingApproval() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let extra = try DeviceRequest(name: "Other Mac", publicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        let repo = try await CloudRepository.open(transport: f.cloud, state: f.directory)
        let requestID = try await repo.request(extra, vault: f.vaults[0])
        _ = try await f.service.execute(.manage(.approve(request: requestID, fingerprint: extra.fingerprint)), vault: f.vaults[0].id.uuidString, offline: false)
        let phone = phoneService(f); defer { phone.lock() }
        let compare = try await pairSetup(f, phone: phone)
        _ = try await f.service.execute(.manage(.revoke(fingerprint: extra.fingerprint)), vault: compare.vault.uuidString, offline: false)
        await #expect(throws: MopError.vaultUntrusted) { try await pairingStep(f.service, .approve(compare.session)) }
    }
}

extension NativePairingTests {
    @Test func hostDoesNotReportCompletionUntilPhoneTrustsVault() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let phone = phoneService(f); defer { phone.lock() }
        let compare = try await pairSetup(f, phone: phone)
        #expect(try await pairingStep(f.service, .approve(compare.session)).phase == .awaitingTrust)
        #expect(try await pairingStep(f.service, .poll(compare.session)).phase == .awaitingTrust)
        // Reproduces leaving the phone's pairing screen after the Mac approved.
        _ = try await phone.execute(.pairing(.cancel(compare.session)), vault: nil, offline: false)
        await #expect(throws: MopError.vaultUntrusted) {
            try await phone.execute(.catalog, vault: compare.vault.uuidString, offline: false)
        }
        #expect(try await pairingStep(f.service, .poll(compare.session)).phase == .awaitingTrust)
        let retry = try await pairSetup(f, phone: phone)
        _ = try await pairingStep(f.service, .approve(retry.session))
        #expect(try await pairingStep(phone, .poll(retry.session)).phase == .complete)
        #expect(try await pairingStep(f.service, .poll(retry.session)).phase == .complete)
        phone.lock()
        let reopened = try await phone.execute(.catalog, vault: retry.vault.uuidString, offline: false)
        #expect(try reopened.requireCatalog().vault == "personal")
    }
    @Test func lostAcknowledgementResponseStillCompletes() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let phone = phoneService(f); defer { phone.lock() }
        let compare = try await pairSetup(f, phone: phone)
        _ = try await pairingStep(f.service, .approve(compare.session))
        await f.cloud.loseNextPairingResponse()
        #expect(try await pairingStep(phone, .poll(compare.session)).phase == .complete)
        #expect(try await pairingStep(f.service, .poll(compare.session)).phase == .complete)
    }
    @Test func invalidAcknowledgementCannotCompleteHost() async throws {
        let f = try await fixture(); defer { f.cleanup() }
        let phone = phoneService(f); defer { phone.lock() }
        let start = try await pairingStep(f.service, .start, vault: f.vaults[0].id.uuidString)
        let qr = try #require(start.qr), invitation = try PairingInvitation.parse(qr)
        _ = try await pairingStep(phone, .join(qr: qr, name: "Phone", strict: false))
        _ = try await pairingStep(f.service, .poll(start.session))
        _ = try await pairingStep(f.service, .approve(start.session))
        let differentRequest = PairingRequest(device: try DeviceRequest(name: "Other", publicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation))
        let wrongReceipt = try PairingReceipt(request: differentRequest, vaultFingerprint: String(repeating: "a", count: 64), revision: String(repeating: "b", count: 64))
        let wrongAck = try PairingAcknowledgement(receipt: wrongReceipt)
        await f.cloud.replacePairing(invitation, bytes: try invitation.seal(wrongAck, direction: .acknowledgement), direction: .acknowledgement)
        await #expect(throws: PairingError.self) { try await pairingStep(f.service, .poll(start.session)) }
    }
}


private final class TestIdentityKeys: IdentityKeyStore, Sendable {
    let values = Mutex<[String: Data]>([:])
    func read(scope: String, id: UUID) throws -> Data? { values.withLock { $0[scope + id.uuidString] } }
    func insert(_ material: Data, scope: String, id: UUID) throws {
        try values.withLock {
            let key = scope + id.uuidString
            guard $0[key] == nil || $0[key] == material else { throw MopError.invalidDevice }
            $0[key] = material
        }
    }
}

@Test func synchronizedIdentityOpensAllVaultsOnUnenrolledDevice() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let keys = TestIdentityKeys()
    let existing = NativeVaultService(state: f.directory, identityKeys: keys, transport: { f.cloud }, device: { _, _, _, _, register in
        let device = TestDevice(key: f.key); try register { device.close() }; return device
    })
    defer { existing.lock() }
    for vault in f.vaults { _ = try await existing.execute(.catalog, vault: vault.id.uuidString) }
    let count = Counter(), newKey = P256.KeyAgreement.PrivateKey()
    let fresh = NativeVaultService(state: f.directory.appendingPathComponent("new-device"), identityKeys: keys, transport: { f.cloud }, device: { _, _, _, _, register in
        count.value.withLock { $0 += 1 }
        let device = TestDevice(key: newKey); try register { device.close() }; return device
    })
    defer { fresh.lock() }
    let discovered = try await fresh.execute(.discover, vault: nil)
    #expect(discovered.vaults.count == 2 && discovered.vaults.allSatisfy { $0.enrolled && $0.format == "mop-vault-v5" })
    for vault in f.vaults {
        let catalog = try await fresh.execute(.catalog, vault: vault.id.uuidString).requireCatalog()
        let read = try await fresh.execute(.read(SecretReference(vault: catalog.vault, item: "item", field: "token")), vault: vault.id.uuidString)
        #expect(read.value == "value")
        let members = try await fresh.execute(.devices, vault: vault.id.uuidString)
        #expect(members.members.count == 1 && members.members[0].role == "owner")
    }
    #expect(count.value.withLock { $0 } == 1)
    fresh.lock()
    _ = try await fresh.execute(.catalog, vault: f.vaults[0].id.uuidString)
    #expect(count.value.withLock { $0 } == 2)
    let waiting = NativeVaultService(state: f.directory.appendingPathComponent("waiting-device"), identityKeys: TestIdentityKeys(), transport: { f.cloud }, device: { _, _, _, _, register in
        let device = TestDevice(key: P256.KeyAgreement.PrivateKey()); try register { device.close() }; return device
    })
    defer { waiting.lock() }
    await #expect(throws: MopError.identityPending) { try await waiting.execute(.catalog, vault: f.vaults[0].id.uuidString) }
}


@Test func newAccountVaultHasOnlyOwnerAndRecoveryFromItsFirstRevision() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let keys = TestIdentityKeys()
    let service = NativeVaultService(state: f.directory, identityKeys: keys, transport: { f.cloud }, device: { _, _, _, _, register in
        let device = TestDevice(key: f.key); try register { device.close() }; return device
    })
    defer { service.lock() }
    let recoveryFile = f.directory.appendingPathExtension("account-recovery.key")
    defer { try? FileManager.default.removeItem(at: recoveryFile) }
    let id = UUID()
    _ = try await service.execute(.create(name: "account-vault", deviceName: "Unused", strict: false, recovery: recoveryFile), vault: id.uuidString)
    let repo = try await CloudRepository.open(transport: f.cloud, state: f.directory)
    let vault = try repo.vault(id)
    #expect(try await vault.revisions().count == 1)
    let snapshot = try await vault.sync(), document = try VaultDocument.decode(snapshot)
    #expect(document.header.format == "mop-vault-v5")
    #expect(Set(document.header.recipients.map(\.kind)) == ["member", "recovery"])
    let recovery = try RecoveryKey(file: recoveryFile)
    let recovered = try CloudSecretStore(vault: vault, snapshot: snapshot, opener: recovery)
    #expect(try recovered.catalog().vault == "account-vault")
}

@Test func unavailableCloudAutomaticallyUsesVerifiedCacheAndReconnects() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let ref = try SecretReference("mop://personal/item/token")
    _ = try await operation(f, .catalog)
    await f.cloud.fail(with: .cloudUnavailable)
    _ = try await operation(f, .catalog)
    let cached = try await operation(f, .read(ref))
    #expect(cached.usingCache && cached.offlineDate != nil)
    #expect(try cached.value?.withUnsafeBytes { String(decoding: $0, as: UTF8.self) } == "value")
    #expect(f.service.isAuthenticated)
    await #expect(throws: MopError.cloudUnavailable) {
        _ = try await operation(f, .write(ref, "must not queue", replace: true))
    }
    await f.cloud.fail(with: nil)
    let online = try await operation(f, .catalog)
    #expect(!online.usingCache && online.offlineDate == nil)
    #expect(f.authentications.value.withLock { $0 } == 1)
}
@Test func cacheFallbackNeverMasksPermissionAccountOrMissingVaultErrors() async throws {
    for failure in [MopError.cloudPermission, .cloudAccount, .vaultMissing, .invalidVault] {
        let f = try await fixture()
        _ = try await operation(f, .catalog)
        await f.cloud.fail(with: failure)
        await #expect(throws: failure) { _ = try await operation(f, .catalog) }
        f.cleanup()
    }
}
@Test func automaticCacheReadSurvivesLockAndRestart() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    _ = try await operation(f, .catalog)
    f.service.lock()
    await f.cloud.fail(with: .cloudUnavailable)
    let result = try await operation(f, .catalog)
    #expect(result.usingCache && result.catalog != nil)
    #expect(f.service.isAuthenticated)
}
