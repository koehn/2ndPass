import CryptoKit
import Foundation
import Synchronization
import Testing
import MopCore
import MopKeychain
import MopVault
import MopCloudKit
@testable import MopAppSupport

private actor TestCloud: CloudTransport {
    nonisolated let container = "iCloud.test.session"
    nonisolated let environment = "Development"
    var user = "user"
    var failure: MopError?
    func fail(with error: MopError?) { failure = error }
    var data: [UUID: [String: CloudObject]] = [:]
    var loseResponse = false
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
    func rejectNextHead() { rejectHead = true }

}
private final class Counter: Sendable {
    let value = Mutex(0)
}
private struct Fixture {
    let directory: URL
    let cloud: TestCloud
    let key: AccountIdentity
    let keys: TestIdentityKeys
    let vaults: [CloudVault]
    let service: NativeVaultService
    let authentications: Counter
    func cleanup() { service.lock(); try? FileManager.default.removeItem(at: directory) }
}
private func fixture() async throws -> Fixture {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-native-session-" + UUID().uuidString)
    let cloud = TestCloud(), keys = TestIdentityKeys()
    let repo = try await CloudRepository.open(transport: cloud, state: directory)
    let key = try await repo.accountIdentity(keys: keys, create: true)
    let device = key
    var vaults: [CloudVault] = []
    for name in ["personal", "work"] {
        let bytes = try VaultSession.createAccountSnapshot(name: name, owner: device, recovery: RecoveryKey())
        let document = try VaultDocument.decode(bytes)
        let slot = try #require(document.header.recipients.first { $0.publicKey == device.publicKey })
        let fingerprint = try VaultTrust.fingerprint(document: document, key: device.unwrap(slot, vaultID: document.header.vaultID))
        let vault = try await repo.create(bytes, fingerprint: fingerprint)
        let store = try CloudSecretStore(vault: vault, snapshot: bytes, opener: device)
        try await store.write(SecretReference(vault: name, item: "item", field: "token"), value: "value", replace: false)
        store.close(); vaults.append(vault)
    }
    let count = Counter()
    let service = NativeVaultService(state: directory, identityKeys: keys, transport: { cloud }, authenticate: { _, _ in
        count.value.withLock { $0 += 1 }
        return {}
    })
    return Fixture(directory: directory, cloud: cloud, key: key, keys: keys, vaults: vaults, service: service, authentications: count)

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
    let remote = try CloudSecretStore(vault: f.vaults[0], snapshot: await f.vaults[0].sync(), opener: f.key)
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
    _ = try await operation(f, .read(ref))
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
    let remote = try CloudSecretStore(vault: f.vaults[0], snapshot: await f.vaults[0].sync(), opener: f.key)
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
    let cloud = f.cloud
    let service = NativeVaultService(state: f.directory, identityKeys: f.keys, transport: { cloud }, authenticate: { _, register in
        try register { barrier.invalidated.withLock { $0 = true } }
        barrier.entered.withLock { $0 = true }
        guard barrier.release.wait(timeout: .now() + 5) == .success else { throw MopError.authentication }
        return {}
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
    let remote = try CloudSecretStore(vault: vault, snapshot: await vault.sync(), opener: f.key)
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

@Test func unchangedUnlockedVaultsReuseAuthenticationWhenReadingAndSwitching() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    _ = try await operation(f, .catalog)
    _ = try await operation(f, .catalog, index: 1)
    for _ in 0..<3 {
        for (index, name) in ["personal", "work"].enumerated() {
            _ = try await operation(f, .catalog, index: index)
            #expect(try await operation(f, .read(SecretReference("mop://" + name + "/item/token")), index: index).value == "value")
        }
    }
    #expect(f.authentications.value.withLock { $0 } == 1)
}

@Test func preparedCreationRequiresExportAndRetainsIdentity() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    var intent = try PendingVaultCreation.prepare(name: "prepared", strict: false, state: f.directory)
    let reloaded = try PendingVaultCreation.prepare(name: "prepared", strict: false, state: f.directory)
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
    var intent = try PendingVaultCreation.prepare(name: "interrupted", strict: false, state: f.directory)
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
    var intent = try PendingVaultCreation.prepare(name: "removed", strict: false, state: f.directory)
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

private final class TestIdentityKeys: IdentityKeyStore, Sendable {
    let values = Mutex<[String: Data]>([:])
    func read(scope: String, id: UUID) throws -> Data? { values.withLock { $0[scope + id.uuidString] } }
    func insert(_ material: Data, scope: String, id: UUID) throws {
        try values.withLock {
            let key = scope + id.uuidString
            guard $0[key] == nil || $0[key] == material else { throw MopError.invalidIdentity }
            $0[key] = material
        }
    }
}

@Test func synchronizedIdentityOpensAllVaultsOnUnenrolledDevice() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let keys = f.keys
    let existing = NativeVaultService(state: f.directory, identityKeys: keys, transport: { f.cloud }, authenticate: { _, _ in {} })
    defer { existing.lock() }
    for vault in f.vaults { _ = try await existing.execute(.catalog, vault: vault.id.uuidString) }
    let count = Counter()
    let fresh = NativeVaultService(state: f.directory.appendingPathComponent("new-device"), identityKeys: keys, transport: { f.cloud }, authenticate: { _, _ in
        count.value.withLock { $0 += 1 }; return {}
    })
    defer { fresh.lock() }
    let discovered = try await fresh.execute(.discover, vault: nil)
    #expect(discovered.vaults.count == 2 && discovered.vaults.allSatisfy { $0.enrolled && $0.format == "mop-vault-v5" })
    for vault in f.vaults {
        let catalog = try await fresh.execute(.catalog, vault: vault.id.uuidString).requireCatalog()
        let read = try await fresh.execute(.read(SecretReference(vault: catalog.vault, item: "item", field: "token")), vault: vault.id.uuidString)
        #expect(read.value == "value")
        let members = try await fresh.execute(.members, vault: vault.id.uuidString)
        #expect(members.members.count == 1 && members.members[0].role == "owner")
    }
    #expect(count.value.withLock { $0 } == 1)
    fresh.lock()
    _ = try await fresh.execute(.catalog, vault: f.vaults[0].id.uuidString)
    #expect(count.value.withLock { $0 } == 2)
    let waiting = NativeVaultService(state: f.directory.appendingPathComponent("waiting-device"), identityKeys: TestIdentityKeys(), transport: { f.cloud }, authenticate: { _, _ in {} })
    defer { waiting.lock() }
    await #expect(throws: MopError.identityPending) { try await waiting.execute(.catalog, vault: f.vaults[0].id.uuidString) }
}


@Test func newAccountVaultHasOnlyOwnerAndRecoveryFromItsFirstRevision() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let keys = f.keys
    let service = NativeVaultService(state: f.directory, identityKeys: keys, transport: { f.cloud }, authenticate: { _, _ in {} })
    defer { service.lock() }
    let recoveryFile = f.directory.appendingPathExtension("account-recovery.key")
    defer { try? FileManager.default.removeItem(at: recoveryFile) }
    let id = UUID()
    _ = try await service.execute(.create(name: "account-vault", strict: false, recovery: recoveryFile), vault: id.uuidString)
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

@Test func nativeAccountAccessIgnoresLegacyDeviceMetadata() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    // Invalid legacy metadata would have failed the former LocalDevice path.
    try SafeFile.write(Data("not a legacy credential".utf8), to: f.directory.appendingPathComponent("device.json"))
    let discovered = try await f.service.execute(.discover, vault: nil)
    #expect(discovered.vaults.count == 2 && discovered.vaults.allSatisfy(\.enrolled))
    #expect(try await operation(f, .read(SecretReference("mop://personal/item/token"))).value == "value")
    #expect(try SafeFile.read(f.directory.appendingPathComponent("device.json")) == Data("not a legacy credential".utf8))
}
