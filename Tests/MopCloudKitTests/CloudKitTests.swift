import CryptoKit
import Foundation
import Testing
import MopCore
import MopVault
@testable import MopCloudKit

private struct TestDevice: VaultKeyOpener {
    let key = P256.KeyAgreement.PrivateKey()
    var publicKey: Data { key.publicKey.x963Representation }
    var request: DeviceRequest { try! DeviceRequest(name: "Test Mac", publicKey: publicKey) }
    func unwrap(_ slot: VaultRecipient, vaultID: UUID) throws -> SymmetricKey {
        try VaultDocument.unwrap(slot, vaultID: vaultID, privateKey: key)
    }
}

private actor MemoryCloud: CloudTransport {
    nonisolated let container = "iCloud.test.mop"
    nonisolated let environment = "Development"
    var user = "account-a"
    var accountError: MopError?
    var data: [UUID: [String: CloudObject]] = [:]
    var saves: [String] = []
    var fetches: [String] = []
    var loseResponse = false
    var failHead: MopError?
    var failBlob: MopError?
    var barrier = false
    var waiter: CheckedContinuation<Void, Never>?
    func account() throws -> String { if let accountError { throw accountError }; return user }
    func zones() -> [UUID] { Array(data.keys) }
    func createZone(_ id: UUID) { if data[id] == nil { data[id] = [:] } }
    func fetch(_ id: String, vault: UUID) throws -> CloudObject? {
        fetches.append(id)
        guard let zone = data[vault] else { throw MopError.vaultMissing }
        return zone[id]
    }
    func save(_ id: String, kind: CloudKind, data bytes: Data, vault: UUID, expected: Data?) async throws -> CloudObject {
        if kind == .head && barrier {
            if let waiting = waiter { barrier = false; waiter = nil; waiting.resume() }
            else { await withCheckedContinuation { waiter = $0 } }
        }
        guard let zone = data[vault] else { throw MopError.vaultMissing }
        if kind == .blob, let failBlob { throw failBlob }
        if kind == .head, let failHead { throw failHead }
        guard zone[id]?.version == expected else { throw MopError.vaultConflict }
        let object = CloudObject(data: bytes, version: Data(UUID().uuidString.utf8))
        data[vault]![id] = object
        saves.append(id)
        if kind == .head && loseResponse { loseResponse = false; throw MopError.cloudUnavailable }
        return object
    }
    func requests(vault: UUID) -> [String] { data[vault]?.keys.filter { $0.hasPrefix("q-") } ?? [] }
    func synchronizeHeads() { barrier = true }
    func validateOfflineAccount() throws { if accountError == .cloudAccount { throw MopError.cloudAccount } }
    func setLoss() { loseResponse = true }
    func setAccount(_ value: String) { user = value }
    func setAccountError(_ value: MopError?) { accountError = value }
    func failBlobs(_ error: MopError?) { failBlob = error }
    func failHeads(_ error: MopError?) { failHead = error }
    func replace(_ id: String, vault: UUID, bytes: Data) { data[vault]![id] = CloudObject(data: bytes, version: Data(UUID().uuidString.utf8)) }
    func delete(_ id: String, vault: UUID) { data[vault]!.removeValue(forKey: id) }
    func removeZone(_ id: UUID) { data.removeValue(forKey: id) }
    func resetCounters() { saves = []; fetches = [] }
}

private struct Fixture {
    let directory: URL
    let cloud: MemoryCloud
    let repo: CloudRepository
    let vault: CloudVault
    let device: TestDevice
    let recovery: RecoveryKey
    let initial: Data
    func store() async throws -> CloudSecretStore {
        try CloudSecretStore(vault: vault, snapshot: await vault.sync(), opener: device)
    }
    func cleanup() { try? FileManager.default.removeItem(at: directory) }
}

private func fixture() async throws -> Fixture {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-cloud-test-" + UUID().uuidString)
    let cloud = MemoryCloud()
    let repo = try await CloudRepository.open(transport: cloud, state: directory)
    let device = TestDevice()
    let recovery = RecoveryKey()
    let bytes = try FileSecretStore.createSnapshot(device: device.request, recovery: recovery)
    let doc = try VaultDocument.decode(bytes)
    let key = try device.unwrap(doc.header.recipients.first { $0.publicKey == device.publicKey }!, vaultID: doc.header.vaultID)
    let vault = try await repo.create(bytes, fingerprint: VaultTrust.fingerprint(document: doc, key: key))
    let store = try CloudSecretStore(vault: vault, snapshot: bytes, opener: device)
    store.close()
    return Fixture(directory: directory, cloud: cloud, repo: repo, vault: vault, device: device, recovery: recovery, initial: bytes)
}

@Test func cloudRoundTripAndIncrementalRecords() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let store = try await f.store(); defer { store.close() }
    let a = try SecretReference("mop://personal/github/token")
    let b = try SecretReference("mop://work/database/password")
    try await store.write(a, value: "UNIQUE-SECRET", replace: false)
    try await store.write(b, value: "second", replace: false)
    await f.cloud.resetCounters()
    try await store.write(a, value: "replacement", replace: true)
    let saves = await f.cloud.saves
    #expect(saves.filter { $0.hasPrefix("s-") }.count == 1)
    #expect(saves.filter { $0.hasPrefix("m-") }.count == 1)
    #expect(saves.filter { $0 == "head" }.count == 1)
    #expect(await f.cloud.fetches.filter { $0.hasPrefix("s-") }.count == 1)
    let opened = try await f.store(); defer { opened.close() }
    #expect(try opened.read(a) == "replacement")
    #expect(try opened.read(b) == "second")
    #expect(try VaultDocument.decode(opened.snapshot).header.format == "mop-vault-v3")
    let remote = await f.cloud.data[f.vault.id]!
    for item in remote.values {
        let text = String(decoding: item.data, as: UTF8.self)
        #expect(!text.contains("UNIQUE-SECRET"))
        #expect(!text.contains(a.description))
    }
    let legacy = try FileSecretStore(snapshot: opened.snapshot, trust: f.vault.trust, opener: f.device)
    defer { legacy.close() }
    #expect(try legacy.read(b) == "second")
}

@Test func staleWriterCannotOverwriteOrReenrollRevokedDevice() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let a = try await f.store(); defer { a.close() }
    let b = try await f.store(); defer { b.close() }
    let ref = try SecretReference("mop://v/i/f")
    try await a.write(ref, value: "winner", replace: false)
    await #expect(throws: MopError.vaultConflict) { try await b.write(ref, value: "loser", replace: false) }
    let current = try await f.store(); defer { current.close() }
    #expect(try current.read(ref) == "winner")
    #expect(try await f.vault.revisions().count == 2)
    let second = TestDevice()
    try await current.enroll(second.request, fingerprint: second.request.fingerprint)
    let stale = try CloudSecretStore(vault: f.vault, snapshot: current.snapshot, opener: second)
    defer { stale.close() }
    try await current.revoke(second.request.fingerprint, currentDevice: f.device.publicKey)
    await #expect(throws: MopError.vaultConflict) { try await stale.write(ref, value: "revoked", replace: true) }
    #expect(throws: MopError.deviceNotEnrolled) { try CloudSecretStore(vault: f.vault, snapshot: current.snapshot, opener: second) }
    #expect(try current.read(ref) == "winner")
}

@Test func lostCommitResponseReconcilesWithoutReplay() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let store = try await f.store(); defer { store.close() }
    let ref = try SecretReference("mop://v/i/f")
    await f.cloud.setLoss()
    await #expect(throws: MopError.cloudUncertain) { try await store.write(ref, value: "committed", replace: false) }
    #expect(try f.vault.status()["pendingCommit"] != "none")
    let count = await f.cloud.saves.count
    let bytes = try await f.vault.sync()
    #expect(try f.vault.status()["pendingCommit"] == "none")
    #expect(try f.vault.status()["lastOutcome"] == "committed")
    #expect(await f.cloud.saves.count == count)
    let read = try CloudSecretStore(vault: f.vault, snapshot: bytes, opener: f.device)
    defer { read.close() }
    #expect(try read.read(ref) == "committed")
}

@Test func failedStagingAndUncommittedHeadLeavePreviousSnapshot() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let ref = try SecretReference("mop://v/i/f")
    await f.cloud.failBlobs(.cloudQuota)
    let store = try await f.store(); defer { store.close() }
    await #expect(throws: MopError.cloudQuota) { try await store.write(ref, value: "staged", replace: false) }
    #expect(try f.vault.status()["pendingCommit"] == "none")
    await f.cloud.failBlobs(nil)
    let next = try await f.store(); defer { next.close() }
    await f.cloud.failHeads(.cloudUnavailable)
    await #expect(throws: MopError.cloudUncertain) { try await next.write(ref, value: "uncommitted", replace: false) }
    await f.cloud.failHeads(nil)
    #expect(try await f.vault.sync() == f.initial)
    #expect(try f.vault.status()["lastOutcome"] == "not-committed")
    #expect(try await f.vault.revisions().count == 1)
}

@Test func offlineUsesVerifiedSnapshotAndRejectsWrites() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let store = try await f.store(); defer { store.close() }
    let ref = try SecretReference("mop://v/i/f")
    try await store.write(ref, value: "offline", replace: false)
    let repo = try await CloudRepository.open(transport: f.cloud, state: f.directory, offline: true)
    let vault = try repo.selected(nil)
    let (bytes, _) = try vault.cached()
    let cached = try CloudSecretStore(vault: vault, snapshot: bytes, opener: f.device, offline: true)
    defer { cached.close() }
    #expect(try cached.read(ref) == "offline")
    await #expect(throws: MopError.offlineWrite) { try await cached.delete(ref) }
    await #expect(throws: MopError.offlineWrite) { try await repo.list() }
}

@Test func changedAccountAndSignoutIsolateDefaultsAndInvalidateBinding() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    await f.cloud.setAccount("account-b")
    let other = try await CloudRepository.open(transport: f.cloud, state: f.directory)
    #expect(throws: MopError.vaultMissing) { try other.selected(nil) }
    await #expect(throws: MopError.cloudAccount) { try await f.vault.sync() }
    await f.cloud.setAccountError(.cloudAccount)
    await #expect(throws: MopError.cloudAccount) { try await CloudRepository.open(transport: f.cloud, state: f.directory) }
    await #expect(throws: MopError.cloudAccount) { try await CloudRepository.open(transport: f.cloud, state: f.directory, offline: true) }
}

@Test func rollbackAndTamperingNeverReplaceVerifiedCache() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let initialHead = try await f.cloud.fetch("head", vault: f.vault.id)!
    let store = try await f.store(); defer { store.close() }
    try await store.write(SecretReference("mop://v/i/f"), value: "safe", replace: false)
    let last = store.snapshot
    await f.cloud.replace("head", vault: f.vault.id, bytes: initialHead.data)
    await #expect(throws: MopError.vaultUntrusted) { try await f.vault.sync() }
    #expect(try f.vault.cached().0 == last)
    let head = try VaultCoding.encode(CloudHead(revision: VaultCoding.digest(last), root: VaultCoding.digest(f.initial)))
    await f.cloud.replace("head", vault: f.vault.id, bytes: head)
    await f.cloud.replace("m-" + VaultCoding.digest(last), vault: f.vault.id, bytes: Data("bad".utf8))
    await #expect(throws: MopError.invalidVault) { try await f.vault.sync() }
    #expect(try f.vault.cached().0 == last)
}

@Test func cloudRequestsRecoveryAndHistoryKeepCurrentAuthorization() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let second = TestDevice()
    let requestID = try await f.repo.request(second.request, vault: f.vault)
    #expect(try await f.repo.request(requestID, vault: f.vault) == second.request)
    let store = try await f.store(); defer { store.close() }
    let ref = try SecretReference("mop://v/i/f")
    try await store.write(ref, value: "old", replace: false)
    let revision = VaultCoding.digest(store.snapshot)
    try await store.enroll(second.request, fingerprint: second.request.fingerprint)
    try await store.write(ref, value: "new", replace: true)
    try await store.revoke(second.request.fingerprint, currentDevice: f.device.publicKey)
    try await store.restore(revision)
    #expect(try store.read(ref) == "old")
    #expect(try !store.recipients().contains { $0.publicKey == second.publicKey })
    let recovered = try CloudSecretStore(vault: f.vault, snapshot: store.snapshot, opener: f.recovery)
    defer { recovered.close() }
    try await recovered.enroll(second.request, fingerprint: second.request.fingerprint)
    #expect(try recovered.read(ref) == "old")
}

@Test func liveWriterCannotBeReconciledAndDeletedZoneStaysDeleted() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let lease = try WriterLease(directory: f.vault.cache.directory)
    await #expect(throws: MopError.cloudUncertain) { try await f.vault.sync() }
    lease.close()
    await f.cloud.removeZone(f.vault.id)
    await #expect(throws: MopError.vaultMissing) { try await f.vault.sync() }
    #expect(await f.cloud.zones().isEmpty)
}

@Test func asynchronousExpansionNeedsNoCloudForLiteralInputs() async throws {
    let service = AsyncSecretService { throw MopError.cloudUnavailable }
    #expect(try await service.inject("hello ${USER}", variables: [:]) == "hello ${USER}")
    #expect(try await service.environment(inherited: ["A": "literal"], files: []) == ["A": "literal"])
}

private func attemptCommit(cloud: MemoryCloud, directory: URL, id: UUID, expected: Data, replacement: Data) async -> MopError? {
    do {
        let vault = CloudVault(id: id, cache: try CloudCache(directory: directory), transport: cloud, accountID: "account-a")
        try await vault.commit(expected: expected, replacement: replacement)
        return nil
    } catch { return (error as? MopError) ?? .inputOutput }
}

@Test func simultaneousHeadSavesHaveExactlyOneWinner() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let a = try VaultSession(snapshot: f.initial, trust: f.vault.trust, opener: f.device)
    let b = try VaultSession(snapshot: f.initial, trust: f.vault.trust, opener: f.device)
    defer { a.close(); b.close() }
    try a.write(SecretReference("mop://v/i/a"), value: "a", replace: false)
    try b.write(SecretReference("mop://v/i/b"), value: "b", replace: false)
    await f.cloud.synchronizeHeads()
    let first = a.snapshot, second = b.snapshot
    let cloud = f.cloud, directory = f.directory, id = f.vault.id, initial = f.initial
    async let one = attemptCommit(cloud: cloud, directory: directory.appendingPathComponent("a"), id: id, expected: initial, replacement: first)
    async let two = attemptCommit(cloud: cloud, directory: directory.appendingPathComponent("b"), id: id, expected: initial, replacement: second)
    let results = await [one, two]
    #expect(results.filter { $0 == nil }.count == 1)
    #expect(results.filter { $0 == .vaultConflict }.count == 1)
    let bytes = try await f.vault.sync()
    #expect(bytes == first || bytes == second)
    #expect(try await f.vault.revisions().count == 2)
}

@Test func interruptedRotationCanFinishTrustWithoutCloudTrustEvidence() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let second = TestDevice()
    let store = try await f.store(); defer { store.close() }
    let ref = try SecretReference("mop://v/i/f")
    try await store.write(ref, value: "retained", replace: false)
    try await store.enroll(second.request, fingerprint: second.request.fingerprint)
    await f.cloud.setLoss()
    await #expect(throws: MopError.cloudUncertain) { try await store.revoke(second.request.fingerprint, currentDevice: f.device.publicKey) }
    let next = try await f.store(); defer { next.close() }
    #expect(try next.read(ref) == "retained")
    #expect(try next.recipients().count == 1)
    #expect(try f.vault.status()["pendingCommit"] == "none")
}

@Test func incompleteFetchAndSameGenerationSubstitutionFailClosed() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let store = try await f.store(); defer { store.close() }
    let ref = try SecretReference("mop://v/i/f")
    try await store.write(ref, value: "value", replace: false)
    let good = store.snapshot
    let doc = try VaultDocument.decode(good)
    let hash = try VaultCoding.digest(VaultCoding.encode(doc.records.values.first!))
    // A new cache has no reusable blobs; a missing server record must not become a snapshot.
    let other = CloudVault(id: f.vault.id, cache: try CloudCache(directory: f.directory.appendingPathComponent("empty")), transport: f.cloud, accountID: "account-a")
    await f.cloud.delete("s-" + hash, vault: f.vault.id)
    await #expect(throws: MopError.invalidVault) { try await other.sync() }
    #expect(throws: MopError.vaultMissing) { try other.cached() }
    // Even a correctly encrypted alternate document at the same generation is rejected.
    var alternate = doc
    alternate.header.parent = String(repeating: "0", count: 64)
    #expect(throws: MopError.vaultUntrusted) { try f.vault.verified(VaultCoding.encode(alternate)) }
    #expect(try f.vault.cached().0 == good)
}

@Test func multipleVaultDefaultsImportAndRecoveryPreserveIdentity() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let second = TestDevice()
    let bytes = try VaultSession.createSnapshot(device: second.request, recovery: f.recovery)
    let doc = try VaultDocument.decode(bytes)
    let key = try second.unwrap(doc.header.recipients.first { $0.publicKey == second.publicKey }!, vaultID: doc.header.vaultID)
    let fingerprint = VaultTrust.fingerprint(document: doc, key: key)
    let vault = try await f.repo.create(bytes, fingerprint: fingerprint)
    #expect(try f.repo.selected(nil).id == f.vault.id)
    try f.repo.use(vault.id)
    #expect(try f.repo.selected(nil).id == vault.id)
    #expect(try f.repo.selected(f.vault.id.uuidString).id == f.vault.id)
    await #expect(throws: MopError.duplicate) { _ = try await f.repo.create(bytes, fingerprint: fingerprint) }
    // Import an exported snapshot into a different simulated account/server.
    let cloud = MemoryCloud()
    let repo = try await CloudRepository.open(transport: cloud, state: f.directory.appendingPathComponent("restored"))
    let imported = try await repo.create(bytes, fingerprint: fingerprint)
    let recovery = try CloudSecretStore(vault: imported, snapshot: bytes, opener: f.recovery)
    defer { recovery.close() }
    #expect(imported.id == doc.header.vaultID)
    let replacement = TestDevice()
    try await recovery.enroll(replacement.request, fingerprint: replacement.request.fingerprint)
    #expect(try recovery.recipients().contains { $0.publicKey == replacement.publicKey })
}

@Test func definiteHeadRejectionReportsQuotaWithoutUncertainJournal() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let store = try await f.store(); defer { store.close() }
    await f.cloud.failHeads(.cloudQuota)
    await #expect(throws: MopError.cloudQuota) { try await store.write(SecretReference("mop://v/i/f"), value: "no", replace: false) }
    #expect(try f.vault.status()["pendingCommit"] == "none")
    #expect(try f.vault.cached().0 == f.initial)
}

@Test func uncertainInitializationWithNoHeadCanBeExplicitlyRetried() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-init-test-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let cloud = MemoryCloud()
    let repo = try await CloudRepository.open(transport: cloud, state: directory)
    let device = TestDevice()
    let bytes = try VaultSession.createSnapshot(device: device.request, recovery: RecoveryKey())
    let doc = try VaultDocument.decode(bytes)
    let slot = doc.header.recipients.first { $0.publicKey == device.publicKey }!
    let fingerprint = try VaultTrust.fingerprint(document: doc, key: device.unwrap(slot, vaultID: doc.header.vaultID))
    await cloud.failHeads(.cloudUnavailable)
    await #expect(throws: MopError.cloudUncertain) { _ = try await repo.create(bytes, fingerprint: fingerprint) }
    let vault = try repo.vault(doc.header.vaultID)
    await cloud.failHeads(nil)
    await #expect(throws: MopError.vaultMissing) { try await vault.sync() }
    #expect(try vault.status()["lastOutcome"] == "head-missing")
    #expect(try vault.status()["pendingCommit"] == "none")
    _ = try await repo.create(bytes, fingerprint: fingerprint)
    let store = try CloudSecretStore(vault: vault, snapshot: bytes, opener: device)
    defer { store.close() }
    #expect(try store.fingerprint() == fingerprint)
}

@Test func delayedRotationCompletionCannotRollBackLocalTrust() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let second = TestDevice(), third = TestDevice()
    let setup = try await f.store(); defer { setup.close() }
    try await setup.enroll(second.request, fingerprint: second.request.fingerprint)
    try await setup.enroll(third.request, fingerprint: third.request.fingerprint)
    let before = setup.snapshot
    let delayed = try VaultSession(snapshot: before, trust: f.vault.trust, opener: f.device)
    defer { delayed.close() }
    try delayed.revoke(second.request.fingerprint, currentDevice: f.device.publicKey)
    try await f.vault.commit(expected: before, replacement: delayed.snapshot, rotationFingerprint: delayed.fingerprint())
    // Another process completes the pending trust and publishes a further rotation.
    let newer = try await f.store(); defer { newer.close() }
    try await newer.revoke(third.request.fingerprint, currentDevice: f.device.publicKey)
    let fingerprint = try newer.fingerprint()
    #expect(throws: MopError.vaultUntrusted) { try f.vault.finishCommittedSession(delayed, rotation: true) }
    let reopened = try await f.store(); defer { reopened.close() }
    #expect(try reopened.fingerprint() == fingerprint)
}

@Test func rejectedDownloadsLeaveNoPersistentBlobsOrSnapshotChanges() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let parts = try JSONSerialization.jsonObject(with: f.initial) as! [String: Any]
    let digest = String(repeating: "0", count: 64)
    for attempt in 0..<3 {
        let invalid = Data(repeating: UInt8(65 + attempt), count: 65_536)
        let hash = VaultCoding.digest(invalid)
        let manifest: [String: Any] = ["format": "mop-cloud-manifest-v1", "header": parts["header"]!,
            "sealed": parts["sealed"]!, "records": [UUID().uuidString: hash]]
        await f.cloud.replace("head", vault: f.vault.id,
            bytes: try VaultCoding.encode(CloudHead(revision: digest, root: digest)))
        await f.cloud.replace("m-" + digest, vault: f.vault.id,
            bytes: try JSONSerialization.data(withJSONObject: manifest))
        await f.cloud.replace("s-" + hash, vault: f.vault.id, bytes: invalid)
        await #expect(throws: MopError.invalidVault) { try await f.vault.sync() }
        #expect(try f.vault.cached().0 == f.initial)
        #expect(try f.vault.status()["downloadedRevision"] == VaultCoding.digest(f.initial))
        #expect(try FileManager.default.contentsOfDirectory(atPath: f.vault.cache.directory.path)
            .filter { $0.hasSuffix(".blob") }.isEmpty)
    }
}

@Test func snapshotReuseBoundsRetentionWithoutPromotingUnverifiedDownloads() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let session = try VaultSession(snapshot: f.initial, trust: f.vault.trust, opener: f.device)
    defer { session.close() }
    let ref = try SecretReference("mop://fixture/item/token")
    let originalFiles = try FileManager.default.contentsOfDirectory(atPath: f.vault.cache.directory.path).sorted()
    for attempt in 0..<8 {
        let before = session.snapshot
        try session.write(ref, value: String(repeating: "x", count: 4096) + String(attempt), replace: attempt > 0)
        try await f.vault.commit(expected: before, replacement: session.snapshot)
        await f.cloud.resetCounters()
        #expect(try await f.vault.sync() == session.snapshot)
        #expect(await f.cloud.fetches.filter { $0.hasPrefix("s-") }.isEmpty)
        #expect(try f.vault.cached().0 == f.initial)
        #expect(try FileManager.default.contentsOfDirectory(atPath: f.vault.cache.directory.path).sorted() == originalFiles)
    }
}

@Test func legacyBlobCleanupPreservesOfflineSnapshotAndCommitJournal() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let payload = Data("obsolete rejected download".utf8)
    let file = f.vault.cache.directory.appendingPathComponent(VaultCoding.digest(payload) + ".blob")
    try SafeFile.write(payload, to: file)
    let journal = CommitJournal(expected: VaultCoding.digest(f.initial), proposed: String(repeating: "1", count: 64),
        root: VaultCoding.digest(f.initial), rotationFingerprint: nil)
    try f.vault.cache.locked { try f.vault.cache.write(journal, "journal.json") }
    let reopened = try CloudCache(directory: f.vault.cache.directory)
    #expect(!FileManager.default.fileExists(atPath: file.path))
    #expect(try f.vault.cached().0 == f.initial)
    #expect(try reopened.locked { try reopened.read("journal.json", as: CommitJournal.self)?.proposed } == journal.proposed)
}

@Test func validRecordsInARejectedRevisionDoNotLeaveCacheFiles() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let store = try await f.store(); defer { store.close() }
    try await store.write(SecretReference("mop://fixture/item/token"), value: "fixture-value", replace: false)
    let doc = try VaultDocument.decode(store.snapshot)
    let wrongDigest = String(repeating: "a", count: 64)
    await f.cloud.replace("m-" + wrongDigest, vault: f.vault.id, bytes: try VaultCoding.encode(CloudManifest(document: doc)))
    await f.cloud.replace("head", vault: f.vault.id,
        bytes: try VaultCoding.encode(CloudHead(revision: wrongDigest, root: wrongDigest)))
    let cache = try CloudCache(directory: f.directory.appendingPathComponent("fresh"))
    let vault = CloudVault(id: f.vault.id, cache: cache, transport: f.cloud, accountID: "account-a")
    await #expect(throws: MopError.invalidVault) { try await vault.sync() }
    #expect(try FileManager.default.contentsOfDirectory(atPath: cache.directory.path).sorted() == ["lock", "writer.lock"])
    #expect(throws: MopError.vaultMissing) { try vault.cached() }
}
