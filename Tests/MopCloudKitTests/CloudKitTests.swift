import CloudKit
import CryptoKit
import Foundation
import Testing
import MopCore
import MopKeychain
import MopVault
@testable import MopCloudKit

private struct TestDevice: VaultSigningOpener {
    let identity = AccountIdentity()
    var publicKey: Data { identity.publicKey }
    var signingPublicKey: Data { identity.signingPublicKey }
    var request: RecipientKey { identity.request }
    func sign(_ data: Data) throws -> Data { try identity.sign(data) }
    func unwrap(_ recipient: VaultRecipient, vaultID: UUID) throws -> SymmetricKey {
        try identity.unwrap(recipient, vaultID: vaultID)
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
    var loseIdentityResponse = false
    var identityWinner: Data?
    var failHead: MopError?
    var failBlob: MopError?
    var barrier = false
    var waiter: CheckedContinuation<Void, Never>?
    func account() throws -> String { if let accountError { throw accountError }; return user }
    var zonesError: MopError?
    var readbackError: MopError?
    func zones() throws -> [UUID] { if let zonesError { throw zonesError }; return Array(data.keys) }
    func setReadbackError(_ error: MopError?) { readbackError = error; zonesError = nil }
    func deleteZone(_ id: UUID) throws {
        if let deleteError, !deleteDespiteError { throw deleteError }
        data.removeValue(forKey: id); deletions.append(id); zonesError = readbackError
        if let deleteError { throw deleteError }
    }
    var deleteError: MopError?
    var deleteDespiteError = false
    var deletions: [UUID] = []
    func configureDeletion(_ error: MopError?, despiteError: Bool = false) { deleteError = error; deleteDespiteError = despiteError }
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
        if id == "account-identity-v1", let identityWinner {
            self.identityWinner = nil
            data[vault]![id] = CloudObject(data: identityWinner, version: Data("winner".utf8))
            throw MopError.vaultConflict
        }
        guard zone[id]?.version == expected else { throw MopError.vaultConflict }
        let object = CloudObject(data: bytes, version: Data(UUID().uuidString.utf8))
        data[vault]![id] = object
        saves.append(id)
        if id == "account-identity-v1", loseIdentityResponse { loseIdentityResponse = false; throw MopError.cloudUnavailable }
        if kind == .head && loseResponse { loseResponse = false; throw MopError.cloudUnavailable }
        return object
    }
    func requests(vault: UUID) -> [String] { data[vault]?.keys.filter { $0.hasPrefix("q-") } ?? [] }
    func synchronizeHeads() { barrier = true }
    func validateOfflineAccount() throws { if accountError == .cloudAccount { throw MopError.cloudAccount } }
    func setIdentityLoss() { loseIdentityResponse = true }
    func raceIdentity(_ bytes: Data) { identityWinner = bytes }
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
    let bytes = try VaultSession.createAccountSnapshot(name: "v", owner: device.identity, recovery: recovery)
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
    let a = try SecretReference("secondpass://v/github/token")
    let b = try SecretReference("secondpass://v/database/password")
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
    #expect(try VaultDocument.decode(opened.snapshot).header.format == "mop-vault-v5")
    let remote = await f.cloud.data[f.vault.id]!
    for item in remote.values {
        let text = String(decoding: item.data, as: UTF8.self)
        #expect(!text.contains("UNIQUE-SECRET"))
        #expect(!text.contains(a.description))
    }
    let legacy = try VaultSession(snapshot: opened.snapshot, trust: f.vault.trust, opener: f.device)
    defer { legacy.close() }
    #expect(try legacy.read(b) == "second")
}

@Test func lostCommitResponseReconcilesWithoutReplay() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let store = try await f.store(); defer { store.close() }
    let ref = try SecretReference("secondpass://v/i/f")
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
    let ref = try SecretReference("secondpass://v/i/f")
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
    let ref = try SecretReference("secondpass://v/i/f")
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
    try await store.write(SecretReference("secondpass://v/i/f"), value: "safe", replace: false)
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

@Test func liveWriterCannotBeReconciledAndDeletedZoneStaysDeleted() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let lease = try WriterLease(directory: f.vault.cache.directory)
    await #expect(throws: MopError.cloudUncertain) { try await f.vault.sync() }
    lease.close()
    await f.cloud.removeZone(f.vault.id)
    await #expect(throws: MopError.vaultMissing) { try await f.vault.sync() }
    #expect(try await f.cloud.zones().isEmpty)
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
    try a.write(SecretReference("secondpass://v/i/a"), value: "a", replace: false)
    try b.write(SecretReference("secondpass://v/i/b"), value: "b", replace: false)
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

@Test func incompleteFetchAndSameGenerationSubstitutionFailClosed() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let store = try await f.store(); defer { store.close() }
    let ref = try SecretReference("secondpass://v/i/f")
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
    #expect(throws: MopError.invalidVault) { try f.vault.verified(VaultCoding.encode(alternate)) }
    #expect(try f.vault.cached().0 == good)
}

@Test func multipleVaultDefaultsImportAndRecoveryPreserveIdentity() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let second = TestDevice()
    let bytes = try VaultSession.createAccountSnapshot(name: "second", owner: second.identity, recovery: f.recovery)
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
    try await recovery.adoptOwner(replacement.identity)
    #expect(recovery.membership?.owner == replacement.identity.identity)
}

@Test func definiteHeadRejectionReportsQuotaWithoutUncertainJournal() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let store = try await f.store(); defer { store.close() }
    await f.cloud.failHeads(.cloudQuota)
    await #expect(throws: MopError.cloudQuota) { try await store.write(SecretReference("secondpass://v/i/f"), value: "no", replace: false) }
    #expect(try f.vault.status()["pendingCommit"] == "none")
    #expect(try f.vault.cached().0 == f.initial)
}

@Test func uncertainInitializationWithNoHeadCanBeExplicitlyRetried() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-init-test-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let cloud = MemoryCloud()
    let repo = try await CloudRepository.open(transport: cloud, state: directory)
    let device = TestDevice()
    let bytes = try VaultSession.createAccountSnapshot(name: "v", owner: device.identity, recovery: RecoveryKey())
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

@Test func rejectedDownloadsLeaveNoPersistentBlobsOrSnapshotChanges() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let parts = try JSONSerialization.jsonObject(with: f.initial) as! [String: Any]
    let digest = String(repeating: "0", count: 64)
    for attempt in 0..<3 {
        let invalid = Data(repeating: UInt8(65 + attempt), count: 65_536)
        let hash = VaultCoding.digest(invalid)
        let manifest: [String: Any] = ["format": "mop-cloud-manifest-v2", "header": parts["header"]!,
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
    let ref = try SecretReference("secondpass://v/item/token")
    let originalFiles = try FileManager.default.contentsOfDirectory(atPath: f.vault.cache.directory.path).sorted()
    for attempt in 0..<8 {
        let before = session.snapshot
        try session.write(ref, value: SecretBytes(utf8: String(repeating: "x", count: 4096) + String(attempt)), replace: attempt > 0)
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
    try await store.write(SecretReference("secondpass://v/item/token"), value: "fixture-value", replace: false)
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

private func addVault(_ f: Fixture, name: String) async throws -> CloudVault {
    let bytes = try VaultSession.createAccountSnapshot(name: name, owner: f.device.identity, recovery: f.recovery)
    let doc = try VaultDocument.decode(bytes)
    let key = try f.device.unwrap(doc.header.recipients.first { $0.publicKey == f.device.publicKey }!, vaultID: doc.header.vaultID)
    let vault = try await f.repo.create(bytes, fingerprint: VaultTrust.fingerprint(document: doc, key: key))
    let store = try CloudSecretStore(vault: vault, snapshot: bytes, opener: f.device)
    store.close()
    return vault
}

@Test func namesDiscoverRenameAndResolveAcrossVerifiedOfflineSnapshots() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let initial = try await f.repo.descriptors(identity: f.device.identity.identity)
    #expect(initial == [VaultDescriptor(id: f.vault.id.uuidString, name: "v", format: "mop-vault-v5", enrolled: true)])
    #expect(try await f.repo.named("v").id == f.vault.id)
    await #expect(throws: MopError.duplicate) { try await f.repo.ensureAvailable("v") }
    let store = try await f.store(); defer { store.close() }
    try await store.write(SecretReference("secondpass://v/mycloud/sshd"), value: "secret", replace: false)
    let before = try VaultDocument.decode(store.snapshot)
    let offline = try await CloudRepository.open(transport: f.cloud, state: f.directory, offline: true)
    await f.cloud.resetCounters()
    #expect(try await offline.named("v").id == f.vault.id)
    #expect(await f.cloud.fetches.isEmpty)
    try await store.rename("personal")
    let after = try VaultDocument.decode(store.snapshot)
    #expect(before.records == after.records)
    #expect(try await f.repo.named("personal").id == f.vault.id)
    await #expect(throws: MopError.vaultMissing) { _ = try await f.repo.named("v") }
    #expect(try await offline.named("personal").id == f.vault.id)
    let cached = try CloudSecretStore(vault: f.vault, snapshot: f.vault.cached().0, opener: f.device, offline: true)
    defer { cached.close() }
    await #expect(throws: MopError.offlineWrite) { try await cached.rename("other") }
}

@Test func multiVaultRoutingIgnoresDefaultAndClosesSessionsAfterFailures() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let second = try await addVault(f, name: "personal")
    let one = try await f.store()
    try await one.write(SecretReference("secondpass://v/item/token"), value: "first", replace: false); one.close()
    let two = try CloudSecretStore(vault: second, snapshot: await second.sync(), opener: f.device)
    try await two.write(SecretReference("secondpass://personal/item/token"), value: "second", replace: false); two.close()
    try f.repo.use(second.id)
    let rows = try await f.repo.descriptors(identity: f.device.identity.identity)
    var opens = 0, closes = 0
    func router(_ selection: String? = nil) -> RoutedSecretStore {
        RoutedSecretStore(repository: f.repo, rows: rows, selection: selection) { row in
            opens += 1
            let vault = try f.repo.vault(UUID(uuidString: row.id)!)
            return try CloudSecretStore(vault: vault, snapshot: await vault.sync(), opener: f.device, onClose: { closes += 1 })
        }
    }
    let service = AsyncSecretService { router() }
    #expect(try await service.inject("{{secondpass://v/item/token}} {{secondpass://personal/item/token}} {{secondpass://v/item/token}}") == "first second first")
    #expect(opens == 2 && closes == 2)
    #expect(try await service.list(vault: nil).map(\.vault) == ["personal", "v"])
    #expect(opens == 4 && closes == 4)
    await #expect(throws: MopError.notFound) { try await service.inject("{{secondpass://v/item/token}}{{secondpass://personal/item/missing}}") }
    #expect(opens == 6 && closes == 6)
    let constrained = AsyncSecretService { router(second.id.uuidString) }
    await #expect(throws: MopError.vaultSelectionMismatch) { try await constrained.read(SecretReference("secondpass://v/item/token")) }
    #expect(opens == 6)
    await #expect(throws: MopError.vaultMissing) { try await service.read(SecretReference("secondpass://unknown/item/token")) }
    #expect(opens == 6)
}

@Test func concurrentDuplicateNamesRequireUUIDAndTamperedNamesCannotRouteSecrets() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let other = try await addVault(f, name: "other")
    await #expect(throws: MopError.duplicate) { try await f.repo.ensureAvailable("v", excluding: other.id) }
    // Simulate two clients passing availability checks before either commits.
    let store = try CloudSecretStore(vault: other, snapshot: await other.sync(), opener: f.device)
    try await store.rename("v"); store.close()
    await #expect(throws: MopError.ambiguousVault) { _ = try await f.repo.named("v") }
    #expect(try await f.repo.named(other.id.uuidString).id == other.id)
    let repair = try CloudSecretStore(vault: other, snapshot: await other.sync(), opener: f.device)
    try await repair.rename("other"); repair.close()
    let original = try await f.vault.sync()
    var tampered = try VaultDocument.decode(original)
    tampered.header.name = "forged"
    let replacement = try VaultCoding.encode(tampered)
    let digest = VaultCoding.digest(replacement)
    await f.cloud.replace("m-" + digest, vault: f.vault.id, bytes: try VaultCoding.encode(CloudManifest(document: tampered)))
    await f.cloud.replace("head", vault: f.vault.id, bytes: try VaultCoding.encode(CloudHead(revision: digest, root: digest)))
    let rows = try await f.repo.descriptors(identity: f.device.identity.identity)
    #expect(rows.contains { $0.name == "forged" }) // discovery is explicitly unverified
    let service = AsyncSecretService {
        RoutedSecretStore(repository: f.repo, rows: rows, selection: nil) { row in
            let vault = try f.repo.vault(UUID(uuidString: row.id)!)
            return try CloudSecretStore(vault: vault, snapshot: await vault.sync(), opener: f.device)
        }
    }
    await #expect(throws: (any Error).self) { try await service.read(SecretReference("secondpass://forged/item/token")) }
    #expect(try f.vault.cached().0 == original)
}

@Test func legacyDiscoveryDoesNotModifyRemoteData() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    var metadata = try JSONSerialization.jsonObject(with: VaultCoding.encode(CloudManifest(document: VaultDocument.decode(f.initial)))) as! [String: Any]
    var header = metadata["header"] as! [String: Any]
    header["format"] = "mop-vault-v3"; header.removeValue(forKey: "name")
    metadata["header"] = header; metadata["format"] = "mop-cloud-manifest-v1"
    await f.cloud.replace("m-" + VaultCoding.digest(f.initial), vault: f.vault.id, bytes: try JSONSerialization.data(withJSONObject: metadata))
    await f.cloud.resetCounters()
    let rows = try await f.repo.descriptors(identity: f.device.identity.identity)
    #expect(rows.count == 1 && !rows[0].supported && rows[0].name == nil)
    await #expect(throws: MopError.legacyVault) { _ = try await f.repo.named(f.vault.id.uuidString) }
    #expect(await f.cloud.saves.isEmpty)
}

@Test func offlineNamesRemainAtLastAuthenticatedRevisionOnAnotherMac() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let secondState = f.directory.appendingPathComponent("second-mac")
    let secondRepo = try await CloudRepository.open(transport: f.cloud, state: secondState)
    let secondVault = try secondRepo.vault(f.vault.id)
    let bytes = try await secondVault.sync()
    try secondVault.establishTrust(bytes, opener: f.device, fingerprint: nil, revision: VaultCoding.digest(bytes))
    let secondSession = try CloudSecretStore(vault: secondVault, snapshot: bytes, opener: f.device)
    secondSession.close()
    let first = try await f.store(); defer { first.close() }
    try await first.rename("renamed")
    let offline = try await CloudRepository.open(transport: f.cloud, state: secondState, offline: true)
    #expect(try await offline.named("v").id == f.vault.id)
    await #expect(throws: MopError.vaultMissing) { _ = try await offline.named("renamed") }
    #expect(try await secondRepo.named("renamed").id == f.vault.id)
    // Downloading new metadata must not promote the offline name.
    _ = try await secondVault.sync()
    #expect(try await offline.named("v").id == f.vault.id)
    let refreshed = try CloudSecretStore(vault: secondVault, snapshot: await secondVault.sync(), opener: f.device)
    refreshed.close()
    #expect(try await offline.named("renamed").id == f.vault.id)
}

@Test func listingSkipsUnenrolledAndFailsRatherThanReturningPartialResults() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    _ = try await addVault(f, name: "other")
    let rows = try await f.repo.descriptors(identity: f.device.identity.identity)
    var diagnostics: [String] = []
    let excluded = rows.map { VaultDescriptor(id: $0.id, name: $0.name, format: $0.format, enrolled: $0.name == "v") }
    let service = AsyncSecretService {
        RoutedSecretStore(repository: f.repo, rows: excluded, selection: nil, diagnostic: { diagnostics.append($0) }) { row in
            #expect(row.name == "v")
            return try await f.store()
        }
    }
    #expect(try await service.list(vault: nil).isEmpty)
    #expect(diagnostics.count == 1 && diagnostics[0].contains("not owned by this account"))
    let failing = AsyncSecretService {
        RoutedSecretStore(repository: f.repo, rows: rows, selection: nil) { row in
            if row.name == "v" { throw MopError.authentication }
            let vault = try f.repo.vault(UUID(uuidString: row.id)!)
            return try CloudSecretStore(vault: vault, snapshot: await vault.sync(), opener: f.device)
        }
    }
    await #expect(throws: MopError.authentication) { try await failing.list(vault: nil) }
}

@Test func deletePurgesOnlyTargetAndPreventsOfflineResurrection() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let other = try await addVault(f, name: "other")
    let otherSnapshot = try other.cached().0
    let store = try await f.store(); defer { store.close() }
    let live = store.snapshot
    let target = try await f.repo.deletionTarget("v")
    #expect(target.id == f.vault.id.uuidString)
    try await f.repo.delete(f.vault.id)
    #expect(try await f.cloud.zones() == [other.id])
    #expect(try other.cached().0 == otherSnapshot)
    #expect(throws: MopError.vaultMissing) { try f.repo.selected(nil) }
    #expect(throws: MopError.vaultMissing) { try f.vault.cached() }
    #expect(throws: MopError.vaultMissing) { try f.vault.verified(live) }
    #expect(try FileManager.default.contentsOfDirectory(atPath: f.vault.cache.directory.path).sorted() == ["deleted.json", "lock", "writer.lock"])
    await #expect(throws: MopError.vaultMissing) {
        try await store.write(SecretReference("secondpass://v/item/field"), value: "late", replace: false)
    }
    #expect(try other.cached().0 == otherSnapshot)
}

@Test func deletionPreservesUnrelatedDefaultAndAllowsExplicitBackupImport() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let other = try await addVault(f, name: "other")
    try f.repo.use(other.id)
    let before = try await f.store()
    let fingerprint = try before.fingerprint(); before.close()
    try await f.repo.delete(f.vault.id)
    #expect(try f.repo.selected(nil).id == other.id)
    let restored = try await f.repo.create(f.initial, fingerprint: fingerprint)
    let store = try CloudSecretStore(vault: restored, snapshot: f.initial, opener: f.device)
    defer { store.close() }
    #expect(try restored.cached().0 == f.initial)
}

@Test func legacyDeletionByUUIDNeedsNoDecryptableManifest() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    await f.cloud.replace("m-" + VaultCoding.digest(f.initial), vault: f.vault.id, bytes: Data("legacy-unreadable".utf8))
    let target = try await f.repo.deletionTarget(f.vault.id.uuidString)
    #expect(target.id == f.vault.id.uuidString && target.name == nil)
    try await f.repo.delete(f.vault.id)
    #expect(try await f.cloud.zones().isEmpty)
    // Retrying the same UUID finishes cleanup even after the remote zone is gone.
    let retry = try await f.repo.deletionTarget(f.vault.id.uuidString)
    #expect(retry.id == target.id)
    try await f.repo.delete(f.vault.id)
}

@Test func deletionLostResponseChecksRemoteBeforeCleaningCache() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    await f.cloud.configureDeletion(.cloudUnavailable, despiteError: true)
    try await f.repo.delete(f.vault.id)
    #expect(await f.cloud.deletions == [f.vault.id])
    #expect(throws: MopError.vaultMissing) { try f.vault.cached() }
}

@Test func uncertainOrDeniedDeletionPreservesCacheAndDefault() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    await f.cloud.configureDeletion(.cloudUnavailable)
    await #expect(throws: MopError.vaultDeleteUncertain) { try await f.repo.delete(f.vault.id) }
    #expect(try f.vault.cached().0 == f.initial)
    #expect(try f.repo.selected(nil).id == f.vault.id)
    await f.cloud.configureDeletion(.cloudPermission)
    await #expect(throws: MopError.cloudPermission) { try await f.repo.delete(f.vault.id) }
    #expect(try f.vault.cached().0 == f.initial)
    await f.cloud.configureDeletion(nil)
    await f.cloud.setReadbackError(.cloudUnavailable)
    await #expect(throws: MopError.vaultDeleteUncertain) { try await f.repo.delete(f.vault.id) }
    #expect(try f.vault.cached().0 == f.initial)
    #expect(try f.repo.selected(nil).id == f.vault.id)
    await f.cloud.setReadbackError(nil)
    try await f.repo.delete(f.vault.id)
    #expect(throws: MopError.vaultMissing) { try f.vault.cached() }
}

@Test func deletionRejectsOfflineAccountChangeAndActiveWriter() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let offline = try await CloudRepository.open(transport: f.cloud, state: f.directory, offline: true)
    await #expect(throws: MopError.offlineWrite) { try await offline.delete(f.vault.id) }
    await f.cloud.setAccount("other")
    await #expect(throws: MopError.cloudAccount) { try await f.repo.delete(f.vault.id) }
    await f.cloud.setAccount("account-a")
    let lease = try WriterLease(directory: f.vault.cache.directory)
    defer { lease.close() }
    await #expect(throws: MopError.cloudUncertain) { try await f.repo.delete(f.vault.id) }
    #expect(await f.cloud.deletions.isEmpty)
    #expect(try f.vault.cached().0 == f.initial)
}

@Test func deletionCleanupFailureCanBeRetriedBySameUUID() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    try f.repo.scope.locked { try f.repo.scope.write(123, "default.json") }
    await #expect(throws: MopError.vaultDeleteCleanup) { try await f.repo.delete(f.vault.id) }
    #expect(try await f.cloud.zones().isEmpty)
    #expect(throws: MopError.vaultMissing) { try f.vault.cached() }
    try f.repo.scope.locked { try f.repo.scope.remove("default.json") }
    try await f.repo.delete(f.vault.id)
}

@Test func deletionKeepsResolvedUUIDWhenNameIsReassigned() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let target = try await f.repo.deletionTarget("v")
    let store = try await f.store(); defer { store.close() }
    try await store.rename("renamed")
    let replacement = try await addVault(f, name: "v")
    try await f.repo.delete(UUID(uuidString: target.id)!)
    #expect(try await f.cloud.zones() == [replacement.id])
    #expect(try await f.repo.named("v").id == replacement.id)
}


@Test func invalidCloudRequestIsNotReportedAsOffline() {
    let error = CKError(.invalidArguments, userInfo: [NSLocalizedDescriptionKey: "PRIVATE SERVER DETAIL"])
    #expect(AppleCloudTransport.map(error) == .cloudInvalidRequest)
    #expect(AppleCloudTransport.map(CKError(.networkFailure)) == .cloudUnavailable)
    #expect(!(MopError.cloudInvalidRequest.errorDescription ?? "").contains("PRIVATE"))
    let partial = CKError(.partialFailure, userInfo: [CKPartialErrorsByItemIDKey: ["request": error]])
    #expect(AppleCloudTransport.map(partial) == .cloudInvalidRequest)
}

@Test func typedItemCloudCommitOfflineCatalogAndStaleEdit() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let store = try await f.store(); defer { store.close() }
    let item = VaultItem(name: "login", type: .login, fields: [
        ItemField(path: "username", type: .username, value: "visible-user"),
        ItemField(path: "password", type: .password, value: "concealed-password")
    ])
    try await store.saveItem(ItemEdit(revision: store.catalog().revision, item: item, create: true))
    let original = try store.catalog()
    var reordered = original.items[0]; reordered.fields.reverse()
    await f.cloud.resetCounters()
    try await store.saveItem(ItemEdit(revision: original.revision, item: reordered, create: false))
    #expect(await f.cloud.saves.filter { $0 == "head" }.count == 1)
    #expect(await f.cloud.saves.filter { $0.hasPrefix("s-") }.isEmpty)
    let reopened = try await f.store(); defer { reopened.close() }
    #expect(try reopened.catalog().items[0].fields.map(\.path) == ["password", "username"])
    #expect(try reopened.catalog().items[0].fields.map(\.value) == [nil, "visible-user"])
    let offline = try CloudSecretStore(vault: f.vault, snapshot: f.vault.cached().0, opener: f.device, offline: true)
    defer { offline.close() }
    #expect(try offline.catalog().items == reopened.catalog().items)
    await #expect(throws: MopError.offlineWrite) { try await offline.saveItem(ItemEdit(revision: original.revision, item: item, create: false)) }
    await #expect(throws: MopError.vaultConflict) { try await reopened.saveItem(ItemEdit(revision: original.revision, item: item, create: false)) }
}

@Test func routedStoreClosesSharedAuthorizationAfterAllStoresOnSuccessAndFailure() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    _ = try await addVault(f, name: "other")
    let rows = try await f.repo.descriptors(identity: f.device.identity.identity)
    for failSecond in [false, true] {
        var stores: [CloudSecretStore] = []
        var opened = 0, closed = 0
        let service = AsyncSecretService {
            RoutedSecretStore(repository: f.repo, rows: rows, selection: nil, onClose: {
                closed += 1
                for store in stores { #expect(throws: MopError.authentication) { try store.list(vault: nil) } }
            }) { row in
                opened += 1
                if failSecond && opened == 2 { throw MopError.authentication }
                let vault = try f.repo.vault(UUID(uuidString: row.id)!)
                let store = try CloudSecretStore(vault: vault, snapshot: await vault.sync(), opener: f.device)
                stores.append(store)
                return store
            }
        }
        if failSecond { await #expect(throws: MopError.authentication) { try await service.list(vault: nil) } }
        else { _ = try await service.list(vault: nil) }
        #expect(opened == 2 && closed == 1)
    }
}

@Test(arguments: [false, true]) func cloudTrustSurvivesSandboxRelocation(legacy: Bool) async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let trustDirectory = f.vault.cache.directory.appendingPathComponent("trust")
    if legacy {
        let old = VaultTrust(vault: f.vault.cache.directory.appendingPathComponent("identity"), directory: trustDirectory)
        try VaultSession.trustSnapshot(f.initial, trust: old, opener: f.device, revision: VaultCoding.digest(f.initial))
        try FileManager.default.removeItem(at: trustDirectory.appendingPathComponent("cloud.json"))
    }
    let relocated = f.directory.appendingPathExtension("new-sandbox")
    defer { try? FileManager.default.removeItem(at: relocated) }
    try FileManager.default.moveItem(at: f.directory, to: relocated)
    let repo = try await CloudRepository.open(transport: f.cloud, state: relocated)
    let vault = try repo.vault(f.vault.id)
    let store = try CloudSecretStore(vault: vault, snapshot: await vault.sync(), opener: f.device)
    #expect(try store.catalog().vault == "v")
    store.close()
    #expect(FileManager.default.fileExists(atPath: vault.cache.directory.appendingPathComponent("trust/cloud.json").path))
    // Reopening also uses the migrated stable binding, not the old absolute path.
    let reopened = try CloudSecretStore(vault: vault, snapshot: await vault.sync(), opener: f.device)
    #expect(try reopened.catalog().vault == "v")
    reopened.close()
    let wrongScope = VaultTrust(cloudBinding: "another-account-or-environment", directory: vault.cache.directory.appendingPathComponent("trust"))
    #expect(throws: MopError.vaultUntrusted) { try VaultSession(snapshot: f.initial, trust: wrongScope, opener: f.device) }
}

private final class MemoryIdentityKeys: IdentityKeyStore {
    var values: [String: Data] = [:]
    func read(scope: String, id: UUID) throws -> Data? { values[scope + id.uuidString] }
    func insert(_ material: Data, scope: String, id: UUID) throws {
        let key = scope + id.uuidString
        if let existing = values[key], existing != material { throw MopError.invalidIdentity }
        values[key] = material
    }
}

private struct IdentityFixture {
    let directory: URL
    let cloud: MemoryCloud
    let repo: CloudRepository
    func cleanup() { try? FileManager.default.removeItem(at: directory) }
}
private func identityFixture() async throws -> IdentityFixture {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-identity-test-" + UUID().uuidString)
    let cloud = MemoryCloud()
    return try await IdentityFixture(directory: directory, cloud: cloud, repo: CloudRepository.open(transport: cloud, state: directory))
}

@Test func accountIdentityWaitsForKeychainAndSurvivesNewDeviceAndOffline() async throws {
    let f = try await identityFixture(); defer { f.cleanup() }
    let keys = MemoryIdentityKeys()
    let first = try await f.repo.accountIdentity(keys: keys, create: true)
    defer { first.close() }
    let anchor = try #require(try await f.repo.identityAnchor())
    #expect(anchor.identity == first.identity)
    #expect(!(try await f.repo.list()).contains(CloudRepository.identityZone))
    let secondState = f.directory.appendingPathComponent("second-device")
    let second = try await CloudRepository.open(transport: f.cloud, state: secondState)
    let delayedKeys = MemoryIdentityKeys()
    await #expect(throws: MopError.identityPending) { _ = try await second.accountIdentity(keys: delayedKeys, create: true) }
    #expect(delayedKeys.values.isEmpty)
    delayedKeys.values = keys.values
    let synced = try await second.accountIdentity(keys: delayedKeys, create: true)
    #expect(synced.identity == first.identity)
    #expect(keys.values.count == 1)
    let offline = try await CloudRepository.open(transport: f.cloud, state: secondState, offline: true)
    #expect(try await offline.accountIdentity(keys: delayedKeys, create: false).identity == first.identity)
    await f.cloud.delete("account-identity-v1", vault: CloudRepository.identityZone)
    await #expect(throws: MopError.identityPending) { _ = try await second.accountIdentity(keys: delayedKeys, create: true) }
    #expect(delayedKeys.values.count == 1)
}

@Test func accountRecoveryCommitAndFreshDeviceTrust() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let owner = AccountIdentity()
    let store = try CloudSecretStore(vault: f.vault, snapshot: await f.vault.sync(), opener: f.recovery)
    let before = store.snapshot
    try await store.adoptOwner(owner)
    #expect(store.snapshot != before)
    #expect(try await f.vault.revisions().contains(VaultCoding.digest(before)))
    let second = try await CloudRepository.open(transport: f.cloud, state: f.directory.appendingPathComponent("second"))
    let discovered = try await second.descriptors(identity: owner.identity)
    #expect(discovered.count == 1 && discovered[0].enrolled && discovered[0].supported)
    let vault = try second.vault(f.vault.id)
    let opened = try CloudSecretStore(vault: vault, snapshot: await vault.sync(), opener: owner)
    #expect(try opened.catalog().vault == "v")
    let count = await f.cloud.saves.count
    try await opened.adoptOwner(owner)
    #expect(await f.cloud.saves.count == count)
    let secondDevice = TestDevice()
    // Recovery/device slots cannot forge an owner-authorized revision.
    #expect(throws: MopError.notVaultMember) { try CloudSecretStore(vault: vault, snapshot: opened.snapshot, opener: secondDevice) }
}

@Test func cancelledAccountRecoveryDoesNotPublishChanges() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let store = try CloudSecretStore(vault: f.vault, snapshot: await f.vault.sync(), opener: f.recovery), owner = AccountIdentity()
    let original = store.snapshot
    await #expect(throws: MopError.authentication) {
        try await store.adoptOwner(owner, beforePublish: { throw MopError.authentication })
    }
    #expect(try await f.vault.sync() == original)
    #expect(try VaultDocument.decode(await f.vault.sync()).header.membership?.owner == f.device.identity.identity)
}


@Test func identityConditionalCreationUsesWinnerWithoutReplacingMissingKeys() async throws {
    let f = try await identityFixture(); defer { f.cleanup() }
    let winner = AccountIdentity(), keyID = UUID()
    let anchor = try CloudIdentityAnchor(keyID: keyID, identity: winner, scope: f.repo.identityScope)
    await f.cloud.raceIdentity(try VaultCoding.encode(anchor))
    let keys = MemoryIdentityKeys()
    await #expect(throws: MopError.identityPending) { _ = try await f.repo.accountIdentity(keys: keys, create: true) }
    #expect(keys.values.count == 1) // losing candidate is never published/overwritten
    await #expect(throws: MopError.identityPending) { _ = try await f.repo.accountIdentity(keys: keys, create: true) }
    #expect(keys.values.count == 1)
    try winner.withMaterial { try keys.insert($0, scope: f.repo.identityScope, id: keyID) }
    #expect(try await f.repo.accountIdentity(keys: keys, create: true).identity == winner.identity)
    #expect(try await f.repo.identityAnchor() == anchor)
}

@Test func lostIdentityAcknowledgementReconcilesWithoutRepeatingCreation() async throws {
    let f = try await identityFixture(); defer { f.cleanup() }
    await f.cloud.setIdentityLoss()
    let keys = MemoryIdentityKeys()
    let identity = try await f.repo.accountIdentity(keys: keys, create: true)
    #expect(try await f.repo.identityAnchor()?.identity == identity.identity)
    #expect(await f.cloud.saves.filter { $0 == "account-identity-v1" }.count == 1)
    #expect(keys.values.count == 1)
    await f.cloud.setAccount("another-account")
    await #expect(throws: MopError.cloudAccount) { _ = try await f.repo.accountIdentity(keys: keys, create: true) }
    #expect(keys.values.count == 1)
}

@Test func interruptedOwnerRecoveryReconcilesCommittedRotation() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let owner = AccountIdentity(), store = try CloudSecretStore(vault: f.vault, snapshot: await f.vault.sync(), opener: f.recovery)
    await f.cloud.setLoss()
    await #expect(throws: MopError.cloudUncertain) { try await store.adoptOwner(owner) }
    let committed = try await f.vault.sync()
    let reopened = try CloudSecretStore(vault: f.vault, snapshot: committed, opener: owner)
    #expect(reopened.membership?.owner == owner.identity)
    #expect(try VaultDocument.decode(committed).header.recipients.allSatisfy { $0.kind != "device" })
    let recovered = try CloudSecretStore(vault: f.vault, snapshot: committed, opener: f.recovery)
    #expect(try recovered.catalog().vault == "v")
}

@Test func commandReadsAndSubstitutionGenerateOTPForSeedsAndURLs() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let store = try await f.store()
    let secret = "JBSWY3DPEHPK3PXP"
    let item = VaultItem(name: "login", type: .login, fields: [
        ItemField(path: "seed", type: .otp, value: secret),
        ItemField(path: "url", type: .otp, value: "otpauth://totp/Test?secret=\(secret)"),
        ItemField(path: "token", type: .concealed, value: "ordinary-secret")
    ])
    try await store.saveItem(ItemEdit(revision: store.catalog().revision, item: item, create: true))
    store.close()
    let rows = try await f.repo.descriptors(identity: f.device.identity.identity)
    let otp = try TimeBasedOTP(secret)
    for offline in [false, true] {
        let service = AsyncSecretService {
            RoutedSecretStore(repository: f.repo, rows: rows, selection: nil) { _ in
                if offline { return try CloudSecretStore(vault: f.vault, snapshot: f.vault.cached().0, opener: f.device, offline: true) }
                return try await f.store()
            }
        }
        for path in ["seed", "url"] {
            let start = Date()
            let value = try await service.read(SecretReference("secondpass://v/login/\(path)"))
            let expected = try [SecretBytes(utf8: otp.code(at: start)), SecretBytes(utf8: otp.code())]
            #expect(expected.contains(value))
        }
        let start = Date()
        let injected = try await service.inject("{{secondpass://v/login/url}}")
        let expected = try [SecretBytes(utf8: otp.code(at: start)), SecretBytes(utf8: otp.code())]
        #expect(expected.contains(injected))
        #expect(try await service.read(SecretReference("secondpass://v/login/token")) == "ordinary-secret")
    }
}

@Test func v5HistoryStopsBeforeDeviceEraWithoutDownloadingItsRecords() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    var old = try VaultDocument.decode(f.initial)
    old.header.format = "mop-vault-v4"; old.header.membership = nil
    old.signature = nil; old.signer = nil
    let oldBytes = try VaultCoding.encode(old), oldDigest = VaultCoding.digest(oldBytes)
    var header = try VaultDocument.decode(f.initial).header
    header.generation = 2; header.parent = oldDigest
    let slot = try #require(header.recipients.first { $0.publicKey == f.device.publicKey })
    let key = try f.device.unwrap(slot, vaultID: f.vault.id)
    let current = try VaultDocument.seal(header: header, index: [:], records: [:], key: key, signer: f.device)
    let currentBytes = try VaultCoding.encode(current), currentDigest = VaultCoding.digest(currentBytes)
    // A pre-v5 manifest may point at absent blobs: supported history never reads them.
    var oldManifest = try JSONSerialization.jsonObject(with: VaultCoding.encode(CloudManifest(document: old))) as! [String: Any]
    oldManifest["records"] = [UUID().uuidString: String(repeating: "a", count: 64)]
    await f.cloud.replace("m-" + oldDigest, vault: f.vault.id, bytes: try JSONSerialization.data(withJSONObject: oldManifest))
    await f.cloud.replace("m-" + currentDigest, vault: f.vault.id, bytes: try VaultCoding.encode(CloudManifest(document: current)))
    await f.cloud.replace("head", vault: f.vault.id, bytes: try VaultCoding.encode(CloudHead(revision: currentDigest, root: oldDigest)))
    await f.cloud.resetCounters()
    #expect(try await f.vault.revisions() == [currentDigest])
    #expect(!(await f.cloud.fetches).contains { $0.hasPrefix("s-") })
    let store = try await f.store()
    await #expect(throws: MopError.invalidVault) { try await store.restore(oldDigest) }
    #expect(store.snapshot == currentBytes)
    try await store.write(SecretReference("secondpass://v/item/value"), value: "current", replace: false)
    #expect(try await f.vault.revisions() == [VaultCoding.digest(store.snapshot), currentDigest])
    try await store.restore(currentDigest)
    #expect(try store.catalog().items.isEmpty)
}

@Test func v4CloudAndOfflineSnapshotsAreRejectedWithoutConversion() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    var old = try VaultDocument.decode(f.initial)
    old.header.format = "mop-vault-v4"; old.header.membership = nil
    old.signature = nil; old.signer = nil
    let bytes = try VaultCoding.encode(old), digest = VaultCoding.digest(bytes)
    await f.cloud.replace("m-" + digest, vault: f.vault.id, bytes: try VaultCoding.encode(CloudManifest(document: old)))
    await f.cloud.replace("head", vault: f.vault.id, bytes: try VaultCoding.encode(CloudHead(revision: digest, root: digest)))
    await f.cloud.resetCounters()
    let rows = try await f.repo.descriptors(identity: f.device.identity.identity)
    #expect(rows.count == 1 && !rows[0].supported && !rows[0].enrolled)
    await #expect(throws: MopError.legacyVault) { try await f.vault.sync() }
    await #expect(throws: MopError.legacyVault) { try await f.vault.revisions() }
    #expect(await f.cloud.saves.isEmpty)
    try f.vault.cache.locked {
        try f.vault.cache.write(CachedSnapshot(revision: digest, root: digest, version: Data(), fetched: Date(), document: bytes), "snapshot.json")
    }
    #expect(throws: MopError.legacyVault) { try f.vault.cached() }
}

@Test func delayedRecoveryCompletionCannotRollBackLocalTrust() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    let second = AccountIdentity(), third = AccountIdentity()
    let before = try await f.vault.sync()
    let delayed = try VaultSession(snapshot: before, trust: f.vault.trust, opener: f.recovery)
    defer { delayed.close() }
    try delayed.adoptOwner(second)
    try await f.vault.commit(expected: before, replacement: delayed.snapshot, rotationFingerprint: delayed.fingerprint())
    let newer = try CloudSecretStore(vault: f.vault, snapshot: await f.vault.sync(), opener: f.recovery)
    defer { newer.close() }
    try await newer.adoptOwner(third)
    let fingerprint = try newer.fingerprint()
    #expect(throws: MopError.vaultUntrusted) { try f.vault.finishCommittedSession(delayed, rotation: true) }
    let reopened = try CloudSecretStore(vault: f.vault, snapshot: await f.vault.sync(), opener: third)
    defer { reopened.close() }
    #expect(try reopened.fingerprint() == fingerprint)
}

@Test func oldDownloadedCacheCannotBlockSupportedV5Sync() async throws {
    let f = try await fixture(); defer { f.cleanup() }
    var old = try VaultDocument.decode(f.initial)
    old.header.format = "mop-vault-v4"; old.header.membership = nil
    old.signature = nil; old.signer = nil
    let bytes = try VaultCoding.encode(old), digest = VaultCoding.digest(bytes)
    try f.vault.cache.locked {
        try f.vault.cache.write(CachedSnapshot(revision: digest, root: digest, version: Data(), fetched: Date(), document: bytes), "downloaded.json")
    }
    #expect(try await f.vault.sync() == f.initial)
}
