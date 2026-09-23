import CryptoKit
import Foundation
import Testing
import MopCore
@testable import MopVault

// Software keys are used only in this test target. Production has no fallback.
private struct TestDevice: VaultKeyOpener {
    let key = P256.KeyAgreement.PrivateKey()
    var publicKey: Data { key.publicKey.x963Representation }
    var request: DeviceRequest { try! DeviceRequest(name: "Test Mac", publicKey: publicKey) }
    func unwrap(_ recipient: VaultRecipient, vaultID: UUID) throws -> SymmetricKey {
        try VaultDocument.unwrap(recipient, vaultID: vaultID, privateKey: key)
    }
}

private func fixture() throws -> (URL, VaultTrust, Data, TestDevice, RecoveryKey) {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-session-test-" + UUID().uuidString)
    try SafeFile.privateDirectory(directory)
    let trust = VaultTrust(vault: directory.appendingPathComponent("identity"), directory: directory.appendingPathComponent("local-trust"))
    let device = TestDevice()
    let recovery = RecoveryKey()
    let snapshot = try VaultSession.createSnapshot(name: "v", device: device.request, recovery: recovery)
    // These bytes were generated here, independently of any untrusted transport.
    try VaultSession.trustSnapshot(snapshot, trust: trust, opener: device, revision: VaultCoding.digest(snapshot))
    return (directory, trust, snapshot, device, recovery)
}

private final class CountingOpener: VaultKeyOpener {
    let device: TestDevice
    var purposes: [String] = []
    var allowRecords = true
    init(_ device: TestDevice) { self.device = device }
    var publicKey: Data { device.publicKey }
    func unwrap(_ recipient: VaultRecipient, vaultID: UUID) throws -> SymmetricKey {
        purposes.append(recipient.purpose)
        if recipient.purpose != "index", !allowRecords { throw MopError.authentication }
        return try device.unwrap(recipient, vaultID: vaultID)
    }
}

@Test func snapshotCRUDAndTamperDetection() throws {
    let (directory, trust, initial, device, _) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let ref = try SecretReference("mop://v/github/token")
    let store = try VaultSession(snapshot: initial, trust: trust, opener: device)
    defer { store.close() }
    try store.write(ref, value: "VERY_SECRET\n多行", replace: false)
    let bytes = store.snapshot
    #expect(!String(decoding: bytes, as: UTF8.self).contains("VERY_SECRET"))
    #expect(!String(decoding: bytes, as: UTF8.self).contains(ref.description))
    #expect(try store.read(ref) == "VERY_SECRET\n多行")
    #expect(try store.list(vault: "v") == [ref])
    #expect(throws: MopError.duplicate) { try store.write(ref, value: "bad", replace: false) }
    var tampered = try VaultDocument.decode(bytes)
    tampered.header.generation += 1
    #expect(throws: MopError.invalidVault) {
        try VaultSession(snapshot: VaultCoding.encode(tampered), trust: trust, opener: device)
    }
    tampered = try VaultDocument.decode(bytes)
    tampered.sealed[tampered.sealed.startIndex + 15] ^= 1
    #expect(throws: MopError.invalidVault) {
        try VaultSession(snapshot: VaultCoding.encode(tampered), trust: trust, opener: device)
    }
    try store.write(ref, value: "", replace: true)
    #expect(try store.read(ref) == "")
    try store.delete(ref)
    #expect(throws: MopError.notFound) { try store.read(ref) }
    store.close()
    #expect(throws: MopError.authentication) { try store.list(vault: nil) }
}

@Test func rejectSymlinksAndOverwrites() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-permission-" + UUID().uuidString)
    try SafeFile.privateDirectory(directory)
    defer { try? FileManager.default.removeItem(at: directory) }
    let file = directory.appendingPathComponent("secret")
    try SafeFile.write(Data("test".utf8), to: file)
    #expect(throws: MopError.duplicate) { try SafeFile.write(Data("overwrite".utf8), to: file) }
    #expect(try SafeFile.read(file, privateFile: true) == Data("test".utf8))
    let link = directory.appendingPathComponent("link")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
    #expect(throws: (any Error).self) { try SafeFile.read(link, privateFile: true) }
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
    #expect(throws: MopError.filePermissions) { try SafeFile.read(file, privateFile: true) }
}

@Test func recipientMetadataAndVaultIdentityAreAuthenticated() throws {
    let (directory, trust, initial, device, _) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let bytes = initial
    var altered = try VaultDocument.decode(bytes)
    let slot = altered.header.recipients[0]
    altered.header.recipients[0] = VaultRecipient(kind: slot.kind, name: "Altered device name", publicKey: slot.publicKey,
                                                 encapsulatedKey: slot.encapsulatedKey, wrappedKey: slot.wrappedKey)
    #expect(throws: MopError.invalidVault) { try VaultSession(snapshot: VaultCoding.encode(altered), trust: trust, opener: device) }
    let original = try VaultDocument.decode(bytes)
    let ownSlot = original.header.recipients.first { $0.publicKey == device.publicKey }!
    #expect(throws: (any Error).self) { try device.unwrap(ownSlot, vaultID: UUID()) }
    let unsupported = VaultDocument(header: VaultHeader(format: "mop-vault-v999", vaultID: original.header.vaultID, name: "v",
                                                       generation: 1, recipients: original.header.recipients), sealed: original.sealed)
    #expect(throws: MopError.invalidVault) { try VaultDocument.decode(VaultCoding.encode(unsupported)) }
}

@Test func writesUseFreshNoncesAndFailedMutationsPreserveSnapshot() throws {
    let (directory, trust, initial, device, _) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try VaultSession(snapshot: initial, trust: trust, opener: device)
    defer { store.close() }
    let ref = try SecretReference("mop://v/i/f")
    try store.write(ref, value: "same", replace: false)
    let first = store.snapshot
    #expect(throws: MopError.duplicate) { try store.write(ref, value: "other", replace: false) }
    #expect(store.snapshot == first)
    try store.write(ref, value: "same", replace: true)
    let second = store.snapshot
    #expect(try VaultDocument.decode(first).sealed.prefix(12) != VaultDocument.decode(second).sealed.prefix(12))
    #expect(try VaultDocument.decode(second).header.parent == VaultCoding.digest(first))
}

@Test func legacyFormatsAreRejected() throws {
    let (directory, trust, initial, device, _) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    var document = try VaultDocument.decode(initial)
    #expect(document.header.format == "mop-vault-v4")
    for format in ["mop-vault-v1", "mop-vault-v2"] {
        document.header.format = format
        #expect(throws: MopError.invalidVault) { try VaultSession(snapshot: VaultCoding.encode(document), trust: trust, opener: device) }
    }
}

@Test func privateFilesStripInheritedACLsAndRejectExistingGrants() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-acl-test-" + UUID().uuidString)
    try SafeFile.privateDirectory(directory)
    defer { try? FileManager.default.removeItem(at: directory) }
    func chmod(_ args: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = args
        try process.run()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0)
    }
    try chmod(["+a", "everyone allow read,search,file_inherit,directory_inherit", directory.path])
    #expect(throws: MopError.filePermissions) { try SafeFile.privateDirectory(directory) }
    let recoveryURL = directory.appendingPathComponent("recovery.key")
    let recovery = RecoveryKey()
    try recovery.save(to: recoveryURL)
    // Inherited allow entries must be removed before any key bytes are written.
    #expect(try RecoveryKey(file: recoveryURL).publicKey == recovery.publicKey)
    try chmod(["+a", "everyone allow read", recoveryURL.path])
    #expect(throws: MopError.filePermissions) { try RecoveryKey(file: recoveryURL) }
    try chmod(["-N", recoveryURL.path])
    #expect(try RecoveryKey(file: recoveryURL).publicKey == recovery.publicKey)
}

@Test func readsOnlyRequestedRecordAndMutationsPreserveOtherCiphertexts() throws {
    let (directory, trust, initial, device, _) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let spy = CountingOpener(device)
    let store = try VaultSession(snapshot: initial, trust: trust, opener: spy)
    defer { store.close() }
    let first = try SecretReference("mop://v/i/first")
    let second = try SecretReference("mop://v/i/section/second")
    try store.write(first, value: "one", replace: false)
    try store.write(second, value: "two", replace: false)
    #expect(spy.purposes == ["index"])
    let before = try VaultDocument.decode(store.snapshot)
    let indexKey = try device.unwrap(before.header.recipients.first { $0.publicKey == device.publicKey }!, vaultID: before.header.vaultID)
    let index = try before.decryptIndex(key: indexKey)
    #expect(try store.list(vault: nil) == [first, second].sorted())
    #expect(spy.purposes == ["index"])
    #expect(try store.read(first) == "one")
    #expect(spy.purposes == ["index", "record:" + index[first.relativePath]!])
    spy.allowRecords = false
    #expect(throws: MopError.authentication) { try store.read(second) }
    try store.write(first, value: "replacement", replace: true)
    let after = try VaultDocument.decode(store.snapshot)
    #expect(after.records[index[second.relativePath]!] == before.records[index[second.relativePath]!])
    #expect(after.records[index[first.relativePath]!] == nil)
    try store.delete(second) // Neither replacement nor deletion opens old values.
    store.close()
    #expect(throws: MopError.authentication) { try store.read(first) }
}

@Test func recordTableTamperingAndContextSubstitutionFailClosed() throws {
    let (directory, trust, initial, device, _) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try VaultSession(snapshot: initial, trust: trust, opener: device)
    defer { store.close() }
    try store.write(SecretReference("mop://v/i/a"), value: "alpha", replace: false)
    try store.write(SecretReference("mop://v/i/b"), value: "beta", replace: false)
    let original = try VaultDocument.decode(store.snapshot)
    let ids = original.records.keys.sorted()
    var changed = original
    changed.records[ids[0]]!.sealed[12] ^= 1
    #expect(throws: MopError.invalidVault) { try VaultSession(snapshot: VaultCoding.encode(changed), trust: trust, opener: device) }
    changed = original
    changed.records.removeValue(forKey: ids[0])
    #expect(throws: MopError.invalidVault) { try VaultSession(snapshot: VaultCoding.encode(changed), trust: trust, opener: device) }
    changed = original
    changed.records[ids[0]] = original.records[ids[1]]
    #expect(throws: MopError.invalidVault) { try VaultSession(snapshot: VaultCoding.encode(changed), trust: trust, opener: device) }
    let record = original.records[ids[0]]!
    var slot = record.recipients.first { $0.publicKey == device.publicKey }!
    slot.purpose = "index"
    #expect(throws: (any Error).self) { try device.unwrap(slot, vaultID: original.header.vaultID) }
    #expect(throws: (any Error).self) { try record.read(id: ids[0], vaultID: UUID(), opener: device) }
    #expect(throws: (any Error).self) { try record.read(id: ids[1], vaultID: original.header.vaultID, opener: device) }
}

@Test func enrollmentRewrapsWithoutChangingValuesAndRevocationRotatesEveryRecord() throws {
    let (directory, trust, initial, device, _) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let spy = CountingOpener(device)
    let store = try VaultSession(snapshot: initial, trust: trust, opener: spy)
    defer { store.close() }
    for name in ["a", "b"] { try store.write(SecretReference("mop://v/i/" + name), value: SecretBytes(utf8: name), replace: false) }
    let before = try VaultDocument.decode(store.snapshot)
    let other = TestDevice()
    try store.enroll(other.request, expectedFingerprint: other.request.fingerprint)
    let enrolled = try VaultDocument.decode(store.snapshot)
    #expect(spy.purposes.filter { $0.hasPrefix("record:") }.count == 2)
    for (id, record) in before.records {
        #expect(enrolled.records[id]!.sealed == record.sealed)
        #expect(enrolled.records[id]!.recipients.count == 3)
    }
    try store.revoke(other.request.fingerprint, currentDevice: device.publicKey)
    let revoked = try VaultDocument.decode(store.snapshot)
    for (id, record) in enrolled.records {
        let rotated = revoked.records[id]!
        #expect(rotated.sealed != record.sealed)
        #expect(rotated.recipients.count == 2)
        let oldKey = try record.key(id: id, vaultID: before.header.vaultID, opener: other)
        let newKey = try rotated.key(id: id, vaultID: before.header.vaultID, opener: device)
        #expect(oldKey != newKey)
    }
}

@Test func renamePreservesIdentityRecordsAndHistoricalRestoreKeepsName() throws {
    let (directory, trust, initial, device, recovery) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try VaultSession(snapshot: initial, trust: trust, opener: device)
    defer { store.close() }
    let ref = try SecretReference("mop://v/my%2Fcloud/section/sshd")
    try store.write(ref, value: "original", replace: false)
    let before = store.snapshot
    let document = try VaultDocument.decode(before)
    let fingerprint = try store.fingerprint()
    let key = try device.unwrap(document.header.recipients.first { $0.publicKey == device.publicKey }!, vaultID: document.header.vaultID)
    #expect(try document.decryptIndex(key: key).keys.sorted() == [ref.relativePath])
    try store.rename("personal")
    let renamed = try VaultDocument.decode(store.snapshot)
    #expect(renamed.header.vaultID == document.header.vaultID)
    #expect(renamed.header.recipients == document.header.recipients)
    #expect(renamed.records == document.records)
    #expect(try store.fingerprint() == fingerprint)
    #expect(throws: MopError.vaultSelectionMismatch) { try store.read(ref) }
    let current = try SecretReference(vault: "personal", relativePath: ref.relativePath)
    #expect(try store.read(current) == "original")
    try store.write(current, value: "changed", replace: true)
    try store.restore(before)
    #expect(store.name == "personal")
    #expect(try store.read(current) == "original")
    let recovered = try VaultSession(snapshot: store.snapshot, trust: trust, opener: recovery)
    defer { recovered.close() }
    #expect(try recovered.read(current) == "original")
    var tampered = try VaultDocument.decode(store.snapshot)
    tampered.header.name = "forged"
    #expect(throws: MopError.invalidVault) {
        try VaultSession(snapshot: VaultCoding.encode(tampered), trust: trust, opener: device)
    }
    var legacy = try JSONSerialization.jsonObject(with: store.snapshot) as! [String: Any]
    var header = legacy["header"] as! [String: Any]
    header["format"] = "mop-vault-v3"; header.removeValue(forKey: "name"); legacy["header"] = header
    #expect(throws: MopError.legacyVault) { try VaultDocument.decode(JSONSerialization.data(withJSONObject: legacy)) }
}

@Test func deviceEnrollmentRevocationAndRecovery() throws {
    let (directory, trust, initial, first, recovery) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let second = TestDevice()
    let ref = try SecretReference("mop://v/i/f")
    let a = try VaultSession(snapshot: initial, trust: trust, opener: first)
    defer { a.close() }
    try a.write(ref, value: "shared", replace: false)
    #expect(throws: MopError.deviceNotEnrolled) { try VaultSession(snapshot: a.snapshot, trust: trust, opener: second) }
    #expect(throws: MopError.invalidDevice) { try a.enroll(second.request, expectedFingerprint: "wrong") }
    try a.enroll(second.request, expectedFingerprint: second.request.fingerprint)
    let b = try VaultSession(snapshot: a.snapshot, trust: trust, opener: second)
    defer { b.close() }
    #expect(try b.read(ref) == "shared")
    let beforeRevoke = a.snapshot
    try a.revoke(second.request.fingerprint, currentDevice: first.publicKey)
    try a.pinCommittedKey() // In production this happens only after CloudKit commits.
    #expect(throws: MopError.deviceNotEnrolled) { try VaultSession(snapshot: a.snapshot, trust: trust, opener: second) }
    #expect(throws: MopError.vaultUntrusted) { try VaultSession(snapshot: beforeRevoke, trust: trust, opener: second) }
    let old = try VaultDocument.decode(beforeRevoke)
    let oldKey = try second.unwrap(old.header.recipients.first { $0.publicKey == second.publicKey }!, vaultID: old.header.vaultID)
    let id = try old.decryptIndex(key: oldKey)[ref.relativePath]!
    #expect(try old.records[id]!.read(id: id, vaultID: old.header.vaultID, opener: second) == "shared")
    let recovered = try VaultSession(snapshot: a.snapshot, trust: trust, opener: recovery)
    defer { recovered.close() }
    #expect(try recovered.read(ref) == "shared")
    try recovered.enroll(second.request, expectedFingerprint: second.request.fingerprint)
    let recoveryFile = directory.appendingPathComponent("offline.key")
    try recovery.save(to: recoveryFile)
    #expect(try RecoveryKey(file: recoveryFile).publicKey == recovery.publicKey)
}

@Test func enrollmentInOneVaultDoesNotGrantAccessToAnother() throws {
    let (directory, trust, initial, device, _) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let other = TestDevice()
    let second = try VaultSession.createSnapshot(name: "other", device: other.request, recovery: RecoveryKey())
    let otherTrust = VaultTrust(vault: directory.appendingPathComponent("other"), directory: directory.appendingPathComponent("other-trust"))
    try VaultSession.trustSnapshot(second, trust: otherTrust, opener: other, revision: VaultCoding.digest(second))
    #expect(throws: MopError.deviceNotEnrolled) { try VaultSession(snapshot: second, trust: otherTrust, opener: device) }
    #expect(throws: MopError.deviceNotEnrolled) { try VaultSession(snapshot: initial, trust: trust, opener: other) }
}

@Test func rejectsForgedSnapshotsAndHistoryDespiteValidEncryption() throws {
    let (directory, trust, original, device, _) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let document = try VaultDocument.decode(original)
    let attacker = TestDevice()
    let attackerKey = SymmetricKey(size: .bits256)
    var header = document.header
    header.generation += 1; header.parent = VaultCoding.digest(original)
    header.recipients = try header.recipients.map {
        try VaultDocument.wrap(key: attackerKey, request: DeviceRequest(name: $0.name, publicKey: $0.publicKey), kind: $0.kind, vaultID: header.vaultID)
    }
    header.recipients.append(try VaultDocument.wrap(key: attackerKey, request: attacker.request, kind: "device", vaultID: header.vaultID))
    let forged = try VaultCoding.encode(VaultDocument.seal(header: header, index: [:], records: [:], key: attackerKey))
    #expect(throws: MopError.vaultUntrusted) { try VaultSession(snapshot: forged, trust: trust, opener: device) }
    #expect(throws: MopError.vaultUntrusted) {
        try VaultSession.trustSnapshot(forged, trust: trust, opener: device, revision: VaultCoding.digest(original))
    }
    let store = try VaultSession(snapshot: original, trust: trust, opener: device)
    defer { store.close() }
    #expect(throws: MopError.vaultUntrusted) {
        try VaultSession.trustSnapshot(forged, trust: trust, opener: device, fingerprint: store.fingerprint())
    }
    #expect(throws: MopError.vaultUntrusted) { try store.restore(forged) }
    #expect(store.snapshot == original)
    try store.write(SecretReference("mop://v/i/new"), value: "protected-future-secret", replace: false)
    #expect(throws: MopError.deviceNotEnrolled) { try VaultSession(snapshot: store.snapshot, trust: trust, opener: attacker) }
}

@Test func separateDeviceTrustAndRotationRequireIndependentEvidence() throws {
    let (directory, trust, initial, first, recovery) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let second = TestDevice(), removed = TestDevice()
    let store = try VaultSession(snapshot: initial, trust: trust, opener: first)
    defer { store.close() }
    try store.enroll(second.request, expectedFingerprint: second.request.fingerprint)
    try store.enroll(removed.request, expectedFingerprint: removed.request.fingerprint)
    let otherTrust = VaultTrust(vault: directory.appendingPathComponent("identity"), directory: directory.appendingPathComponent("other-trust"))
    let oldFingerprint = try store.fingerprint()
    #expect(throws: MopError.vaultUntrusted) { try VaultSession(snapshot: store.snapshot, trust: otherTrust, opener: second) }
    #expect(throws: MopError.vaultUntrusted) { try VaultSession(snapshot: store.snapshot, trust: otherTrust, opener: recovery) }
    #expect(throws: MopError.vaultUntrusted) {
        try VaultSession.trustSnapshot(store.snapshot, trust: otherTrust, opener: second, fingerprint: String(repeating: "0", count: 64))
    }
    try VaultSession.trustSnapshot(store.snapshot, trust: otherTrust, opener: second, fingerprint: oldFingerprint)
    let ref = try SecretReference("mop://v/i/f")
    try store.write(ref, value: "before rotation", replace: false)
    let oldSnapshot = store.snapshot
    try store.revoke(removed.request.fingerprint, currentDevice: first.publicKey)
    let rotated = store.snapshot
    // Creating the candidate snapshot must not advance durable trust.
    #expect(throws: MopError.vaultUntrusted) { try VaultSession(snapshot: rotated, trust: trust, opener: first) }
    try store.pinCommittedKey()
    #expect(try store.fingerprint() != oldFingerprint)
    #expect(throws: MopError.vaultUntrusted) { try VaultSession(snapshot: rotated, trust: otherTrust, opener: second) }
    try VaultSession.trustSnapshot(rotated, trust: otherTrust, opener: second, fingerprint: store.fingerprint())
    let trusted = try VaultSession(snapshot: rotated, trust: otherTrust, opener: second)
    defer { trusted.close() }
    #expect(try trusted.read(ref) == "before rotation")
    #expect(throws: MopError.vaultUntrusted) { try VaultSession(snapshot: oldSnapshot, trust: trust, opener: first) }
    try store.restore(oldSnapshot)
    #expect(try store.read(ref) == "before rotation")
    #expect(try !store.recipients().contains { $0.fingerprint == removed.request.fingerprint })
    // An encrypted backup authenticates through independent revision evidence.
    let backup = directory.appendingPathComponent("backup.mopfile")
    try SafeFile.write(store.snapshot, to: backup)
    let backupTrust = VaultTrust(vault: backup, directory: directory.appendingPathComponent("backup-trust"))
    let bytes = try SafeFile.read(backup)
    try VaultSession.trustSnapshot(bytes, trust: backupTrust, opener: recovery, revision: VaultCoding.digest(store.snapshot))
    let recovered = try VaultSession(snapshot: bytes, trust: backupTrust, opener: recovery)
    defer { recovered.close() }
    #expect(try recovered.read(ref) == "before rotation")
}

@Test func changingVaultIdentityOrLosingPinsNeverEstablishesTrust() throws {
    let (directory, trust, original, device, recovery) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let other = try VaultSession.createSnapshot(name: "v", device: device.request, recovery: recovery)
    #expect(throws: MopError.vaultUntrusted) { try VaultSession(snapshot: other, trust: trust, opener: device) }
    try FileManager.default.removeItem(at: directory.appendingPathComponent("local-trust"))
    #expect(throws: MopError.vaultUntrusted) { try VaultSession(snapshot: original, trust: trust, opener: device) }
    #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("local-trust").path))
}
