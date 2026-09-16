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

private func fixture() throws -> (URL, VaultDisk, TestDevice, RecoveryKey) {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-test-" + UUID().uuidString)
    try SafeFile.privateDirectory(directory)
    let disk = VaultDisk(url: directory.appendingPathComponent(".mopfile"), trustDirectory: directory.appendingPathComponent("local-trust"))
    let device = TestDevice()
    let recovery = RecoveryKey()
    try FileSecretStore.initialize(disk: disk, device: device.request, recovery: recovery)
    return (directory, disk, device, recovery)
}

@Test func encryptedFileCRUDAndTamperDetection() throws {
    let (directory, disk, device, _) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let ref = try SecretReference("mop://personal/github/token")
    let store = try FileSecretStore(disk: disk, snapshot: disk.read(), opener: device)
    defer { store.close() }
    try store.write(ref, value: "VERY_SECRET\n多行", replace: false)
    let bytes = try disk.read()
    #expect(!String(decoding: bytes, as: UTF8.self).contains("VERY_SECRET"))
    #expect(!String(decoding: bytes, as: UTF8.self).contains(ref.description))
    #expect(try store.read(ref) == "VERY_SECRET\n多行")
    #expect(try store.list(vault: "personal") == [ref])
    #expect(throws: MopError.duplicate) { try store.write(ref, value: "bad", replace: false) }
    var tampered = try VaultDocument.decode(bytes)
    tampered.header.generation += 1
    #expect(throws: MopError.invalidVault) {
        try FileSecretStore(disk: disk, snapshot: VaultCoding.encode(tampered), opener: device)
    }
    tampered = try VaultDocument.decode(bytes)
    tampered.sealed[tampered.sealed.startIndex + 15] ^= 1
    #expect(throws: MopError.invalidVault) {
        try FileSecretStore(disk: disk, snapshot: VaultCoding.encode(tampered), opener: device)
    }
    try store.write(ref, value: "", replace: true)
    #expect(try store.read(ref) == "")
    try store.delete(ref)
    #expect(throws: MopError.notFound) { try store.read(ref) }
    store.close()
    #expect(throws: MopError.authentication) { try store.list(vault: nil) }
}

@Test func deviceEnrollmentRevocationAndRecovery() throws {
    let (directory, disk, first, recovery) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let second = TestDevice()
    let ref = try SecretReference("mop://v/i/f")
    let a = try FileSecretStore(disk: disk, snapshot: disk.read(), opener: first)
    defer { a.close() }
    try a.write(ref, value: "shared", replace: false)
    #expect(throws: MopError.deviceNotEnrolled) { try FileSecretStore(disk: disk, snapshot: disk.read(), opener: second) }
    #expect(throws: MopError.invalidDevice) { try a.enroll(second.request, expectedFingerprint: "wrong") }
    try a.enroll(second.request, expectedFingerprint: second.request.fingerprint)
    let b = try FileSecretStore(disk: disk, snapshot: disk.read(), opener: second)
    defer { b.close() }
    #expect(try b.read(ref) == "shared")
    let beforeRevoke = try disk.read()
    try a.revoke(second.request.fingerprint, currentDevice: first.publicKey)
    #expect(throws: MopError.deviceNotEnrolled) { try FileSecretStore(disk: disk, snapshot: disk.read(), opener: second) }
    #expect(throws: MopError.vaultConflict) { try b.write(ref, value: "stale", replace: true) }
    let old = try VaultDocument.decode(beforeRevoke)
    let oldKey = try second.unwrap(old.header.recipients.first { $0.publicKey == second.publicKey }!, vaultID: old.header.vaultID)
    #expect(try old.decrypt(key: oldKey)[ref.description] == "shared") // Historical ciphertext remains decryptable.
    #expect(throws: MopError.vaultUntrusted) { try FileSecretStore(disk: disk, snapshot: beforeRevoke, opener: second) }
    let recovered = try FileSecretStore(disk: disk, snapshot: disk.read(), opener: recovery)
    defer { recovered.close() }
    #expect(try recovered.read(ref) == "shared")
    try recovered.enroll(second.request, expectedFingerprint: second.request.fingerprint)
    let recoveryFile = directory.appendingPathComponent("offline.key")
    try recovery.save(to: recoveryFile)
    #expect(try RecoveryKey(file: recoveryFile).publicKey == recovery.publicKey)
}

@Test func staleWritesAndExplicitHistoryResolution() throws {
    let (directory, disk, device, _) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let initial = try disk.read()
    let a = try FileSecretStore(disk: disk, snapshot: initial, opener: device)
    let b = try FileSecretStore(disk: disk, snapshot: initial, opener: device)
    defer { a.close(); b.close() }
    let ref = try SecretReference("mop://v/i/f")
    try a.write(ref, value: "winner", replace: false)
    #expect(throws: MopError.vaultConflict) { try b.write(ref, value: "loser", replace: false) }
    let before = try disk.read()
    let revisions = try disk.revisions()
    #expect(revisions.contains(VaultCoding.digest(initial)))
    #expect(revisions.contains(VaultCoding.digest(before)))
    try FileSecretStore.resolve(disk: disk, revision: VaultCoding.digest(initial), opener: device)
    let restored = try FileSecretStore(disk: disk, snapshot: disk.read(), opener: device)
    #expect(try restored.list(vault: nil).isEmpty)
    #expect(try restored.recipients().map(\.fingerprint) == [device.request.fingerprint])
    restored.close()
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
    let (directory, disk, device, _) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let bytes = try disk.read()
    var altered = try VaultDocument.decode(bytes)
    let slot = altered.header.recipients[0]
    altered.header.recipients[0] = VaultRecipient(kind: slot.kind, name: "Altered device name", publicKey: slot.publicKey,
                                                 encapsulatedKey: slot.encapsulatedKey, wrappedKey: slot.wrappedKey)
    #expect(throws: MopError.invalidVault) { try FileSecretStore(disk: disk, snapshot: VaultCoding.encode(altered), opener: device) }
    let original = try VaultDocument.decode(bytes)
    let ownSlot = original.header.recipients.first { $0.publicKey == device.publicKey }!
    #expect(throws: (any Error).self) { try device.unwrap(ownSlot, vaultID: UUID()) }
    let unsupported = VaultDocument(header: VaultHeader(format: "mop-vault-v999", vaultID: original.header.vaultID,
                                                       generation: 1, recipients: original.header.recipients), sealed: original.sealed)
    #expect(throws: MopError.invalidVault) { try VaultDocument.decode(VaultCoding.encode(unsupported)) }
}

@Test func writesUseFreshNoncesAndFailedMutationsPreserveDisk() throws {
    let (directory, disk, device, _) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try FileSecretStore(disk: disk, snapshot: disk.read(), opener: device)
    defer { store.close() }
    let ref = try SecretReference("mop://v/i/f")
    try store.write(ref, value: "same", replace: false)
    let first = try disk.read()
    #expect(throws: MopError.duplicate) { try store.write(ref, value: "other", replace: false) }
    #expect(try disk.read() == first)
    try store.write(ref, value: "same", replace: true)
    let second = try disk.read()
    #expect(try VaultDocument.decode(first).sealed.prefix(12) != VaultDocument.decode(second).sealed.prefix(12))
    #expect(try VaultDocument.decode(second).header.parent == VaultCoding.digest(first))
}

@Test func upgradesV1OnlyAfterSuccessfulSectionWriteAndRestoresWithoutDowngrade() throws {
    let (directory, disk, device, recovery) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let initial = try disk.read()
    let document = try VaultDocument.decode(initial)
    #expect(document.header.format == "mop-vault-v2")
    let key = try device.unwrap(document.header.recipients.first { $0.publicKey == device.publicKey }!, vaultID: document.header.vaultID)
    var header = document.header
    header.format = "mop-vault-v1"
    let oldReference = try SecretReference("mop://v/i/f")
    let sectioned = try SecretReference("mop://v/i/s/f")
    let v1 = try VaultCoding.encode(VaultDocument.seal(header: header, secrets: [oldReference.description: "old"], key: key))
    try disk.commit(expected: initial, replacement: v1)
    let store = try FileSecretStore(disk: disk, snapshot: disk.read(), opener: device)
    defer { store.close() }
    #expect(throws: MopError.notFound) { try store.write(sectioned, value: "bad", replace: true) }
    #expect(try disk.read() == v1)
    try store.write(oldReference, value: "new", replace: true)
    #expect(try VaultDocument.decode(disk.read()).header.format == "mop-vault-v1")
    let stale = try FileSecretStore(disk: disk, snapshot: disk.read(), opener: device)
    defer { stale.close() }
    try store.write(sectioned, value: "section", replace: false)
    let upgraded = try disk.read()
    #expect(try VaultDocument.decode(upgraded).header.format == "mop-vault-v2")
    #expect(try store.read(oldReference) == "new")
    #expect(try store.read(sectioned) == "section")
    #expect(throws: MopError.vaultConflict) { try stale.write(sectioned, value: "bad", replace: false) }
    #expect(try disk.read() == upgraded)
    let second = TestDevice()
    try store.enroll(second.request, expectedFingerprint: second.request.fingerprint)
    let enrolled = try FileSecretStore(disk: disk, snapshot: disk.read(), opener: second)
    #expect(try enrolled.read(sectioned) == "section")
    enrolled.close()
    let recovered = try FileSecretStore(disk: disk, snapshot: disk.read(), opener: recovery)
    #expect(try recovered.read(sectioned) == "section")
    recovered.close()
    try FileSecretStore.resolve(disk: disk, revision: VaultCoding.digest(v1), opener: device)
    #expect(try VaultDocument.decode(disk.read()).header.format == "mop-vault-v2")
    let restored = try FileSecretStore(disk: disk, snapshot: disk.read(), opener: device)
    #expect(try restored.read(oldReference) == "old")
    #expect(try restored.recipients().count == 2)
    restored.close()
    let invalidV1 = try VaultCoding.encode(VaultDocument.seal(header: header, secrets: [sectioned.description: "bad"], key: key))
    #expect(throws: MopError.invalidVault) { try FileSecretStore(disk: disk, snapshot: invalidV1, opener: device) }
}

@Test func enrollmentInOneFileDoesNotGrantAccessToAnother() throws {
    let (directory, first, device, _) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let other = TestDevice()
    let second = VaultDisk(url: directory.appendingPathComponent("second.mopfile"), trustDirectory: directory.appendingPathComponent("local-trust"))
    try FileSecretStore.initialize(disk: second, device: other.request, recovery: RecoveryKey())
    let reference = try SecretReference("mop://same/item/field")
    let a = try FileSecretStore(disk: first, snapshot: first.read(), opener: device)
    let b = try FileSecretStore(disk: second, snapshot: second.read(), opener: other)
    defer { a.close(); b.close() }
    try a.write(reference, value: "first", replace: false)
    try b.write(reference, value: "second", replace: false)
    #expect(throws: MopError.deviceNotEnrolled) { try FileSecretStore(disk: second, snapshot: second.read(), opener: device) }
    #expect(throws: MopError.deviceNotEnrolled) { try FileSecretStore(disk: first, snapshot: first.read(), opener: other) }
}

@Test func rejectsForgedVaultAndForgedHistoryDespiteValidEncryption() throws {
    let (directory, disk, device, _) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let original = try disk.read()
    let document = try VaultDocument.decode(original)
    let attacker = TestDevice()
    let attackerKey = SymmetricKey(size: .bits256)
    var header = document.header
    header.generation += 1
    header.parent = VaultCoding.digest(original)
    header.recipients = try header.recipients.map {
        try VaultDocument.wrap(key: attackerKey, request: DeviceRequest(name: $0.name, publicKey: $0.publicKey), kind: $0.kind, vaultID: header.vaultID)
    }
    header.recipients.append(try VaultDocument.wrap(key: attackerKey, request: attacker.request, kind: "device", vaultID: header.vaultID))
    let forgedDocument = try VaultDocument.seal(header: header, secrets: [:], key: attackerKey)
    let forged = try VaultCoding.encode(forgedDocument)
    try disk.commit(expected: original, replacement: forged)
    #expect(throws: MopError.vaultUntrusted) { try FileSecretStore(disk: disk, snapshot: disk.read(), opener: device) }
    #expect(throws: MopError.vaultUntrusted) { try FileSecretStore.resolve(disk: disk, revision: VaultCoding.digest(original), opener: device) }
    #expect(throws: MopError.vaultUntrusted) { try FileSecretStore.establishTrust(disk: disk, opener: device, revision: VaultCoding.digest(original)) }
    let originalKey = try device.unwrap(document.header.recipients.first { $0.publicKey == device.publicKey }!, vaultID: header.vaultID)
    #expect(throws: MopError.vaultUntrusted) {
        try FileSecretStore.establishTrust(disk: disk, opener: device, fingerprint: VaultTrust.fingerprint(document: document, key: originalKey))
    }
    try disk.commit(expected: forged, replacement: original)
    #expect(throws: MopError.vaultUntrusted) { try FileSecretStore.resolve(disk: disk, revision: VaultCoding.digest(forged), opener: device) }
    #expect(try disk.read() == original)
    let store = try FileSecretStore(disk: disk, snapshot: disk.read(), opener: device)
    defer { store.close() }
    try store.write(SecretReference("mop://v/i/new"), value: "protected-future-secret", replace: false)
    #expect(throws: MopError.deviceNotEnrolled) { try FileSecretStore(disk: disk, snapshot: disk.read(), opener: attacker) }
}

@Test func separateDeviceTrustAndRotationRequireIndependentEvidence() throws {
    let (directory, disk, first, recovery) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let second = TestDevice()
    let removed = TestDevice()
    let store = try FileSecretStore(disk: disk, snapshot: disk.read(), opener: first)
    defer { store.close() }
    try store.enroll(second.request, expectedFingerprint: second.request.fingerprint)
    try store.enroll(removed.request, expectedFingerprint: removed.request.fingerprint)
    let otherDisk = VaultDisk(url: disk.url, trustDirectory: directory.appendingPathComponent("other-trust"))
    let oldFingerprint = try store.fingerprint()
    #expect(throws: MopError.vaultUntrusted) { try FileSecretStore(disk: otherDisk, snapshot: otherDisk.read(), opener: second) }
    #expect(throws: MopError.vaultUntrusted) { try FileSecretStore(disk: otherDisk, snapshot: otherDisk.read(), opener: recovery) }
    #expect(throws: MopError.vaultUntrusted) { try FileSecretStore.establishTrust(disk: otherDisk, opener: second, fingerprint: String(repeating: "0", count: 64)) }
    try FileSecretStore.establishTrust(disk: otherDisk, opener: second, fingerprint: oldFingerprint)
    let otherStore = try FileSecretStore(disk: otherDisk, snapshot: otherDisk.read(), opener: second)
    #expect(try otherStore.fingerprint() == oldFingerprint)
    otherStore.close()
    let reference = try SecretReference("mop://v/i/f")
    try store.write(reference, value: "before rotation", replace: false)
    let oldSnapshot = try disk.read()
    try store.revoke(removed.request.fingerprint, currentDevice: first.publicKey)
    let rotated = try disk.read()
    #expect(try store.fingerprint() != oldFingerprint)
    #expect(throws: MopError.vaultUntrusted) { try FileSecretStore(disk: otherDisk, snapshot: rotated, opener: second) }
    try FileSecretStore.establishTrust(disk: otherDisk, opener: second, fingerprint: store.fingerprint())
    let trusted = try FileSecretStore(disk: otherDisk, snapshot: rotated, opener: second)
    #expect(try trusted.read(reference) == "before rotation")
    trusted.close()
    #expect(throws: MopError.vaultUntrusted) { try FileSecretStore(disk: disk, snapshot: oldSnapshot, opener: first) }
    try FileSecretStore.resolve(disk: disk, revision: VaultCoding.digest(oldSnapshot), opener: first)
    let restored = try FileSecretStore(disk: disk, snapshot: disk.read(), opener: first)
    #expect(try restored.fingerprint() == store.fingerprint())
    #expect(try restored.read(reference) == "before rotation")
    restored.close()
    // A replacement Mac can bootstrap using independently verified backup bytes.
    let replacement = VaultDisk(url: disk.url, trustDirectory: directory.appendingPathComponent("replacement-trust"))
    try FileSecretStore.establishTrust(disk: replacement, opener: recovery, revision: VaultCoding.digest(disk.read()))
    let recovered = try FileSecretStore(disk: replacement, snapshot: replacement.read(), opener: recovery)
    #expect(try recovered.read(reference) == "before rotation")
    recovered.close()
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

@Test func changingVaultIdentityOrLosingPinsNeverEstablishesTrust() throws {
    let (directory, disk, device, recovery) = try fixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let original = try disk.read()
    let other = VaultDisk(url: directory.appendingPathComponent("other-vault"), trustDirectory: directory.appendingPathComponent("other-pins"))
    try FileSecretStore.initialize(disk: other, device: device.request, recovery: recovery)
    #expect(throws: MopError.vaultUntrusted) { try FileSecretStore(disk: disk, snapshot: other.read(), opener: device) }
    try FileManager.default.removeItem(at: directory.appendingPathComponent("local-trust"))
    #expect(throws: MopError.vaultUntrusted) { try FileSecretStore(disk: disk, snapshot: original, opener: device) }
    #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("local-trust").path))
}
