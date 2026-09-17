// Audit probes: disposable software keys only, no production vault/authentication.
import CryptoKit
import Darwin
import Foundation
import MopCore
import MopVault

struct FixtureDevice: VaultKeyOpener {
    let key = P256.KeyAgreement.PrivateKey()
    var publicKey: Data { key.publicKey.x963Representation }
    var request: DeviceRequest { try! DeviceRequest(name: "Audit fixture", publicKey: publicKey) }
    func unwrap(_ recipient: VaultRecipient, vaultID: UUID) throws -> SymmetricKey {
        try VaultDocument.unwrap(recipient, vaultID: vaultID, privateKey: key)
    }
}
func run(_ path: String, _ arguments: [String]) throws {
    let p = Process(); p.executableURL = URL(fileURLWithPath: path); p.arguments = arguments
    try p.run(); p.waitUntilExit()
    guard p.terminationStatus == 0 else { throw NSError(domain: "audit-command", code: Int(p.terminationStatus)) }
}
let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-audit-" + UUID().uuidString)
try SafeFile.privateDirectory(root)
defer { try? FileManager.default.removeItem(at: root) }

// Canonically equal Strings can carry different secret bytes.
let composed = "audit-\u{00e9}-token"
let decomposed = "audit-e\u{0301}-token"
var masker = SecretMasker(patterns: MaskPatterns(secrets: [composed, decomposed]))
let result = masker.consume(Data((composed + "|" + decomposed).utf8), final: true)
let masked = Data("[concealed by mop]|[concealed by mop]".utf8)
precondition(result == masked)
print("UNICODE: byte-distinct secrets=\(Data(composed.utf8) != Data(decomposed.utf8)), both masked=\(result == masked)")

// Recovery writes strip inherited ACLs; private directories reject allow ACLs.
let aclRoot = root.appendingPathComponent("acl")
try SafeFile.privateDirectory(aclRoot)
try run("/bin/chmod", ["+a", "everyone allow read,search,file_inherit,directory_inherit", aclRoot.path])
let recoveryFile = aclRoot.appendingPathComponent("recovery.key")
try RecoveryKey().save(to: recoveryFile)
_ = try SafeFile.read(recoveryFile, privateFile: true)
do {
    try SafeFile.privateDirectory(aclRoot)
    fatalError("Unsafe directory ACL accepted")
} catch MopError.filePermissions { }
print("ACL: recovery ACL stripped; unsafe directory rejected:")
try run("/bin/ls", ["-lde", aclRoot.path, recoveryFile.path])
let output = aclRoot.appendingPathComponent("output")
try OutputFile(url: output, force: false, mode: 0o600, protectedFiles: [], protectedDirectories: []).write(Data("fixture".utf8))
print("ACL: OutputFile comparison (final ACL stripped):")
try run("/bin/ls", ["-le", output.path])

let disk = VaultDisk(url: root.appendingPathComponent("vault"), trustDirectory: root.appendingPathComponent("trust"))
let victim = FixtureDevice()
let recovery = RecoveryKey()
try FileSecretStore.initialize(disk: disk, device: victim.request, recovery: recovery)
let original = try disk.read()
let publicDocument = try VaultDocument.decode(original)
let attacker = FixtureDevice()
let attackerKey = SymmetricKey(size: .bits256)
var forgedHeader = publicDocument.header
forgedHeader.generation += 1
forgedHeader.parent = VaultCoding.digest(original)
// The attacker uses only public metadata to rewrap a key they chose.
forgedHeader.recipients = try publicDocument.header.recipients.map { slot in
    let request = try DeviceRequest(name: slot.name, publicKey: slot.publicKey)
    return try VaultDocument.wrap(key: attackerKey, request: request, kind: slot.kind, vaultID: publicDocument.header.vaultID)
}
forgedHeader.recipients.append(try VaultDocument.wrap(key: attackerKey, request: attacker.request, kind: "device", vaultID: publicDocument.header.vaultID))
let forged = try VaultCoding.encode(VaultDocument.seal(header: forgedHeader, index: [:], records: [:], key: attackerKey))
try SafeFile.write(forged, to: disk.url, replace: true)
do {
    _ = try FileSecretStore(disk: disk, snapshot: disk.read(), opener: victim)
    fatalError("Forged vault accepted")
} catch MopError.vaultUntrusted {
    print("FORGERY: replacement rejected before any future secret can be written")
}

// Replay an older valid file after revocation, then accept a new write.
let replayDisk = VaultDisk(url: root.appendingPathComponent("replay"), trustDirectory: root.appendingPathComponent("trust"))
try FileSecretStore.initialize(disk: replayDisk, device: victim.request, recovery: recovery)
let first = try FileSecretStore(disk: replayDisk, snapshot: replayDisk.read(), opener: victim)
try first.enroll(attacker.request, expectedFingerprint: attacker.request.fingerprint)
let beforeRevocation = try replayDisk.read()
try first.revoke(attacker.request.fingerprint, currentDevice: victim.publicKey)
first.close()
try SafeFile.write(beforeRevocation, to: replayDisk.url, replace: true)
do {
    _ = try FileSecretStore(disk: replayDisk, snapshot: replayDisk.read(), opener: victim)
    fatalError("Revoked-key replay accepted")
} catch MopError.vaultUntrusted {
    print("REPLAY: old encryption key rejected by the updated local pin")
}
