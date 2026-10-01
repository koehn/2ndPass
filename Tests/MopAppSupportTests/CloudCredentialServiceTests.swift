import CryptoKit
import Foundation
import Synchronization
import Testing
import MopCore
@testable import MopCredentials
@testable import MopAppSupport

private final class CredentialVaultFixture: VaultService, @unchecked Sendable {
    struct State { var catalog = ItemCatalog(vault: "personal", revision: "r1", items: []); var saved: [String: SecretBytes] = [:]; var active = true; var generation = 0; var failSave = false }
    let state = Mutex(State())
    var authenticatedAt: TimeInterval? { state.withLock { $0.active ? 1 : nil } }
    var sessionGeneration: Int { state.withLock { $0.generation } }
    func lock() { state.withLock { $0.active = false; $0.generation += 1 } }
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult {
        try state.withLock { state in
            guard state.active else { throw MopError.authentication }
            var result = VaultResult()
            switch operation {
            case .catalog:
                var catalog = state.catalog; catalog.canEdit = true; result.catalog = catalog
            case .save(let edit):
                if state.failSave { throw MopError.cloudUnavailable }
                var item = edit.item; item.storageID = UUID().uuidString
                for index in item.fields.indices where item.fields[index].type.concealed {
                    if let value = item.fields[index].value { state.saved[SecretReference.encode(item.name) + "/" + item.fields[index].path] = SecretBytes(utf8: value) }
                    item.fields[index].value = nil
                }
                state.catalog.items.append(item); result.catalog = state.catalog
            case .read(let reference): result.value = state.saved[reference.relativePath]
            default: throw MopError.notFound
            }
            return result
        }
    }
}
@Test func cloudPasskeyCeremonyPreservesKeyIdentityAndIsolation() async throws {
    let vault = CredentialVaultFixture(), id = UUID().uuidString
    let service = CloudCredentialService(vault), hash = Data(repeating: 1, count: 32)
    let row = try await service.registerPasskey(vault: id, relyingParty: "example.com", userName: "alice", userHandle: Data([1]), clientDataHash: hash, algorithms: [-7])
    #expect(row.item.fields.allSatisfy { $0.value == nil })
    let assertion = try await service.assertPasskey(row, relyingParty: "example.com", allowed: [], clientDataHash: hash)
    #expect(assertion.authenticatorData[32] == 0x1d)
    let publicKey = try P256.Signing.PublicKey(x963Representation: row.credential.publicKey)
    #expect(publicKey.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: assertion.signature), for: assertion.authenticatorData + hash))
    await #expect(throws: (any Error).self) { try await service.assertPasskey(row, relyingParty: "other.example.com", allowed: [], clientDataHash: hash) }
    await #expect(throws: (any Error).self) { try await service.assertPasskey(row, relyingParty: "example.com", allowed: [Data([7])], clientDataHash: hash) }
    let suggestion = try #require(AutoFillIdentity(passkey: row.item, vaultID: id))
    #expect(AutoFillEntry.vaultID(suggestion.recordIdentifier) == id)
    #expect(suggestion.credentialID == row.credential.credentialID)
    #expect(AutoFillIdentity(passkey: row.item, vaultID: UUID().uuidString)?.recordIdentifier != suggestion.recordIdentifier)
    vault.lock()
    await #expect(throws: (any Error).self) { try await service.assertPasskey(row, relyingParty: "example.com", allowed: [], clientDataHash: hash) }
}
@Test func failedCloudRegistrationAndLocalImportsFailClosed() async throws {
    let vault = CredentialVaultFixture(), service = CloudCredentialService(vault)
    vault.state.withLock { $0.failSave = true }
    await #expect(throws: MopError.cloudUnavailable) { try await service.registerPasskey(vault: UUID().uuidString, relyingParty: "example.com", userName: "alice", userHandle: Data([1]), clientDataHash: Data(repeating: 1, count: 32), algorithms: [-7]) }
    #expect(vault.state.withLock { $0.catalog.items.isEmpty })
    await #expect(throws: CredentialFailure.localImport) { try await service.importSSH(vault: "local", name: "test", bytes: "invalid", purposes: [.ssh]) }
}

private func openSSHFixture(_ key: CloudKey) -> String {
    let publicBytes = Data(key.publicKey.suffix(32))
    var payload = SSHWire.uint32(7) + SSHWire.uint32(7) + SSHWire.text("ssh-ed25519")
    payload += SSHWire.string(publicBytes) + SSHWire.string(Data(key.privateBytes) + publicBytes) + SSHWire.text("test")
    var padding: UInt8 = 1
    while payload.count % 8 != 0 { payload.append(padding); padding += 1 }
    let data = Data("openssh-key-v1\0".utf8) + SSHWire.text("none") + SSHWire.text("none") + SSHWire.string(Data()) + SSHWire.uint32(1) + SSHWire.string(key.sshBlob) + SSHWire.string(payload)
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + data.base64EncodedString() + "\n-----END OPENSSH PRIVATE KEY-----"
}

@Test func sshSaveDerivesPublicDataAndPreservesDraftEdits() async throws {
    let vault = CredentialVaultFixture(), service = CloudCredentialService(vault)
    let key = try CloudKey.generate(.ed25519)
    var item = VaultItem(name: "renamed", type: .sshKey, fields: [
        ItemField(path: "privateKey", type: .privateKey),
        ItemField(path: "publicKey", value: "untrusted public key"),
        ItemField(path: "fingerprint", value: "untrusted fingerprint"),
        ItemField(path: "notes", type: .notes, value: "Edited notes")
    ])
    item.metadata = ItemMetadata(); item.metadata?.tags = ["edited"]
    vault.state.withLock { $0.saved["original/privateKey"] = SecretBytes(utf8: openSSHFixture(key)) }
    let edit = ItemEdit(revision: "r1", item: item, create: false, originalName: "original")
    let prepared = try await service.prepareSSHSave(edit, vault: "personal", purpose: .gitSigning)
    #expect(prepared.revision == "r1" && prepared.originalName == "original" && !prepared.create)
    #expect(prepared.item.name == "renamed" && prepared.item.metadata == item.metadata)
    #expect(prepared.item.credential?.publicKey == key.publicKey)
    #expect(prepared.item.credential?.purposes == [.gitSigning])
    #expect(prepared.item.fields.first { $0.path == "notes" }?.value == "Edited notes")
    #expect(!prepared.item.fields.contains { ["privateKey", "passphrase", "fingerprint", "publicKey"].contains($0.path) })
    let encoded = try #require(prepared.item.fields.first { $0.path == KeyCredential.privateField }?.value)
    let restored = try CloudKey(algorithm: .ed25519, privateBytes: SecretBytes(copying: #require(Data(base64Encoded: encoded))))
    #expect(restored.publicKey == key.publicKey)
    let again = try await service.prepareSSHSave(prepared, vault: "personal")
    #expect(again.item == prepared.item)
    var stale = edit; stale.revision = "old"
    await #expect(throws: MopError.vaultConflict) { try await service.prepareSSHSave(stale, vault: "personal") }
    await #expect(throws: CredentialFailure.localImport) { try await service.prepareSSHSave(edit, vault: "local") }
}

@Test func newSSHSaveValidatesBeforeWriting() async throws {
    let vault = CredentialVaultFixture(), service = CloudCredentialService(vault)
    let key = try CloudKey.generate(.ed25519)
    var item = VaultItem(name: "new", type: .sshKey, fields: [ItemField(path: "privateKey", type: .privateKey, value: openSSHFixture(key))])
    let prepared = try await service.prepareSSHSave(ItemEdit(revision: "r1", item: item, create: true), vault: "personal")
    #expect(prepared.create && prepared.item.credential?.publicKey == key.publicKey)
    item.fields[0].value = "not a private key"
    await #expect(throws: CredentialFailure.unsupportedFormat) {
        try await service.prepareSSHSave(ItemEdit(revision: "r1", item: item, create: true), vault: "personal")
    }
    #expect(vault.state.withLock { $0.catalog.items.isEmpty })
}

#if os(macOS)
@Test func encryptedSSHSaveUsesPassphraseWithoutKeepingIt() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let file = directory.appendingPathComponent("key")
    let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    process.arguments = ["-q", "-t", "ed25519", "-N", "test passphrase", "-f", file.path]
    try process.run(); process.waitUntilExit(); #expect(process.terminationStatus == 0)
    let pem = try String(contentsOf: file, encoding: .utf8)
    let vault = CredentialVaultFixture(), service = CloudCredentialService(vault)
    var item = VaultItem(name: "encrypted", type: .sshKey, fields: [ItemField(path: "privateKey", type: .privateKey, value: pem)])
    let edit = ItemEdit(revision: "r1", item: item, create: true)
    await #expect(throws: CredentialFailure.passphraseRequired) { try await service.prepareSSHSave(edit, vault: "personal") }
    await #expect(throws: CredentialFailure.incorrectPassphrase) { try await service.prepareSSHSave(edit, vault: "personal", passphrase: "wrong") }
    let prepared = try await service.prepareSSHSave(edit, vault: "personal", passphrase: "test passphrase")
    #expect(prepared.item.credential?.algorithm == .ed25519)
    #expect(!prepared.item.fields.contains { $0.path == "passphrase" || $0.value == pem })
    // Existing items may already contain a concealed passphrase.
    item.fields.append(ItemField(path: "passphrase", type: .password))
    vault.state.withLock { $0.saved["encrypted/passphrase"] = "test passphrase" }
    let existing = try await service.prepareSSHSave(ItemEdit(revision: "r1", item: item, create: false), vault: "personal")
    #expect(existing.item.credential?.publicKey == prepared.item.credential?.publicKey)
}
#endif

private final class PasskeyDiscoveryFixture: VaultService, @unchecked Sendable {
    let readable: String
    let unavailable = UUID().uuidString
    let catalog: ItemCatalog
    let state = Mutex((generation: 0, lockOnRead: false))
    init(catalog: ItemCatalog, readable: String) { self.catalog = catalog; self.readable = readable }
    var authenticatedAt: TimeInterval? { 1 }
    var sessionGeneration: Int { state.withLock { $0.generation } }
    func lock() { state.withLock { $0.generation += 1 } }
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult {
        var result = VaultResult()
        switch operation {
        case .discover:
            result.vaults = [unavailable, readable].map { VaultDescriptor(id: $0, name: "vault", format: "mop-vault-v7", enrolled: true) }
        case .catalog:
            if state.withLock({ $0.lockOnRead }) { lock(); throw MopError.authentication }
            guard vault == readable else { throw MopError.cloudUnavailable }
            result.catalog = catalog
        default: throw MopError.invalidVault
        }
        return result
    }
}

@Test func cloudPasskeyDiscoverySurvivesUnavailableVaultAndChecksScope() async throws {
    let store = CredentialVaultFixture(), id = UUID().uuidString
    let row = try await CloudCredentialService(store).registerPasskey(vault: id, relyingParty: "example.com", userName: "alice", userHandle: Data([1]), clientDataHash: Data(repeating: 1, count: 32), algorithms: [-7])
    var catalog = ItemCatalog(vault: "personal", revision: "r1", items: [row.item]); catalog.canEdit = false
    let fixture = PasskeyDiscoveryFixture(catalog: catalog, readable: id)
    let service = CloudCredentialService(fixture)
    let found = try await service.discoverPasskeys(relyingParty: "example.com", allowed: [], registration: false)
    #expect(found.unavailableVaults == 1 && found.records.count == 1)
    #expect(found.records.first?.vault == id && found.vaults.count == 1)
    #expect(found.records.first?.item.fields.allSatisfy { $0.value == nil } == true)
    let otherRP = try await service.discoverPasskeys(relyingParty: "other.example.com", allowed: [], registration: false)
    #expect(otherRP.records.isEmpty)
    let denied = try await service.discoverPasskeys(relyingParty: "example.com", allowed: [Data(repeating: 2, count: 32)], registration: false)
    #expect(denied.records.isEmpty)
    let allowed = try await service.discoverPasskeys(relyingParty: "example.com", allowed: [#require(row.credential.credentialID)], registration: false)
    #expect(allowed.records.count == 1)
    let registration = try await service.discoverPasskeys(relyingParty: "example.com", allowed: [], registration: true)
    #expect(registration.vaults.isEmpty) // Viewers may use passkeys, but cannot create them.
    fixture.state.withLock { $0.lockOnRead = true }
    await #expect(throws: MopError.authentication) { try await service.discoverPasskeys(relyingParty: "example.com", allowed: [], registration: false) }
}

@Test func passkeyPickerReadsPublicIndexWhileLockedAndRevalidatesSelection() async throws {
    let vault = CredentialVaultFixture(), id = UUID().uuidString
    let service = CloudCredentialService(vault)
    let row = try await service.registerPasskey(vault: id, relyingParty: "example.com", userName: "alice", userHandle: Data([1]), clientDataHash: Data(repeating: 1, count: 32), algorithms: [-7])
    let suggestion = try #require(AutoFillIdentity(passkey: row.item, vaultID: id))
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let index = AutoFillIndex(directory: directory)
    try index.update { _ in [suggestion] }
    vault.lock()
    let listed = try index.load().filter { $0.matchesPasskey(relyingParty: "example.com", allowed: []) }
    #expect(listed == [suggestion])
    #expect(!suggestion.matchesPasskey(relyingParty: "other.example.com", allowed: []))
    #expect(!suggestion.matchesPasskey(relyingParty: "example.com", allowed: [Data(repeating: 9, count: 32)]))
    let credentialID = try #require(suggestion.credentialID)
    #expect(suggestion.matchesPasskey(relyingParty: "example.com", allowed: [credentialID]))
    await #expect(throws: MopError.authentication) { try await service.resolvePasskey(suggestion, relyingParty: "example.com", allowed: []) }
    vault.state.withLock { $0.active = true }
    let resolved = try await service.resolvePasskey(suggestion, relyingParty: "example.com", allowed: [])
    #expect(resolved.credential == row.credential)
    var forged = suggestion; forged.userHandle = Data([2])
    await #expect(throws: MopError.notFound) { try await service.resolvePasskey(forged, relyingParty: "example.com", allowed: []) }
    vault.state.withLock { $0.catalog.items = [] }
    #expect(try index.load() == [suggestion]) // A stale index grants no access.
    await #expect(throws: MopError.notFound) { try await service.resolvePasskey(suggestion, relyingParty: "example.com", allowed: []) }
}
