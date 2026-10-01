import CryptoKit
import Foundation
import Testing
import MopCore
@testable import MopVaultNext

/// Software keys deliberately exist only in this test target. These tests do not
/// establish Enclave behavior, Apple Account identity, or CloudKit permissions.
final class TestDevice: DeviceOperations {
    let identity: DevicePublicKey
    private var encryption: P256.KeyAgreement.PrivateKey?
    private var signing: P256.Signing.PrivateKey?
    var unwrappedContexts: [Data] = []
    init(member: UUID = UUID()) throws {
        let encryption = P256.KeyAgreement.PrivateKey(), signing = P256.Signing.PrivateKey()
        identity = try DevicePublicKey(member: member, encryption: encryption.publicKey.x963Representation, signing: signing.publicKey.x963Representation)
        self.encryption = encryption; self.signing = signing
    }
    func sign(_ bytes: Data) throws -> Data {
        guard let signing else { throw MopError.authentication }
        return try signing.signature(for: bytes).rawRepresentation
    }
    func unwrap(_ envelope: KeyEnvelope, context: Data) throws -> SymmetricKey {
        guard let encryption else { throw MopError.authentication }
        unwrappedContexts.append(context)
        return try envelope.open(using: encryption, context: context)
    }
    func close() { encryption = nil; signing = nil }
}

private func text(_ value: SecretBytes) -> String { String(decoding: value, as: UTF8.self) }
private func add(_ device: TestDevice, role: MemberRole, to vault: VerifiedVault, owner: TestDevice) throws -> VerifiedVault {
    let now = Date(timeIntervalSince1970: 1_000)
    let invite = try VaultEngine.invite(member: device.identity.member, role: role, to: vault, owner: owner, now: now, expires: now.addingTimeInterval(100))
    let accepted = try Acceptance(invitation: invite, expectedCheckpoint: vault.digest, device: device, now: now)
    return try VaultEngine.approve(accepted, expectedDeviceFingerprint: device.identity.fingerprint, in: vault, owner: owner, now: now)
}

@Test func twoAccountsFourDevicesEnrollmentRemovalAndRecovery() throws {
    let a1 = try TestDevice(), a2 = try TestDevice(member: a1.identity.member)
    let b1 = try TestDevice(), b2 = try TestDevice(member: b1.identity.member)
    let recovery = try TestDevice(member: a1.identity.member)
    var vault = try VaultEngine.create(name: "shared", owner: a1, recovery: recovery.identity)
    #expect(vault.membership.accounts.count == 1)
    vault = try VaultEngine.write("service/password", value: SecretBytes(copying: Data("first".utf8)), in: vault, device: a1)
    #expect(throws: MopError.notVaultMember) { try VaultEngine.read("service/password", in: vault, device: a2) }
    let beforeEnrollment = vault
    vault = try add(a2, role: .owner, to: vault, owner: a1)
    // Addition rewraps existing keys without decrypting/resealing values.
    #expect(vault.revision.records.mapValues(\.ciphertext) == beforeEnrollment.revision.records.mapValues(\.ciphertext))
    vault = try add(b1, role: .editor, to: vault, owner: a2)
    vault = try add(b2, role: .editor, to: vault, owner: a1)
    #expect(vault.membership.accounts.count == 2)
    #expect(vault.membership.devices.count == 4)
    for device in [a1, a2, b1, b2] {
        #expect(try text(VaultEngine.read("service/password", in: vault, device: device)) == "first")
    }
    let stale = try VaultEngine.write("service/password", value: SecretBytes(copying: Data("stale".utf8)), in: vault, device: b1)
    let copied = vault
    vault = try VaultEngine.remove(device: b1.identity.device, from: vault, owner: a2)
    #expect(Set(vault.revision.records.keys).isDisjoint(with: copied.revision.records.keys))
    #expect(throws: MopError.notVaultMember) { try VaultEngine.read("service/password", in: vault, device: b1) }
    #expect(throws: MopError.vaultUntrusted) { try vault.applying(stale.bytes) }
    #expect(try text(VaultEngine.read("service/password", in: copied, device: b1)) == "first") // irrevocable old copy
    vault = try VaultEngine.write("service/password", value: SecretBytes(copying: Data("new".utf8)), in: vault, device: b2)
    #expect(try text(VaultEngine.read("service/password", in: vault, device: a1)) == "new")
    vault = try VaultEngine.remove(member: b2.identity.member, from: vault, owner: a1)
    #expect(throws: MopError.notVaultMember) { try VaultEngine.read("service/password", in: vault, device: b2) }
    let replacement = try TestDevice(member: a1.identity.member), nextRecovery = try TestDevice(member: a1.identity.member)
    vault = try VaultEngine.recover(vault, using: recovery, owner: replacement.identity)
    #expect(vault.membership.devices.contains(replacement.identity))
    #expect(vault.membership.devices.contains(a1.identity))
    #expect(try text(VaultEngine.read("service/password", in: vault, device: replacement)) == "new")
    #expect(try text(VaultEngine.read("service/password", in: vault, device: a1)) == "new")
    #expect(try text(VaultEngine.read("service/password", in: vault, device: recovery)) == "new")
}

@Test func rolesAndFreshAccountRecovery() throws {
    let owner = try TestDevice(), viewer = try TestDevice(), recovery = try TestDevice(member: owner.identity.member)
    var vault = try VaultEngine.create(name: "personal", owner: owner, recovery: recovery.identity)
    vault = try VaultEngine.write("login/password", value: SecretBytes(copying: Data("secret".utf8)), in: vault, device: owner)
    vault = try add(viewer, role: .viewer, to: vault, owner: owner)
    #expect(try text(VaultEngine.read("login/password", in: vault, device: viewer)) == "secret")
    #expect(throws: MopError.cloudPermission) { try VaultEngine.write("login/password", value: nil, in: vault, device: viewer) }
    #expect(throws: MopError.cloudPermission) { try VaultEngine.remove(member: owner.identity.member, from: vault, owner: viewer) }
    #expect(throws: MopError.cloudPermission) { try VaultEngine.setRole(.editor, member: viewer.identity.member, in: vault, owner: viewer) }
    vault = try VaultEngine.setRole(.editor, member: viewer.identity.member, in: vault, owner: owner)
    vault = try VaultEngine.write("login/password", value: SecretBytes(copying: Data("edited".utf8)), in: vault, device: viewer)
    let newOwner = try TestDevice(), newRecovery = try TestDevice()
    #expect(throws: MopError.invalidRecovery) { try VaultEngine.recover(vault, using: recovery, owner: newOwner.identity) }

}

@Test func invitationExpiryFingerprintAndReplay() throws {
    let owner = try TestDevice(), next = try TestDevice(), recovery = try TestDevice(member: owner.identity.member)
    let vault = try VaultEngine.create(name: "personal", owner: owner, recovery: recovery.identity)
    let now = Date(timeIntervalSince1970: 1_000)
    let invitation = try VaultEngine.invite(member: next.identity.member, role: .viewer, to: vault, owner: owner, now: now, expires: now.addingTimeInterval(100))
    #expect(throws: MopError.vaultUntrusted) { try Acceptance(invitation: invitation, expectedCheckpoint: String(repeating: "0", count: 64), device: next, now: now) }
    #expect(throws: MopError.invalidIdentity) { try Acceptance(invitation: invitation, expectedCheckpoint: vault.digest, device: next, now: now.addingTimeInterval(101)) }
    let acceptance = try Acceptance(invitation: invitation, expectedCheckpoint: vault.digest, device: next, now: now)
    #expect(throws: MopError.vaultUntrusted) { try VaultEngine.approve(acceptance, expectedDeviceFingerprint: owner.identity.fingerprint, in: vault, owner: owner, now: now) }
    let granted = try VaultEngine.approve(acceptance, expectedDeviceFingerprint: next.identity.fingerprint, in: vault, owner: owner, now: now)
    #expect(throws: MopError.vaultUntrusted) { try VaultEngine.approve(acceptance, expectedDeviceFingerprint: next.identity.fingerprint, in: granted, owner: owner, now: now) }
    let edited = try VaultEngine.write("x/password", value: SecretBytes(copying: Data("x".utf8)), in: vault, device: owner)
    #expect(throws: MopError.vaultUntrusted) { try VaultEngine.approve(acceptance, expectedDeviceFingerprint: next.identity.fingerprint, in: edited, owner: owner, now: now) }
}

@Test func catalogAndRequestedSecretOnlyAreUnwrapped() throws {
    let owner = try TestDevice(), recovery = try TestDevice(member: owner.identity.member)
    var vault = try VaultEngine.create(name: "personal", owner: owner, recovery: recovery.identity)
    for i in 0..<3 { vault = try VaultEngine.write("item\(i)/password", value: SecretBytes(copying: Data("value\(i)".utf8)), in: vault, device: owner) }
    owner.unwrappedContexts = []
    #expect(try VaultEngine.references(in: vault, device: owner).count == 3)
    #expect(owner.unwrappedContexts.count == 1)
    owner.unwrappedContexts = []
    #expect(try text(VaultEngine.read("item1/password", in: vault, device: owner)) == "value1")
    #expect(owner.unwrappedContexts.count == 2)
    let snapshot = String(decoding: vault.bytes, as: UTF8.self)
    #expect(!snapshot.contains("item1") && !snapshot.contains("value1"))
    owner.close()
    #expect(throws: MopError.authentication) { try VaultEngine.read("item1/password", in: vault, device: owner) }
}

@Test func signedSelfPromotionAndCrossVaultSubstitutionFail() throws {
    let owner = try TestDevice(), editor = try TestDevice(), recovery = try TestDevice(member: owner.identity.member)
    var vault = try VaultEngine.create(name: "personal", owner: owner, recovery: recovery.identity)
    vault = try add(editor, role: .editor, to: vault, owner: owner)
    let malicious = try Membership(accounts: [AccountMember(id: editor.identity.member, role: .owner, devices: [editor.identity])])
    let header = Revision.Header(requiredFeatures: vault.revision.header.requiredFeatures, format: "mop-vault-v7", vault: vault.id, name: vault.name, generation: vault.generation + 1,
        parent: vault.digest, epoch: vault.revision.header.epoch + 1, membership: malicious, operation: .membership,
        acceptedInvitations: vault.revision.header.acceptedInvitations)
    let forged = try Revision.seal(header: header, references: [:], records: [:], signer: editor)
    #expect(throws: MopError.cloudPermission) { try vault.applying(forged.encoded()) }
    let unrelated = try VaultEngine.create(name: "other", owner: owner, recovery: recovery.identity)
    let update = try VaultEngine.write("item/password", value: SecretBytes(copying: Data("value".utf8)), in: unrelated, device: owner)
    #expect(throws: MopError.vaultUntrusted) { try vault.applying(update.bytes) }
    #expect(throws: MopError.vaultUntrusted) { try VerifiedVault(checkpoint: vault.bytes, independentlyVerifiedDigest: unrelated.digest) }
    var altered = vault.bytes
    altered.append(0x20)
    #expect(throws: MopError.invalidVault) { try Revision.decode(altered) }
}

@Test func backupCheckpointAndOfflineRecoveryRotation() throws {
    let owner = try TestDevice(), recovery = try TestDevice(member: owner.identity.member), replacement = try TestDevice(member: owner.identity.member)
    var vault = try VaultEngine.create(name: "personal", owner: owner, recovery: recovery.identity)
    vault = try VaultEngine.write("item/password", value: SecretBytes(copying: Data("value".utf8)), in: vault, device: owner)
    let imported = try VerifiedVault(checkpoint: vault.bytes, independentlyVerifiedDigest: vault.digest)
    #expect(try text(VaultEngine.read("item/password", in: imported, device: recovery)) == "value")
    let rotated = try VaultEngine.setOfflineRecovery(replacement.identity, in: vault, owner: owner)
    #expect(throws: MopError.notVaultMember) { try VaultEngine.read("item/password", in: rotated, device: recovery) }
    #expect(try text(VaultEngine.read("item/password", in: rotated, device: replacement)) == "value")
    #expect(Set(vault.revision.records.keys).isDisjoint(with: rotated.revision.records.keys))
}

@Test func recoveryDeviceCanBelongToOwnersAccountWithoutOrdinaryMembership() throws {
    let owner = try TestDevice(), recovery = try TestDevice(member: owner.identity.member)
    let vault = try VaultEngine.create(name: "personal", owner: owner, recovery: recovery.identity)
    #expect(vault.membership.role(of: recovery.identity) == nil)
    #expect(throws: MopError.cloudPermission) {
        try VaultEngine.write("item/password", value: SecretBytes(utf8: "value"), in: vault, device: recovery)
    }
    let replacement = try TestDevice(member: owner.identity.member), nextRecovery = try TestDevice(member: owner.identity.member)
    let restored = try VaultEngine.recover(vault, using: recovery, owner: replacement.identity)
    #expect(restored.membership.devices.contains(replacement.identity))
    #expect(restored.membership.devices.contains(owner.identity))
}
