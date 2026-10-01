import Foundation
import Testing
import MopCore
import MopCredentials
@testable import MopVaultNext

@Test func cloudKeyPayloadsAreConcealedAndVersionGated() throws {
    let owner = try TestDevice(), key = try CloudKey.generate(.ed25519)
    let item = try key.item(name: "ssh", purposes: [.ssh])
    let root = try VaultEngine.create(name: "personal", owner: owner)
    let vault = try VaultEngine.saveItem(.init(revision: root.digest, item: item, create: true), in: root, device: owner)
    #expect(vault.revision.header.requiredFeatures?.contains("key-credentials-1") == true)
    let catalog = try VaultEngine.catalog(in: vault, device: owner)
    #expect(catalog.items[0].credential == item.credential)
    #expect(catalog.items[0].fields.allSatisfy { $0.value == nil })
    let raw = try VaultEngine.read("ssh/credentialPrivateKey", in: vault, device: owner)
    #expect(raw == SecretBytes(utf8: item.fields[0].value!))
    #expect(!String(decoding: vault.bytes, as: UTF8.self).contains(item.fields[0].value!))
    var downgraded = catalog.items[0]; downgraded.credential = nil
    #expect(throws: (any Error).self) { try VaultEngine.saveItem(.init(revision: vault.digest, item: downgraded, create: false), in: vault, device: owner) }
    var malformed = item; malformed.credential?.publicKey = Data([0])
    #expect(throws: (any Error).self) { try VaultEngine.saveItem(.init(revision: root.digest, item: malformed, create: true), in: root, device: owner) }
}
@Test func cloudKeysFollowMembershipAndRevocation() throws {
    let owner = try TestDevice(), peer = try TestDevice()
    var vault = try VaultEngine.create(name: "personal", owner: owner)
    let item = try CloudKey.generate(.p256).item(name: "ssh", purposes: [.gitSigning])
    vault = try VaultEngine.saveItem(.init(revision: vault.digest, item: item, create: true), in: vault, device: owner)
    let invitation = try VaultEngine.invite(member: peer.identity.member, role: .viewer, to: vault, owner: owner, expires: Date().addingTimeInterval(300))
    let acceptance = try Acceptance(invitation: invitation, expectedCheckpoint: vault.digest, device: peer)
    vault = try VaultEngine.approve(acceptance, expectedDeviceFingerprint: peer.identity.fingerprint, in: vault, owner: owner)
    #expect(try VaultEngine.read("ssh/credentialPrivateKey", in: vault, device: peer) == SecretBytes(utf8: item.fields[0].value!))
    #expect(try VaultEngine.catalog(in: vault, device: peer).canEdit == false)
    #expect(throws: MopError.cloudPermission) { try VaultEngine.saveItem(.init(revision: vault.digest, item: item, create: false), in: vault, device: peer) }
    vault = try VaultEngine.remove(device: peer.identity.device, from: vault, owner: owner)
    #expect(throws: (any Error).self) { try VaultEngine.read("ssh/credentialPrivateKey", in: vault, device: peer) }
    #expect(try VaultEngine.read("ssh/credentialPrivateKey", in: vault, device: owner) == SecretBytes(utf8: item.fields[0].value!))
}

@Test func cloudCredentialRecoveryPreservesPrivateMaterialAndPasskeyIdentifiers() throws {
    let owner = try TestDevice(), recovery = try TestDevice(member: owner.identity.member), replacement = try TestDevice(member: owner.identity.member)
    let key = try CloudKey.generate(.p256)
    var item = try key.item(name: "passkey", purposes: [.ssh]); item.type = .passkey
    item.credential = KeyCredential(algorithm: .p256, publicKey: key.publicKey, purposes: [.passkey], relyingParty: "example.com", userName: "alice", userHandle: Data([1]), credentialID: Data(repeating: 7, count: 32))
    var vault = try VaultEngine.create(name: "personal", owner: owner, recovery: recovery.identity)
    vault = try VaultEngine.saveItem(.init(revision: vault.digest, item: item, create: true), in: vault, device: owner)
    vault = try VaultEngine.recover(vault, using: recovery, owner: replacement.identity)
    #expect(try VaultEngine.catalog(in: vault, device: replacement).items[0].credential == item.credential)
    #expect(try VaultEngine.read("passkey/credentialPrivateKey", in: vault, device: replacement) == SecretBytes(utf8: item.fields[0].value!))
}
