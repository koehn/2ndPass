import Foundation
import Testing
import MopCore
@testable import MopVaultNext

@Test func typedItemEditsAndRemovalPreserveOnlyCurrentEncryptedFields() throws {
    let owner = try TestDevice(), recovery = try TestDevice()
    var vault = try VaultEngine.create(name: "personal", owner: owner, recovery: recovery.identity)
    let item = VaultItem(name: "login", type: .login, fields: [ItemField(path: "username", type: .username, value: "alice"), ItemField(path: "password", type: .password, value: "secret")])
    vault = try VaultEngine.saveItem(ItemEdit(revision: vault.digest, item: item, create: true), in: vault, device: owner)
    let catalog = try VaultEngine.catalog(in: vault, device: owner)
    #expect(catalog.items[0].fields[1].value == nil)
    #expect(catalog.items[0].fields[0].value == "alice")
    var renamed = catalog.items[0]; renamed.name = "renamed"
    vault = try VaultEngine.saveItem(ItemEdit(revision: vault.digest, item: renamed, create: false, originalName: "login"), in: vault, device: owner)
    #expect(try VaultEngine.read("renamed/password", in: vault, device: owner) == SecretBytes(utf8: "secret"))
    vault = try VaultEngine.write("renamed/password", value: nil, in: vault, device: owner)
    #expect(try VaultEngine.catalog(in: vault, device: owner).items[0].fields.map(\.path) == ["username"])
    #expect(throws: MopError.notFound) { try VaultEngine.read("renamed/password", in: vault, device: owner) }
}

@Test func softwareKeyFormatsAreNotAcceptedAsV6Checkpoints() throws {
    let old = Data("{\"format\":\"mop-vault-v5\"}".utf8)
    #expect(throws: MopError.invalidVault) { try VerifiedVault(checkpoint: old, independentlyVerifiedDigest: Codec.digest(old)) }
}

@Test func recoveryRotationCannotReuseTheRetiredPrivateKeysUnderNewIDs() throws {
    let owner = try TestDevice(), recovery = try TestDevice()
    let vault = try VaultEngine.create(name: "personal", owner: owner, recovery: recovery.identity)
    let relabeled = try DevicePublicKey(member: UUID(), encryption: recovery.identity.encryption, signing: recovery.identity.signing)
    #expect(throws: MopError.invalidRecovery) { try VaultEngine.replaceRecovery(with: relabeled, in: vault, owner: owner) }
}

@Test func vaultWithoutRecoveryCanAddItAfterSavingSecrets() throws {
    let owner = try TestDevice(), recovery = try TestDevice(), replacement = try TestDevice()
    var vault = try VaultEngine.create(name: "personal", owner: owner)
    #expect(vault.membership.recovery == nil)
    vault = try VaultEngine.write("login/password", value: SecretBytes(utf8: "existing-secret"), in: vault, device: owner)
    #expect(throws: MopError.notVaultMember) { try VaultEngine.read("login/password", in: vault, device: recovery) }
    #expect(throws: MopError.invalidRecovery) { try VaultEngine.recover(vault, using: recovery, owner: owner.identity, replacementRecovery: replacement.identity) }
    let old = vault
    vault = try VaultEngine.replaceRecovery(with: recovery.identity, in: vault, owner: owner)
    #expect(vault.membership.recovery == recovery.identity)
    #expect(vault.revision.records.keys.sorted() == old.revision.records.keys.sorted())
    #expect(try VaultEngine.read("login/password", in: vault, device: recovery) == SecretBytes(utf8: "existing-secret"))
    let recovered = try VaultEngine.recover(vault, using: recovery, owner: owner.identity, replacementRecovery: replacement.identity)
    #expect(try VaultEngine.read("login/password", in: recovered, device: owner) == SecretBytes(utf8: "existing-secret"))
}

@Test func probeNamespacesCannotAppearInUserDiscoveryOrProduction() throws {
    let id = UUID()
    let user = try VaultAddress(container: "iCloud.test", environment: "Development", account: "a", database: .private, owner: "owner", vault: id)
    let probe = try VaultAddress(container: "iCloud.test", environment: "Development", account: "a", database: .private, owner: "owner", vault: id, namespace: .probe)
    #expect(VaultAddress.discoveredVault(in: user.zoneName) == id)
    #expect(VaultAddress.discoveredVault(in: probe.zoneName) == nil)
    #expect(user.binding != probe.binding)
    #expect(throws: MopError.cloudInvalidRequest) { try VaultAddress(container: "iCloud.test", environment: "Production", account: "a", database: .private, owner: "owner", vault: id, namespace: .probe) }
}

@Test func enrollmentRequestsBindVaultAccountExpiryAndTranscript() throws {
    let member = AccountScope.member(container: "iCloud.test", environment: "Development", account: "a")
    let key = try TestDevice(member: member), owner = try TestDevice(member: member)
    let vault = try VaultEngine.create(name: "personal", owner: owner)
    let address = try VaultAddress(container: "iCloud.test", environment: "Development", account: "a", database: .private, owner: "__defaultOwner__", vault: vault.id)
    let device = try DeviceRequest(container: address.container, environment: address.environment, account: address.account, recovery: false, device: key)
    let request = try EnrollmentRequest(vault: vault.id, request: device, name: "Mac", device: key)
    try request.validate(at: address)
    #expect(throws: MopError.invalidIdentity) { try request.validate(at: address, now: request.expires) }
    let wrong = try VaultAddress(container: address.container, environment: address.environment, account: "b", database: .private, owner: address.owner, vault: address.vault)
    #expect(throws: MopError.invalidIdentity) { try request.validate(at: wrong) }
    var raw = try JSONSerialization.jsonObject(with: ExchangeFile.encode(request)) as! [String: Any]
    raw["name"] = "Forged Mac"
    let changed = try ExchangeFile.decode(EnrollmentRequest.self, from: JSONSerialization.data(withJSONObject: raw))
    #expect(throws: MopError.invalidIdentity) { try changed.validate(at: address) }
    var exchange = EnrollmentExchange(request: request)
    let invitation = try VaultEngine.invite(member: member, role: .owner, to: vault, owner: owner, expires: request.expires)
    exchange.invitation = InvitationPacket(request: device, invitation: invitation, address: address, checkpoint: vault.bytes)
    _ = try exchange.verifiedInvitation(at: address)
    #expect(exchange.verificationCode?.count == 29)
    var box = EnrollmentMailbox(); box.exchanges = [exchange, exchange]
    #expect(throws: MopError.invalidVault) { try box.encoded() }
}

@Test func previouslyEnrolledDeviceCanReestablishTrustWithFreshOwnerApproval() throws {
    let owner = try TestDevice(), next = try TestDevice(member: owner.identity.member)
    var vault = try VaultEngine.create(name: "personal", owner: owner)
    for _ in 0..<2 {
        let invitation = try VaultEngine.invite(member: next.identity.member, role: .owner, to: vault, owner: owner, expires: Date().addingTimeInterval(60))
        let acceptance = try Acceptance(invitation: invitation, expectedCheckpoint: vault.digest, device: next)
        vault = try VaultEngine.approve(acceptance, expectedDeviceFingerprint: next.identity.fingerprint, in: vault, owner: owner)
        #expect(vault.membership.devices.count == 2)
        #expect(vault.acceptedEnrollment(invitation.nonce))
        #expect(throws: MopError.vaultUntrusted) { try VaultEngine.approve(acceptance, expectedDeviceFingerprint: next.identity.fingerprint, in: vault, owner: owner) }
    }
}
