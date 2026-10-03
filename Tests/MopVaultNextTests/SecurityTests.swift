import Foundation
import Testing
import MopCore
@testable import MopVaultNext

private func enroll(_ device: TestDevice, role: MemberRole, vault: VerifiedVault, owner: TestDevice) throws -> VerifiedVault {
    let now = Date()
    let invitation = try VaultEngine.invite(member: device.identity.member, role: role, to: vault, owner: owner, now: now, expires: now.addingTimeInterval(100))
    let acceptance = try Acceptance(invitation: invitation, expectedCheckpoint: vault.digest, device: device, now: now)
    return try VaultEngine.approve(acceptance, expectedDeviceFingerprint: device.identity.fingerprint, in: vault, owner: owner, now: now)
}
private func value(_ bytes: SecretBytes) -> String { String(decoding: bytes, as: UTF8.self) }

@Test func historyCapturesRawAndItemWritesWithoutUnchangedValues() throws {
    let owner = try TestDevice()
    var vault = try VaultEngine.create(name: "history", owner: owner)
    #expect(vault.supportsSecurity)
    vault = try VaultEngine.write("api/token", value: "first", in: vault, device: owner)
    vault = try VaultEngine.write("api/token", value: "first", in: vault, device: owner)
    #expect(try VaultEngine.securityMetadata(in: vault, device: owner).histories.isEmpty)
    var item = try VaultEngine.catalog(in: vault, device: owner).items[0]
    item.fields[0].value = "second"
    vault = try VaultEngine.saveItem(ItemEdit(revision: vault.digest, item: item, create: false), in: vault, device: owner)
    let history = try #require(VaultEngine.securityMetadata(in: vault, device: owner).histories.first)
    #expect(history.entries.count == 1)
    #expect(try value(VaultEngine.readHistory(history.entries[0].id, revision: vault.digest, in: vault, device: owner)) == "first")
    #expect(try VaultEngine.references(in: vault, device: owner) == ["api/token"])
    #expect(!String(decoding: vault.bytes, as: UTF8.self).contains("first"))
    item = try VaultEngine.catalog(in: vault, device: owner).items[0]
    item.name = "renamed"
    vault = try VaultEngine.saveItem(ItemEdit(revision: vault.digest, item: item, create: false, originalName: "api"), in: vault, device: owner)
    #expect(try VaultEngine.securityMetadata(in: vault, device: owner).histories[0].id == history.id)
    vault = try VaultEngine.restoreHistory(history.entries[0].id, revision: vault.digest, in: vault, device: owner)
    #expect(try value(VaultEngine.read("renamed/token", in: vault, device: owner)) == "first")
    #expect(try VaultEngine.securityMetadata(in: vault, device: owner).histories[0].entries.count == 2)
    let backup = try VerifiedVault.restoreBackup(vault.backup(), independentlyVerifiedDigest: vault.digest)
    #expect(try VaultEngine.securityMetadata(in: backup, device: owner) == VaultEngine.securityMetadata(in: vault, device: owner))
}

@Test func historyRetentionDeletionAndRevisionConflicts() throws {
    let owner = try TestDevice()
    var vault = try VaultEngine.create(name: "history", owner: owner)
    for i in 0...22 { vault = try VaultEngine.write("api/token", value: SecretBytes(utf8: "value-\(i)"), in: vault, device: owner) }
    let history = try #require(VaultEngine.securityMetadata(in: vault, device: owner).histories.first)
    #expect(history.entries.count == 20)
    #expect(vault.revision.records.count == 21)
    #expect(try value(VaultEngine.readHistory(history.entries.last!.id, revision: vault.digest, in: vault, device: owner)) == "value-2")
    #expect(throws: MopError.vaultConflict) { try VaultEngine.restoreHistory(history.entries[0].id, revision: "stale", in: vault, device: owner) }
    let cleared = try VaultEngine.clearHistory(history.id, revision: vault.digest, in: vault, device: owner)
    #expect(cleared.revision.records.count == 1)
    vault = try VaultEngine.write("api/token", value: nil, in: vault, device: owner)
    #expect(vault.revision.records.isEmpty)
    #expect(try VaultEngine.securityMetadata(in: vault, device: owner).histories.isEmpty)
}

@Test func historySurvivesTrashRotationAndRecoveryWithPermissions() throws {
    let owner = try TestDevice(), reader = try TestDevice()
    let recovery = try TestDevice(member: owner.identity.member)
    var vault = try VaultEngine.create(name: "history", owner: owner, recovery: recovery.identity)
    vault = try VaultEngine.write("login/password", value: "first", in: vault, device: owner)
    vault = try VaultEngine.write("login/password", value: "second", in: vault, device: owner)
    vault = try enroll(reader, role: .viewer, vault: vault, owner: owner)
    var history = try #require(VaultEngine.securityMetadata(in: vault, device: reader).histories.first)
    #expect(try value(VaultEngine.readHistory(history.entries[0].id, revision: vault.digest, in: vault, device: reader)) == "first")
    #expect(throws: MopError.cloudPermission) { try VaultEngine.clearHistory(history.id, revision: vault.digest, in: vault, device: reader) }
    #expect(throws: MopError.cloudPermission) { try VaultEngine.restoreHistory(history.entries[0].id, revision: vault.digest, in: vault, device: reader) }
    vault = try VaultEngine.trashItem(name: "login", revision: vault.digest, in: vault, device: owner)
    let deleted = try #require(VaultEngine.catalog(in: vault, device: owner, deleted: true).items.first?.deletion?.id)
    vault = try VaultEngine.restoreItem(id: deleted, revision: vault.digest, in: vault, device: owner)
    vault = try VaultEngine.remove(member: reader.identity.member, from: vault, owner: owner)
    history = try #require(VaultEngine.securityMetadata(in: vault, device: owner).histories.first)
    #expect(try value(VaultEngine.readHistory(history.entries[0].id, revision: vault.digest, in: vault, device: owner)) == "first")
    let replacement = try TestDevice(member: owner.identity.member)
    vault = try VaultEngine.recover(vault, using: recovery, owner: replacement.identity)
    history = try #require(VaultEngine.securityMetadata(in: vault, device: replacement).histories.first)
    #expect(try value(VaultEngine.readHistory(history.entries[0].id, revision: vault.digest, in: vault, device: replacement)) == "first")
}

@Test func legacyV7ExplicitUpgradeAndUnsupportedFeatures() throws {
    let owner = try TestDevice()
    let membership = try Membership(accounts: [AccountMember(id: owner.identity.member, role: .owner, devices: [owner.identity])])
    let header = Revision.Header(format: "mop-vault-v7", vault: UUID(), name: "old", generation: 1, parent: nil, epoch: 1, membership: membership, operation: .create, acceptedInvitations: [])
    let revision = try Revision.seal(header: header, references: [:], records: [:], signer: owner)
    var vault = try VerifiedVault(revision: revision, bytes: revision.encoded())
    vault = try VaultEngine.write("item/password", value: "old", in: vault, device: owner)
    #expect(!vault.supportsSecurity)
    let oldBackup = try vault.backup(), digest = vault.digest
    vault = try VaultEngine.upgradeSecurity(revision: digest, in: vault, device: owner)
    #expect(vault.supportsSecurity)
    #expect(try VaultEngine.securityMetadata(in: vault, device: owner).histories.isEmpty)
    vault = try VaultEngine.write("item/password", value: "new", in: vault, device: owner)
    #expect(try VaultEngine.securityMetadata(in: vault, device: owner).histories[0].entries.count == 1)
    #expect(try !VerifiedVault.restoreBackup(oldBackup, independentlyVerifiedDigest: digest).supportsSecurity)
    var invalidHeader = vault.revision.header
    invalidHeader.requiredFeatures = ["future-feature"]
    #expect(throws: MopError.invalidVault) { try Revision.seal(header: invalidHeader, references: [:], records: [:], signer: owner) }
}

@Test func credentialRegistrationEvidenceAndDeviceRemoval() throws {
    let owner = try TestDevice(), backup = try TestDevice(member: owner.identity.member)
    var vault = try VaultEngine.create(name: "credentials", owner: owner)
    vault = try enroll(backup, role: .owner, vault: vault, owner: owner)
    var account = CredentialAccount(service: "https://example.test", account: "alice")
    account.registrations = [CredentialRegistration(protocolName: "ssh", publicIdentifier: "key-a", deviceID: owner.identity.device.uuidString, deviceLabel: "Mac"),
                             CredentialRegistration(protocolName: "ssh", publicIdentifier: "key-b", deviceID: backup.identity.device.uuidString, deviceLabel: "Other Mac")]
    #expect(!account.hasConfirmedAlternate)
    account.registrations[0].state = .confirmed
    account.registrations[1].state = .confirmed
    vault = try VaultEngine.saveCredentialAccount(account, revision: vault.digest, in: vault, device: owner)
    account = try VaultEngine.securityMetadata(in: vault, device: owner).accounts[0]
    #expect(account.hasConfirmedAlternate)
    #expect(account.registrations.allSatisfy { $0.confirmedBy == owner.identity.member.uuidString })
    var sameDevice = account
    sameDevice.registrations[1].deviceID = sameDevice.registrations[0].deviceID
    #expect(!sameDevice.hasConfirmedAlternate)
    var sameKey = account
    sameKey.registrations[1].publicIdentifier = sameKey.registrations[0].publicIdentifier
    #expect(!sameKey.hasConfirmedAlternate)
    vault = try VaultEngine.remove(device: backup.identity.device, from: vault, owner: owner)
    #expect(try !VaultEngine.securityMetadata(in: vault, device: owner).accounts[0].hasConfirmedAlternate)
    #expect(try VaultEngine.catalog(in: vault, device: owner).items.isEmpty)
}

@Test func historyFollowsStableFieldIdentityThroughPathSwaps() throws {
    let owner = try TestDevice()
    var vault = try VaultEngine.create(name: "paths", owner: owner)
    vault = try VaultEngine.write("item/a", value: "old-a", in: vault, device: owner)
    vault = try VaultEngine.write("item/b", value: "old-b", in: vault, device: owner)
    vault = try VaultEngine.write("item/a", value: "new-a", in: vault, device: owner)
    vault = try VaultEngine.write("item/b", value: "new-b", in: vault, device: owner)
    var item = try VaultEngine.catalog(in: vault, device: owner).items[0]
    for i in item.fields.indices { item.fields[i].path = item.fields[i].path == "a" ? "b" : "a" }
    vault = try VaultEngine.saveItem(ItemEdit(revision: vault.digest, item: item, create: false), in: vault, device: owner)
    let histories = try VaultEngine.securityMetadata(in: vault, device: owner).histories
    let a = try #require(histories.first { $0.path == "a" })
    #expect(try value(VaultEngine.read("item/a", in: vault, device: owner)) == "new-b")
    #expect(try value(VaultEngine.readHistory(a.entries[0].id, revision: vault.digest, in: vault, device: owner)) == "old-b")
}

@Test func convertingTokenToPasswordStillPreservesThePreviousValue() throws {
    let owner = try TestDevice()
    var vault = try VaultEngine.create(name: "types", owner: owner)
    vault = try VaultEngine.write("item/secret", value: "old-token", in: vault, device: owner)
    var item = try VaultEngine.catalog(in: vault, device: owner).items[0]
    item.fields[0].type = .password; item.fields[0].value = "new-password"
    vault = try VaultEngine.saveItem(ItemEdit(revision: vault.digest, item: item, create: false), in: vault, device: owner)
    let entry = try #require(VaultEngine.securityMetadata(in: vault, device: owner).histories.first?.entries.first)
    #expect(try value(VaultEngine.readHistory(entry.id, revision: vault.digest, in: vault, device: owner)) == "old-token")
}

@Test func encryptedPasswordCheckCacheRoundTripsAndInvalidates() throws {
    let owner = try TestDevice(), viewer = try TestDevice()
    var vault = try VaultEngine.create(name: "checks", owner: owner)
    let item = VaultItem(name: "login", fields: [ItemField(path: "password", type: .password, value: "secret")])
    vault = try VaultEngine.saveItem(ItemEdit(revision: vault.digest, item: item, create: true), in: vault, device: owner)
    vault = try enroll(viewer, role: .viewer, vault: vault, owner: owner)
    let catalog = try VaultEngine.catalog(in: vault, device: owner)
    let check = CachedPasswordCheck(record: try #require(catalog.items[0].fields[0].recordVersion), context: ["login", ""],
        weak: true, exposed: true, checkedAt: Date(), breachCheckedAt: Date(), reuseGroup: nil,
        scope: String(repeating: "a", count: 64), batch: UUID())
    #expect(throws: MopError.cloudPermission) {
        try VaultEngine.savePasswordChecks([check], revision: vault.digest, in: vault, device: viewer)
    }
    let old = vault.digest
    vault = try #require(try VaultEngine.savePasswordChecks([check], revision: vault.digest, in: vault, device: owner))
    #expect(throws: MopError.vaultConflict) { try VaultEngine.savePasswordChecks([check], revision: old, in: vault, device: owner) }
    #expect(try VaultEngine.savePasswordChecks([check], revision: vault.digest, in: vault, device: owner) == nil)
    #expect(!String(decoding: vault.bytes, as: UTF8.self).contains("passwordChecks"))
    let restored = try VerifiedVault.restoreBackup(vault.backup(), independentlyVerifiedDigest: vault.digest)
    #expect(try VaultEngine.catalog(in: restored, device: viewer).security?.passwordChecks == [check])
    let changed = try VaultEngine.write("login/password", value: "changed", in: vault, device: owner)
    #expect(try VaultEngine.catalog(in: changed, device: owner).security?.passwordChecks?.isEmpty == true)
    var archived = try VaultEngine.catalog(in: vault, device: owner).items[0]
    archived.metadata = ItemMetadata(archived: true)
    let archive = try VaultEngine.saveItem(ItemEdit(revision: vault.digest, item: archived, create: false), in: vault, device: owner)
    #expect(try VaultEngine.catalog(in: archive, device: owner).security?.passwordChecks?.isEmpty == true)
    let oldMetadata = try JSONDecoder().decode(VaultSecurityMetadata.self, from: Data("{\"histories\":[],\"accounts\":[]}".utf8))
    #expect(oldMetadata.passwordChecks == nil)
}
