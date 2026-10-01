import Foundation
import Testing
import MopCore
@testable import MopVaultNext

@Test func removalReportsFieldProgressAndCanStopBeforePublication() throws {
    let owner = try TestDevice(), other = try TestDevice(member: owner.identity.member)
    var vault = try VaultEngine.create(name: "personal", owner: owner)
    vault = try VaultEngine.write("login/password", value: SecretBytes(utf8: "secret"), in: vault, device: owner)
    let invitation = try VaultEngine.invite(member: other.identity.member, role: .owner, to: vault, owner: owner, expires: Date().addingTimeInterval(60))
    let acceptance = try Acceptance(invitation: invitation, expectedCheckpoint: vault.digest, device: other)
    vault = try VaultEngine.approve(acceptance, expectedDeviceFingerprint: other.identity.fingerprint, in: vault, owner: owner)
    #expect(throws: MopError.operationCancelled) {
        try VaultEngine.remove(device: other.identity.device, from: vault, owner: owner) { completed, _ in
            if completed == 1 { throw MopError.operationCancelled }
        }
    }
    var counts: [Int] = []
    let removed = try VaultEngine.remove(device: other.identity.device, from: vault, owner: owner) { completed, total in
        #expect(total == 1)
        counts.append(completed)
    }
    #expect(counts == [0, 1])
    #expect(try VaultEngine.read("login/password", in: removed, device: owner) == SecretBytes(utf8: "secret"))
    #expect(throws: MopError.notVaultMember) { try VaultEngine.read("login/password", in: removed, device: other) }
}

@Test func typedItemEditsAndRemovalPreserveOnlyCurrentEncryptedFields() throws {
    let owner = try TestDevice(), recovery = try TestDevice(member: owner.identity.member)
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
    let owner = try TestDevice(), recovery = try TestDevice(member: owner.identity.member)
    let vault = try VaultEngine.create(name: "personal", owner: owner, recovery: recovery.identity)
    let relabeled = try DevicePublicKey(member: UUID(), encryption: recovery.identity.encryption, signing: recovery.identity.signing)
    #expect(throws: MopError.invalidRecovery) { try VaultEngine.setOfflineRecovery(relabeled, in: vault, owner: owner) }
}

@Test func vaultWithoutRecoveryCanAddItAfterSavingSecrets() throws {
    let owner = try TestDevice(), recovery = try TestDevice(member: owner.identity.member), replacement = try TestDevice(member: owner.identity.member)
    var vault = try VaultEngine.create(name: "personal", owner: owner)
    #expect(vault.membership.offlineRecovery == nil)
    vault = try VaultEngine.write("login/password", value: SecretBytes(utf8: "existing-secret"), in: vault, device: owner)
    #expect(throws: MopError.notVaultMember) { try VaultEngine.read("login/password", in: vault, device: recovery) }
    #expect(throws: MopError.invalidRecovery) { try VaultEngine.recover(vault, using: recovery, owner: owner.identity) }
    let old = vault
    vault = try VaultEngine.setOfflineRecovery(recovery.identity, in: vault, owner: owner)
    #expect(vault.membership.offlineRecovery == recovery.identity)
    #expect(vault.revision.records.keys.sorted() == old.revision.records.keys.sorted())
    #expect(try VaultEngine.read("login/password", in: vault, device: recovery) == SecretBytes(utf8: "existing-secret"))
    let recovered = try VaultEngine.recover(vault, using: recovery, owner: owner.identity)
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
    let device = try DeviceRequest(container: address.container, environment: address.environment, account: address.account, device: key)
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
    exchange.invitation = InvitationPacket(request: device, invitation: invitation, address: address, checkpoint: Data())
    #expect(try exchange.verifiedInvitation(at: address, referencedCheckpoint: vault.bytes).digest == vault.digest)
    #expect(throws: MopError.vaultUntrusted) { try exchange.verifiedInvitation(at: address) }
    let other = try VaultEngine.create(name: "other", owner: owner)
    #expect(throws: MopError.vaultUntrusted) { try exchange.verifiedInvitation(at: address, referencedCheckpoint: other.bytes) }
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

@Test func importCreatesOneRevisionAndReimportSkipsSecrets() throws {
    let owner = try TestDevice()
    let original = try VaultEngine.create(name: "personal", owner: owner)
    var item = VaultItem(name: "Login", type: .login, fields: [ItemField(path: "username", type: .username, value: "alice"), ItemField(path: "password", type: .password, value: "unique-password")])
    item.metadata = ItemMetadata(tags: ["work"])
    let document = ImportDocument(format: .appleCSV, records: [.init(id: 1, item: item)])
    let preview = try VaultEngine.previewImport(document, in: original, device: owner)
    let imported = try VaultEngine.importItems(preview.items, revision: original.digest, in: original, device: owner)
    #expect(imported.revision.header.generation == original.revision.header.generation + 1)
    #expect(imported.revision.header.parent == original.digest)
    #expect(imported.revision.header.requiredFeatures == ["item-model-1"])
    #expect(try VaultEngine.catalog(in: imported, device: owner).items[0].fields[1].value == nil)
    #expect(try VaultEngine.previewImport(document, in: imported, device: owner).preview.report.rows[0].disposition == .duplicate)
    #expect(throws: MopError.vaultConflict) { try VaultEngine.importItems([], revision: original.digest, in: imported, device: owner) }
    #expect(throws: MopError.cloudPermission) { try VaultEngine.importItems([], revision: original.digest, in: original, device: TestDevice()) }
    let renamed = try VaultEngine.rename("renamed", in: imported, device: owner)
    #expect(renamed.revision.header.requiredFeatures == ["item-model-1"])
}

@Test func importsMoreThan4096FieldsAndRetainsByteBound() throws {
    let owner = try TestDevice()
    let original = try VaultEngine.create(name: "personal", owner: owner)
    let fields = (0..<4097).map { ItemField(path: "field\($0)", type: .concealed, value: "value\($0)") }
    let imported = try VaultEngine.importItems([VaultItem(name: "Large", fields: fields)], revision: original.digest, in: original, device: owner)
    #expect(imported.revision.records.count == 4097)
    #expect(try VaultEngine.read("Large/field4096", in: imported, device: owner) == SecretBytes(utf8: "value4096"))
    let oversized = VaultItem(name: "Too large", fields: [ItemField(path: "data", value: String(repeating: "x", count: 16 * 1024 * 1024))])
    #expect(throws: ImportFailure.capacity) { try VaultEngine.importItems([oversized], revision: original.digest, in: original, device: owner) }
}

@Test func editingRawReferenceItemsStillWorks() throws {
    let owner = try TestDevice()
    var vault = try VaultEngine.create(name: "personal", owner: owner)
    vault = try VaultEngine.write("raw/value", value: "secret", in: vault, device: owner)
    var item = try VaultEngine.catalog(in: vault, device: owner).items[0]
    item.name = "renamed"
    let edited = try VaultEngine.saveItem(.init(revision: vault.digest, item: item, create: false, originalName: "raw"), in: vault, device: owner)
    #expect(try VaultEngine.read("renamed/value", in: edited, device: owner) == "secret")
}

@Test func extendedModelMarkerChangesLegacyCanonicalEncodingAndCannotBeRemoved() throws {
    let owner = try TestDevice()
    let root = try VaultEngine.create(name: "personal", owner: owner)
    #expect(root.revision.header.requiredFeatures == nil)
    var item = VaultItem(name: "note", type: .secureNote, fields: [ItemField(path: "note", value: "secret")])
    item.metadata = ItemMetadata(archived: true)
    let extended = try VaultEngine.saveItem(.init(revision: root.digest, item: item, create: true), in: root, device: owner)
    var oldHeader = extended.revision.header
    oldHeader.requiredFeatures = nil
    // An older decoder discards the unknown header key; canonical re-encoding therefore differs.
    let oldEncoding = Revision(header: oldHeader, catalog: extended.revision.catalog, records: extended.revision.records, itemKeys: extended.revision.itemKeys,
                               author: extended.revision.author, signature: extended.revision.signature)
    #expect(try oldEncoding.encoded() != extended.bytes)
    var stripped = try VaultEngine.header(extended, operation: .content)
    stripped.requiredFeatures = nil
    let payload = try extended.revision.payload(device: owner)
    var legacyItem = payload.items[0]; legacyItem.metadata = nil
    let downgrade = try Revision.seal(header: stripped, references: payload.references, records: extended.revision.records, itemKeys: extended.revision.itemKeys, items: [legacyItem], signer: owner)
    #expect(throws: MopError.invalidVault) { try extended.applying(downgrade.encoded()) }
}

@Test func attachmentsSurviveEditsTrashCheckpointAndRecovery() throws {
    let owner = try TestDevice(), recovery = try TestDevice(member: owner.identity.member), replacement = try TestDevice(member: owner.identity.member)
    var vault = try VaultEngine.create(name: "personal", owner: owner, recovery: recovery.identity)
    // Upgrade a vault that already requires the extended item model.
    var first = VaultItem(name: "First", type: .secureNote, fields: [.init(path: "note", value: "secret")])
    first.metadata = ItemMetadata(tags: ["test"])
    vault = try VaultEngine.saveItem(.init(revision: vault.digest, item: first, create: true), in: vault, device: owner)
    let attachment = try Attachment(fileName: "binary.dat", data: Data([0, 128, 255, 13, 10]))
    let item = VaultItem(name: "File", type: .document, fields: [.init(path: "file", type: .attachment, value: try attachment.encodedValue())])
    vault = try VaultEngine.importItems([item], revision: vault.digest, in: vault, device: owner)
    #expect(vault.revision.header.requiredFeatures == ["attachment-blobs-1", "attachments-1", "item-model-1", "offline-recovery-1"])
    var downgradedHeader = try VaultEngine.header(vault, operation: .content)
    downgradedHeader.requiredFeatures = ["item-model-1"]
    let downgrade = try Revision.seal(header: downgradedHeader,
        references: vault.revision.references(device: owner), records: vault.revision.records, itemKeys: vault.revision.itemKeys, signer: owner)
    #expect(throws: MopError.invalidVault) { try vault.applying(downgrade.encoded()) }
    var stored = try #require(VaultEngine.catalog(in: vault, device: owner).items.first { $0.name == "File" })
    #expect(stored.fields[0].value == nil)
    stored.name = "Renamed"
    vault = try VaultEngine.saveItem(.init(revision: vault.digest, item: stored, create: false, originalName: "File"), in: vault, device: owner)
    vault = try VaultEngine.trashItem(name: "Renamed", revision: vault.digest, in: vault, device: owner)
    let trashed = try #require(VaultEngine.catalog(in: vault, device: owner, deleted: true).items.first)
    vault = try VaultEngine.restoreItem(id: trashed.deletion!.id, revision: vault.digest, in: vault, device: owner)
    let checkpoint = try vault.backup()
    vault = try VerifiedVault.restoreBackup(checkpoint, independentlyVerifiedDigest: vault.digest)
    vault = try VaultEngine.recover(vault, using: recovery, owner: owner.identity)
    let value = try VaultEngine.read("Renamed/file", in: vault, device: owner)
    #expect(try Attachment.decode(String(decoding: value, as: UTF8.self)) == attachment)
    #expect(throws: AttachmentFailure.invalid) {
        try VaultEngine.write("Renamed/file", value: SecretBytes(utf8: "not a file"), in: vault, device: owner)
    }
    vault = try VaultEngine.write("Renamed/file", value: nil, in: vault, device: owner)
    #expect(throws: MopError.notFound) { try VaultEngine.read("Renamed/file", in: vault, device: owner) }
    #expect(vault.revision.header.requiredFeatures == ["attachment-blobs-1", "attachments-1", "item-model-1", "offline-recovery-1"])
}

@Test func attachmentBatchExceedsOldCapacityWithoutGrowingRevision() throws {
    let owner = try TestDevice()
    let vault = try VaultEngine.create(name: "personal", owner: owner)
    let attachment = try Attachment(fileName: "large.bin", data: Data(repeating: 42, count: 5 * 1024 * 1024))
    let value = try attachment.encodedValue()
    let items = (1...2).map { VaultItem(name: "File \($0)", type: .document, fields: [.init(path: "file", type: .attachment, value: value)]) }
    let imported = try VaultEngine.importItems(items, revision: vault.digest, in: vault, device: owner)
    #expect(imported.bytes.count < 64 * 1024)
    #expect(imported.attachmentDigests.count == 2)
    #expect(imported.loadedAttachments.values.reduce(0) { $0 + $1.count } > 10 * 1024 * 1024)
    #expect(try VaultEngine.catalog(in: vault, device: owner).items.isEmpty)
}

@Test func compoundFieldsRemainConcealedAndRejectInvalidWrites() throws {
    let owner = try TestDevice()
    var vault = try VaultEngine.create(name: "personal", owner: owner)
    let value = try CompoundField(#"{"street":"A road","zip":"00123","extra":{"x":"kept"}}"#).encodedValue
    let item = VaultItem(name: "Address", fields: [.init(path: "address", type: .address, value: value)])
    vault = try VaultEngine.saveItem(.init(revision: vault.digest, item: item, create: true), in: vault, device: owner)
    #expect(vault.revision.header.requiredFeatures == ["compound-fields-1", "item-model-1"])
    let stored = try #require(VaultEngine.catalog(in: vault, device: owner).items.first)
    #expect(stored.fields[0].value == nil)
    vault = try VaultEngine.saveItem(.init(revision: vault.digest, item: stored, create: false), in: vault, device: owner)
    let read = try VaultEngine.read("Address/address", in: vault, device: owner)
    #expect(String(decoding: read, as: UTF8.self) == value)
    #expect(throws: CompoundFieldFailure.invalid) { try VaultEngine.write("Address/address", value: SecretBytes(utf8: "[]"), in: vault, device: owner) }
    let bytes = try vault.revision.encoded()
    let reloaded = try VerifiedVault(checkpoint: bytes, independentlyVerifiedDigest: Codec.digest(bytes))
    #expect(try VaultEngine.read("Address/address", in: reloaded, device: owner) == read)
}

@Test func importProgressCountsCompletedItemsAndCanCancel() throws {
    let owner = try TestDevice(), root = try VaultEngine.create(name: "personal", owner: owner)
    let items = (0..<3).map { VaultItem(name: "item-\($0)", fields: [.init(path: "password", type: .password, value: "synthetic")]) }
    var counts: [Int] = []
    _ = try VaultEngine.importItems(items, revision: root.digest, in: root, device: owner) { completed, total in
        #expect(total == 3); counts.append(completed)
    }
    #expect(counts == [0, 1, 2, 3])
    #expect(throws: CancellationError.self) {
        try VaultEngine.importItems(items, revision: root.digest, in: root, device: owner) { completed, _ in
            if completed == 1 { throw CancellationError() }
        }
    }
    #expect(try VaultEngine.catalog(in: root, device: owner).items.isEmpty)
}
