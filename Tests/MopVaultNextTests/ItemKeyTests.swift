import CryptoKit
import Foundation
import Testing
import MopCore
@testable import MopVaultNext

private func enroll(_ peer: TestDevice, in vault: VerifiedVault, owner: TestDevice) throws -> VerifiedVault {
    let invitation = try VaultEngine.invite(member: peer.identity.member, role: .editor, to: vault, owner: owner, expires: Date().addingTimeInterval(300))
    let acceptance = try Acceptance(invitation: invitation, expectedCheckpoint: vault.digest, device: peer)
    return try VaultEngine.approve(acceptance, expectedDeviceFingerprint: peer.identity.fingerprint, in: vault, owner: owner)
}
private func fixture(owner: TestDevice) throws -> VerifiedVault {
    let root = try VaultEngine.create(name: "personal", owner: owner)
    let attachment = try Attachment(fileName: "example.bin", data: Data(repeating: 7, count: 1024))
    return try VaultEngine.importItems([
        VaultItem(name: "login", fields: [.init(path: "password", type: .password, value: "secret"), .init(path: "other", type: .password, value: "second")]),
        VaultItem(name: "document", fields: [.init(path: "file", type: .attachment, value: try attachment.encodedValue())])
    ], revision: root.digest, in: root, device: owner)
}
private func itemUnwraps(_ device: TestDevice) -> Int {
    device.unwrappedContexts.filter { String(decoding: $0, as: UTF8.self).contains("mop-v7-item-key") }.count
}

@Test func itemEnrollmentPreservesEnvelopesAndDoesNotNeedAttachments() throws {
    let owner = try TestDevice(), peer = try TestDevice()
    let before = try fixture(owner: owner)
    let disk = try VerifiedVault(checkpoint: before.bytes, independentlyVerifiedDigest: before.digest)
    owner.unwrappedContexts = []
    let after = try enroll(peer, in: disk, owner: owner)
    #expect(itemUnwraps(owner) == 2)
    #expect(after.loadedAttachments.isEmpty)
    #expect(after.attachmentDigests == before.attachmentDigests)
    #expect(try Codec.encode(after.revision.records) == Codec.encode(before.revision.records))
    for (id, key) in before.revision.itemKeys {
        #expect(after.revision.itemKeys[id]?.generation == key.generation)
        for (recipient, envelope) in key.envelopes { #expect(after.revision.itemKeys[id]?.envelopes[recipient] == envelope) }
    }
    #expect(try VaultEngine.read("login/password", in: after, device: peer) == "secret")
    owner.unwrappedContexts = []
    let role = try VaultEngine.setRole(.viewer, member: peer.identity.member, in: after, owner: owner)
    #expect(itemUnwraps(owner) == 0)
    #expect(role.revision.itemKeys == after.revision.itemKeys)
}

@Test func itemRemovalRotatesDeletedItemsAndRejectsPreviousKeys() throws {
    let owner = try TestDevice(), peer = try TestDevice()
    var before = try enroll(peer, in: fixture(owner: owner), owner: owner)
    before = try VaultEngine.trashItem(name: "document", revision: before.digest, in: before, device: owner)
    var oldKeys: [String: SymmetricKey] = [:]
    for (id, key) in before.revision.itemKeys { oldKeys[id] = try key.unwrap(vault: before.id, item: id, device: peer) }
    owner.unwrappedContexts = []
    let after = try VaultEngine.remove(device: peer.identity.device, from: before, owner: owner)
    #expect(itemUnwraps(owner) == 2)
    #expect(after.attachmentDigests.isDisjoint(with: before.attachmentDigests))
    for (id, record) in after.revision.records {
        let item = try #require(record.itemID), key = try #require(after.revision.itemKeys[item])
        #expect(key.generation == before.revision.itemKeys[item]!.generation + 1)
        #expect(key.envelopes[peer.identity.fingerprint] == nil)
        let aad = try Codec.encode(FieldContext(vault: after.id, item: item, generation: key.generation, field: id))
        #expect(throws: (any Error).self) { try record.open(using: oldKeys[item]!, authenticating: aad) }
        let currentKey = try key.unwrap(vault: after.id, item: item, device: owner)
        #expect(!(try record.open(using: currentKey, authenticating: aad)).isEmpty)
    }
}

@Test func itemEditsReuseKeyAndKeepUnchangedFields() throws {
    let owner = try TestDevice()
    let before = try fixture(owner: owner)
    owner.unwrappedContexts = []
    let edited = try VaultEngine.write("login/password", value: "new", in: before, device: owner)
    #expect(itemUnwraps(owner) == 1)
    #expect(edited.revision.itemKeys == before.revision.itemKeys)
    let refs = try before.revision.references(device: owner), next = try edited.revision.references(device: owner)
    #expect(refs["login/password"] != next["login/password"])
    #expect(refs["login/other"] == next["login/other"])
    #expect(edited.attachmentDigests == before.attachmentDigests)
    var item = try #require(VaultEngine.catalog(in: edited, device: owner).items.first { $0.name == "login" })
    item.name = "renamed"
    let renamed = try VaultEngine.saveItem(.init(revision: edited.digest, item: item, create: false, originalName: "login"), in: edited, device: owner)
    #expect(renamed.revision.itemKeys == edited.revision.itemKeys)
    #expect(try Codec.encode(renamed.revision.records) == Codec.encode(edited.revision.records))
}

@Test func itemContextsAndSignedTransitionsRejectSubstitution() throws {
    let owner = try TestDevice(), peer = try TestDevice()
    let before = try fixture(owner: owner)
    let payload = try before.revision.payload(device: owner)
    let field = try #require(payload.references["login/password"])
    let record = try #require(before.revision.records[field]), item = try #require(record.itemID)
    let wrapped = try #require(before.revision.itemKeys[item])
    let key = try wrapped.unwrap(vault: before.id, item: item, device: owner)
    for aad in [FieldContext(vault: UUID(), item: item, generation: wrapped.generation, field: field),
                FieldContext(vault: before.id, item: UUID().uuidString, generation: wrapped.generation, field: field),
                FieldContext(vault: before.id, item: item, generation: wrapped.generation + 1, field: field),
                FieldContext(vault: before.id, item: item, generation: wrapped.generation, field: UUID().uuidString)] {
        #expect(throws: (any Error).self) { try record.open(using: key, authenticating: Codec.encode(aad)) }
    }
    #expect(throws: (any Error).self) { try wrapped.unwrap(vault: UUID(), item: item, device: owner) }
    let after = try enroll(peer, in: before, owner: owner)
    var records = after.revision.records
    records[field] = try SealedObject.field(Data("forged".utf8), key: key, vault: before.id, item: item, generation: wrapped.generation, id: field)
    let forged = try Revision.seal(header: after.revision.header, references: payload.references, records: records,
        itemKeys: after.revision.itemKeys, items: payload.items, signer: owner)
    #expect(throws: MopError.invalidVault) { try before.applying(forged) }
    var keys = after.revision.itemKeys
    keys[item] = try ItemKey.wrap(key, vault: before.id, item: item, generation: wrapped.generation, recipients: after.membership.recipients)
    let changedEnvelope = try Revision.seal(header: after.revision.header, references: payload.references, records: after.revision.records,
        itemKeys: keys, items: payload.items, signer: owner)
    #expect(throws: MopError.invalidVault) { try before.applying(changedEnvelope) }
    keys[item]!.envelopes.removeValue(forKey: peer.identity.fingerprint)
    #expect(throws: MopError.invalidVault) {
        try Revision.seal(header: after.revision.header, references: payload.references, records: after.revision.records, itemKeys: keys, items: payload.items, signer: owner)
    }
}

@Test func oldFormatsAndNamespacesAreNotAcceptedByV7() throws {
    let owner = try TestDevice(), root = try VaultEngine.create(name: "personal", owner: owner)
    let old = Data(String(decoding: root.bytes, as: UTF8.self).replacingOccurrences(of: "mop-vault-v7", with: "mop-vault-v6").utf8)
    #expect(throws: MopError.legacyVault) { try VerifiedVault(checkpoint: old, independentlyVerifiedDigest: Codec.digest(old)) }
    #expect(VaultAddress.discoveredVault(in: "mop-v6-" + UUID().uuidString) == nil)
    #expect(throws: MopError.legacyVault) { try VerifiedVault.restoreBackup(Data("{\"format\":\"mop-attachment-backup-1\"}".utf8), independentlyVerifiedDigest: root.digest) }
}
