import Foundation
import Testing
import MopCore
import MopCredentials
import MopSync
@testable import MopVaultNext

private func portableArchiveFixture(owner: TestDevice) throws -> PortableVaultArchive {
    var login = VaultItem(name: "Login", type: .login, fields: [ItemField(path: "username", type: .username, value: "alice"), ItemField(path: "password", type: .password, value: "current-secret")])
    login.metadata = ItemMetadata(tags: ["work", "important"], favorite: true, archived: true,
        source: ImportSourceIdentity(provider: "fixture", container: "source", item: "login"), createdAt: Date(timeIntervalSince1970: 1_700_000_000))
    let file = try Attachment(fileName: "fixture.bin", data: Data([0, 13, 10, 128, 255]))
    let document = VaultItem(name: "File", type: .document, fields: [.init(path: "file", type: .attachment, value: try file.encodedValue())])
    var trashed = VaultItem(name: "Deleted", type: .secureNote, fields: [.init(path: "note", type: .concealed, value: "retained-trash-secret")])
    trashed.deletion = ItemDeletion(originalName: "Deleted", deletedAt: Date(timeIntervalSince1970: 100))
    let key = try CloudKey.generate(.p256)
    var passkey = try key.item(name: "Passkey", purposes: [.ssh]); passkey.type = .passkey
    passkey.credential = KeyCredential(algorithm: .p256, publicKey: key.publicKey, purposes: [.passkey], relyingParty: "example.com", userName: "alice", userHandle: Data([1]), credentialID: Data(repeating: 7, count: 32))
    var archive = try portableDocument(name: "portable-fixture", items: [login, document, trashed, passkey])
    let itemID = try #require(archive.itemIDs["Login"]), oldID = UUID().uuidString
    let history = SecretFieldHistory(itemID: itemID, path: "password", entries: [SecretHistoryEntry(id: oldID, replacedAt: Date(timeIntervalSince1970: 100))])
    archive.items[0].fields[1].historyID = history.id
    archive.records[oldID] = PortableArchiveRecord(itemID: itemID, bytes: SecretBytes(utf8: "old-secret"))
    var security = VaultSecurityMetadata(); security.histories = [history]; archive.security = security
    try archive.validate(); return archive
}

@Test func portableArchiveRejectsWrongKeyTamperAndTruncation() throws {
    let owner = try TestDevice()
    let source = try portableArchiveFixture(owner: owner)
    let archive = try PortableArchive.seal(source)
    let other = try PortableArchive.seal(source)
    #expect(throws: (any Error).self) { try PortableArchive.open(archive.data, recoveryKey: other.recoveryKey) }
    var altered = archive.data
    altered[altered.count / 2] ^= 1
    #expect(throws: (any Error).self) { try PortableArchive.open(altered, recoveryKey: archive.recoveryKey) }
    #expect(throws: (any Error).self) { try PortableArchive.open(Data(archive.data.dropLast()), recoveryKey: archive.recoveryKey) }
}

@Test func portableArchiveRejectsMissingOrUnreferencedLogicalRecords() throws {
    let owner = try TestDevice()
    let source = try portableArchiveFixture(owner: owner)
    let complete = try source
    var missing = complete
    missing.records.removeValue(forKey: try #require(missing.references.values.first))
    #expect(throws: (any Error).self) { try PortableArchive.seal(missing) }
    var extra = complete
    extra.records[UUID().uuidString] = PortableArchiveRecord(itemID: try #require(complete.itemIDs.values.first), bytes: SecretBytes(utf8: "orphan"))
    #expect(throws: (any Error).self) { try PortableArchive.seal(extra) }
    var duplicated = complete
    duplicated.items.append(try #require(complete.items.first))
    #expect(throws: (any Error).self) { try PortableArchive.seal(duplicated) }
}

@Test func portableArchiveRoundTripsCurrentContentForFreshOwner() throws {
    let originalOwner = try TestDevice(), destination = try TestDevice()
    let original = try portableArchiveFixture(owner: originalOwner)
    let exported = try PortableArchive.seal(original)
    originalOwner.close()
    let restored = try PortableArchive.open(exported.data, recoveryKey: exported.recoveryKey)
    #expect(restored == original)
    let membership = try Membership(accounts: [.init(id: destination.identity.member, role: .owner, devices: [destination.identity])])
    let genesis = try MembershipEnvelope.genesis(membership: membership, owner: destination)
    let history = try TrustedMembershipHistory(genesis: genesis, vault: genesis.header.vault, pinnedDigest: genesis.digest())
    for item in restored.items {
        let id = try #require(restored.itemIDs[item.name])
        var security = VaultSecurityMetadata()
        security.histories = restored.security?.histories.filter { $0.itemID == id } ?? []
        let single = PortableVaultArchive(name: restored.name, items: [item], itemIDs: [item.name: id],
            references: restored.references.filter { restored.records[$0.value]?.itemID == id },
            records: restored.records.filter { $0.value.itemID == id }, security: security)
        let components = try ContentItemArchive.components(single)
        let publication = try ContentEnvelope.seal(components.values, vault: history.vault, item: components.item, history: history, signer: destination)
        let grant = try #require(publication.grants.first)
        var decoded: [String: SecretBytes] = [:]
        for name in components.values.keys {
            decoded[name] = try publication.content.open(component: name, grant: grant, history: history, device: destination)
        }
        let removedCatalog = decoded.removeValue(forKey: ContentItemArchive.catalogComponent)
        let catalogBytes = try #require(removedCatalog)
        let catalog = try ContentItemArchive.catalog(catalogBytes, item: components.item, componentNames: Set(components.values.keys))
        let reconstructed = try ContentItemArchive.archive(name: restored.name, item: components.item, catalog: catalog, records: decoded)
        #expect(reconstructed.items == single.items)
        #expect(reconstructed.records == single.records)
        #expect(reconstructed.security?.histories == single.security?.histories)
    }
}
