import Foundation
import Testing
import MopCore
@testable import MopVaultNext

private struct SelectiveFixture {
    let owner: TestDevice
    let membership: Membership
    let membershipState: String
    let authority: MembershipEnvelope
    let envelope: ItemEnvelope
    let archive: PortableVaultArchive
}

private func selectiveFixture() throws -> SelectiveFixture {
    let owner = try TestDevice(), source = try testAuthority(owner: owner)
    let attachment = try Attachment(fileName: "document.bin", data: Data(repeating: 42, count: 64 * 1024))
    var archive = try portableDocument(items: [VaultItem(name: "Login", type: .login, fields: [
        ItemField(path: "username", type: .username, value: "alice"),
        ItemField(path: "password", type: .password, value: "current-secret"),
        ItemField(path: "document", type: .attachment, value: try attachment.encodedValue())])])
    let itemID = try #require(archive.itemIDs["Login"]), previous = UUID().uuidString
    var history = SecretFieldHistory(itemID: itemID, path: "password", entries: [SecretHistoryEntry(id: previous, replacedAt: Date(timeIntervalSince1970: 100))])
    archive.items[0].fields[1].historyID = history.id
    archive.records[previous] = PortableArchiveRecord(itemID: itemID, bytes: SecretBytes(utf8: "previous-secret"))
    var security = VaultSecurityMetadata(); security.histories = [history]; archive.security = security
    let authority = try MembershipEnvelope.genesis(vault: source.id, membership: source.membership, owner: owner)
    let state = try authority.digest()
    let envelope = try ItemEnvelope.seal(archive, vault: source.id, generation: 1,
        membership: source.membership, membershipStateDigest: state, signer: owner)
    return SelectiveFixture(owner: owner, membership: source.membership, membershipState: state, authority: authority, envelope: envelope, archive: archive)
}

@Test func selectiveConflictResolutionRetainsLocalCiphertextAndAdvancesBeyondBothBranches() throws {
    let fixture = try selectiveFixture()
    var localCatalog = try fixture.envelope.catalog(device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState)
    localCatalog.item.metadata = ItemMetadata(favorite: true)
    let local = try fixture.envelope.edit(catalog: localCatalog, changedRecords: [:], removedRecords: [],
        membership: fixture.membership, membershipStateDigest: fixture.membershipState, signer: fixture.owner)
    var remoteCatalog = localCatalog
    remoteCatalog.item.metadata = ItemMetadata(tags: ["remote"])
    let remote = try fixture.envelope.edit(catalog: remoteCatalog, changedRecords: [:], removedRecords: [],
        membership: fixture.membership, membershipStateDigest: fixture.membershipState, signer: fixture.owner)
    let resolved = try local.resolvingConflict(with: remote, catalog: localCatalog,
        membership: fixture.membership, membershipStateDigest: fixture.membershipState, signer: fixture.owner)
    #expect(resolved.header.generation == 3)
    #expect(resolved.header.base == remote.header.version)
    #expect(resolved.header.version != local.header.version && resolved.header.version != remote.header.version)
    #expect(resolved.encryptedRecords == local.encryptedRecords)
    #expect(resolved.header.keyGeneration == local.header.keyGeneration)
    #expect(try resolved.catalog(device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState).item.metadata?.favorite == true)
}

@Test func metadataAndRenameRetainEveryFieldAndAttachmentCiphertext() throws {
    let fixture = try selectiveFixture()
    var catalog = try fixture.envelope.catalog(device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState)
    catalog.item.name = "Renamed"
    catalog.item.metadata = ItemMetadata(tags: ["work"], favorite: true)
    catalog.references = Dictionary(uniqueKeysWithValues: catalog.references.map { ($0.key.replacingOccurrences(of: "Login/", with: "Renamed/"), $0.value) })
    let edited = try fixture.envelope.edit(catalog: catalog, changedRecords: [:], removedRecords: [],
        membership: fixture.membership, membershipStateDigest: fixture.membershipState, signer: fixture.owner)
    #expect(edited.header.version != fixture.envelope.header.version)
    #expect(edited.header.base == fixture.envelope.header.version)
    #expect(edited.header.generation == 2)
    #expect(edited.header.keyGeneration == fixture.envelope.header.keyGeneration)
    #expect(edited.encryptedRecords == fixture.envelope.encryptedRecords)
    #expect(edited.envelopes == fixture.envelope.envelopes)
    let reopened = try edited.catalog(device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState)
    #expect(reopened.item.name == "Renamed")
    #expect(reopened.item.metadata?.favorite == true)
    #expect(reopened.item.fields.allSatisfy { $0.value == nil })
    let password = try #require(reopened.references["Renamed/password"])
    #expect(try edited.read(record: password, device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState) == SecretBytes(utf8: "current-secret"))
}

@Test func changingOneFieldResealsOnlyThatRecordAndRetainsAttachmentAndHistory() throws {
    let fixture = try selectiveFixture()
    var catalog = try fixture.envelope.catalog(device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState)
    let username = try #require(catalog.references["Login/username"])
    let nextUsername = UUID().uuidString
    catalog.references["Login/username"] = nextUsername
    let edited = try fixture.envelope.edit(catalog: catalog, changedRecords: [nextUsername: SecretBytes(utf8: "bob")], removedRecords: [username],
        membership: fixture.membership, membershipStateDigest: fixture.membershipState, signer: fixture.owner)
    #expect(edited.encryptedRecords[username] == nil)
    #expect(edited.encryptedRecords[nextUsername] != fixture.envelope.encryptedRecords[username])
    for (id, ciphertext) in fixture.envelope.encryptedRecords where id != username {
        #expect(edited.encryptedRecords[id] == ciphertext)
    }
    #expect(try edited.read(record: nextUsername, device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState) == SecretBytes(utf8: "bob"))
    #expect(try edited.catalog(device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState).histories == catalog.histories)
}

@Test func passwordReplacementRetainsPreviousCiphertextAsHistoryWithoutReencrypting() throws {
    let fixture = try selectiveFixture()
    var catalog = try fixture.envelope.catalog(device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState)
    let previousPassword = try #require(catalog.references["Login/password"])
    let historyIndex = try #require(catalog.histories.firstIndex { $0.path == "password" })
    catalog.histories[historyIndex].entries.append(SecretHistoryEntry(id: previousPassword, replacedAt: Date()))
    let nextPassword = UUID().uuidString
    catalog.references["Login/password"] = nextPassword
    let edited = try fixture.envelope.edit(catalog: catalog, changedRecords: [nextPassword: SecretBytes(utf8: "new-secret")], removedRecords: [],
        membership: fixture.membership, membershipStateDigest: fixture.membershipState, signer: fixture.owner)
    #expect(edited.encryptedRecords.count == fixture.envelope.encryptedRecords.count + 1)
    for (id, ciphertext) in fixture.envelope.encryptedRecords { #expect(edited.encryptedRecords[id] == ciphertext) }
    #expect(try edited.read(record: previousPassword, device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState) == SecretBytes(utf8: "current-secret"))
    #expect(try edited.read(record: nextPassword, device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState) == SecretBytes(utf8: "new-secret"))
}

private struct SelectiveSignedStatement: Encodable {
    let domain = "2ndpass-item-envelope-signature-2"
    let header: ItemEnvelope.Header
    let encryptedCatalog: Data
    let encryptedRecords: [String: Data]
    let envelopes: [String: KeyEnvelope]
}

@Test func metadataEditDoesNotDecryptUnchangedOpaqueFieldCiphertext() throws {
    let fixture = try selectiveFixture()
    var catalog = try fixture.envelope.catalog(device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState)
    let attachment = try #require(catalog.references["Login/document"])
    var records = fixture.envelope.encryptedRecords
    var corrupted = try #require(records[attachment]); corrupted[corrupted.count - 1] ^= 1
    records[attachment] = corrupted
    let statement = SelectiveSignedStatement(header: fixture.envelope.header, encryptedCatalog: fixture.envelope.encryptedCatalog,
        encryptedRecords: records, envelopes: fixture.envelope.envelopes)
    let signedOpaque = ItemEnvelope(header: fixture.envelope.header, encryptedCatalog: fixture.envelope.encryptedCatalog,
        encryptedRecords: records, envelopes: fixture.envelope.envelopes, signature: try fixture.owner.sign(Codec.encode(statement)))
    try signedOpaque.verify(vault: signedOpaque.header.vault, item: signedOpaque.header.item,
        membership: fixture.membership, membershipStateDigest: fixture.membershipState)
    catalog.item.metadata = ItemMetadata(favorite: true)
    let edited = try signedOpaque.edit(catalog: catalog, changedRecords: [:], removedRecords: [],
        membership: fixture.membership, membershipStateDigest: fixture.membershipState, signer: fixture.owner)
    #expect(edited.encryptedRecords == records)
    // The byte sequence authenticates as an author-signed opaque record but fails
    // field AEAD. Successful editing therefore proves it was never decrypted.
    #expect(throws: (any Error).self) {
        try edited.read(record: attachment, device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState)
    }
}

@Test func selectiveEditRejectsDanglingRecordsAndImplicitMembershipRotation() throws {
    let fixture = try selectiveFixture()
    let catalog = try fixture.envelope.catalog(device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState)
    let password = try #require(catalog.references["Login/password"])
    #expect(throws: (any Error).self) {
        try fixture.envelope.edit(catalog: catalog, changedRecords: [password: SecretBytes(utf8: "replacement")], removedRecords: [],
            membership: fixture.membership, membershipStateDigest: fixture.membershipState, signer: fixture.owner)
    }
    #expect(throws: (any Error).self) {
        try fixture.envelope.edit(catalog: catalog, changedRecords: [:], removedRecords: [password],
            membership: fixture.membership, membershipStateDigest: fixture.membershipState, signer: fixture.owner)
    }
    #expect(throws: (any Error).self) {
        try fixture.envelope.edit(catalog: catalog, changedRecords: [UUID().uuidString: SecretBytes(utf8: "orphan")], removedRecords: [],
            membership: fixture.membership, membershipStateDigest: fixture.membershipState, signer: fixture.owner)
    }
    #expect(throws: (any Error).self) {
        try fixture.envelope.edit(catalog: catalog, changedRecords: [:], removedRecords: [],
            membership: fixture.membership, membershipStateDigest: String(repeating: "0", count: 64), signer: fixture.owner)
    }
}

@Test func explicitRekeyChangesAllCiphertextAndAddsOnlyAuthorizedRecipients() throws {
    let fixture = try selectiveFixture(), peer = try TestDevice()
    let roster = try Membership(accounts: fixture.membership.accounts + [AccountMember(id: peer.identity.member, role: .viewer, devices: [peer.identity])])
    let authority = try MembershipEnvelope.successor(of: fixture.authority, membership: roster, owner: fixture.owner)
    let digest = try authority.digest()
    let rekeyed = try fixture.envelope.rekey(name: fixture.archive.name,
        previousMembership: fixture.membership, previousMembershipStateDigest: fixture.membershipState,
        membership: roster, membershipStateDigest: digest, signer: fixture.owner)
    #expect(rekeyed.header.keyGeneration != fixture.envelope.header.keyGeneration)
    #expect(rekeyed.header.base == fixture.envelope.header.version)
    #expect(rekeyed.header.generation == 2)
    #expect(rekeyed.header.membership == digest)
    for (id, oldCiphertext) in fixture.envelope.encryptedRecords { #expect(rekeyed.encryptedRecords[id] != oldCiphertext) }
    let archive = try rekeyed.portableArchive(name: fixture.archive.name, device: peer, membership: roster, membershipStateDigest: digest)
    #expect(archive.records == fixture.archive.records)
    #expect(throws: (any Error).self) {
        try fixture.envelope.portableArchive(name: fixture.archive.name, device: peer,
            membership: fixture.membership, membershipStateDigest: fixture.membershipState)
    }
}

@Test func repeatedPasswordReplacementBoundsHistoryAndPreservesUnrelatedAttachment() throws {
    let fixture = try selectiveFixture()
    var envelope = fixture.envelope
    let initialCatalog = try envelope.catalog(device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState)
    let attachmentID = try #require(initialCatalog.references["Login/document"])
    let originalPasswordID = try #require(initialCatalog.references["Login/password"])
    for index in 0..<25 {
        let catalog = try envelope.catalog(device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState)
        let patch = try catalog.replacingField("password", value: SecretBytes(utf8: "replacement-\(index)"), itemID: envelope.header.item,
            at: Date(timeIntervalSince1970: 2_000_000_000 + Double(index)))
        envelope = try envelope.edit(catalog: patch.catalog, changedRecords: patch.changedRecords, removedRecords: patch.removedRecords,
            membership: fixture.membership, membershipStateDigest: fixture.membershipState, signer: fixture.owner)
        #expect(envelope.encryptedRecords[attachmentID] == fixture.envelope.encryptedRecords[attachmentID])
    }
    let finalCatalog = try envelope.catalog(device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState)
    let history = try #require(finalCatalog.histories.first { $0.path == "password" })
    #expect(history.entries.count == 20)
    #expect(envelope.encryptedRecords[originalPasswordID] == nil)
    let latestHistorical = try #require(history.entries.first?.id)
    #expect(try envelope.read(record: latestHistorical, device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState) == SecretBytes(utf8: "replacement-23"))
    let current = try #require(finalCatalog.references["Login/password"])
    #expect(try envelope.read(record: current, device: fixture.owner, membership: fixture.membership, membershipStateDigest: fixture.membershipState) == SecretBytes(utf8: "replacement-24"))
}
