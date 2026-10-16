import Foundation
import Testing
import MopCore
@testable import MopVaultNext

private struct SelectiveFixture {
    let owner: TestDevice
    let history: TrustedMembershipHistory
    let content: ContentEnvelope
    let grant: ContentKeyGrant
    let values: [String: SecretBytes]
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
    let fieldHistory = SecretFieldHistory(itemID: itemID, path: "password", entries: [SecretHistoryEntry(id: previous, replacedAt: Date(timeIntervalSince1970: 100))])
    archive.items[0].fields[1].historyID = fieldHistory.id
    archive.records[previous] = PortableArchiveRecord(itemID: itemID, bytes: SecretBytes(utf8: "previous-secret"))
    var security = VaultSecurityMetadata(); security.histories = [fieldHistory]; archive.security = security
    let authority = try MembershipEnvelope.genesis(vault: source.id, membership: source.membership, owner: owner)
    let history = try TrustedMembershipHistory(genesis: authority, vault: source.id, pinnedDigest: authority.digest())
    let components = try ContentItemArchive.components(archive)
    let publication = try ContentEnvelope.seal(components.values, vault: source.id, item: components.item, history: history, signer: owner)
    return SelectiveFixture(owner: owner, history: history, content: publication.content,
        grant: try #require(publication.grants.first), values: components.values, archive: archive)
}

private func catalog(_ content: ContentEnvelope, fixture: SelectiveFixture) throws -> ItemContentCatalog {
    try ContentItemArchive.catalog(content.open(component: ContentItemArchive.catalogComponent, grant: fixture.grant,
        history: fixture.history, device: fixture.owner), item: content.header.item, componentNames: Set(content.components.keys))
}

@Test func metadataAndRenamePreserveEveryFieldAttachmentAndHistory() throws {
    let fixture = try selectiveFixture()
    var projection = try catalog(fixture.content, fixture: fixture)
    projection.item.name = "Renamed"
    projection.item.metadata = ItemMetadata(tags: ["work"], favorite: true)
    projection.references = Dictionary(uniqueKeysWithValues: projection.references.map { ($0.key.replacingOccurrences(of: "Login/", with: "Renamed/"), $0.value) })
    var values = fixture.values
    values[ContentItemArchive.catalogComponent] = try ContentItemArchive.encode(projection)
    let edited = try fixture.content.editing(values, grant: fixture.grant, history: fixture.history, device: fixture.owner)
    #expect(edited.header.base == fixture.content.header.version)
    #expect(edited.header.keyGeneration == fixture.content.header.keyGeneration)
    let reopened = try catalog(edited, fixture: fixture)
    #expect(reopened.item.name == "Renamed" && reopened.item.metadata?.favorite == true)
    #expect(reopened.item.fields.allSatisfy { $0.value == nil })
    #expect(reopened.histories == projection.histories)
    for (id, bytes) in fixture.values where id != ContentItemArchive.catalogComponent {
        #expect(try edited.open(component: id, grant: fixture.grant, history: fixture.history, device: fixture.owner) == bytes)
    }
}

@Test func repeatedPasswordReplacementBoundsHistoryAndPreservesUnrelatedAttachment() throws {
    let fixture = try selectiveFixture()
    var content = fixture.content, values = fixture.values
    let initial = try catalog(content, fixture: fixture)
    let attachment = try #require(initial.references["Login/document"])
    let originalPassword = try #require(initial.references["Login/password"])
    for index in 0..<25 {
        let projection = try catalog(content, fixture: fixture)
        let patch = try projection.replacingField("password", value: SecretBytes(utf8: "replacement-\(index)"), itemID: content.header.item,
            at: Date(timeIntervalSince1970: 2_000_000_000 + Double(index)))
        for id in patch.removedRecords { values.removeValue(forKey: id) }
        values.merge(patch.changedRecords) { _, new in new }
        values[ContentItemArchive.catalogComponent] = try ContentItemArchive.encode(patch.catalog)
        content = try content.editing(values, grant: fixture.grant, history: fixture.history, device: fixture.owner)
        #expect(try content.open(component: attachment, grant: fixture.grant, history: fixture.history, device: fixture.owner) == fixture.values[attachment])
    }
    let final = try catalog(content, fixture: fixture)
    let history = try #require(final.histories.first { $0.path == "password" })
    #expect(history.entries.count == 20)
    #expect(content.components[originalPassword] == nil)
    let latest = try #require(history.entries.first?.id)
    #expect(try content.open(component: latest, grant: fixture.grant, history: fixture.history, device: fixture.owner) == "replacement-23")
    let current = try #require(final.references["Login/password"])
    #expect(try content.open(component: current, grant: fixture.grant, history: fixture.history, device: fixture.owner) == "replacement-24")
    #expect(content.header.keyGeneration == fixture.content.header.keyGeneration)
}
