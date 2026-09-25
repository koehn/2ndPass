import Foundation
import Testing
import MopCore
@testable import MopAppSupport

private func login() -> VaultItem {
    VaultItem(name: "Example", type: .login, fields: [
        ItemField(path: "username", type: .username, value: "alice"),
        ItemField(path: "password", type: .password, value: "must-not-be-indexed"),
        ItemField(path: "website", type: .website, value: "https://Example.COM/login?secret=private")])
}
@Test func autoFillIndexesOnlyLoginMetadataAndOpaqueLocators() throws {
    let id = UUID().uuidString
    var item = login()
    item.fields.append(ItemField(path: "alternate", type: .website, value: "example.com"))
    let entries = AutoFillEntry.entries(catalog: ItemCatalog(vault: "personal", revision: "", items: [item]), vaultID: id)
    let entry = try #require(entries.first)
    #expect(entries.count == 1)
    #expect(entry.website == "example.com")
    #expect(entry.username == "alice")
    #expect(AutoFillEntry.vaultID(entry.recordIdentifier) == id)
    #expect(!entry.recordIdentifier.contains("Example"))
    #expect(!entry.recordIdentifier.contains("alice"))
    #expect(entry.identity.serviceIdentifier.identifier == "example.com")
    item.fields[1].value = "new-password"
    let next = AutoFillEntry.entries(catalog: ItemCatalog(vault: "renamed", revision: "new", items: [item]), vaultID: id)
    #expect(next.first?.recordIdentifier == entry.recordIdentifier)
    item.fields[0].value = "bob"
    #expect(AutoFillEntry.entries(catalog: ItemCatalog(vault: "personal", revision: "", items: [item]), vaultID: id).first?.recordIdentifier != entry.recordIdentifier)
}
@Test func autoFillRejectsAmbiguousAndNonLoginItems() {
    let id = UUID().uuidString
    var item = login()
    item.fields[1].path = "first-secret"
    item.fields.append(ItemField(path: "other", type: .password))
    #expect(AutoFillEntry.entries(catalog: ItemCatalog(vault: "v", revision: "", items: [item]), vaultID: id).isEmpty)
    item = login(); item.type = .apiCredential
    #expect(AutoFillEntry.entries(catalog: ItemCatalog(vault: "v", revision: "", items: [item]), vaultID: id).isEmpty)
    #expect(AutoFillEntry.vaultID("../../private") == nil)
    for website in ["javascript:alert(1)", "https://user:password@example.com", "https://", "file:///tmp/secret", "https://exam ple.com"] {
        #expect(AutoFillEntry.website(website) == nil)
    }
}

@Test func sharedAutoFillIndexPreservesVaultsWithoutReadingAppleStore() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let index = AutoFillIndex(directory: root)
    let first = UUID().uuidString, second = UUID().uuidString
    let catalog = ItemCatalog(vault: "personal", revision: "", items: [login()])
    let a = AutoFillEntry.entries(catalog: catalog, vaultID: first).map(AutoFillIdentity.init)
    let b = AutoFillEntry.entries(catalog: catalog, vaultID: second).map(AutoFillIdentity.init)
    #expect(try index.load().isEmpty)
    try index.update { _ in a }
    try index.update { $0 + b }
    // A different process/instance can load the picker without vault authentication.
    #expect(try AutoFillIndex(directory: root).load().count == 2)
    let data = try Data(contentsOf: root.appendingPathComponent("identities.json"))
    let rows = try #require(JSONSerialization.jsonObject(with: data) as? [[String: Any]])
    #expect(rows.allSatisfy { Set($0.keys) == ["website", "username", "recordIdentifier"] })
    #expect(!String(decoding: data, as: UTF8.self).contains("must-not-be-indexed"))
    try index.update { $0.filter { AutoFillEntry.vaultID($0.recordIdentifier) != first } }
    #expect(try index.load() == b)
    try index.update { _ in [] }
    #expect(try index.load().isEmpty)
}

private actor PublishedAutoFillIdentities {
    var rows: [AutoFillIdentity] = []
    func save(_ rows: [AutoFillIdentity]) { self.rows = rows }
}

@Test func autoFillPublisherKeepsAllVaultsAcrossRefreshAndEdits() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let published = PublishedAutoFillIdentities()
    let publisher = AutoFillPublisher(directory: root, publish: { await published.save($0) })
    let first = UUID().uuidString, second = UUID().uuidString
    let catalog = ItemCatalog(vault: "personal", revision: "", items: [login()])
    try await publisher.publish(catalog: catalog, vaultID: first)
    try await publisher.publish(catalog: catalog, vaultID: second)
    try await publisher.prune(keeping: [first, second])
    try await publisher.publish(catalog: catalog, vaultID: first)
    #expect(try AutoFillIndex(directory: root).load().count == 2)
    #expect(await published.rows.count == 2)
    try await publisher.remove(vaultID: first)
    #expect(try AutoFillIndex(directory: root).load().map { AutoFillEntry.vaultID($0.recordIdentifier) } == [second])
    #expect(await published.rows.count == 1)
}

@Test func autoFillUsesPrimaryLoginFieldsWithAdditionalFields() throws {
    var item = login()
    item.fields += [ItemField(path: "contact", type: .email, value: "contact@example.net"),
                    ItemField(path: "other-user", type: .username, value: "secondary"),
                    ItemField(path: "other-password", type: .password),
                    ItemField(path: "notes", type: .notes, value: "notes")]
    let entry = try #require(AutoFillEntry.entries(catalog: ItemCatalog(vault: "v", revision: "", items: [item]), vaultID: UUID().uuidString).first)
    #expect(entry.username == "alice")
    #expect(entry.reference.field == "password")
    #expect(AutoFillEntry.exclusionReason(for: item) == nil)
}
@Test func autoFillExplainsFieldNamesWithoutCorrectTypes() {
    var item = login()
    item.fields[0].type = .text
    #expect(AutoFillEntry.exclusionReason(for: item)?.contains("Username") == true)
    item.fields[0].type = .username; item.fields[1].type = .concealed
    #expect(AutoFillEntry.exclusionReason(for: item)?.contains("Password") == true)
    item.fields[1].type = .password; item.fields[2].type = .text
    #expect(AutoFillEntry.exclusionReason(for: item)?.contains("Website") == true)
}
