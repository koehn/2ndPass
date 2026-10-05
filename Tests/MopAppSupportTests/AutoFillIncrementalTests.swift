import AuthenticationServices
import Foundation
import Synchronization
import Testing
import MopCore
@testable import MopAppSupport

private actor SuggestionStore {
    var rows: [String: AutoFillIdentity] = [:]
    var replacements = 0
    var saves: [[AutoFillIdentity]] = []
    var removals: [[AutoFillIdentity]] = []
    var failSave = false
    func failing(_ value: Bool) { failSave = value }
    func replace(_ values: [AutoFillIdentity]) {
        replacements += 1; rows = Dictionary(uniqueKeysWithValues: values.map { ($0.id, $0) })
    }
    func save(_ values: [AutoFillIdentity]) throws {
        if failSave { throw MopError.inputOutput }
        saves.append(values)
        for value in values { rows[value.id] = value }
    }
    func remove(_ values: [AutoFillIdentity]) {
        removals.append(values)
        for value in values { rows[value.id] = nil }
    }
    func reset() { rows = [:] }
}
private func publisher(_ root: URL, _ store: SuggestionStore,
                       incremental: Bool = true,
                       local: @escaping @Sendable () throws -> [AutoFillIdentity] = { [] }) -> AutoFillPublisher {
    AutoFillPublisher(directory: root, publish: { await store.replace($0) }, incremental: { incremental },
        save: { try await store.save($0) }, remove: { await store.remove($0) }, local: local)
}

@Test func automaticReconciliationRepairsMissingSystemSuggestionsWithoutCatalogOrUnlock() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = SuggestionStore(), first = publisher(root, store), vault = UUID().uuidString
    let catalog = try suggestionCatalog([(suggestionItem(UUID(), user: "alice"), UUID())])
    try await first.publish(catalog: catalog, vaultID: vault)
    await store.reset()
    // The durable checkpoint and picker still contain Alice; only Apple's
    // store was reset. A fresh app instance must detect this automatically.
    let restarted = publisher(root, store)
    try await restarted.reconcile()
    #expect(await store.rows.values.map(\.username) == ["alice"])
    #expect(await store.replacements == 2)
    try await restarted.reconcile()
    #expect(await store.replacements == 3)
    #expect(await store.saves.isEmpty)
}
private func suggestionItem(_ id: UUID, user: String) -> VaultItem {
    var item = VaultItem(name: "Private-title-" + id.uuidString, type: .login, fields: [
        ItemField(path: "username", type: .username, value: user),
        ItemField(path: "password", type: .password, value: "never-persist-this-secret"),
        ItemField(path: "website", type: .website, value: "example.test")])
    item.storageID = id.uuidString
    return item
}
private func suggestionCatalog(_ items: [(VaultItem, UUID)]) throws -> ItemCatalog {
    let versions = Dictionary(uniqueKeysWithValues: items.map { ($0.0.storageID!, $0.1.uuidString) })
    return ItemCatalog(vault: "private-vault", revision: try JSONEncoder().encode(versions).base64EncodedString(), items: items.map(\.0))
}

@Test func pruningObsoleteVaultSuggestionsSurvivesRefreshAndRestart() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = SuggestionStore(), current = UUID().uuidString, obsolete = UUID().uuidString
    let local = try #require(AutoFillIdentity(identity: ASPasskeyCredentialIdentity(
        relyingPartyIdentifier: "example.test", userName: "local", credentialID: Data(repeating: 1, count: 32),
        userHandle: Data([1]), recordIdentifier: "local/" + UUID().uuidString)))
    let first = publisher(root, store, local: { [local] })
    try await first.publish(catalog: suggestionCatalog([(suggestionItem(UUID(), user: "current"), UUID())]), vaultID: current)
    try await first.publish(catalog: suggestionCatalog([(suggestionItem(UUID(), user: "obsolete"), UUID())]), vaultID: obsolete)
    try await first.prune(keeping: [current])
    #expect(Set(await store.rows.values.map(\.username)) == ["current", "local"])
    let restarted = publisher(root, store, local: { [local] })
    try await restarted.refresh()
    #expect(Set(await store.rows.values.map(\.username)) == ["current", "local"])
    #expect(try AutoFillIndex(directory: root).load().map(\.username) == ["current"])
}

@Test func incrementalSuggestionsReuseVersionsAndPublishOnlyChangedIdentitiesAcrossRestart() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = SuggestionStore(), vault = UUID().uuidString
    let a = suggestionItem(UUID(), user: "alice"), b = suggestionItem(UUID(), user: "bob"), av = UUID(), bv = UUID()
    let initial = try suggestionCatalog([(a, av), (b, bv)])
    let first = publisher(root, store)
    try await first.publish(catalog: initial, vaultID: vault)
    #expect(await store.replacements == 1)
    let next = publisher(root, store)
    try await next.publish(catalog: initial, vaultID: vault)
    #expect(await store.replacements == 1)
    #expect(await store.saves.isEmpty)
    // Same version must reuse the projection rather than recomputing the supplied row.
    var unchanged = a; unchanged.fields[0].value = "must-not-be-recomputed"
    try await next.publish(catalog: suggestionCatalog([(unchanged, av), (b, bv)]), vaultID: vault)
    #expect(await store.saves.isEmpty)
    var changed = b; changed.fields[0].value = "robert"
    try await next.publish(catalog: suggestionCatalog([(a, av), (changed, UUID())]), vaultID: vault)
    #expect(await store.replacements == 1)
    #expect(await store.saves.last?.map(\.username) == ["robert"])
    #expect(await store.removals.last?.map(\.username) == ["bob"])
    let disk = try String(contentsOf: root.appendingPathComponent("projection.json"), encoding: .utf8)
    #expect(!disk.contains("Private-title") && !disk.contains("private-vault") && !disk.contains("never-persist-this-secret"))
}

@Test func partialSuggestionsDoNotDeleteAbsentItemsAndExplicitRemovalDoes() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = SuggestionStore(), p = publisher(root, store), vault = UUID().uuidString
    let a = suggestionItem(UUID(), user: "alice"), b = suggestionItem(UUID(), user: "bob"), av = UUID(), bv = UUID()
    try await p.publish(catalog: suggestionCatalog([(a, av), (b, bv)]), vaultID: vault)
    try await p.publish(catalog: suggestionCatalog([(a, av)]), vaultID: vault, complete: false)
    #expect(await store.rows.count == 2)
    #expect(await store.removals.isEmpty)
    try await p.publish(catalog: suggestionCatalog([]), vaultID: vault, complete: false, removing: [b.storageID!])
    #expect(await store.rows.values.map(\.username) == ["alice"])
    try await p.publish(catalog: suggestionCatalog([]), vaultID: vault)
    #expect(await store.rows.isEmpty)
}

@Test func failedIncrementalPublicationRemainsPendingAcrossRestart() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = SuggestionStore(), p = publisher(root, store), vault = UUID().uuidString
    var item = suggestionItem(UUID(), user: "alice")
    try await p.publish(catalog: suggestionCatalog([(item, UUID())]), vaultID: vault)
    item.fields[0].value = "new-alice"
    await store.failing(true)
    await #expect(throws: MopError.inputOutput) {
        try await p.publish(catalog: suggestionCatalog([(item, UUID())]), vaultID: vault)
    }
    #expect(await p.status().phase == .failed)
    let pending = try JSONDecoder().decode(AutoFillPublicationState.self, from: Data(contentsOf: root.appendingPathComponent("projection.json")))
    #expect(pending.requiresReconciliation)
    #expect(pending.published?.map(\.username) == ["alice"])
    #expect(pending.items[vault]?.values.flatMap(\.identities).map(\.username) == ["new-alice"])
    // Simulate termination after saving desired state but before updating the picker index.
    try AutoFillIndex(directory: root).update { _ in pending.published ?? [] }
    await store.failing(false)
    let restarted = publisher(root, store)
    try await restarted.refreshLocalPasskeys()
    #expect(await store.rows.values.map(\.username) == ["new-alice"])
    #expect(await restarted.status().phase == .current)
}

@Test func localPasskeysShareCoordinationAndFailedInventoryDoesNotDeleteThem() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let identity = ASPasskeyCredentialIdentity(relyingPartyIdentifier: "example.test", userName: "local",
        credentialID: Data(repeating: 1, count: 32), userHandle: Data([1]), recordIdentifier: "local/" + UUID().uuidString)
    let local = try #require(AutoFillIdentity(identity: identity))
    let inventory = Mutex<[AutoFillIdentity]>([local]), fails = Mutex(false)
    let store = SuggestionStore()
    let p = publisher(root, store, local: {
        if fails.withLock({ $0 }) { throw MopError.authentication }
        return inventory.withLock { $0 }
    })
    let vault = UUID().uuidString, item = suggestionItem(UUID(), user: "cloud")
    try await p.publish(catalog: suggestionCatalog([(item, UUID())]), vaultID: vault)
    #expect(await store.rows.count == 2)
    fails.withLock { $0 = true }
    try await p.refreshLocalPasskeys()
    #expect(await store.rows.count == 2)
    fails.withLock { $0 = false }; inventory.withLock { $0 = [] }
    try await p.refreshLocalPasskeys()
    #expect(await store.removals.last?.map(\.id) == [local.id])
    #expect(await store.rows.values.map(\.username) == ["cloud"])
}

@Test func fullReconciliationRepairsResetCorruptionAndUnsupportedStores() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = SuggestionStore(), p = publisher(root, store), vault = UUID().uuidString
    let a = suggestionItem(UUID(), user: "alice"), av = UUID()
    let catalog = try suggestionCatalog([(a, av)])
    try await p.publish(catalog: catalog, vaultID: vault)
    await store.reset()
    try await p.refresh()
    #expect(await store.rows.count == 1)
    let file = root.appendingPathComponent("projection.json")
    try Data("broken".utf8).write(to: file)
    try await p.publish(catalog: catalog, vaultID: vault)
    #expect(await store.replacements == 3)
    var state = try JSONDecoder().decode(AutoFillPublicationState.self, from: Data(contentsOf: file))
    state.schema += 1
    try JSONEncoder().encode(state).write(to: file)
    try await p.publish(catalog: catalog, vaultID: vault)
    #expect(await store.replacements == 4)
    let unsupported = publisher(root, store, incremental: false)
    var changed = a; changed.fields[0].value = "new-alice"
    try await unsupported.publish(catalog: suggestionCatalog([(changed, UUID())]), vaultID: vault)
    #expect(await store.replacements == 5)
    #expect(await store.saves.isEmpty)
}

@Test func separatePublishersSerializeCloudAndLocalUpdates() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = SuggestionStore(), a = publisher(root, store), b = publisher(root, store)
    let first = try suggestionCatalog([(suggestionItem(UUID(), user: "alice"), UUID())])
    let second = try suggestionCatalog([(suggestionItem(UUID(), user: "bob"), UUID())])
    async let one: Void = a.publish(catalog: first, vaultID: UUID().uuidString)
    async let two: Void = b.publish(catalog: second, vaultID: UUID().uuidString)
    _ = try await (one, two)
    #expect(await store.rows.count == 2)
    #expect(await store.replacements == 1)
}
