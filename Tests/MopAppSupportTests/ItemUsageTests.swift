import Foundation
import Testing
import MopCore
@testable import MopAppSupport

private func usageIdentity(account: String = UUID().uuidString, vault: String = UUID().uuidString, item: String = UUID().uuidString) -> ItemUsageIdentity {
    .init(account: account, vault: vault, item: item)
}

@Test func localUsageMergesConcurrentWritersAndSurvivesRestart() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = ItemUsageStore(state: root), id = usageIdentity(), other = usageIdentity()
    let date = Date()
    try await withThrowingTaskGroup(of: Void.self) { group in
        for offset in 0..<12 {
            group.addTask { try await ItemUsageStore(state: root).record([id], at: date.addingTimeInterval(Double(offset))) }
        }
        try await group.waitForAll()
    }
    try await store.record([other], at: date)
    let loaded = try await ItemUsageStore(state: root).load(accounts: [id.account])
    #expect(loaded == [id: date.addingTimeInterval(11)])
    let file = root.appendingPathComponent("v7").appendingPathComponent(id.account).appendingPathComponent("usage.json")
    #expect(try file.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
    #expect((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue == 0o600)
}

@Test func usagePruningDoesNotEraseAnotherVaultOrNewerEvents() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = ItemUsageStore(state: root), id = usageIdentity(), date = Date()
    let retained = usageIdentity(account: id.account, vault: id.vault)
    let newer = usageIdentity(account: id.account, vault: id.vault)
    let otherVault = usageIdentity(account: id.account)
    try await store.record([id, retained, otherVault], at: date)
    try await store.record([newer], at: date.addingTimeInterval(1))
    try await store.prune(account: id.account, vault: id.vault, keeping: [retained.item], before: date)
    let records = try await store.load(accounts: [id.account])
    #expect(records[id] == nil && records[retained] == date && records[otherVault] == date)
    #expect(records[newer] == date.addingTimeInterval(1))
    // Late writes must not resurrect usage for a removed account.
    let directory = root.appendingPathComponent("v7").appendingPathComponent(id.account)
    try LocalFile.write(Data("true".utf8), to: directory.appendingPathComponent("removed.json"))
    await #expect(throws: MopError.deviceRemoved) { try await store.record([id], at: date) }
    #expect(try await store.load(accounts: [id.account]).isEmpty)
}

@Test func malformedUsageIsLoggedWithoutFailingSecretAccessOrDestroyingData() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = ItemUsageStore(state: root), id = usageIdentity()
    let directory = try LocalDirectory(directory: root.appendingPathComponent("v7").appendingPathComponent(id.account))
    let file = directory.directory.appendingPathComponent("usage.json")
    try LocalFile.write(Data("invalid".utf8), to: file)
    await ItemUsageLogging.record([id], store: store)
    #expect(try LocalFile.read(file, privateFile: true) == Data("invalid".utf8))
}
