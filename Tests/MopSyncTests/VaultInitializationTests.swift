import Foundation
@preconcurrency import CoreData
import Testing
@testable import MopSync

private struct InitializationPermit: RepositoryWritePermit {
    var allowed = true
    func withWritePermission<T>(_ body: () throws -> T) throws -> T {
        guard allowed else { throw CancellationError() }
        return try body()
    }
}

private func initializationLocation() throws -> URL {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-initialization-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return directory
}

@Test func competingVaultInitializationsCommitExactlyOneCompleteBatch() async throws {
    let directory = try initializationLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("items.sqlite")
    let one = try EncryptedItemRepository(storeURL: url)
    let two = try EncryptedItemRepository(storeURL: url)
    let scope = VaultScope(account: "race", vaultID: UUID())
    let first = EncryptedItemVersion(scope: ItemScope(account: scope.account, vaultID: scope.vaultID, itemID: UUID()), baseVersionID: nil, ciphertext: Data([1]))
    let second = EncryptedItemVersion(scope: ItemScope(account: scope.account, vaultID: scope.vaultID, itemID: UUID()), baseVersionID: nil, ciphertext: Data([2]))
    async let a: Bool = attemptInitialization(one, scope: scope, version: first, setup: "one")
    async let b: Bool = attemptInitialization(two, scope: scope, version: second, setup: "two")
    let outcomes = await [a, b]
    #expect(outcomes.filter { $0 }.count == 1)
    let reopened = try EncryptedItemRepository(storeURL: url)
    let marker = try #require(try await reopened.vaultInitialization(scope))
    let winner = marker.setupID == "one" ? first : second
    let loser = marker.setupID == "one" ? second : first
    #expect(try await reopened.item(winner.scope) == winner)
    #expect(try await reopened.item(loser.scope) == nil)
    #expect(try await reopened.pendingMutations(account: scope.account).count == 1)
}

private func attemptInitialization(_ repository: EncryptedItemRepository, scope: VaultScope, version: EncryptedItemVersion, setup: String) async -> Bool {
    do {
        _ = try await repository.initializeVault(scope: scope, versions: [version], membershipState: Data([7]), setupID: setup, authorization: InitializationPermit())
        return true
    } catch { return false }
}

@Test func vaultInitializationIsDurableAndRetryDoesNotOverwriteLaterEdits() async throws {
    let directory = try initializationLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("items.sqlite")
    let repository = try EncryptedItemRepository(storeURL: url)
    let scope = VaultScope(account: "bootstrap", vaultID: UUID())
    let first = EncryptedItemVersion(scope: ItemScope(account: scope.account, vaultID: scope.vaultID, itemID: UUID()), baseVersionID: nil, ciphertext: Data([1]))
    let second = EncryptedItemVersion(scope: ItemScope(account: scope.account, vaultID: scope.vaultID, itemID: UUID()), baseVersionID: nil, ciphertext: Data([2]))
    let receipt = try await repository.initializeVault(scope: scope, versions: [first, second], membershipState: Data([7]), setupID: "setup", authorization: InitializationPermit())
    let reopened = try EncryptedItemRepository(storeURL: url)
    #expect(try await reopened.vaultInitialization(scope) == receipt)
    #expect(try await reopened.pendingMutations(account: scope.account).count == 2)
    #expect(try await reopened.item(first.scope) == first)
    #expect(try await reopened.item(second.scope) == second)
    let edited = EncryptedItemVersion(scope: first.scope, baseVersionID: first.versionID, ciphertext: Data([3]), generation: 2)
    _ = try await reopened.commitLocalMutation(edited)
    let retried = try await reopened.initializeVault(scope: scope, versions: [second, first], membershipState: Data([7]), setupID: "setup", authorization: InitializationPermit())
    #expect(retried == receipt)
    #expect(try await reopened.item(first.scope) == edited)
    #expect(try await reopened.pendingMutations(account: scope.account).count == 3)
    await #expect(throws: ItemRepositoryError.initializationMismatch) {
        try await reopened.initializeVault(scope: scope, versions: [first, second], membershipState: Data([8]), setupID: "setup", authorization: InitializationPermit())
    }
}

@Test func invalidVaultInitializationLeavesNoPartialItemsReceiptsOrRequests() async throws {
    let directory = try initializationLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let scope = VaultScope(account: "bootstrap", vaultID: UUID())
    let first = EncryptedItemVersion(scope: ItemScope(account: scope.account, vaultID: scope.vaultID, itemID: UUID()), baseVersionID: nil, ciphertext: Data([1]))
    let wrongScope = EncryptedItemVersion(scope: ItemScope(account: "other", vaultID: scope.vaultID, itemID: UUID()), baseVersionID: nil, ciphertext: Data([2]))
    await #expect(throws: ItemRepositoryError.invalidInitialization) {
        try await repository.initializeVault(scope: scope, versions: [first, wrongScope], membershipState: Data([7]), setupID: "setup", authorization: InitializationPermit())
    }
    await #expect(throws: CancellationError.self) {
        try await repository.initializeVault(scope: scope, versions: [first], membershipState: Data([7]), setupID: "setup", authorization: InitializationPermit(allowed: false))
    }
    #expect(try await repository.item(first.scope) == nil)
    #expect(try await repository.item(wrongScope.scope) == nil)
    #expect(try await repository.vaultInitialization(scope) == nil)
    #expect(try await repository.pendingMutations(account: scope.account).isEmpty)
    #expect(try await repository.pendingSyncRequests(account: scope.account, database: "private").isEmpty)
}

@Test func vaultInitializationCannotRepurposeExistingLocalWork() async throws {
    let directory = try initializationLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let scope = VaultScope(account: "existing", vaultID: UUID())
    let existing = EncryptedItemVersion(scope: ItemScope(account: scope.account, vaultID: scope.vaultID, itemID: UUID()), baseVersionID: nil, ciphertext: Data([1]))
    let mutation = try await repository.commitLocalMutation(existing)
    let imported = EncryptedItemVersion(scope: ItemScope(account: scope.account, vaultID: scope.vaultID, itemID: UUID()), baseVersionID: nil, ciphertext: Data([2]))
    await #expect(throws: ItemRepositoryError.existingVault) {
        try await repository.initializeVault(scope: scope, versions: [imported], membershipState: Data([7]), setupID: "new", authorization: InitializationPermit())
    }
    try await repository.acknowledge(mutationID: mutation.id, account: scope.account, serverSystemFields: Data([1]))
    await #expect(throws: ItemRepositoryError.existingVault) {
        try await repository.initializeVault(scope: scope, versions: [imported], membershipState: Data([7]), setupID: "new", authorization: InitializationPermit())
    }
    #expect(try await repository.vaultInitialization(scope) == nil)
    #expect(try await repository.item(imported.scope) == nil)
    #expect(try await repository.item(existing.scope) == existing)
    #expect(try await repository.mutationReceipt(id: mutation.id, account: scope.account)?.status == .cloudConfirmed)
}

@Test func vaultInitializationRollsBackWhenSecondPendingInsertFails() async throws {
    let directory = try initializationLocation()
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("items.sqlite")
    let repository = try EncryptedItemRepository(storeURL: url)
    let unrelated = EncryptedItemVersion(scope: ItemScope(account: "unrelated", vaultID: UUID(), itemID: UUID()), baseVersionID: nil, ciphertext: Data([9]))
    let unrelatedMutation = try await repository.commitLocalMutation(unrelated)
    _ = try await repository.requestSync(account: "rollback", database: "private", reason: .manual)
    // The first item updates a durable request successfully; the second reaches
    // request-generation overflow after staging item, pending and receipt rows.
    let coordinator = NSPersistentStoreCoordinator(managedObjectModel: RepositoryModel.make())
    let store = try coordinator.addPersistentStore(type: .sqlite, at: url,
        options: [NSPersistentHistoryTrackingKey: true, NSPersistentStoreRemoteChangeNotificationPostOptionKey: true])
    let context = NSManagedObjectContext(concurrencyType: .privateQueueConcurrencyType)
    context.persistentStoreCoordinator = coordinator
    try context.performAndWait {
        let request = NSFetchRequest<NSManagedObject>(entityName: "SyncRequest")
        request.predicate = NSPredicate(format: "account == %@", "rollback")
        let row = try #require(try context.fetch(request).first)
        row.setValue(Int64.max - 1, forKey: "generation")
        try context.save()
    }
    try coordinator.remove(store)
    let scope = VaultScope(account: "rollback", vaultID: UUID())
    let versions = (0..<2).map { EncryptedItemVersion(scope: ItemScope(account: scope.account, vaultID: scope.vaultID, itemID: UUID()), baseVersionID: nil, ciphertext: Data([UInt8($0)])) }
    await #expect(throws: ItemRepositoryError.corruptStore) {
        try await repository.initializeVault(scope: scope, versions: versions, membershipState: Data([7]), setupID: "rollback", authorization: InitializationPermit())
    }
    let reopened = try EncryptedItemRepository(storeURL: url)
    for version in versions { #expect(try await reopened.item(version.scope) == nil) }
    #expect(try await reopened.vaultInitialization(scope) == nil)
    #expect(try await reopened.pendingMutations(account: scope.account).isEmpty)
    #expect(try await reopened.pendingSyncRequests(account: scope.account, database: "private").first?.generation == Int64.max - 1)
    #expect(try await reopened.pendingMutations(account: "unrelated").map(\.id) == [unrelatedMutation.id])
}
