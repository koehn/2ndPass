import Foundation
import Testing
@testable import MopSync

private func repositoryLocation() throws -> URL {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-repository-test-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return directory.appendingPathComponent("items.sqlite")
}

@Test func durableItemAndPendingMutationSurviveReopeningSQLite() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let scope = ItemScope(account: "account-a", vaultID: UUID(), itemID: UUID())
    let version = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1, 2, 3]))
    let repository = try EncryptedItemRepository(storeURL: url)
    let receipt = try await repository.commitLocalMutation(version)
    let reopened = try EncryptedItemRepository(storeURL: url)
    #expect(try await reopened.item(scope) == version)
    #expect(try await reopened.pendingMutations(account: scope.account) == [receipt])
    #expect(try await reopened.pendingMutations(account: "other-account").isEmpty)
    #expect(try await reopened.items(account: "other-account", vaultID: scope.vaultID).isEmpty)
}

@Test func staleDraftCannotOverwriteAnotherLocalSave() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    let scope = ItemScope(account: "account-a", vaultID: UUID(), itemID: UUID())
    let original = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1]))
    _ = try await repository.commitLocalMutation(original)
    let next = EncryptedItemVersion(scope: scope, baseVersionID: original.versionID, ciphertext: Data([2]), generation: 2)
    _ = try await repository.commitLocalMutation(next)
    await #expect(throws: ItemRepositoryError.staleLocalVersion) {
        try await repository.commitLocalMutation(EncryptedItemVersion(scope: scope, baseVersionID: original.versionID, ciphertext: Data([3]), generation: 2))
    }
    #expect(try await repository.item(scope) == next)
    #expect(try await repository.pendingMutations(account: scope.account).count == 2)
}

@Test func acknowledgingOlderUploadPreservesNewerPendingEdit() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    let scope = ItemScope(account: "account-a", vaultID: UUID(), itemID: UUID())
    let first = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1]))
    let receipt = try await repository.commitLocalMutation(first)
    let second = EncryptedItemVersion(scope: scope, baseVersionID: first.versionID, ciphertext: Data([2]), generation: 2)
    let pending = try await repository.commitLocalMutation(second)
    try await repository.acknowledge(mutationID: receipt.id, account: scope.account, serverSystemFields: Data([9]))
    #expect(try await repository.item(scope) == second)
    #expect(try await repository.pendingMutations(account: scope.account) == [pending])
}

@Test func remoteChangeCannotErasePendingLocalVersion() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    let scope = ItemScope(account: "account-a", vaultID: UUID(), itemID: UUID())
    let local = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1]))
    let pending = try await repository.commitLocalMutation(local)
    let remote = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([2]))
    await #expect(throws: ItemRepositoryError.pendingLocalChanges) {
        try await repository.applyRemote(remote, serverSystemFields: Data([9]))
    }
    #expect(try await repository.item(scope) == local)
    #expect(try await repository.pendingMutations(account: scope.account) == [pending])
}

@Test func engineStateRemainsBoundToAccountAndDatabaseAcrossRestart() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    try await repository.saveEngineState(Data([1, 2]), account: "account-a", database: "private")
    try await repository.saveEngineState(Data([3, 4]), account: "account-a", database: "shared")
    let reopened = try EncryptedItemRepository(storeURL: url)
    #expect(try await reopened.engineState(account: "account-a", database: "private") == Data([1, 2]))
    #expect(try await reopened.engineState(account: "account-a", database: "shared") == Data([3, 4]))
    #expect(try await reopened.engineState(account: "account-b", database: "private") == nil)
}

@Test func conflictPreservesBothEncryptedVersionsAcrossReopen() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    let scope = ItemScope(account: "account-a", vaultID: UUID(), itemID: UUID())
    let local = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1]))
    _ = try await repository.commitLocalMutation(local)
    let remote = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([2]))
    let conflict = try await repository.recordConflict(remote: remote, serverSystemFields: Data([9]))
    let reopened = try EncryptedItemRepository(storeURL: url)
    #expect(try await reopened.conflicts(account: scope.account) == [conflict])
    #expect(conflict.local == local)
    #expect(conflict.remote == remote)
    #expect(try await reopened.conflicts(account: "account-b").isEmpty)
}

@Test func persistentHistoryFindsAnotherStoreClientsChanges() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let reader = try EncryptedItemRepository(storeURL: url)
    let writer = try EncryptedItemRepository(storeURL: url)
    let scope = ItemScope(account: "account-a", vaultID: UUID(), itemID: UUID())
    let first = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1]))
    _ = try await writer.commitLocalMutation(first)
    let batch = try await reader.history(after: nil)
    #expect(batch.transactionCount >= 1)
    let token = try #require(batch.token)
    try await reader.checkpointHistory(token: token, consumer: "autofill", account: scope.account)
    #expect(try await reader.historyCheckpoint(consumer: "autofill", account: scope.account) == token)
    #expect(try await reader.historyCheckpoint(consumer: "app", account: scope.account) == nil)
    let second = EncryptedItemVersion(scope: scope, baseVersionID: first.versionID, ciphertext: Data([2]), generation: 2)
    _ = try await writer.commitLocalMutation(second)
    #expect(try await reader.history(after: token).transactionCount >= 1)
    #expect(try await reader.item(scope) == second)
}

@Test func identicalItemIDsInDistinctSharedZonesDoNotCollide() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    let vault = UUID(), item = UUID()
    let scopes = [
        ItemScope(account: "account", vaultID: vault, itemID: item),
        ItemScope(account: "account", vaultID: vault, itemID: item, database: "shared", zoneOwner: "owner-a"),
        ItemScope(account: "account", vaultID: vault, itemID: item, database: "shared", zoneOwner: "owner-b")
    ]
    for (index, scope) in scopes.enumerated() {
        _ = try await repository.commitLocalMutation(EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([UInt8(index)])))
    }
    for (index, scope) in scopes.enumerated() {
        #expect(try await repository.item(scope)?.ciphertext == Data([UInt8(index)]))
    }
    #expect(try await repository.pendingMutations(account: "account").count == 3)
}

@Test func emptyCiphertextRejectsSaveWithoutLeavingPendingWork() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    let scope = ItemScope(account: "account", vaultID: UUID(), itemID: UUID())
    let version = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data())
    await #expect(throws: ItemRepositoryError.emptyCiphertext) { try await repository.commitLocalMutation(version) }
    #expect(try await repository.item(scope) == nil)
    #expect(try await repository.pendingMutations(account: "account").isEmpty)
}

@Test func concurrentRepositoryWritersCannotBothReplaceSameBase() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let first = try EncryptedItemRepository(storeURL: url)
    let second = try EncryptedItemRepository(storeURL: url)
    let scope = ItemScope(account: "account", vaultID: UUID(), itemID: UUID())
    let base = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([0]))
    _ = try await first.commitLocalMutation(base)
    let one = EncryptedItemVersion(scope: scope, baseVersionID: base.versionID, ciphertext: Data([1]), generation: 2)
    let two = EncryptedItemVersion(scope: scope, baseVersionID: base.versionID, ciphertext: Data([2]), generation: 2)
    let successful = await withTaskGroup(of: Bool.self) { group in
        group.addTask { do { _ = try await first.commitLocalMutation(one); return true } catch { return false } }
        group.addTask { do { _ = try await second.commitLocalMutation(two); return true } catch { return false } }
        var count = 0
        for await succeeded in group { if succeeded { count += 1 } }
        return count
    }
    #expect(successful == 1)
    let saved = try await first.item(scope)
    #expect(saved == one || saved == two)
    #expect(try await first.pendingMutations(account: scope.account).count == 2)
}

@Test func receiptRequiresCloudAcknowledgementAndSurvivesLaterEdits() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    let scope = ItemScope(account: "account", vaultID: UUID(), itemID: UUID())
    let first = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1]))
    let saved = try await repository.commitLocalMutation(first)
    #expect(try await repository.mutationReceipt(id: saved.id, account: scope.account)?.status == .queued)
    #expect(try await repository.mutationReceipt(id: saved.id, account: "other") == nil)
    let next = try await repository.commitLocalMutation(EncryptedItemVersion(scope: scope, baseVersionID: first.versionID, ciphertext: Data([2]), generation: 2))
    try await repository.acknowledge(mutationID: saved.id, account: scope.account, serverSystemFields: Data([9]))
    let reopened = try EncryptedItemRepository(storeURL: url)
    #expect(try await reopened.mutationReceipt(id: saved.id, account: scope.account)?.status == .cloudConfirmed)
    #expect(try await reopened.mutationReceipt(id: next.id, account: scope.account)?.status == .queued)
    #expect(try await reopened.pendingMutations(account: scope.account) == [next])
}

@Test func durableSyncRequestArrivingDuringDrainSurvivesOldCompletion() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    let original = try await repository.requestSync(account: "account", database: "private", reason: .manual)
    let newer = try await repository.requestSync(account: "account", database: "private", reason: .networkRestored)
    try await repository.markSyncRequestHandled(original)
    let reopened = try EncryptedItemRepository(storeURL: url)
    #expect(try await reopened.pendingSyncRequests(account: "account", database: "private") == [newer])
    #expect(try await reopened.pendingSyncRequests(account: "other", database: "private").isEmpty)
    try await reopened.markSyncRequestHandled(newer)
    #expect(try await reopened.pendingSyncRequests(account: "account", database: "private").isEmpty)
}

@Test func deliveryWaiterReturnsQueuedOnTimeoutAndActualCloudConfirmation() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    let scope = ItemScope(account: "account", vaultID: UUID(), itemID: UUID())
    let saved = try await repository.commitLocalMutation(EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1])))
    let queued = try await MutationDeliveryWaiter.wait(repository: repository, mutationID: saved.id, account: scope.account, timeout: .zero)
    #expect(queued.status == .queued)
    async let waiting = MutationDeliveryWaiter.wait(repository: repository, mutationID: saved.id, account: scope.account, timeout: .seconds(5))
    try await repository.acknowledge(mutationID: saved.id, account: scope.account, serverSystemFields: Data([9]))
    let confirmed = try await waiting
    #expect(confirmed.status == .cloudConfirmed)
    await #expect(throws: ItemRepositoryError.missingMutation) {
        try await MutationDeliveryWaiter.wait(repository: repository, mutationID: saved.id, account: "other", timeout: .zero)
    }
}

@Test func laterAcknowledgementCannotBypassQueuedPredecessor() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    let scope = ItemScope(account: "account", vaultID: UUID(), itemID: UUID())
    let base = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1]))
    let first = try await repository.commitLocalMutation(base)
    let next = try await repository.commitLocalMutation(EncryptedItemVersion(scope: scope, baseVersionID: base.versionID, ciphertext: Data([2]), generation: 2))
    await #expect(throws: ItemRepositoryError.outOfOrderAcknowledgement) {
        try await repository.acknowledge(mutationID: next.id, account: scope.account, serverSystemFields: Data([9]))
    }
    #expect(try await repository.pendingMutations(account: scope.account) == [first, next])
    #expect(try await repository.item(scope) == next.version)
    #expect(try await repository.mutationReceipt(id: first.id, account: scope.account)?.status == .queued)
    #expect(try await repository.mutationReceipt(id: next.id, account: scope.account)?.status == .queued)
}

@Test func remoteGenerationsRejectReplayAndForkButAllowSkippedCloudUpdates() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    let scope = ItemScope(account: "account", vaultID: UUID(), itemID: UUID())
    let first = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1]), generation: 1)
    try await repository.applyRemote(first, serverSystemFields: Data([1]))
    let third = EncryptedItemVersion(scope: scope, baseVersionID: UUID(), ciphertext: Data([3]), generation: 3)
    try await repository.applyRemote(third, serverSystemFields: Data([3]))
    try await repository.applyRemote(third, serverSystemFields: Data([3]))
    await #expect(throws: ItemRepositoryError.remoteVersionConflict) { try await repository.applyRemote(first, serverSystemFields: Data([1])) }
    let fork = EncryptedItemVersion(scope: scope, baseVersionID: UUID(), ciphertext: Data([4]), generation: 3)
    await #expect(throws: ItemRepositoryError.remoteVersionConflict) { try await repository.applyRemote(fork, serverSystemFields: Data([4])) }
    let wrongParent = EncryptedItemVersion(scope: scope, baseVersionID: first.versionID, ciphertext: Data([4]), generation: 4)
    await #expect(throws: ItemRepositoryError.remoteVersionConflict) { try await repository.applyRemote(wrongParent, serverSystemFields: Data([4])) }
    let fourth = EncryptedItemVersion(scope: scope, baseVersionID: third.versionID, ciphertext: Data([4]), generation: 4)
    try await repository.applyRemote(fourth, serverSystemFields: Data([4]))
    #expect(try await repository.item(scope) == fourth)
}

@Test func pendingBatchBoundsPayloadAndSelectsOnlyEachItemsOldestMutation() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    let firstScope = ItemScope(account: "account", vaultID: UUID(), itemID: UUID())
    let secondScope = ItemScope(account: "account", vaultID: firstScope.vaultID, itemID: UUID())
    let first = try await repository.commitLocalMutation(EncryptedItemVersion(scope: firstScope, baseVersionID: nil, ciphertext: Data(repeating: 1, count: 100)))
    _ = try await repository.commitLocalMutation(EncryptedItemVersion(scope: firstScope, baseVersionID: first.version.versionID, ciphertext: Data(repeating: 2, count: 100), generation: 2))
    let second = try await repository.commitLocalMutation(EncryptedItemVersion(scope: secondScope, baseVersionID: nil, ciphertext: Data(repeating: 3, count: 100)))
    #expect(try await repository.pendingMutationHeads(account: "account", database: "private", maximumAggregateCiphertextBytes: 150) == [first])
    #expect(try await repository.pendingMutationHeads(account: "account", database: "private", excluding: [firstScope], maximumAggregateCiphertextBytes: 150) == [second])
    #expect(try await repository.pendingMutationHeads(account: "account", database: "private", maximumAggregateCiphertextBytes: 50) == [first])
}

private struct NameCachePermit: RepositoryWritePermit {
    var allowed = true
    func withWritePermission<T>(_ body: () throws -> T) throws -> T {
        guard allowed else { throw CancellationError() }
        return try body()
    }
}

@Test func localNameCacheSurvivesRestartIsScopedAndCannotCommitAgainstStaleItems() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    let item = ItemScope(account: "owner", vaultID: UUID(), itemID: UUID())
    let version = EncryptedItemVersion(scope: item, baseVersionID: nil, ciphertext: Data([1]))
    _ = try await repository.commitLocalMutation(version)
    let scope = VaultScope(item), versions = [item.itemID: version.versionID], bytes = Data([4, 5, 6])
    let pending = try await repository.pendingMutations(account: item.account)
    let wake = try await repository.latestSyncRequest(account: item.account, database: "private")
    try await repository.saveLocalNameIndex(scope: scope, bytes: bytes, expectedVersions: versions, authorization: NameCachePermit())
    let reopened = try EncryptedItemRepository(storeURL: url)
    #expect(try await reopened.localNameIndex(scope: scope) == bytes)
    for other in [VaultScope(account: "other", vaultID: item.vaultID),
                  VaultScope(account: item.account, vaultID: item.vaultID, database: "shared"),
                  VaultScope(account: item.account, vaultID: item.vaultID, zoneOwner: "other-owner"),
                  VaultScope(account: item.account, vaultID: UUID())] {
        #expect(try await reopened.localNameIndex(scope: other) == nil)
    }
    #expect(try await reopened.pendingMutations(account: item.account) == pending)
    #expect(try await reopened.latestSyncRequest(account: item.account, database: "private") == wake)
    await #expect(throws: CancellationError.self) {
        try await reopened.saveLocalNameIndex(scope: scope, bytes: Data([7]), expectedVersions: versions, authorization: NameCachePermit(allowed: false))
    }
    _ = try await repository.commitLocalMutation(EncryptedItemVersion(scope: item, baseVersionID: version.versionID, ciphertext: Data([2]), generation: 2))
    await #expect(throws: ItemRepositoryError.staleLocalVersion) {
        try await reopened.saveLocalNameIndex(scope: scope, bytes: Data([8]), expectedVersions: versions, authorization: NameCachePermit())
    }
    #expect(try await reopened.localNameIndex(scope: scope) == bytes)
}

@Test func additiveMembershipCatchUpPreservesLocalChangesAndSupersedesOnlyOldReceipts() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    let scope = ItemScope(account: "catch-up", vaultID: UUID(), itemID: UUID())
    let initial = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1]))
    let first = try await repository.commitLocalMutation(initial)
    try await repository.acknowledge(mutationID: first.id, account: scope.account, serverSystemFields: Data([1]))
    let edited = EncryptedItemVersion(scope: scope, baseVersionID: initial.versionID, ciphertext: Data([2]), generation: 2)
    let pending = try await repository.commitLocalMutation(edited)
    let upgraded = EncryptedItemVersion(scope: scope, baseVersionID: edited.versionID, ciphertext: Data([3]), generation: 3)
    let replacement = try await repository.commitMembershipCatchUp(upgraded, authorization: NameCachePermit())
    #expect(try await repository.item(scope) == upgraded)
    #expect(try await repository.pendingMutations(account: scope.account) == [replacement])
    #expect(try await repository.mutationReceipt(id: first.id, account: scope.account)?.status == .cloudConfirmed)
    #expect(try await repository.mutationReceipt(id: pending.id, account: scope.account)?.status == .superseded)
    #expect(try await repository.mutationReceipt(id: replacement.id, account: scope.account)?.status == .queued)
    await #expect(throws: ItemRepositoryError.staleLocalVersion) {
        try await repository.commitMembershipCatchUp(upgraded, authorization: NameCachePermit())
    }
    let remote = EncryptedItemVersion(scope: scope, baseVersionID: initial.versionID, ciphertext: Data([4]), generation: 4)
    _ = try await repository.recordConflict(remote: remote, serverSystemFields: Data([2]))
    let conflictedUpgrade = EncryptedItemVersion(scope: scope, baseVersionID: upgraded.versionID, ciphertext: Data([5]), generation: 4)
    await #expect(throws: ItemRepositoryError.unresolvedConflict) {
        try await repository.commitMembershipCatchUp(conflictedUpgrade, authorization: NameCachePermit())
    }
    #expect(try await repository.item(scope) == upgraded)
}

@Test func displayCatalogWritesAreScopedDurableAndCannotRaceSourceOrKeyReplacement() async throws {
    let url = try repositoryLocation()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let repository = try EncryptedItemRepository(storeURL: url)
    let item = ItemScope(account: "owner", vaultID: UUID(), itemID: UUID()), key = Data([1, 2, 3])
    let scope = VaultScope(item), permit = NameCachePermit()
    let version = EncryptedItemVersion(scope: item, baseVersionID: nil, ciphertext: Data([1]))
    _ = try await repository.commitLocalMutation(version)
    let wake = try await repository.latestSyncRequest(account: item.account, database: item.database)
    #expect(try await repository.reserveDisplayCatalogKey(scope: scope, candidate: key, replacing: nil, authorization: permit) == key)
    let other = try EncryptedItemRepository(storeURL: url)
    #expect(try await other.reserveDisplayCatalogKey(scope: scope, candidate: Data([9]), replacing: nil, authorization: permit) == key)
    let row = EncryptedDisplayCatalogRow(itemID: item.itemID, versionID: version.versionID, keyID: UUID(), ciphertext: Data([4]))
    try await repository.saveDisplayCatalogRows(scope: scope, rows: [row], keyEnvelope: key, authorization: permit)
    #expect(try await other.displayCatalogRows(scope: scope).first?.ciphertext == row.ciphertext)
    #expect(try await other.displayCatalogRows(scope: VaultScope(account: "other", vaultID: item.vaultID)).isEmpty)
    #expect(try await other.latestSyncRequest(account: item.account, database: item.database) == wake)
    await #expect(throws: CancellationError.self) {
        try await other.saveDisplayCatalogRows(scope: scope, rows: [row], keyEnvelope: key, authorization: NameCachePermit(allowed: false))
    }
    _ = try await repository.commitLocalMutation(EncryptedItemVersion(scope: item, baseVersionID: version.versionID, ciphertext: Data([2]), generation: 2))
    await #expect(throws: ItemRepositoryError.staleLocalVersion) {
        try await other.saveDisplayCatalogRows(scope: scope, rows: [row], keyEnvelope: key, authorization: permit)
    }
    let replacement = Data([5])
    _ = try await repository.reserveDisplayCatalogKey(scope: scope, candidate: replacement, replacing: key, authorization: permit)
    #expect(try await other.displayCatalogRows(scope: scope).isEmpty)
    await #expect(throws: ItemRepositoryError.staleLocalVersion) {
        try await other.saveDisplayCatalogRows(scope: scope, rows: [], keyEnvelope: key, authorization: permit)
    }
}
