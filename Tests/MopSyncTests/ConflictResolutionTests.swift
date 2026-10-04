import Foundation
import Testing
@testable import MopSync

private struct ResolutionPermit: RepositoryWritePermit {
    var allowed = true
    func withWritePermission<T>(_ body: () throws -> T) throws -> T {
        guard allowed else { throw CancellationError() }
        return try body()
    }
}

private func conflictedRepository() async throws -> (URL, EncryptedItemRepository, PendingItemMutation, EncryptedItemConflict) {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-conflict-test-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let scope = ItemScope(account: "account", vaultID: UUID(), itemID: UUID())
    let base = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1]))
    try await repository.applyRemote(base, serverSystemFields: Data([1]))
    let local = EncryptedItemVersion(scope: scope, baseVersionID: base.versionID, ciphertext: Data([2]), generation: 2)
    let pending = try await repository.commitLocalMutation(local)
    let remote = EncryptedItemVersion(scope: scope, baseVersionID: base.versionID, ciphertext: Data([3]), generation: 2)
    let conflict = try await repository.recordConflict(remote: remote, serverSystemFields: Data([2]))
    return (directory, repository, pending, conflict)
}

@Test func keepingRemoteSupersedesLocalReceiptWithoutClaimingItsUpload() async throws {
    let (directory, repository, pending, conflict) = try await conflictedRepository()
    defer { try? FileManager.default.removeItem(at: directory) }
    let remote = try await repository.resolveConflictUsingRemote(conflict, authorization: ResolutionPermit())
    #expect(remote == conflict.remote)
    #expect(try await repository.item(remote.scope) == remote)
    #expect(try await repository.acceptedVersion(remote.scope) == remote)
    #expect(try await repository.pendingMutations(account: remote.scope.account).isEmpty)
    #expect(try await repository.conflicts(account: remote.scope.account).isEmpty)
    #expect(try await repository.mutationReceipt(id: pending.id, account: remote.scope.account)?.status == .superseded)
    let reopened = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    #expect(try await reopened.mutationReceipt(id: pending.id, account: remote.scope.account)?.status == .superseded)
    #expect(try await reopened.item(remote.scope) == remote)
}

@Test func staleConflictChoiceCannotDiscardNewLocalEdit() async throws {
    let (directory, repository, pending, conflict) = try await conflictedRepository()
    defer { try? FileManager.default.removeItem(at: directory) }
    let changed = EncryptedItemVersion(scope: conflict.local.scope, baseVersionID: conflict.local.versionID,
        ciphertext: Data([4]), generation: 3)
    let newerPending = try await repository.commitLocalMutation(changed)
    await #expect(throws: ItemRepositoryError.staleConflict) {
        try await repository.resolveConflictUsingRemote(conflict, authorization: ResolutionPermit())
    }
    let refreshed = try #require(try await repository.conflicts(account: changed.scope.account).first)
    #expect(refreshed.local == changed)
    #expect(try await repository.item(changed.scope) == changed)
    #expect(try await repository.pendingMutations(account: changed.scope.account).map(\.id) == [pending.id, newerPending.id])
}

@Test func staleConflictChoiceCannotDiscardNewRemoteVersionOrBypassLock() async throws {
    let (directory, repository, pending, conflict) = try await conflictedRepository()
    defer { try? FileManager.default.removeItem(at: directory) }
    let remote = EncryptedItemVersion(scope: conflict.remote.scope, baseVersionID: conflict.remote.versionID,
        ciphertext: Data([4]), generation: 3)
    let newer = try await repository.recordConflict(remote: remote, serverSystemFields: Data([3]))
    await #expect(throws: ItemRepositoryError.staleConflict) {
        try await repository.resolveConflictUsingRemote(conflict, authorization: ResolutionPermit())
    }
    await #expect(throws: CancellationError.self) {
        try await repository.resolveConflictUsingRemote(newer, authorization: ResolutionPermit(allowed: false))
    }
    #expect(try await repository.conflicts(account: conflict.local.scope.account) == [newer])
    #expect(try await repository.pendingMutations(account: conflict.local.scope.account) == [pending])
}

@Test func resolvedConflictQueuesNewReceiptAndConfirmsOnlyAfterAcknowledgement() async throws {
    let (directory, repository, pending, conflict) = try await conflictedRepository()
    defer { try? FileManager.default.removeItem(at: directory) }
    let resolved = EncryptedItemVersion(scope: conflict.local.scope, baseVersionID: conflict.remote.versionID,
        ciphertext: Data([4]), generation: 3)
    let queued = try await repository.resolveConflict(conflict, with: resolved, authorization: ResolutionPermit())
    #expect(try await repository.item(resolved.scope) == resolved)
    #expect(try await repository.acceptedVersion(resolved.scope) == conflict.remote)
    #expect(try await repository.mutationReceipt(id: pending.id, account: resolved.scope.account)?.status == .superseded)
    #expect(try await repository.mutationReceipt(id: queued.id, account: resolved.scope.account)?.status == .queued)
    #expect(try await repository.pendingMutations(account: resolved.scope.account) == [queued])
    #expect(try await repository.conflicts(account: resolved.scope.account).isEmpty)
    try await repository.acknowledge(mutationID: queued.id, account: resolved.scope.account, serverSystemFields: Data([3]))
    #expect(try await repository.mutationReceipt(id: queued.id, account: resolved.scope.account)?.status == .cloudConfirmed)
    #expect(try await repository.mutationReceipt(id: pending.id, account: resolved.scope.account)?.status == .superseded)
}

@Test func staleConflictChoiceRejectsChangedServerTokenForBothResolutionPaths() async throws {
    let (directory, repository, pending, conflict) = try await conflictedRepository()
    defer { try? FileManager.default.removeItem(at: directory) }
    let refreshed = try await repository.recordConflict(remote: conflict.remote, serverSystemFields: Data([99]))
    let resolved = EncryptedItemVersion(scope: conflict.local.scope, baseVersionID: conflict.remote.versionID,
        ciphertext: Data([4]), generation: 3)
    await #expect(throws: ItemRepositoryError.staleConflict) {
        try await repository.resolveConflictUsingRemote(conflict, authorization: ResolutionPermit())
    }
    await #expect(throws: ItemRepositoryError.staleConflict) {
        try await repository.resolveConflict(conflict, with: resolved, authorization: ResolutionPermit())
    }
    #expect(try await repository.conflicts(account: conflict.local.scope.account) == [refreshed])
    #expect(try await repository.pendingMutations(account: conflict.local.scope.account) == [pending])
    #expect(try await repository.item(conflict.local.scope) == conflict.local)
}

@Test func conflictIsExcludedFromEngineQueueWithoutDiscardingPendingEdits() async throws {
    let (directory, repository, pending, conflict) = try await conflictedRepository()
    defer { try? FileManager.default.removeItem(at: directory) }
    let account = pending.version.scope.account
    let unrelated = EncryptedItemVersion(scope: ItemScope(account: account,
        vaultID: pending.version.scope.vaultID, itemID: UUID()), baseVersionID: nil, ciphertext: Data([9]))
    _ = try await repository.commitLocalMutation(unrelated)
    #expect(try await repository.pendingScopes(account: account).contains(pending.version.scope))
    #expect(try await repository.pendingScopes(account: account, excludingConflicts: true) == [unrelated.scope])
    #expect(try await repository.conflict(pending.version.scope) == conflict)
    #expect(try await repository.item(pending.version.scope) == pending.version)
    let reopened = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    #expect(try await reopened.pendingScopes(account: account, excludingConflicts: true) == [unrelated.scope])
    let resolved = EncryptedItemVersion(scope: pending.version.scope, baseVersionID: conflict.remote.versionID,
        ciphertext: Data([4]), generation: 3)
    _ = try await repository.resolveConflict(conflict, with: resolved, authorization: ResolutionPermit())
    #expect(try await repository.pendingScopes(account: account, excludingConflicts: true).contains(resolved.scope))
}
