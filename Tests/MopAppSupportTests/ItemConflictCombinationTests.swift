import Foundation
import Testing
import MopCore
import MopSync
@testable import MopVaultNext
@testable import MopAppSupport

private struct OfflineResolutionPermit: RepositoryWritePermit {
    func withWritePermission<T>(_ body: () throws -> T) throws -> T { try body() }
}

@Test(arguments: [ItemVaultConflictSide.local, .remote], [ItemVaultConflictSide.local, .remote])
func concurrentOfflineDevicesCombineFieldsAndContinueUnrelatedSync(passwordSide: ItemVaultConflictSide, notesSide: ItemVaultConflictSide) async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let a = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("a.sqlite/ContentPreview3/Content3.sqlite"))
    let b = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("b.sqlite/ContentPreview3/Content3.sqlite"))
    let owner = try SessionDevice(), second = try SessionDevice(member: owner.identity.member)
    let membership = try Membership(accounts: [AccountMember(id: owner.identity.member, role: .owner, devices: [owner.identity, second.identity])])
    let vault = UUID()
    let authority = try MembershipEnvelope.genesis(vault: vault, membership: membership, owner: owner)
    let history = try TrustedMembershipHistory(genesis: authority, vault: vault, pinnedDigest: authority.digest())
    let binding = ItemVaultBinding(account: "offline-test", database: "private", zoneOwner: "__defaultOwner__", vaultID: vault)
    let first = try await currentTestSession(repository: a, binding: binding, history: history, device: owner)
    let other = try await currentTestSession(repository: b, binding: binding, history: history, device: second)
    var archive = try sessionArchive()
    let item = try #require(archive.itemIDs["Login"]), note = UUID().uuidString
    archive.items[0].fields.append(ItemField(path: "notes", type: .notes))
    archive.references["Login/notes"] = note
    archive.records[note] = PortableArchiveRecord(itemID: item, bytes: SecretBytes(utf8: "original note"))
    let initial = try await first.save(archive, expectedBase: nil)
    try await confirmCurrentMutation(initial, repository: a)
    try await transferCurrentVersion(initial.version, from: a, to: b)
    let id = initial.version.scope.itemID
    // Each device edits from the same accepted version while disconnected.
    let local = try await first.replaceField(itemID: id, expectedBase: initial.version.versionID, path: "password", value: SecretBytes(utf8: "local password"))
    let remote = try await other.replaceField(itemID: id, expectedBase: initial.version.versionID, path: "notes", value: SecretBytes(utf8: "remote note"))
    try await confirmCurrentMutation(remote, repository: b)
    await #expect(throws: ItemRepositoryError.pendingLocalChanges) {
        try await transferCurrentVersion(remote.version, from: b, to: a)
    }
    let remotePublication = try await currentPublication(remote.version, repository: b, history: history)
    let conflict = try await branchCurrentPublication(remotePublication, repository: a, scope: remote.version.scope, history: history, fields: Data([2]))
    #expect(conflict.local == local.version && conflict.remote == remote.version)
    let preview = try await first.conflictPreview(conflict)
    #expect(preview.local.editOrigin?.deviceID == owner.identity.device)
    #expect(preview.remote.editOrigin?.deviceID == second.identity.device)
    #expect(preview.localUpdatedAt != nil && preview.remoteUpdatedAt != nil)
    #expect(!preview.localDeviceName.isEmpty && !preview.remoteDeviceName.isEmpty)
    let reopened = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("a.sqlite/ContentPreview3/Content3.sqlite"))
    #expect(try await reopened.contentConflicts(account: binding.account).first == conflict)
    let unrelated = try await first.save(sessionArchive(), expectedBase: nil)
    #expect(try await a.pendingScopes(account: binding.account, excludingConflicts: true) == [unrelated.version.scope])
    try await confirmCurrentMutation(unrelated, repository: a)
    #expect(try await a.contentConflicts(account: binding.account).first == conflict)
    await #expect(throws: MopError.invalidVault) {
        try await first.combinedConflict(conflict, metadata: .local, fields: [:])
    }
    let patch = try await first.combinedConflict(conflict, metadata: notesSide, fields: ["password": passwordSide, "notes": notesSide])
    try await first.contentSession.queueConflictChoice(conflict, catalog: patch.catalog,
        changedRecords: patch.changedRecords, removedRecords: patch.removedRecords)
    let decision = try #require(try await a.operations(account: binding.account, database: "private").first { $0.kind == .resolveConflict })
    let (reviewed, replacement) = try await a.contentConflictDecision(decision)
    let pending = try #require(try await a.resolveContentConflict(reviewed, replacement: replacement,
        serverSystemFields: conflict.serverSystemFields, policy: GrantBackedContentStorage.recipientPolicy(history: history),
        decision: decision, permit: OfflineResolutionPermit()))
    let version = pending.version
    try await confirmCurrentMutation(pending, repository: a)
    try await transferCurrentVersion(version, from: a, to: b)
    #expect(try await a.item(version.scope) == b.item(version.scope))
    for (path, expected) in [("password", passwordSide == .local ? "local password" : "session-secret"), ("notes", notesSide == .local ? "original note" : "remote note")] {
        let record = try #require(patch.catalog.references["Login/" + path])
        #expect(try await other.reveal(itemID: id, recordID: record, expectedVersion: version.versionID) == SecretBytes(utf8: expected))
    }
    #expect(patch.catalog.histories.count == (passwordSide == .local ? 1 : 0))
    await #expect(throws: ItemRepositoryError.staleConflict) {
        try await first.combinedConflict(conflict, metadata: .local, fields: ["password": passwordSide, "notes": notesSide])
    }
    #expect(try await a.contentConflicts(account: binding.account).isEmpty)
}
