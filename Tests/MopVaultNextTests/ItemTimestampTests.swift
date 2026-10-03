import Foundation
import Testing
import MopCore
@testable import MopVaultNext

@Test func itemTimesAndIdentitySurviveEditsRenameArchiveAndRestore() throws {
    let owner = try TestDevice(), created = Date()
    var vault = try VaultEngine.create(name: "personal", owner: owner)
    let item = VaultItem(name: "entry", fields: [ItemField(path: "value", type: .text, value: "first")])
    vault = try VaultEngine.saveItem(.init(revision: vault.digest, item: item, create: true), in: vault, device: owner, at: created)
    var saved = try #require(VaultEngine.catalog(in: vault, device: owner).items.first)
    let identity = try #require(saved.storageID)
    #expect(saved.metadata?.createdAt == created && saved.metadata?.addedAt == created && saved.metadata?.updatedAt == created)
    saved.name = "renamed"; saved.metadata?.favorite = true; saved.metadata?.archived = true
    saved.metadata?.createdAt = .distantPast; saved.metadata?.addedAt = .distantPast // Cannot forge history during edits.
    saved.storageID = UUID().uuidString // Never accepted from the caller.
    let updated = created.addingTimeInterval(1)
    vault = try VaultEngine.saveItem(.init(revision: vault.digest, item: saved, create: false, originalName: "entry"), in: vault, device: owner, at: updated)
    saved = try #require(VaultEngine.catalog(in: vault, device: owner).items.first)
    #expect(saved.storageID == identity)
    #expect(saved.metadata?.createdAt == created && saved.metadata?.addedAt == created && saved.metadata?.updatedAt == updated)
    vault = try VaultEngine.rename("renamed-vault", in: vault, device: owner)
    #expect(try VaultEngine.catalog(in: vault, device: owner).items.first?.metadata?.updatedAt == updated)
    vault = try VaultEngine.trashItem(name: "renamed", revision: vault.digest, in: vault, device: owner, at: updated)
    let deleted = try #require(VaultEngine.catalog(in: vault, device: owner, deleted: true).items.first)
    #expect(deleted.storageID == identity && deleted.metadata?.updatedAt == updated)
    let restoredAt = created.addingTimeInterval(2)
    vault = try VaultEngine.restoreItem(id: #require(deleted.deletion?.id), revision: vault.digest, in: vault, device: owner, at: restoredAt)
    saved = try #require(VaultEngine.catalog(in: vault, device: owner).items.first)
    #expect(saved.storageID == identity && saved.metadata?.updatedAt == restoredAt)
    #expect(saved.metadata?.createdAt == created && saved.metadata?.addedAt == created)
    #expect(throws: MopError.vaultConflict) {
        try VaultEngine.saveItem(.init(revision: "stale", item: saved, create: false), in: vault, device: owner, at: .distantFuture)
    }
    #expect(try VaultEngine.catalog(in: vault, device: owner).items.first?.metadata?.updatedAt == restoredAt)
}

@Test func rawWritesAndFieldDeletesTrackTimeWithoutRecreatingHistory() throws {
    let owner = try TestDevice(), created = Date()
    var vault = try VaultEngine.create(name: "personal", owner: owner)
    vault = try VaultEngine.write("entry/first", value: "one", in: vault, device: owner, at: created)
    let first = try #require(VaultEngine.catalog(in: vault, device: owner).items.first)
    #expect(first.metadata?.createdAt == created && first.metadata?.addedAt == created)
    vault = try VaultEngine.write("entry/second", value: "two", in: vault, device: owner, at: created.addingTimeInterval(1))
    vault = try VaultEngine.write("entry/first", value: nil, in: vault, device: owner, at: created.addingTimeInterval(2))
    let updated = try #require(VaultEngine.catalog(in: vault, device: owner).items.first)
    #expect(updated.storageID == first.storageID && updated.metadata?.createdAt == created)
    #expect(updated.metadata?.updatedAt == created.addingTimeInterval(2))
    #expect(updated.fields.map(\.path) == ["second"])

    // Simulate an existing pre-timestamp item without a migration or fabricated dates.
    let payload = try vault.revision.payload(device: owner)
    var legacy = payload.items
    legacy[0].metadata = nil
    vault = try vault.applying(Revision.seal(header: VaultEngine.header(vault, operation: .content),
        references: payload.references, records: vault.revision.records, itemKeys: vault.revision.itemKeys, items: legacy, security: payload.security, signer: owner))
    vault = try VaultEngine.write("entry/second", value: "three", in: vault, device: owner, at: created.addingTimeInterval(3))
    let migrated = try #require(VaultEngine.catalog(in: vault, device: owner).items.first)
    #expect(migrated.metadata?.createdAt == nil && migrated.metadata?.addedAt == nil)
    #expect(migrated.metadata?.updatedAt == created.addingTimeInterval(3))
}

@Test func importTimesPreserveKnownHistoryAndDoNotAffectDuplicateDetection() throws {
    let owner = try TestDevice(), imported = Date()
    var vault = try VaultEngine.create(name: "personal", owner: owner)
    var known = VaultItem(name: "known", fields: [ItemField(path: "value", type: .text, value: "public")])
    known.metadata = ItemMetadata(createdAt: imported.addingTimeInterval(-200), updatedAt: imported.addingTimeInterval(-100))
    let unknown = VaultItem(name: "unknown", fields: [ItemField(path: "value", type: .text, value: "other")])
    vault = try VaultEngine.importItems([known, unknown], revision: vault.digest, in: vault, device: owner, at: imported)
    let items = try VaultEngine.catalog(in: vault, device: owner).items
    #expect(items.allSatisfy { $0.metadata?.addedAt == imported })
    #expect(items[0].metadata?.createdAt == known.metadata?.createdAt && items[0].metadata?.updatedAt == known.metadata?.updatedAt)
    #expect(items[1].metadata?.createdAt == nil && items[1].metadata?.updatedAt == nil)
    let document = ImportDocument(format: .bitwardenJSON, records: [ImportRecord(id: 1, item: known)])
    let preview = try VaultEngine.previewImport(document, in: vault, device: owner)
    #expect(preview.items.isEmpty)
    #expect(try VaultEngine.catalog(in: vault, device: owner).items[0].metadata?.addedAt == imported)
}
