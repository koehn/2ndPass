import Foundation
import Testing
import MopCore
import MopVaultNext
@testable import MopAppSupport

private func projectionEntry(_ id: UUID, name: String) -> ItemVaultCatalogEntry {
    var item = VaultItem(name: name, fields: [ItemField(path: "username", type: .username, value: name)])
    item.storageID = id.uuidString
    var catalog = ItemEnvelopeCatalog(item: item, references: [:])
    catalog.histories = [SecretFieldHistory(itemID: id.uuidString, path: "password")]
    return ItemVaultCatalogEntry(itemID: id, versionID: UUID(), catalog: catalog)
}

@Test func incrementalProjectionMatchesIndependentReconstructionAcrossEdits() throws {
    let ids = (1...128).map { UUID(uuidString: String(format: "00000000-0000-0000-0000-%012x", $0))! }
    let work = ItemCatalogProjectionWork(), metadataVersion = UUID()
    var entries = Dictionary(uniqueKeysWithValues: ids.enumerated().map { index, id in
        (id, projectionEntry(id, name: ["zebra", "éclair", "alpha", "Alpha"][index % 4]))
    })
    var metadata = VaultEnvelopeMetadata(name: "projection")
    var projection = ItemCatalogProjection(previous: nil, entries: entries, items: entries.mapValues { $0.catalog.item },
        changedIDs: Set(ids), metadata: metadata, metadataVersion: metadataVersion, usageScope: "member", work: work)
    let original = try projection.catalog()
    let originalItems = original.items
    var sortedBudget = ids.count
    for step in 0..<40 {
        let id = ids[(step * 17) % ids.count]
        var changed: Set<UUID> = []
        switch step % 4 {
        case 0: // A rename can move a row across either end of the ordered list.
            entries[id] = projectionEntry(id, name: step % 8 == 0 ? "0-first" : "zz-last")
            changed.insert(id)
        case 1:
            entries[id] = nil
        case 2:
            let added = UUID()
            entries[added] = projectionEntry(added, name: "alpha")
            changed.insert(added)
        default:
            metadata.name = "renamed-\(step)"
        }
        sortedBudget += changed.count
        projection = ItemCatalogProjection(previous: projection, entries: entries, items: entries.mapValues { $0.catalog.item },
            changedIDs: changed, metadata: metadata, metadataVersion: metadataVersion, usageScope: "member", work: work)
        let expected = entries.values.sorted {
            ($0.catalog.item.name, $0.itemID.uuidString) < ($1.catalog.item.name, $1.itemID.uuidString)
        }
        let actual = try projection.catalog()
        #expect(actual.items == expected.map { $0.catalog.item })
        #expect(actual.security?.histories == expected.flatMap { $0.catalog.histories })
        #expect(actual.vault == metadata.name)
        let revision = try JSONDecoder().decode([String: String].self, from: #require(Data(base64Encoded: actual.revision)))
        #expect(revision == Dictionary(uniqueKeysWithValues: expected.map { ($0.itemID.uuidString, $0.versionID.uuidString) }))
        #expect(work.value.sortedRows == sortedBudget)
        let builds = work.value.snapshots
        _ = try projection.catalog()
        #expect(work.value.snapshots == builds)
        #expect(original.items == originalItems)
    }
}
