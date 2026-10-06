import Foundation
import Synchronization
import MopCore
import MopVaultNext

/// Work counters describe aggregate projection work, not secrets or item identities.
/// Shared across snapshots so tests can enforce work budgets through the service.
final class ItemCatalogProjectionWork: Sendable {
    private let counts = Mutex((snapshots: 0, sortedRows: 0))
    var value: (snapshots: Int, sortedRows: Int) { counts.withLock { $0 } }
    func sorted(_ count: Int) { counts.withLock { $0.sortedRows += count } }
    func materialized() { counts.withLock { $0.snapshots += 1 } }
}

/// Immutable authenticated rows with incremental ordering. An aggregate catalog
/// is materialized once on demand; background row preparation need not build it.
final class ItemCatalogProjection: Sendable {
    let entries: [UUID: ItemVaultCatalogEntry]
    let items: [UUID: VaultItem]
    let orderedIDs: [UUID]
    let versions: [UUID: UUID]
    let metadata: VaultEnvelopeMetadata
    let usageScope: String
    let work: ItemCatalogProjectionWork
    private let snapshot = Mutex<ItemCatalog?>(nil)

    init(previous: ItemCatalogProjection?, entries: [UUID: ItemVaultCatalogEntry], items: [UUID: VaultItem],
         changedIDs: Set<UUID>, metadata: VaultEnvelopeMetadata, metadataVersion: UUID, usageScope: String,
         work: ItemCatalogProjectionWork) {
        self.entries = entries; self.items = items; self.metadata = metadata
        self.usageScope = usageScope; self.work = work
        func precedes(_ lhs: UUID, _ rhs: UUID) -> Bool {
            (entries[lhs]!.catalog.item.name, lhs.uuidString) < (entries[rhs]!.catalog.item.name, rhs.uuidString)
        }
        // Rows still present at their previous source versions retain their order.
        // Only inserted/replaced rows need sorting, including renames and trash.
        let retained = (previous?.orderedIDs ?? []).filter { entries[$0] != nil && !changedIDs.contains($0) }
        let added = changedIDs.filter { entries[$0] != nil }.sorted(by: precedes)
        work.sorted(added.count)
        var ordered: [UUID] = []; ordered.reserveCapacity(entries.count)
        var left = 0, right = 0
        while left < retained.count && right < added.count {
            if precedes(retained[left], added[right]) { ordered.append(retained[left]); left += 1 }
            else { ordered.append(added[right]); right += 1 }
        }
        ordered.append(contentsOf: retained[left...]); ordered.append(contentsOf: added[right...])
        orderedIDs = ordered
        var versions = previous?.versions ?? [:]
        for id in versions.keys where id != ItemVaultSession.metadataRecordID && entries[id] == nil { versions[id] = nil }
        for id in added { versions[id] = entries[id]!.versionID }
        versions[ItemVaultSession.metadataRecordID] = metadataVersion
        self.versions = versions
    }

    func catalog() throws -> ItemCatalog {
        try snapshot.withLock { value in
            if let value { return value }
            let result = try catalog(for: orderedIDs)
            work.materialized()
            value = result
            return result
        }
    }

    /// Publication of a partial batch needs neither a full revision map nor the
    /// other rows' visible fields and histories.
    func catalog(for ids: [UUID]) throws -> ItemCatalog {
        let rows = ids.compactMap { entries[$0] }
        let revision = try setupEncode(Dictionary(uniqueKeysWithValues: rows.map {
            ($0.itemID.uuidString, $0.versionID.uuidString)
        })).base64EncodedString()
        var result = ItemCatalog(vault: metadata.name, revision: revision, items: ids.compactMap { items[$0] })
        result.canEdit = true; result.security = metadata.security ?? VaultSecurityMetadata()
        result.security?.histories = rows.flatMap { $0.catalog.histories }
        result.securityEnabled = true; result.canUpgradeSecurity = false
        result.usageScope = usageScope
        return result
    }

    /// Health enrichment does not change source rows or their ordering.
    func installHealth(_ catalog: ItemCatalog) { snapshot.withLock { $0 = catalog } }
}
