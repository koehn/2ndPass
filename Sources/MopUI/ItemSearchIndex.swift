import Foundation
import OSLog
import MopCore

/// Session-only index of public catalog text. Concealed field names and values
/// are deliberately excluded, just as they are in the catalog search UI.
final class ItemSearchIndex {
    private static let signposter = OSSignposter(subsystem: "com.koehn.mop", category: "Search")

    /// Timing only: never record queries, tags, item names, or values.
    static func noteInput() { signposter.emitEvent("Search input") }

    struct Snapshot {
        let rows: [ItemRow]
        let results: [ItemSearchResult]
        let ids: Set<ItemRow.ID>
    }
    private struct Entry {
        let row: ItemRow
        let name: String
        let vault: String
        let tags: [(text: String, normalized: String)]
        let fields: [(field: ItemField, label: String, value: String)]
    }
    let rows: [ItemRow]
    private let entries: [Entry]
    private let locale: Locale
    private var lastQuery: String?
    private var lastSnapshot: Snapshot?

    init(rows: [ItemRow], deleted: Bool = false) {
        let interval = Self.signposter.beginInterval("Build search index")
        defer { Self.signposter.endInterval("Build search index", interval) }
        self.rows = rows
        let locale = Locale.current
        self.locale = locale
        entries = rows.map { row in
            Entry(row: row,
                  name: Self.normalize(deleted ? row.item.deletion?.originalName ?? row.item.name : row.item.name, locale: locale),
                  vault: Self.normalize(row.vaultName, locale: locale),
                  tags: (row.item.metadata?.tags ?? []).map { ($0, Self.normalize($0, locale: locale)) },
                  fields: row.item.fields.filter { !$0.type.concealed }.map {
                      ($0, Self.normalize($0.path.removingPercentEncoding ?? $0.path, locale: locale),
                       Self.normalize($0.value ?? "", locale: locale))
                  })
        }
    }

    private static func normalize(_ value: String, locale: Locale) -> String {
        value.folding(options: .caseInsensitive, locale: locale).precomposedStringWithCanonicalMapping
    }

    func search(_ text: String) -> Snapshot {
        let query = Self.normalize(text.trimmingCharacters(in: .whitespacesAndNewlines), locale: locale)
        if query == lastQuery, let lastSnapshot { return lastSnapshot }
        let interval = Self.signposter.beginInterval("Filter search index")
        defer { Self.signposter.endInterval("Filter search index", interval) }
        let snapshot: Snapshot
        if query.isEmpty {
            snapshot = Snapshot(rows: rows, results: [], ids: Set(rows.map(\.id)))
        } else {
            let results = entries.compactMap { entry -> ItemSearchResult? in
                let field = entry.fields.first { $0.label.contains(query) || $0.value.contains(query) }?.field
                let tag = entry.tags.first { $0.normalized.contains(query) }?.text
                guard field != nil || tag != nil || entry.name.contains(query) || entry.vault.contains(query) else { return nil }
                var result = ItemSearchResult(row: entry.row, field: field, tag: tag)
                result.row.searchDetail = result.detail
                return result
            }
            snapshot = Snapshot(rows: results.map(\.row), results: results, ids: Set(results.map(\.id)))
        }
        lastQuery = query
        lastSnapshot = snapshot
        return snapshot
    }
}
