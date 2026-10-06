import Foundation
import OSLog
import Observation
import MopCore

/// Session-only index of public catalog text. Concealed field names and values
/// are deliberately excluded, just as they are in the catalog search UI.
@MainActor @Observable
final class ItemSearchIndex {
    nonisolated private static let signposter = OSSignposter(subsystem: "com.koehn.mop", category: "Search")

    /// Timing only: never record queries, tags, item names, or values.
    static func noteInput() { signposter.emitEvent("Search input") }

    struct Snapshot {
        let rows: [ItemRow]
        let results: [ItemSearchResult]
        let ids: Set<ItemRow.ID>
    }
    private struct Entry: Sendable {
        let row: ItemRow
        let name: String
        let vault: String
        let tags: [(text: String, normalized: String)]
        let fields: [(field: ItemField, label: String, value: String)]
    }
    let rows: [ItemRow]
    private var entries: [Entry]?
    @ObservationIgnored private var preparation: Task<[Entry]?, Never>?
    private let deleted: Bool
    var isPreparing: Bool { entries == nil }
    private let locale: Locale
    @ObservationIgnored private var lastQuery: String?
    @ObservationIgnored private var lastSnapshot: Snapshot?
    @ObservationIgnored private var cachedAlphabetTargets: [AlphabetTarget<ItemRow.ID>]?

    init(rows: [ItemRow], deleted: Bool = false) {
        self.rows = rows
        self.deleted = deleted
        let locale = Locale.current
        self.locale = locale
        if rows.isEmpty { entries = []; return }
        let task = Task.detached(priority: .userInitiated) {
            let interval = Self.signposter.beginInterval("Build search index")
            defer { Self.signposter.endInterval("Build search index", interval) }
            var entries: [Entry] = []
            entries.reserveCapacity(rows.count)
            for row in rows {
                guard !Task.isCancelled else { return nil as [Entry]? }
                entries.append(Self.entry(row, deleted: deleted, locale: locale))
            }
            return entries as [Entry]?
        }
        preparation = task
        Task { [weak self] in
            guard let entries = await task.value, let self else { return }
            self.entries = entries
            self.preparation = nil
        }
    }

    deinit { preparation?.cancel() }

    nonisolated private static func entry(_ row: ItemRow, deleted: Bool, locale: Locale) -> Entry {
        Entry(row: row,
              name: normalize(deleted ? row.item.deletion?.originalName ?? row.item.name :
                  (row.item.credential?.purposes == [.passkey]
                   ? [row.item.displayTitle, row.subtitle ?? "", row.item.name].joined(separator: " ")
                   : row.item.name), locale: locale),
              vault: normalize(row.vaultName, locale: locale),
              tags: (row.item.metadata?.tags ?? []).map { ($0, normalize($0, locale: locale)) },
              fields: row.item.fields.filter { !$0.type.concealed }.map {
                  ($0, normalize($0.path.removingPercentEncoding ?? $0.path, locale: locale),
                   normalize($0.value ?? "", locale: locale))
              })
    }

    nonisolated private static func normalize(_ value: String, locale: Locale) -> String {
        value.folding(options: .caseInsensitive, locale: locale).precomposedStringWithCanonicalMapping
    }

    func alphabetTargets(_ text: String) -> [AlphabetTarget<ItemRow.ID>] {
        let snapshot = search(text)
        if let cachedAlphabetTargets { return cachedAlphabetTargets }
        let targets = AlphabetTarget.build(snapshot.rows, title: { $0.item.displayTitle }, id: { $0.id })
        cachedAlphabetTargets = targets
        return targets
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
            // Queries remain usable while preparation runs. Empty queries never
            // normalize fields, so rendering the unlocked list does not wait.
            let candidates = entries ?? rows.map { Self.entry($0, deleted: deleted, locale: locale) }
            let results = candidates.compactMap { entry -> ItemSearchResult? in
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
        cachedAlphabetTargets = nil
        return snapshot
    }
}
