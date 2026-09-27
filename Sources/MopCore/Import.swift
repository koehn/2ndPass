import Foundation

public enum ImportFormat: String, CaseIterable, Codable, Sendable {
    case auto, appleCSV = "apple-csv", chromeCSV = "chrome-csv", bitwardenCSV = "bitwarden-csv"
    case onePasswordCSV = "1password-csv", lastPassCSV = "lastpass-csv", bitwardenJSON = "bitwarden-json", onePasswordArchive = "1pux"
}
public enum ImportFailure: String, Error, LocalizedError, Sendable {
    case invalidDocument, unsupportedFormat, tooLarge, capacity, invalidSelection
    public var errorDescription: String? {
        switch self {
        case .invalidDocument: "The file is malformed or encrypted. Choose an unencrypted export in a supported format."
        case .unsupportedFormat: "The format is not recognized. Choose the source format or export a supported file."
        case .tooLarge: "The import exceeds 64 MiB or 10,000 records. Export a smaller selection."
        case .capacity: "The selection exceeds this vault’s capacity (16 MiB per encrypted revision). Choose fewer items or another vault."
        case .invalidSelection: "The import selection changed. Review the file again."
        }
    }
}
public struct ImportRecord: Sendable {
    public let id: Int
    public var item: VaultItem?
    public var warnings: [String]
    public init(id: Int, item: VaultItem?, warnings: [String] = []) { self.id = id; self.item = item; self.warnings = warnings }
}
public struct ImportDocument: Sendable {
    public let format: ImportFormat
    public var records: [ImportRecord]
    public init(format: ImportFormat, records: [ImportRecord]) { self.format = format; self.records = records }
}
public enum ImportDisposition: String, Codable, Sendable { case ready, duplicate, conflict, invalid, excluded }
/// Reports contain descriptive names and source schema identifiers, but never
/// field values, attachment contents, or local source-file paths.
public struct ImportRow: Codable, Sendable, Identifiable {
    public let id: Int
    public var name: String
    public let type: ItemType?
    public var disposition: ImportDisposition
    public var warnings: [String]
}
public struct ImportReport: Codable, Sendable {
    public var rows: [ImportRow]
    public var imported = 0
    public var committed = false
    public var ready: Int { rows.filter { $0.disposition == .ready }.count }
    public var needsAttention: Bool { rows.contains { [.conflict, .invalid].contains($0.disposition) || !$0.warnings.isEmpty } }
    public var summary: String {
        let duplicates = rows.filter { $0.disposition == .duplicate }.count
        let conflicts = rows.filter { $0.disposition == .conflict }.count
        let invalid = rows.filter { $0.disposition == .invalid }.count
        return "\(committed ? imported : ready) \(committed ? "imported" : "ready"), \(duplicates) duplicates, \(conflicts) conflicts, \(invalid) invalid."
    }
}
public struct ImportPreview: Sendable {
    public let vault: UUID
    public let revision: String
    public let report: ImportReport
    public init(vault: UUID, revision: String, report: ImportReport) { self.vault = vault; self.revision = revision; self.report = report }
}

public enum ImportPlanner {
    /// Existing items must have their concealed values populated by the authenticated vault service.
    public static func prepare(_ document: ImportDocument, existing: [VaultItem], selected: Set<Int>? = nil) throws -> (items: [VaultItem], report: ImportReport) {
        guard document.records.count <= 10_000, Set(document.records.map(\.id)).count == document.records.count else { throw ImportFailure.tooLarge }
        if let selected, !selected.isSubset(of: Set(document.records.map(\.id))) { throw ImportFailure.invalidSelection }
        var seen = existing.filter { $0.deletion == nil && !$0.isArchived }.map { MatchCandidate(item: $0, record: nil, destinationName: $0.name) }
        var names = Set(existing.map(\.name))
        var accepted: [VaultItem] = [], rows: [ImportRow] = []
        for record in document.records {
            try Task.checkCancellation()
            var row = ImportRow(id: record.id, name: record.item?.name ?? "Record \(record.id)", type: record.item?.type, disposition: .invalid, warnings: record.warnings)
            guard var item = record.item, !item.name.isEmpty, !item.fields.isEmpty, item.deletion == nil,
                  item.fields.allSatisfy({ $0.value != nil }), Set(item.fields.map(\.path)).count == item.fields.count else { rows.append(row); continue }
            if let selected, !selected.contains(record.id) { row.disposition = .excluded; rows.append(row); continue }
            var invalidContent = false
            for field in item.fields where field.type == .attachment || field.type.isCompound {
                do {
                    if field.type == .attachment { _ = try Attachment.decode(field.value ?? "") }
                    else { _ = try CompoundField(field.value ?? "") }
                } catch {
                    let name = (field.label ?? field.path.removingPercentEncoding ?? field.path).debugDescription
                    let reason = (error as? AttachmentFailure)?.errorDescription ?? (error as? CompoundFieldFailure)?.errorDescription ?? "Invalid content."
                    row.warnings.append("Field \(name) (\(field.type.label)): \(reason)")
                    invalidContent = true
                }
            }
            if invalidContent { rows.append(row); continue }
            let matches = item.isArchived ? [] : seen.filter { matchReason(item, $0.item) != nil }
            if !matches.isEmpty {
                let conflicts = matches.filter { !equalContent(item, $0.item) }
                row.disposition = conflicts.isEmpty ? .duplicate : .conflict
                if conflicts.isEmpty {
                    for match in matches {
                        let target = match.record.map { "earlier import row \($0), item \(quote(match.destinationName))" }
                            ?? "existing item \(quote(match.destinationName))"
                        row.warnings.append("Duplicate of \(target) (\(matchReason(item, match.item) ?? "matching identity")). All nonempty field paths, types, and contents, item type, favorite/archive status, and tags match. Skipped; no additional item was created.")
                    }
                }
                for match in conflicts {
                    let target = match.record.map { "earlier import row \($0), item \(quote(match.destinationName))" }
                        ?? "existing item \(quote(match.destinationName))"
                    let reason = matchReason(item, match.item) ?? "matching identity"
                    row.warnings.append("Conflicts with \(target) (\(reason)). Differences: \(differences(item, match.item).joined(separator: "; ")).")
                }
                if !conflicts.isEmpty { row.warnings.append("Skipped; matching items were not overwritten. Review these differences before retrying.") }
            } else {
                let base = item.name
                var suffix = 2
                while names.contains(item.name) { item.name = "\(base) (\(suffix))"; suffix += 1 }
                if item.name.contains("\0") {
                    row.warnings.append("Item name contains a null character."); rows.append(row); continue
                }
                let invalidFields = item.fields.compactMap { field -> String? in
                    let path = SecretReference.encode(item.name) + "/" + field.path
                    let name = (field.label ?? field.path.removingPercentEncoding ?? field.path).debugDescription
                    if path.utf8.count > 4096 {
                        return "Item name and field \(name) exceed the encoded reference limit of 4096 bytes."
                    }
                    if (try? SecretReference(vault: "import", relativePath: path)) == nil {
                        return "Invalid field name or encoded path: \(name)."
                    }
                    return nil
                }
                if !invalidFields.isEmpty {
                    row.warnings += invalidFields; rows.append(row); continue
                }
                row.name = item.name; row.disposition = .ready
                names.insert(item.name); accepted.append(item)
                // Compare using the source title so repeated source records also match.
                var identityItem = item; identityItem.name = base
                if !item.isArchived {
                    seen.append(MatchCandidate(item: identityItem, record: record.id, destinationName: item.name))
                }
            }
            rows.append(row)
        }
        return (accepted, ImportReport(rows: rows))
    }
    private static func sites(_ item: VaultItem) -> Set<String> {
        Set(item.fields.filter { $0.type == .website }.compactMap { field in
            guard let value = field.value, !value.isEmpty else { return nil }
            guard var url = URLComponents(string: value), let scheme = url.scheme, let host = url.host else { return value }
            url.scheme = scheme.lowercased(); url.host = host.lowercased()
            if (url.scheme == "https" && url.port == 443) || (url.scheme == "http" && url.port == 80) { url.port = nil }
            return url.string ?? value
        })
    }
    private struct MatchCandidate {
        let item: VaultItem
        let record: Int?
        let destinationName: String
    }
    private static func quote(_ value: String) -> String { value.debugDescription }
    private static func matchReason(_ a: VaultItem, _ b: VaultItem) -> String? {
        // Stable identities are authoritative: distinct exported records must not
        // collapse merely because their titles or login credentials coincide.
        if let x = a.metadata?.source, let y = b.metadata?.source {
            return x == y ? "same source item identity" : nil
        }
        guard a.type == b.type else { return nil }
        let x = sites(a), y = sites(b)
        if a.type == .login, !x.isEmpty, !y.isEmpty {
            return !x.isDisjoint(with: y) && a.fields.first(where: { $0.type == .username })?.value == b.fields.first(where: { $0.type == .username })?.value
                ? "same website and username" : nil
        }
        return a.name == b.name ? "same item type and title" : nil
    }
    /// Mirror equalContent's comparison, but never include scalar field values.
    private static func differences(_ source: VaultItem, _ matching: VaultItem) -> [String] {
        var result: [String] = []
        if source.type != matching.type { result.append("item type \(matching.type.label) → \(source.type.label)") }
        let a = source.fields.filter { !($0.value ?? "").isEmpty }
        let b = matching.fields.filter { !($0.value ?? "").isEmpty }
        func name(_ field: ItemField) -> String {
            let path = field.path.removingPercentEncoding ?? field.path
            if let label = field.label, label != path { return quote(label) + " [" + quote(path) + "]" }
            return quote(path)
        }
        let added = a.filter { field in !b.contains { $0.path == field.path } }
        let absent = b.filter { field in !a.contains { $0.path == field.path } }
        if !added.isEmpty { result.append("fields only in source: " + added.map(name).joined(separator: ", ")) }
        if !absent.isEmpty { result.append("fields only in matching item: " + absent.map(name).joined(separator: ", ")) }
        for field in a.sorted(by: { $0.path < $1.path }) {
            guard let old = b.first(where: { $0.path == field.path }) else { continue }
            if field.type != old.type { result.append("field \(name(field)) type \(old.type.label) → \(field.type.label)") }
            if field.value != old.value { result.append("field \(name(field)) content changed") }
        }
        if source.isFavorite != matching.isFavorite { result.append("favorite status") }
        if source.isArchived != matching.isArchived { result.append("archive status") }
        if Set(source.metadata?.tags ?? []) != Set(matching.metadata?.tags ?? []) { result.append("tags") }
        return result
    }
    private static func equalContent(_ a: VaultItem, _ b: VaultItem) -> Bool {
        func fields(_ item: VaultItem) -> [String] {
            item.fields.filter { !($0.value ?? "").isEmpty }.map { field in
                // Length prefixes avoid collisions with user-controlled separators.
                [field.path, field.type.rawValue, field.value ?? ""].map { "\($0.utf8.count):\($0)" }.joined()
            }.sorted()
        }
        return a.type == b.type && fields(a) == fields(b) && a.isArchived == b.isArchived && a.isFavorite == b.isFavorite
            && Set(a.metadata?.tags ?? []) == Set(b.metadata?.tags ?? [])
    }
}
