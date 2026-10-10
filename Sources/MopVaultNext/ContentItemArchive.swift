import Foundation
import MopCore

/// The portable item graph is independent of cloud storage. Only its catalog is
/// decoded for list views; concealed fields and attachments stay separate.
public enum ContentItemArchive {
    public static let catalogComponent = "catalog"
    public static let metadataComponent = "metadata"

    public static func components(_ archive: PortableVaultArchive, editOrigin: ItemEditOrigin? = nil) throws -> (item: UUID, values: [String: SecretBytes]) {
        try archive.validate()
        guard archive.items.count == 1, let item = archive.items.first,
              let id = archive.itemIDs[item.name].flatMap(UUID.init(uuidString:)),
              archive.security?.accounts.isEmpty ?? true,
              archive.security?.passwordChecks?.isEmpty ?? true else { throw PortableArchiveFailure.invalid }
        var projection = item
        for index in projection.fields.indices { projection.fields[index].value = nil }
        let catalog = ItemEnvelopeCatalog(item: projection, references: archive.references,
            histories: archive.security?.histories ?? [],
            projectedValuePaths: item.fields.filter { $0.value != nil }.map(\.path), editOrigin: editOrigin)
        try catalog.validate(itemID: id, recordIDs: Set(archive.records.keys))
        var values = archive.records.mapValues(\.bytes)
        values[catalogComponent] = try encode(catalog)
        return (id, values)
    }

    public static func catalog(_ bytes: SecretBytes, item: UUID, componentNames: Set<String>) throws -> ItemEnvelopeCatalog {
        guard componentNames.contains(catalogComponent) else { throw PortableArchiveFailure.invalid }
        let catalog = try bytes.withFoundationData { try JSONDecoder().decode(ItemEnvelopeCatalog.self, from: $0) }
        try catalog.validate(itemID: item, recordIDs: componentNames.subtracting([catalogComponent]))
        return catalog
    }

    public static func archive(name: String, item: UUID, catalog: ItemEnvelopeCatalog,
                               records: [String: SecretBytes]) throws -> PortableVaultArchive {
        try catalog.validate(itemID: item, recordIDs: Set(records.keys))
        var projection = catalog.item
        for index in projection.fields.indices where catalog.projectedValuePaths.contains(projection.fields[index].path) {
            guard let id = catalog.references[SecretReference.encode(projection.name) + "/" + projection.fields[index].path],
                  let bytes = records[id] else { throw PortableArchiveFailure.invalid }
            projection.fields[index].value = String(decoding: try bytes.validatedUTF8(), as: UTF8.self)
        }
        var security = VaultSecurityMetadata()
        security.histories = catalog.histories
        let archive = PortableVaultArchive(name: name, items: [projection], itemIDs: [projection.name: item.uuidString],
            references: catalog.references, records: records.mapValues { PortableArchiveRecord(itemID: item.uuidString, bytes: $0) }, security: security)
        try archive.validate()
        return archive
    }

    public static func encode<T: Encodable>(_ value: T) throws -> SecretBytes {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        var bytes = try encoder.encode(value)
        defer { SecretBytes.wipe(&bytes) }
        return SecretBytes(copying: bytes)
    }
}

extension ContentItemArchive {
    /// Storage IDs and save attribution are representation details. Compare the
    /// complete retained graph by field path and history order, including secrets.
    /// This never selects a winner by time; equivalence accepts the server copy.
    public static func identical(_ lhs: [String: SecretBytes], _ rhs: [String: SecretBytes], item: UUID) throws -> Bool {
        guard let a = lhs[catalogComponent], let b = rhs[catalogComponent] else { return lhs == rhs }
        var left = try catalog(a, item: item, componentNames: Set(lhs.keys))
        var right = try catalog(b, item: item, componentNames: Set(rhs.keys))
        func canonical(_ value: inout ItemEnvelopeCatalog, records: [String: SecretBytes]) throws -> [String: SecretBytes] {
            value.editOrigin = nil; value.item.metadata?.updatedAt = nil
            var values: [String: SecretBytes] = [:]
            for path in value.references.keys.sorted() {
                guard let id = value.references[path], let bytes = records[id] else { throw MopError.invalidVault }
                let canonical = "field:" + path
                values[canonical] = bytes; value.references[path] = canonical
            }
            for index in value.item.fields.indices { value.item.fields[index].historyID = nil }
            value.histories.sort { $0.path < $1.path }
            for index in value.histories.indices {
                value.histories[index].id = UUID(uuidString: "00000000-0000-0000-0000-000000000000")!
                for entry in value.histories[index].entries.indices {
                    guard let bytes = records[value.histories[index].entries[entry].id] else { throw MopError.invalidVault }
                    let canonical = "history:" + value.histories[index].path + ":" + String(entry)
                    values[canonical] = bytes; value.histories[index].entries[entry].id = canonical
                    value.histories[index].entries[entry].replacedAt = Date(timeIntervalSince1970: 0)
                }
            }
            value.projectedValuePaths.sort()
            return values
        }
        let leftValues = try canonical(&left, records: lhs), rightValues = try canonical(&right, records: rhs)
        return left == right && leftValues == rightValues
    }
}
