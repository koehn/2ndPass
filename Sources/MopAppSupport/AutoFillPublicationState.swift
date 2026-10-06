import Foundation
import CryptoKit
import MopCore

/// Public suggestion metadata only. Never persist catalog titles, references or secrets.
struct AutoFillPublicationState: Codable, Equatable {
    /// An untrusted routing hint only. The selected item must reproduce the
    /// requested identity from its authenticated, current contents before reveal.
    static func itemID(for identifier: String, directory: URL) throws -> UUID {
        guard let vault = AutoFillEntry.vaultID(identifier) else { throw MopError.notFound }
        let cache = try LocalDirectory(directory: directory)
        return try cache.locked {
            let data = try LocalFile.read(directory.appendingPathComponent("projection.json"), privateFile: true)
            let state = try JSONDecoder().decode(Self.self, from: data)
            guard state.schema == currentSchema else { throw MopError.notFound }
            let matches = (state.items[vault] ?? [:]).filter { $0.value.identities.contains { $0.id == identifier } }
            guard matches.count == 1, let key = matches.keys.first, let id = UUID(uuidString: key) else { throw MopError.notFound }
            return id
        }
    }
    static let currentSchema = 1
    var schema = currentSchema
    struct Item: Codable, Equatable {
        var version: String?
        var identities: [AutoFillIdentity]
    }
    var items: [String: [String: Item]] = [:]
    var desiredCloud: [AutoFillIdentity]? = nil
    var local: [AutoFillIdentity] = []
    var published: [AutoFillIdentity]? = nil
    // Written before invoking the system. A crash or uncertain failure requires replacement.
    var requiresReconciliation = true

    mutating func project(_ catalog: ItemCatalog, vaultID: String, complete: Bool,
                          removing itemIDs: Set<String>, previous: [AutoFillIdentity]) -> [AutoFillIdentity] {
        let versions = Data(base64Encoded: catalog.revision).flatMap {
            try? JSONDecoder().decode([String: String].self, from: $0)
        } ?? [:]
        var rows = items[vaultID] ?? [:]
        var replaced = Set<String>()
        var present = Set<String>()
        for item in catalog.items {
            let id = item.storageID ?? SHA256.hash(data: Data(item.name.utf8)).map { String(format: "%02x", $0) }.joined()
            present.insert(id)
            let version = item.storageID.flatMap { versions[$0] }
            if let old = rows[id], version != nil, old.version == version { continue }
            replaced.formUnion(rows[id]?.identities.map(\.id) ?? [])
            let single = ItemCatalog(vault: catalog.vault, revision: catalog.revision, items: [item])
            var identities = AutoFillEntry.entries(catalog: single, vaultID: vaultID).map(AutoFillIdentity.init)
            if let passkey = AutoFillIdentity(passkey: item, vaultID: vaultID) { identities.append(passkey) }
            rows[id] = Item(version: version, identities: identities)
        }
        for id in Array(rows.keys) where itemIDs.contains(id) || (complete && !present.contains(id)) {
            replaced.formUnion(rows.removeValue(forKey: id)?.identities.map(\.id) ?? [])
        }
        items[vaultID] = rows
        let retained = previous.filter {
            complete ? AutoFillEntry.vaultID($0.id) != vaultID : !replaced.contains($0.id)
        }
        // A partial catalog may add/change known rows, but absent rows never imply deletion.
        return Self.unique(retained + rows.values.flatMap(\.identities))
    }
    static func unique(_ entries: [AutoFillIdentity]) -> [AutoFillIdentity] {
        Dictionary(entries.map { ($0.id, $0) }, uniquingKeysWith: { _, new in new }).values.sorted { $0.id < $1.id }
    }
}
