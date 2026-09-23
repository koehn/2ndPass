import CryptoKit
import Foundation
import MopCore

/// Only the index is decrypted at open. Record keys and values are opened on demand.
/// Mutations produce in-memory snapshots; CloudKit publishes them conditionally.
public final class VaultSession: SecretStore {
    private let trust: VaultTrust
    public private(set) var snapshot: Data
    private var document: VaultDocument
    private var key: SymmetricKey?
    private var items: [VaultItem]
    private var index: [String: String]
    private var opener: (any VaultKeyOpener)?
    private var onClose: (() -> Void)?

    /// Cryptographic session independent of storage. Cloud commits are published
    /// asynchronously by the caller; trust is advanced only after confirmation.
    public init(snapshot: Data, trust: VaultTrust, opener: any VaultKeyOpener,
                onClose: @escaping () -> Void = {}) throws {
        let document = try VaultDocument.decode(snapshot)
        guard let slot = document.header.recipients.first(where: { $0.publicKey == opener.publicKey }) else { throw MopError.deviceNotEnrolled }
        let key = try opener.unwrap(slot, vaultID: document.header.vaultID)
        try trust.verify(document: document, key: key)
        let catalog = try document.decryptCatalog(key: key)
        let index = catalog.references
        self.items = catalog.items
        self.trust = trust
        self.snapshot = snapshot
        self.document = document
        self.key = key
        self.index = index
        self.opener = opener
        self.onClose = onClose
    }

    private func requireKey() throws -> SymmetricKey {
        guard let key else { throw MopError.authentication }
        return key
    }

    public var name: String { document.header.name }

    private func check(_ reference: SecretReference) throws {
        guard reference.vault == name else { throw MopError.vaultSelectionMismatch }
        guard !items.contains(where: { $0.name == reference.item && $0.deletion != nil }) else { throw MopError.notFound }
    }

    public func rename(_ name: String) throws {
        try VaultName.validate(name)
        var header = document.header
        header.name = name
        try commit(index: index, records: document.records, header: header)
    }

    public func read(_ reference: SecretReference) throws -> SecretBytes {
        _ = try requireKey()
        try check(reference)
        guard let id = index[reference.relativePath], let record = document.records[id] else { throw MopError.notFound }
        return try record.read(id: id, vaultID: document.header.vaultID, opener: requireOpener())
    }

    private func requireOpener() throws -> any VaultKeyOpener {
        guard let opener else { throw MopError.authentication }
        return opener
    }

    public func write(_ reference: SecretReference, value: SecretBytes, replace: Bool) throws {
        _ = try requireKey()
        try check(reference)
        let exists = index[reference.relativePath] != nil
        if exists && !replace { throw MopError.duplicate }
        if !exists && replace { throw MopError.notFound }
        var index = self.index
        var records = document.records
        if let old = index[reference.relativePath] { records.removeValue(forKey: old) }
        let id = UUID().uuidString
        index[reference.relativePath] = id
        records[id] = try VaultRecord.create(value: value, id: id, header: document.header)
        var items = self.items
        if let i = items.firstIndex(where: { $0.name == reference.item }) {
            if let f = items[i].fields.firstIndex(where: { $0.path == fieldPath(reference) }) {
                items[i].fields[f].passwordQuality = items[i].fields[f].type == .password
                    ? PasswordEstimator.estimate(String(decoding: value, as: UTF8.self)) : nil
                items[i].fields[f].value = items[i].fields[f].type.concealed ? nil : String(decoding: value, as: UTF8.self)
            } else {
                items[i].fields.append(ItemField(path: fieldPath(reference)))
            }
        }
        try commit(index: index, records: records, items: items)
    }

    public func delete(_ reference: SecretReference) throws {
        _ = try requireKey()
        try check(reference)
        var index = self.index
        guard let id = index.removeValue(forKey: reference.relativePath) else { throw MopError.notFound }
        var records = document.records
        records.removeValue(forKey: id)
        var items = self.items
        for i in items.indices where items[i].name == reference.item { items[i].fields.removeAll { $0.path == fieldPath(reference) } }
        items.removeAll { $0.fields.isEmpty }
        try commit(index: index, records: records, items: items)
    }

    public func list(vault: String?) throws -> [SecretReference] {
        _ = try requireKey()
        let deletedNames = Set(items.filter { $0.deletion != nil }.map(\.name))
        return try index.keys.map { try SecretReference(vault: document.header.name, relativePath: $0) }
            .filter { (vault == nil || $0.vault == vault) && !deletedNames.contains($0.item) }.sorted()
    }

    private func fieldPath(_ ref: SecretReference) -> String {
        [ref.section, ref.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
    }

    public func catalog() throws -> ItemCatalog {
        let refs = try list(vault: nil)
        let names = Set(refs.map(\.item))
        let result = names.sorted().map { name in
            var item = items.first { $0.name == name } ?? VaultItem(name: name, fields: [])
            for ref in refs where ref.item == name {
                if !item.fields.contains(where: { $0.path == fieldPath(ref) }) {
                    item.fields.append(ItemField(path: fieldPath(ref)))
                }
            }
            return item
        }
        return ItemCatalog(vault: name, revision: VaultCoding.digest(snapshot), items: result)
    }

    /// Validate and save the complete item in one authenticated snapshot/cloud commit.
    public func saveItem(_ edit: ItemEdit) throws {
        _ = try requireKey()
        guard edit.revision == VaultCoding.digest(snapshot) else { throw MopError.vaultConflict }
        let item = edit.item
        guard item.deletion == nil, !items.contains(where: { $0.name == item.name && $0.deletion != nil }) else { throw MopError.invalidReference }
        let sourceName = edit.originalName ?? item.name
        guard !edit.create || edit.originalName == nil else { throw MopError.invalidReference }
        let currentItems = try catalog().items
        let existing = currentItems.first { $0.name == sourceName }
        if sourceName != item.name, currentItems.contains(where: { $0.name == item.name }) { throw MopError.duplicate }
        if edit.create && existing != nil { throw MopError.duplicate }
        if !edit.create && existing == nil { throw MopError.notFound }
        guard !item.fields.isEmpty, Set(item.fields.map(\.path)).count == item.fields.count else { throw MopError.invalidReference }
        var index = self.index
        var records = document.records
        if sourceName != item.name {
            let prefix = SecretReference.encode(sourceName) + "/"
            for (path, id) in self.index where path.hasPrefix(prefix) {
                index.removeValue(forKey: path)
                index[SecretReference.encode(item.name) + "/" + path.dropFirst(prefix.count)] = id
            }
        }
        var saved = item
        for f in item.fields.indices {
            let field = item.fields[f]
            let ref = try SecretReference(vault: name, relativePath: SecretReference.encode(item.name) + "/" + field.path)
            guard ref.item == item.name else { throw MopError.invalidReference }
            let old = existing?.fields.first { $0.path == field.path }
            if let value = field.value, old?.value != value || old?.type.concealed != false {
                if let id = index[ref.relativePath] { records.removeValue(forKey: id) }
                let id = UUID().uuidString
                records[id] = try VaultRecord.create(value: SecretBytes(utf8: value), id: id, header: document.header)
                index[ref.relativePath] = id
            } else {
                guard old != nil else { throw MopError.notFound }
            }
            // Compute alongside the ciphertext commit; never trust caller-supplied ratings.
            if field.type == .password {
                if let value = field.value {
                    saved.fields[f].passwordQuality = PasswordEstimator.estimate(value)
                } else {
                    saved.fields[f].passwordQuality = old?.type == .password ? old?.passwordQuality : nil
                }
            } else { saved.fields[f].passwordQuality = nil }
            if field.type.concealed { saved.fields[f].value = nil }
            else if field.value == nil {
                saved.fields[f].value = try old?.value ?? String(decoding: read(SecretReference(vault: name, relativePath: SecretReference.encode(sourceName) + "/" + field.path)), as: UTF8.self)
            }
        }
        for old in existing?.fields ?? [] where !item.fields.contains(where: { $0.path == old.path }) {
            if let id = index.removeValue(forKey: SecretReference.encode(item.name) + "/" + old.path) { records.removeValue(forKey: id) }
        }
        var items = self.items.filter { $0.name != sourceName }
        items.append(saved)
        try commit(index: index, records: records, items: items)
    }

    public func recentlyDeleted(at date: Date) throws -> ItemCatalog {
        _ = try requireKey()
        return ItemCatalog(vault: name, revision: VaultCoding.digest(snapshot),
            items: items.filter { $0.deletion.map { !$0.isExpired(at: date) } == true })
    }

    /// Move only encrypted index paths and metadata; record ciphertext is unchanged.
    public func trashItem(name itemName: String, revision: String, at date: Date) throws {
        _ = try requireKey()
        guard revision == VaultCoding.digest(snapshot) else { throw MopError.vaultConflict }
        guard var item = try catalog().items.first(where: { $0.name == itemName }) else { throw MopError.notFound }
        let deletion = ItemDeletion(originalName: itemName, deletedAt: date)
        let archivedName = "mop-deleted-" + deletion.id.uuidString
        guard !items.contains(where: { $0.name == archivedName }),
              !index.keys.contains(where: { $0.hasPrefix(SecretReference.encode(archivedName) + "/") }) else { throw MopError.duplicate }
        item.name = archivedName; item.deletion = deletion
        var index = self.index
        for field in item.fields {
            let old = SecretReference.encode(itemName) + "/" + field.path
            guard let record = index.removeValue(forKey: old) else { throw MopError.invalidVault }
            index[SecretReference.encode(archivedName) + "/" + field.path] = record
        }
        try commit(index: index, records: document.records, items: items.filter { $0.name != itemName } + [item])
    }

    public func restoreItem(id: UUID, revision: String, at date: Date) throws {
        _ = try requireKey()
        guard revision == VaultCoding.digest(snapshot) else { throw MopError.vaultConflict }
        guard var item = items.first(where: { $0.deletion?.id == id }), let deletion = item.deletion,
              !deletion.isExpired(at: date) else { throw MopError.notFound }
        guard !items.contains(where: { $0.name == deletion.originalName }),
              !index.keys.contains(where: { $0.hasPrefix(SecretReference.encode(deletion.originalName) + "/") }) else { throw MopError.duplicate }
        let archivedName = item.name
        var index = self.index
        for field in item.fields {
            let old = SecretReference.encode(archivedName) + "/" + field.path
            guard let record = index.removeValue(forKey: old) else { throw MopError.invalidVault }
            index[SecretReference.encode(deletion.originalName) + "/" + field.path] = record
        }
        item.name = deletion.originalName; item.deletion = nil
        try commit(index: index, records: document.records, items: items.filter { $0.name != archivedName } + [item])
    }

    @discardableResult public func purgeExpiredItems(at date: Date) throws -> Bool {
        _ = try requireKey()
        let expired = items.filter { $0.deletion?.isExpired(at: date) == true }
        guard !expired.isEmpty else { return false }
        var index = self.index
        var records = document.records
        for item in expired {
            for field in item.fields {
                if let id = index.removeValue(forKey: SecretReference.encode(item.name) + "/" + field.path) { records.removeValue(forKey: id) }
            }
        }
        let names = Set(expired.map(\.name))
        try commit(index: index, records: records, items: items.filter { !names.contains($0.name) })
        return true
    }

    public func recipients() throws -> [DeviceRequest] {
        _ = try requireKey()
        return try document.header.recipients.filter { $0.kind == "device" }.map { try DeviceRequest(name: $0.name, publicKey: $0.publicKey) }
    }

    public func enroll(_ request: DeviceRequest, expectedFingerprint: String) throws {
        let key = try requireKey()
        try request.validate()
        guard request.fingerprint == expectedFingerprint else { throw MopError.invalidDevice }
        guard !document.header.recipients.contains(where: { $0.fingerprint == request.fingerprint }) else { throw MopError.duplicate }
        guard document.header.recipients.count < 64 else { throw MopError.invalidVault }
        var header = document.header
        header.recipients.append(try VaultDocument.wrap(key: key, request: request, kind: "device", vaultID: header.vaultID))
        let opener = try requireOpener()
        var records = document.records
        for (id, record) in records {
            records[id] = try record.enrolling(request, id: id, vaultID: header.vaultID, opener: opener)
        }
        try commit(index: index, records: records, header: header)
    }

    public func revoke(_ fingerprint: String, currentDevice: Data) throws {
        _ = try requireKey()
        guard fingerprint != VaultCoding.digest(currentDevice),
              document.header.recipients.contains(where: { $0.kind == "device" && $0.fingerprint == fingerprint }) else { throw MopError.invalidDevice }
        var header = document.header
        let newKey = SymmetricKey(size: .bits256)
        header.recipients = try header.recipients.filter { $0.fingerprint != fingerprint }.map {
            try VaultDocument.wrap(key: newKey, request: DeviceRequest(name: $0.name, publicKey: $0.publicKey), kind: $0.kind, vaultID: header.vaultID)
        }
        // Rotate every value key: deleting recipient slots alone leaves old keys useful.
        var records: [String: VaultRecord] = [:]
        let opener = try requireOpener()
        for (id, record) in document.records {
            let value = try record.read(id: id, vaultID: header.vaultID, opener: opener)
            records[id] = try VaultRecord.create(value: value, id: id, header: header)
        }
        try commit(index: index, records: records, header: header, newKey: newKey)
    }

    private func commit(index: [String: String], records: [String: VaultRecord], header: VaultHeader? = nil, newKey: SymmetricKey? = nil, items: [VaultItem]? = nil) throws {
        let selectedKey = try newKey ?? requireKey()
        var next = header ?? document.header
        guard next.generation < UInt64.max else { throw MopError.invalidVault }
        next.generation += 1
        next.parent = VaultCoding.digest(snapshot)
        next.recipients.sort { $0.fingerprint < $1.fingerprint }
        let document = try VaultDocument.seal(header: next, index: index, records: records, key: selectedKey, items: items ?? self.items)
        let bytes = try VaultCoding.encode(document)
        self.items = items ?? self.items
        self.document = document
        self.snapshot = bytes
        self.index = index
        self.key = selectedKey
    }

    public func close() {
        key = nil
        index.removeAll(keepingCapacity: false)
        items.removeAll(keepingCapacity: false)
        opener = nil
        onClose?()
        onClose = nil
    }

    public func fingerprint() throws -> String {
        VaultTrust.fingerprint(document: document, key: try requireKey())
    }

    public func pinCommittedKey() throws {
        try trust.pin(document: document, key: requireKey())
    }

    public static func createSnapshot(id: UUID = UUID(), name: String, device: DeviceRequest, recovery: RecoveryKey) throws -> Data {
        let key = SymmetricKey(size: .bits256)
        let recipients = try [
            VaultDocument.wrap(key: key, request: device, kind: "device", vaultID: id),
            VaultDocument.wrap(key: key, request: recovery.request, kind: "recovery", vaultID: id)
        ].sorted { $0.fingerprint < $1.fingerprint }
        let header = VaultHeader(format: "mop-vault-v4", vaultID: id, name: name, generation: 1, parent: nil, recipients: recipients)
        return try VaultCoding.encode(VaultDocument.seal(header: header, index: [:], records: [:], key: key))
    }

    /// Bootstrap trust only with independently obtained fingerprint or revision evidence.
    public static func trustSnapshot(_ bytes: Data, trust: VaultTrust, opener: any VaultKeyOpener,
                                     fingerprint: String? = nil, revision: String? = nil) throws {
        guard (fingerprint == nil) != (revision == nil),
              VaultTrust.validFingerprint(fingerprint ?? revision ?? "") else { throw MopError.vaultUntrusted }
        if let revision { guard VaultCoding.digest(bytes) == revision else { throw MopError.vaultUntrusted } }
        let doc = try VaultDocument.decode(bytes)
        guard let slot = doc.header.recipients.first(where: { $0.publicKey == opener.publicKey }) else { throw MopError.deviceNotEnrolled }
        let key = try opener.unwrap(slot, vaultID: doc.header.vaultID)
        if let fingerprint { guard VaultTrust.fingerprint(document: doc, key: key) == fingerprint else { throw MopError.vaultUntrusted } }
        _ = try doc.decryptIndex(key: key)
        try trust.pin(document: doc, key: key)
    }

    public func restore(_ bytes: Data) throws {
        let selected = try VaultDocument.decode(bytes)
        guard selected.header.vaultID == document.header.vaultID,
              let slot = selected.header.recipients.first(where: { $0.publicKey == opener?.publicKey }),
              document.header.recipients.contains(where: { $0.publicKey == opener?.publicKey && $0.kind == "device" }) else { throw MopError.deviceNotEnrolled }
        let opener = try requireOpener()
        let oldKey = try opener.unwrap(slot, vaultID: document.header.vaultID)
        try trust.verify(document: selected, key: oldKey, historical: true)
        let catalog = try selected.decryptCatalog(key: oldKey)
        let index = catalog.references
        var records: [String: VaultRecord] = [:]
        for (id, record) in selected.records {
            records[id] = try VaultRecord.create(value: record.read(id: id, vaultID: document.header.vaultID, opener: opener), id: id, header: document.header)
        }
        try commit(index: index, records: records, items: catalog.items)
    }

    deinit { close() }
}
