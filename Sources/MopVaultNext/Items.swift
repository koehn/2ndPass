import Foundation
import CryptoKit
import MopCore

/// An unlocked session's verified ciphertext and catalog. No concealed field plaintext,
/// private keys, or unwrapped item keys are retained here.
public struct VaultReadSnapshot: Sendable {
    public let vault: VerifiedVault
    public let catalog: ItemCatalog
    fileprivate let references: [String: String]

    public func read(_ reference: SecretReference, device: any DeviceOperations, allowsAttachments: Bool = true) throws -> (value: SecretBytes, field: ItemField, itemID: String?) {
        guard reference.vault == vault.name else { throw MopError.vaultSelectionMismatch }
        guard vault.membership.role(of: device.identity) != nil else { throw MopError.notVaultMember }
        let path = [reference.section, reference.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
        guard let item = catalog.items.first(where: { $0.name == reference.item }),
              let field = item.fields.first(where: { $0.path == path }),
              let id = references[reference.relativePath] else { throw MopError.notFound }
        guard allowsAttachments || field.type != .attachment else { throw MopError.notFound }
        var bytes = try VaultEngine.openRecord(id, in: vault, device: device)
        defer { SecretBytes.wipe(&bytes) }
        return (SecretBytes(copying: bytes), field, item.storageID)
    }
}

public extension VaultEngine {
    static func purgeExpired(in vault: VerifiedVault, device: any DeviceOperations, at date: Date = Date()) throws -> VerifiedVault? {
        let role = vault.membership.role(of: device.identity)
        guard role == .owner || role == .editor else { return nil }
        var payload = try vault.revision.payload(device: device), records = vault.revision.records, keys = vault.revision.itemKeys
        let expired = payload.items.filter { $0.deletion?.isExpired(at: date) == true }
        guard !expired.isEmpty else { return nil }
        for item in expired { for field in item.fields {
            if let id = payload.references.removeValue(forKey: SecretReference.encode(item.name) + "/" + field.path) { records.removeValue(forKey: id) }
        } }
        payload.items.removeAll { $0.deletion?.isExpired(at: date) == true }
        return try vault.applying(Revision.seal(header: header(vault, operation: .content), references: payload.references,
            records: records, itemKeys: keys, items: payload.items, signer: device))
    }
    static func catalog(in vault: VerifiedVault, device: any DeviceOperations, deleted: Bool = false) throws -> ItemCatalog {
        let payload = try vault.revision.payload(device: device)
        return try catalog(payload, in: vault, device: device, deleted: deleted)
    }
    /// One payload decryption for both lists and the authoritative usage-pruning inventory.
    static func catalogs(in vault: VerifiedVault, device: any DeviceOperations) throws -> (active: ItemCatalog, deleted: ItemCatalog, retainedIDs: Set<String>, reader: VaultReadSnapshot) {
        let payload = try vault.revision.payload(device: device)
        let active = try catalog(payload, in: vault, device: device)
        return (active,
                try catalog(payload, in: vault, device: device, deleted: true),
                Set(payload.itemIDs.values), VaultReadSnapshot(vault: vault, catalog: active, references: payload.references))
    }
    internal static func catalog(_ payload: CatalogPayload, in vault: VerifiedVault, device: any DeviceOperations, deleted: Bool = false) throws -> ItemCatalog {
        var items = payload.items
        // Raw reference writes also appear as custom items in the catalog.
        for path in payload.references.keys.sorted() {
            let reference = try SecretReference(vault: vault.name, relativePath: path)
            let field = [reference.section, reference.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
            if let index = items.firstIndex(where: { $0.name == reference.item }) {
                if !items[index].fields.contains(where: { $0.path == field }) { items[index].fields.append(ItemField(path: field)) }
            } else { items.append(VaultItem(name: reference.item, fields: [ItemField(path: field)])) }
        }
        for index in items.indices { items[index].storageID = payload.itemIDs[items[index].name] }
        var result = ItemCatalog(vault: vault.name, revision: vault.digest, items: items.filter {
            deleted ? ($0.deletion != nil && !$0.deletion!.isExpired(at: Date())) : $0.deletion == nil
        }.sorted { $0.name < $1.name })
        let role = vault.membership.role(of: device.identity)
        result.canEdit = role == .owner || role == .editor
        return result
    }

    static func saveItem(_ edit: ItemEdit, in vault: VerifiedVault, device: any DeviceOperations, at date: Date = Date()) throws -> VerifiedVault {
        guard edit.revision == vault.digest else { throw MopError.vaultConflict }
        let role = vault.membership.role(of: device.identity)
        guard role == .owner || role == .editor else { throw MopError.cloudPermission }
        var payload = try vault.revision.payload(device: device)
        var records = vault.revision.records, keys = vault.revision.itemKeys
        try apply(edit, payload: &payload, records: &records, keys: &keys, vault: vault, device: device, at: date)
        do {
            return try vault.applying(Revision.seal(header: header(vault, operation: .content), references: payload.references,
                records: records, itemKeys: keys, items: payload.items, signer: device))
        } catch MopError.invalidVault where edit.item.fields.contains(where: { $0.type == .attachment }) {
            throw AttachmentFailure.capacity
        }
    }

    private static func apply(_ edit: ItemEdit, payload: inout CatalogPayload, records: inout [String: SealedObject], keys: inout [String: ItemKey], vault: VerifiedVault, device: any DeviceOperations, at date: Date, importing: Bool = false) throws {
        var current = payload.items.filter { $0.deletion == nil }
        for path in payload.references.keys.sorted() {
            let ref = try SecretReference(vault: vault.name, relativePath: path)
            let field = [ref.section, ref.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
            if let index = current.firstIndex(where: { $0.name == ref.item }) {
                if !current[index].fields.contains(where: { $0.path == field }) { current[index].fields.append(ItemField(path: field)) }
            } else if !payload.items.contains(where: { $0.name == ref.item }) {
                current.append(VaultItem(name: ref.item, fields: [ItemField(path: field)]))
            }
        }
        let original = edit.originalName ?? edit.item.name
        let old = current.first { $0.name == original }
        guard edit.create ? old == nil && !payload.items.contains(where: { $0.name == original }) : old != nil else { throw MopError.duplicate }
        guard original == edit.item.name || !current.contains(where: { $0.name == edit.item.name }),
              edit.item.deletion == nil, !edit.item.fields.isEmpty,
              Set(edit.item.fields.map(\.path)).count == edit.item.fields.count else { throw MopError.invalidVault }
        guard edit.item.autoFill?.validationError(in: edit.item.fields) == nil else { throw MopError.invalidVault }
        var item = edit.item
        item.storageID = nil
        if item.metadata == nil { item.metadata = ItemMetadata() }
        if importing {
            item.metadata?.addedAt = date
        } else {
            item.metadata?.createdAt = edit.create ? date : old?.metadata?.createdAt
            item.metadata?.addedAt = edit.create ? date : old?.metadata?.addedAt
            item.metadata?.updatedAt = date
        }
        let existingID = try payload.references.first { try SecretReference(vault: vault.name, relativePath: $0.key).item == original }.flatMap { records[$0.value]?.itemID }
        let itemID = existingID ?? UUID().uuidString
        var itemKey: SymmetricKey?
        func key() throws -> SymmetricKey {
            if let itemKey { return itemKey }
            let result: SymmetricKey
            if let old = keys[itemID] { result = try old.unwrap(vault: vault.id, item: itemID, device: device) }
            else {
                result = SymmetricKey(size: .bits256)
                keys[itemID] = try ItemKey.wrap(result, vault: vault.id, item: itemID, generation: 1, recipients: vault.membership.recipients)
            }
            itemKey = result
            return result
        }
        var kept = Set<String>()
        for index in item.fields.indices {
            let field = item.fields[index]
            let path = SecretReference.encode(item.name) + "/" + field.path
            _ = try SecretReference(vault: vault.name, relativePath: path)
            let previousPath = SecretReference.encode(original) + "/" + field.path
            kept.insert(previousPath)
            let recordID: String
            if let value = field.value, !(old?.fields.contains(where: { $0.path == field.path && $0.type == field.type && $0.value == value }) ?? false) {
                if field.type == .attachment { _ = try Attachment.decode(value) }
                if field.type.isCompound { _ = try CompoundField(value) }
                recordID = UUID().uuidString
                var bytes = Data(value.utf8)
                defer { SecretBytes.wipe(&bytes) }
                let material = try key()
                records[recordID] = try SealedObject.field(bytes, key: material, vault: vault.id, item: itemID, generation: keys[itemID]!.generation, id: recordID)
                if let previous = payload.references[previousPath] { records.removeValue(forKey: previous) }
            } else {
                if field.type.isCompound, old?.fields.first(where: { $0.path == field.path })?.type != field.type { throw CompoundFieldFailure.invalid }
                if field.type == .attachment, old?.fields.first(where: { $0.path == field.path })?.type != .attachment { throw AttachmentFailure.invalid }
                guard let previous = payload.references[previousPath] else { throw MopError.notFound }
                recordID = previous
                if !field.type.concealed {
                    guard let record = records[previous] else { throw MopError.invalidVault }
                    let material = try key()
                    var value = try record.open(using: material, authenticating: Codec.encode(FieldContext(vault: vault.id, item: itemID, generation: keys[itemID]!.generation, field: previous)))
                    defer { SecretBytes.wipe(&value) }
                    item.fields[index].value = String(decoding: value, as: UTF8.self)
                }
            }
            payload.references.removeValue(forKey: previousPath)
            payload.references[path] = recordID
            if field.type == .password {
                item.fields[index].passwordQuality = field.value.map { PasswordEstimator.estimate($0, userInputs: [item.name]) }
                    ?? old?.fields.first(where: { $0.path == field.path })?.passwordQuality
            } else { item.fields[index].passwordQuality = nil }
            if field.type.concealed { item.fields[index].value = nil }
        }
        for field in old?.fields ?? [] {
            let path = SecretReference.encode(original) + "/" + field.path
            if !kept.contains(path), let id = payload.references.removeValue(forKey: path) { records.removeValue(forKey: id) }
        }
        payload.items.removeAll { $0.name == original }
        payload.items.append(item)
    }

    /// Prepares a single revision; callers publish it once through PublicationCoordinator.
    static func importItems(_ items: [VaultItem], revision: String, in vault: VerifiedVault, device: any DeviceOperations, at date: Date = Date(), progress: ((Int, Int) throws -> Void)? = nil) throws -> VerifiedVault {
        guard revision == vault.digest else { throw MopError.vaultConflict }
        guard let role = vault.membership.role(of: device.identity), role == .owner || role == .editor else { throw MopError.cloudPermission }
        var payload = try vault.revision.payload(device: device), records = vault.revision.records, keys = vault.revision.itemKeys
        try progress?(0, items.count)
        for (index, item) in items.enumerated() {
            try Task.checkCancellation()
            try apply(ItemEdit(revision: revision, item: item, create: true), payload: &payload, records: &records, keys: &keys, vault: vault, device: device, at: date, importing: true)
            try progress?(index + 1, items.count)
        }
        do {
            return try vault.applying(Revision.seal(header: header(vault, operation: .content), references: payload.references,
                records: records, itemKeys: keys, items: payload.items, signer: device))
        } catch MopError.invalidVault { throw ImportFailure.capacity }
    }
    static func previewImport(_ document: ImportDocument, selected: Set<Int>? = nil, in vault: VerifiedVault, device: any DeviceOperations) throws -> (items: [VaultItem], preview: ImportPreview) {
        guard let role = vault.membership.role(of: device.identity), role == .owner || role == .editor else { throw MopError.cloudPermission }
        let payload = try vault.revision.payload(device: device)
        var existing = try catalog(payload, in: vault, device: device).items
        for i in existing.indices {
            var key: SymmetricKey?
            for j in existing[i].fields.indices where existing[i].fields[j].value == nil {
                try Task.checkCancellation()
                let path = SecretReference.encode(existing[i].name) + "/" + existing[i].fields[j].path
                guard let id = payload.references[path], let record = vault.revision.records[id], let item = record.itemID, let wrapped = vault.revision.itemKeys[item] else { throw MopError.invalidVault }
                if key == nil { key = try wrapped.unwrap(vault: vault.id, item: item, device: device) }
                var bytes = try record.open(using: key!, authenticating: Codec.encode(FieldContext(vault: vault.id, item: item, generation: wrapped.generation, field: id)))
                defer { SecretBytes.wipe(&bytes) }
                existing[i].fields[j].value = String(decoding: bytes, as: UTF8.self)
            }
        }
        existing += payload.items.filter { $0.deletion != nil }
        let plan = try ImportPlanner.prepare(document, existing: existing, selected: selected)
        return (plan.items, ImportPreview(vault: vault.id, revision: vault.digest, report: plan.report))
    }

    static func trashItem(name: String, revision: String, in vault: VerifiedVault, device: any DeviceOperations, at date: Date = Date()) throws -> VerifiedVault {
        var payload = try vault.revision.payload(device: device)
        guard let item = try catalog(payload, in: vault, device: device).items.first(where: { $0.name == name }) else { throw MopError.notFound }
        var deleted = item
        deleted.deletion = ItemDeletion(originalName: name, deletedAt: date)
        deleted.name = "deleted-" + deleted.deletion!.id.uuidString
        for field in item.fields {
            let old = SecretReference.encode(name) + "/" + field.path
            payload.references[SecretReference.encode(deleted.name) + "/" + field.path] = payload.references.removeValue(forKey: old)
        }
        payload.items.removeAll { $0.name == name }; payload.items.append(deleted)
        return try metadata(payload, expected: revision, in: vault, device: device)
    }
    static func restoreItem(id: UUID, revision: String, in vault: VerifiedVault, device: any DeviceOperations, at date: Date = Date()) throws -> VerifiedVault {
        var payload = try vault.revision.payload(device: device)
        guard let index = payload.items.firstIndex(where: { $0.deletion?.id == id }),
              let deletion = payload.items[index].deletion, !deletion.isExpired(at: date),
              !payload.items.contains(where: { $0.name == deletion.originalName }) else { throw MopError.duplicate }
        let oldName = payload.items[index].name
        for field in payload.items[index].fields {
            payload.references[SecretReference.encode(deletion.originalName) + "/" + field.path] = payload.references.removeValue(forKey: SecretReference.encode(oldName) + "/" + field.path)
        }
        payload.items[index].name = deletion.originalName; payload.items[index].deletion = nil
        if payload.items[index].metadata == nil { payload.items[index].metadata = ItemMetadata() }
        payload.items[index].metadata?.updatedAt = date
        return try metadata(payload, expected: revision, in: vault, device: device)
    }
    private static func metadata(_ payload: CatalogPayload, expected: String, in vault: VerifiedVault, device: any DeviceOperations) throws -> VerifiedVault {
        guard expected == vault.digest else { throw MopError.vaultConflict }
        let role = vault.membership.role(of: device.identity)
        guard role == .owner || role == .editor else { throw MopError.cloudPermission }
        return try vault.applying(Revision.seal(header: header(vault, operation: .content), references: payload.references,
            records: vault.revision.records, itemKeys: vault.revision.itemKeys, items: payload.items, signer: device))
    }
    static func rename(_ name: String, in vault: VerifiedVault, device: any DeviceOperations) throws -> VerifiedVault {
        guard vault.membership.role(of: device.identity) == .owner else { throw MopError.cloudPermission }
        try CloudVaultBoundary.validateName(name)
        let old = try header(vault, operation: .content)
        let next = Revision.Header(requiredFeatures: old.requiredFeatures, format: old.format, vault: old.vault, name: name, generation: old.generation, parent: old.parent,
            epoch: old.epoch, membership: old.membership, operation: old.operation, acceptedInvitations: old.acceptedInvitations)
        let payload = try vault.revision.payload(device: device)
        return try vault.applying(Revision.seal(header: next, references: payload.references, records: vault.revision.records, itemKeys: vault.revision.itemKeys, items: payload.items, signer: device))
    }
}
