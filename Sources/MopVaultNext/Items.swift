import Foundation
import MopCore

public extension VaultEngine {
    static func purgeExpired(in vault: VerifiedVault, device: any DeviceOperations, at date: Date = Date()) throws -> VerifiedVault? {
        let role = vault.membership.role(of: device.identity)
        guard role == .owner || role == .editor else { return nil }
        var payload = try vault.revision.payload(device: device), records = vault.revision.records
        let expired = payload.items.filter { $0.deletion?.isExpired(at: date) == true }
        guard !expired.isEmpty else { return nil }
        for item in expired { for field in item.fields {
            if let id = payload.references.removeValue(forKey: SecretReference.encode(item.name) + "/" + field.path) { records.removeValue(forKey: id) }
        } }
        payload.items.removeAll { $0.deletion?.isExpired(at: date) == true }
        return try vault.applying(Revision.seal(header: header(vault, operation: .content), references: payload.references,
            records: records, items: payload.items, signer: device).encoded())
    }
    static func catalog(in vault: VerifiedVault, device: any DeviceOperations, deleted: Bool = false) throws -> ItemCatalog {
        let payload = try vault.revision.payload(device: device)
        var items = payload.items
        // Raw reference writes also appear as custom items in the catalog.
        for path in payload.references.keys.sorted() {
            let reference = try SecretReference(vault: vault.name, relativePath: path)
            let field = [reference.section, reference.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
            if let index = items.firstIndex(where: { $0.name == reference.item }) {
                if !items[index].fields.contains(where: { $0.path == field }) { items[index].fields.append(ItemField(path: field)) }
            } else { items.append(VaultItem(name: reference.item, fields: [ItemField(path: field)])) }
        }
        return ItemCatalog(vault: vault.name, revision: vault.digest, items: items.filter {
            deleted ? ($0.deletion != nil && !$0.deletion!.isExpired(at: Date())) : $0.deletion == nil
        }.sorted { $0.name < $1.name })
    }

    static func saveItem(_ edit: ItemEdit, in vault: VerifiedVault, device: any DeviceOperations) throws -> VerifiedVault {
        guard edit.revision == vault.digest else { throw MopError.vaultConflict }
        let role = vault.membership.role(of: device.identity)
        guard role == .owner || role == .editor else { throw MopError.cloudPermission }
        var payload = try vault.revision.payload(device: device)
        var records = vault.revision.records
        let current = try catalog(in: vault, device: device).items
        let original = edit.originalName ?? edit.item.name
        let old = current.first { $0.name == original }
        guard edit.create ? old == nil : old != nil else { throw MopError.duplicate }
        guard original == edit.item.name || !current.contains(where: { $0.name == edit.item.name }),
              edit.item.deletion == nil, !edit.item.fields.isEmpty,
              Set(edit.item.fields.map(\.path)).count == edit.item.fields.count else { throw MopError.invalidVault }
        guard edit.item.autoFill?.validationError(in: edit.item.fields) == nil else { throw MopError.invalidVault }
        var item = edit.item
        var kept = Set<String>()
        for index in item.fields.indices {
            let field = item.fields[index]
            let path = SecretReference.encode(item.name) + "/" + field.path
            _ = try SecretReference(vault: vault.name, relativePath: path)
            let previousPath = SecretReference.encode(original) + "/" + field.path
            kept.insert(previousPath)
            let recordID: String
            if let value = field.value {
                recordID = UUID().uuidString
                var bytes = Data(value.utf8)
                defer { SecretBytes.wipe(&bytes) }
                records[recordID] = try SealedObject.seal(bytes, vault: vault.id, epoch: vault.revision.header.epoch, object: recordID,
                    membership: vault.membership, authenticating: Codec.encode(ObjectContext(vault: vault.id, object: recordID)))
                if let previous = payload.references[previousPath] { records.removeValue(forKey: previous) }
            } else {
                guard let previous = payload.references[previousPath] else { throw MopError.notFound }
                recordID = previous
                if !field.type.concealed {
                    let value = try read(previousPath, in: vault, device: device)
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
        return try vault.applying(Revision.seal(header: header(vault, operation: .content), references: payload.references,
            records: records, items: payload.items, signer: device).encoded())
    }

    static func trashItem(name: String, revision: String, in vault: VerifiedVault, device: any DeviceOperations) throws -> VerifiedVault {
        var payload = try vault.revision.payload(device: device)
        guard let item = try catalog(in: vault, device: device).items.first(where: { $0.name == name }) else { throw MopError.notFound }
        var deleted = item
        deleted.deletion = ItemDeletion(originalName: name, deletedAt: Date())
        deleted.name = "deleted-" + deleted.deletion!.id.uuidString
        for field in item.fields {
            let old = SecretReference.encode(name) + "/" + field.path
            payload.references[SecretReference.encode(deleted.name) + "/" + field.path] = payload.references.removeValue(forKey: old)
        }
        payload.items.removeAll { $0.name == name }; payload.items.append(deleted)
        return try metadata(payload, expected: revision, in: vault, device: device)
    }
    static func restoreItem(id: UUID, revision: String, in vault: VerifiedVault, device: any DeviceOperations) throws -> VerifiedVault {
        var payload = try vault.revision.payload(device: device)
        guard let index = payload.items.firstIndex(where: { $0.deletion?.id == id }),
              let deletion = payload.items[index].deletion, !deletion.isExpired(at: Date()),
              !payload.items.contains(where: { $0.name == deletion.originalName }) else { throw MopError.duplicate }
        let oldName = payload.items[index].name
        for field in payload.items[index].fields {
            payload.references[SecretReference.encode(deletion.originalName) + "/" + field.path] = payload.references.removeValue(forKey: SecretReference.encode(oldName) + "/" + field.path)
        }
        payload.items[index].name = deletion.originalName; payload.items[index].deletion = nil
        return try metadata(payload, expected: revision, in: vault, device: device)
    }
    private static func metadata(_ payload: CatalogPayload, expected: String, in vault: VerifiedVault, device: any DeviceOperations) throws -> VerifiedVault {
        guard expected == vault.digest else { throw MopError.vaultConflict }
        let role = vault.membership.role(of: device.identity)
        guard role == .owner || role == .editor else { throw MopError.cloudPermission }
        return try vault.applying(Revision.seal(header: header(vault, operation: .content), references: payload.references,
            records: vault.revision.records, items: payload.items, signer: device).encoded())
    }
    static func rename(_ name: String, in vault: VerifiedVault, device: any DeviceOperations) throws -> VerifiedVault {
        guard vault.membership.role(of: device.identity) == .owner else { throw MopError.cloudPermission }
        try VaultName.validate(name)
        let old = try header(vault, operation: .content)
        let next = Revision.Header(format: old.format, vault: old.vault, name: name, generation: old.generation, parent: old.parent,
            epoch: old.epoch, membership: old.membership, operation: old.operation, acceptedInvitations: old.acceptedInvitations)
        let payload = try vault.revision.payload(device: device)
        return try vault.applying(Revision.seal(header: next, references: payload.references, records: vault.revision.records, items: payload.items, signer: device).encoded())
    }
}
