import Foundation
import MopCore
import MopSync
import MopVaultNext

extension GrantBackedContentSession {
    private func conflictContent(_ version: EncryptedItemVersion) throws -> ContentEnvelope {
        guard version.scope == binding.item(version.scope.itemID) else { throw MopError.vaultUntrusted }
        let value = try ContentEnvelope.decode(version.ciphertext, history: history, item: version.scope.itemID)
        guard value.header.version == version.versionID, value.header.base == version.baseVersionID,
              value.header.generation == version.generation, value.header.isTombstone == version.isTombstone else { throw MopError.vaultUntrusted }
        return value
    }
    func conflictPreview(_ expected: EncryptedItemConflict) async throws -> ItemVaultConflictPreview {
        try permit.check()
        _ = try await repository.reviewedContentConflict(expected)
        let local = try conflictContent(expected.local), remote = try conflictContent(expected.remote)
        func catalog(_ content: ContentEnvelope) async throws -> ItemContentCatalog {
            if content.header.item == ItemVaultSession.metadataRecordID {
                return ItemContentCatalog(item: VaultItem(name: "Vault settings", fields: []), references: [:])
            }
            if content.header.isTombstone {
                let other = content.header.version == local.header.version ? remote : local
                let name: String
                if other.header.isTombstone { name = "Deleted item" }
                else {
                    let grant = try await grant(for: other)
                    name = try permit.withDevice { device in
                        try ContentItemArchive.catalog(other.open(component: ContentItemArchive.catalogComponent, grant: grant, history: history, device: device),
                            item: other.header.item, componentNames: Set(other.components.keys)).item.name
                    }
                }
                return ItemContentCatalog(item: VaultItem(name: name, fields: []), references: [:])
            }
            let grant = try await grant(for: content)
            return try permit.withDevice { device in
                try ContentItemArchive.catalog(content.open(component: ContentItemArchive.catalogComponent, grant: grant,
                    history: history, device: device), item: content.header.item, componentNames: Set(content.components.keys))
            }
        }
        let name = await ItemVaultSession.editingDeviceName()
        let preview = try await ItemVaultConflictPreview(conflict: expected, local: catalog(local), remote: catalog(remote),
            localAuthorName: local.header.author == identity.fingerprint ? name : nil,
            remoteAuthorName: remote.header.author == identity.fingerprint ? name : nil)
        try permit.check()
        return preview
    }
    func revealConflict(_ expected: EncryptedItemConflict, side: ItemVaultConflictSide, recordID: String) async throws -> SecretBytes {
        try permit.check()
        _ = try await repository.reviewedContentConflict(expected)
        let content = try conflictContent(side == .local ? expected.local : expected.remote), grant = try await grant(for: content)
        return try permit.withDevice { try content.open(component: recordID, grant: grant, history: history, device: $0) }
    }
    func isDuplicateConflict(_ expected: EncryptedItemConflict) async throws -> Bool {
        try permit.check()
        _ = try await repository.reviewedContentConflict(expected)
        return try await comparison().identical(conflictContent(expected.local), conflictContent(expected.remote))
    }
    private func prepareConflictResolution(_ expected: EncryptedItemConflict, catalog: ItemContentCatalog,
                                          changedRecords: [String: SecretBytes], removedRecords: Set<String>) async throws -> PreparedContentPublication {
        try permit.check()
        _ = try await repository.reviewedContentConflict(expected)
        let local = try conflictContent(expected.local), remote = try conflictContent(expected.remote)
        var values: [String: SecretBytes]
        if local.header.isTombstone { values = [:] }
        else if local.header.item == ItemVaultSession.metadataRecordID {
            let grant = try await grant(for: local)
            values = try permit.withDevice { try local.open(components: Set(local.components.keys), grant: grant, history: history, device: $0) }
        } else {
            let names = Set(local.components.keys).subtracting([ContentItemArchive.catalogComponent]).subtracting(removedRecords).union(changedRecords.keys)
            try catalog.validate(itemID: local.header.item, recordIDs: names)
            let grant = try await grant(for: local)
            values = try permit.withDevice { try local.open(components: names.subtracting(changedRecords.keys), grant: grant, history: history, device: $0) }
            values.merge(changedRecords) { _, new in new }; values[ContentItemArchive.catalogComponent] = try ContentItemArchive.encode(catalog)
        }
        let resolved = try permit.withDevice { device in
            try ContentEnvelope.seal(values, vault: binding.vaultID, item: local.header.item,
                generation: remote.header.generation + 1, base: remote.header.version, history: history, signer: device, isTombstone: local.header.isTombstone)
        }
        return try GrantBackedContentStorage.prepare(resolved, scope: expected.local.scope, history: history)

    }
    func queueConflictChoice(_ expected: EncryptedItemConflict, catalog: ItemContentCatalog?,
                             changedRecords: [String: SecretBytes] = [:], removedRecords: Set<String> = []) async throws {
        try permit.check()
        if let pending = try await repository.pendingContentConflictDecision(expected) {
            guard (pending.replacement == nil) == (catalog == nil) else { throw ItemRepositoryError.staleConflict }
            return
        }
        let replacement: PreparedContentPublication?
        if let catalog { replacement = try await prepareConflictResolution(expected, catalog: catalog, changedRecords: changedRecords, removedRecords: removedRecords) }
        else {
            try permit.check()
            _ = try await repository.reviewedContentConflict(expected)
            try conflictContent(expected.remote).verifyForPublication(history: history)
            replacement = nil
        }
        _ = try await repository.enqueueContentConflictDecision(expected, replacement: replacement,
            policy: GrantBackedContentStorage.recipientPolicy(history: history), permit: permit)
    }

}
