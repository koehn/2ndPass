import Foundation
import MopCore
import MopSync
import MopVaultNext

extension GrantBackedContentSession {
    public func catalog(itemID: UUID) async throws -> ItemVaultCatalogEntry {
        guard itemID != ItemVaultSession.metadataRecordID,
              let stored = try await repository.item(binding.item(itemID)), !stored.isTombstone else { throw MopError.notFound }
        let (content, grant) = try await readable(stored: stored, item: itemID)
        return try permit.withDevice { device in
            let bytes = try content.open(component: ContentItemArchive.catalogComponent, grant: grant, history: history, device: device)
            let catalog = try ContentItemArchive.catalog(bytes, item: itemID, componentNames: Set(content.components.keys))
            return ItemVaultCatalogEntry(itemID: itemID, versionID: stored.versionID, catalog: catalog)
        }
    }

    public func displayItem(itemID: UUID) async throws -> ItemVaultDisplayEntry {
        guard itemID != ItemVaultSession.metadataRecordID,
              let stored = try await repository.item(binding.item(itemID)), !stored.isTombstone else { throw MopError.notFound }
        let (content, grant) = try await readable(stored: stored, item: itemID)
        return try permit.withDevice { device in
            let (catalog, values) = try content.openProjection(initial: ContentItemArchive.catalogComponent,
                grant: grant, history: history, device: device) { bytes in
                let catalog = try ContentItemArchive.catalog(bytes, item: itemID, componentNames: Set(content.components.keys))
                let names = try Set(catalog.item.fields.filter { !$0.type.concealed }.map { field in
                    guard let id = catalog.references[SecretReference.encode(catalog.item.name) + "/" + field.path] else { throw MopError.invalidVault }
                    return id
                })
                return (catalog, names)
            }
            var item = catalog.item
            for index in item.fields.indices where !item.fields[index].type.concealed {
                try Task.checkCancellation()
                guard let record = catalog.references[SecretReference.encode(item.name) + "/" + item.fields[index].path],
                      let value = values[record] else { throw MopError.invalidVault }
                item.fields[index].value = String(decoding: try value.validatedUTF8(), as: UTF8.self)
            }
            return ItemVaultDisplayEntry(entry: ItemVaultCatalogEntry(itemID: itemID, versionID: stored.versionID, catalog: catalog), item: item)
        }
    }

    public func save(_ archive: PortableVaultArchive, expectedBase: UUID?, editOrigin: ItemEditOrigin? = nil) async throws -> PendingItemMutation {
        try permit.check()
        let prepared = try ContentItemArchive.components(archive, editOrigin: editOrigin)
        guard prepared.item != ItemVaultSession.metadataRecordID else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        if let expectedBase { return try await edit(item: prepared.item, expected: expectedBase, components: prepared.values) }
        return try await create(item: prepared.item, components: prepared.values)
    }

    public func edit(itemID: UUID, expectedBase: UUID, catalog: ItemEnvelopeCatalog,
                     changedRecords: [String: SecretBytes], removedRecords: Set<String>) async throws -> PendingItemMutation {
        guard itemID != ItemVaultSession.metadataRecordID else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        let (content, grant) = try await readable(item: itemID, expected: expectedBase)
        guard !content.header.isTombstone, !removedRecords.contains(ContentItemArchive.catalogComponent),
              changedRecords[ContentItemArchive.catalogComponent] == nil,
              Set(changedRecords.keys).isDisjoint(with: removedRecords) else { throw MopError.invalidVault }
        let recordIDs = Set(content.components.keys).subtracting([ContentItemArchive.catalogComponent]).subtracting(removedRecords).union(changedRecords.keys)
        try catalog.validate(itemID: itemID, recordIDs: recordIDs)
        // V3 component AAD binds the storage version. Re-encrypt retained
        // components under the same item key; recipient grants are unaffected.
        var values = try permit.withDevice { device in
            try content.open(components: recordIDs.subtracting(changedRecords.keys), grant: grant, history: history, device: device)
        }
        values.merge(changedRecords) { _, new in new }
        values[ContentItemArchive.catalogComponent] = try ContentItemArchive.encode(catalog)
        return try await edit(item: itemID, expected: expectedBase, components: values)
    }

    public func vaultMetadata() async throws -> (versionID: UUID, value: VaultEnvelopeMetadata) {
        let id = ItemVaultSession.metadataRecordID
        guard let stored = try await repository.item(binding.item(id)), !stored.isTombstone else { throw ItemVaultSessionFailure.missingVaultMetadata }
        let (content, grant) = try await readable(item: id, expected: stored.versionID)
        let author = try history.state(forDigest: content.header.membership).membership
        guard author.devices.contains(where: { $0.fingerprint == content.header.author && author.role(of: $0) == .owner }),
              Set(content.components.keys) == [ContentItemArchive.metadataComponent] else { throw MopError.vaultUntrusted }
        let value = try permit.withDevice { device in
            try content.open(component: ContentItemArchive.metadataComponent, grant: grant, history: history, device: device)
                .withFoundationData { try JSONDecoder().decode(VaultEnvelopeMetadata.self, from: $0) }
        }
        try value.validate()
        return (stored.versionID, value)
    }

    public func saveMetadata(_ settings: VaultEnvelopeMetadata, expectedBase: UUID?) async throws -> PendingItemMutation {
        try permit.check()
        guard history.current.membership.role(of: identity) == .owner else { throw MopError.cloudPermission }
        try settings.validate()
        let values = [ContentItemArchive.metadataComponent: try ContentItemArchive.encode(settings)]
        if let expectedBase { return try await edit(item: ItemVaultSession.metadataRecordID, expected: expectedBase, components: values) }
        return try await create(item: ItemVaultSession.metadataRecordID, components: values)
    }

    public func exportPortableLocalSnapshot() async throws -> PortableVaultArchive {
        try permit.check()
        let versions = try await repository.itemsForPortableExport(account: binding.account, vaultID: binding.vaultID,
            database: binding.database, zoneOwner: binding.zoneOwner)
        for version in versions {
            guard try await repository.contentBranches(scope: version.scope).isEmpty else { throw MopError.vaultConflict }
        }
        let settings = try await vaultMetadata()
        guard versions.first(where: { $0.scope.itemID == ItemVaultSession.metadataRecordID })?.versionID == settings.versionID else { throw ItemRepositoryError.staleLocalVersion }
        var result = PortableVaultArchive(name: settings.value.name, items: [], itemIDs: [:], references: [:], records: [:],
            security: settings.value.security, exclusions: settings.value.exclusions)
        for stored in versions where stored.scope.itemID != ItemVaultSession.metadataRecordID && stored.healthItemID == nil && !stored.isTombstone {
            guard try await repository.contentBranches(scope: stored.scope).isEmpty else { throw MopError.vaultConflict }
            let (content, grant) = try await readable(item: stored.scope.itemID, expected: stored.versionID)
            let item = try permit.withDevice { device in
                let catalog = try ContentItemArchive.catalog(content.open(component: ContentItemArchive.catalogComponent,
                    grant: grant, history: history, device: device), item: stored.scope.itemID, componentNames: Set(content.components.keys))
                let records = try content.open(components: Set(content.components.keys).subtracting([ContentItemArchive.catalogComponent]), grant: grant, history: history, device: device)
                return try ContentItemArchive.archive(name: settings.value.name, item: stored.scope.itemID, catalog: catalog, records: records)
            }
            guard Set(result.itemIDs.keys).isDisjoint(with: item.itemIDs.keys), Set(result.records.keys).isDisjoint(with: item.records.keys) else { throw PortableArchiveFailure.invalid }
            result.items += item.items
            result.itemIDs.merge(item.itemIDs) { _, new in new }
            result.references.merge(item.references) { _, new in new }
            result.records.merge(item.records) { _, new in new }
            if let histories = item.security?.histories, !histories.isEmpty {
                if result.security == nil { result.security = VaultSecurityMetadata() }
                result.security?.histories += histories
            }
        }
        // A coherent local snapshot, never a claim of cloud inventory completeness.
        let current = try await repository.itemsForPortableExport(account: binding.account, vaultID: binding.vaultID,
            database: binding.database, zoneOwner: binding.zoneOwner)
        guard Dictionary(uniqueKeysWithValues: versions.map { ($0.scope.itemID, $0.versionID) }) == Dictionary(uniqueKeysWithValues: current.map { ($0.scope.itemID, $0.versionID) }) else { throw ItemRepositoryError.staleLocalVersion }
        for version in current {
            guard try await repository.contentBranches(scope: version.scope).isEmpty else { throw MopError.vaultConflict }
        }
        try permit.check(); try result.validate()
        return result
    }
}
