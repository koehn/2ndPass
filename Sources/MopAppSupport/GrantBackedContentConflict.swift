import Foundation
import CryptoKit
import MopCore
import MopSync
import MopVaultNext

extension GrantBackedContentSession {
    /// A persisted negative observation suppresses repeated decryptions/requests,
    /// never authorizes a read or a retirement. New grants, authority, branches or
    /// available legacy identity invalidate it. No key material is persisted here.
    func recoverStoredConflict(_ expected: EncryptedItemConflict, requestScope: EnrollmentScope? = nil,
                               legacy: (any DeviceOperations)? = nil, isolation: isolated (any Actor)? = #isolation) async throws -> Bool {
        try permit.check()
        _ = try await repository.reviewedContentConflict(expected)
        let recipients = Set(history.orderedStates.flatMap { $0.membership.devices.map(\.fingerprint) })
            .union([identity.fingerprint] + [legacy?.identity.fingerprint].compactMap { $0 })
        guard let snapshot = try await repository.contentMigrationReads(scopes: [expected.local.scope], recipients: recipients)[expected.local.scope] else {
            throw ContentStoreError.invalidRecord
        }
        var digest = SHA256()
        for bytes in [try setupEncode(expected.local), try setupEncode(expected.remote), expected.serverSystemFields,
                      Data(try history.current.digest().utf8), Data(identity.fingerprint.utf8),
                      Data((legacy?.identity.fingerprint ?? "none").utf8), try setupEncode(requestScope)] { digest.update(data: bytes) }
        for version in snapshot.versions.sorted(by: { $0.version.versionID.uuidString < $1.version.versionID.uuidString }) {
            digest.update(data: try setupEncode(version))
        }
        for grant in snapshot.grants.sorted(by: { $0.identifier < $1.identifier }) { digest.update(data: try setupEncode(grant)) }
        let observation = Data(digest.finalize())
        let scopeKey = try setupEncode(expected.local.scope).base64EncodedString()
        let marker = "conflict-key-wait:" + scopeKey + ":" + expected.remote.versionID.uuidString
        if try await repository.engineState(account: binding.account, database: marker) == observation { return true }
        let local = try conflictContent(expected.local), remote = try conflictContent(expected.remote)
        var ancestors: [ContentEnvelope] = []
        var seen = Set<UUID>()
        for head in [local, remote] {
            var cursor = head
            while let base = cursor.header.base, seen.insert(base).inserted {
                guard let stored = snapshot.versions.first(where: { $0.version.versionID == base }) else { break }
                let parent = try conflictContent(stored.version)
                guard parent.header.version == base, parent.header.generation + 1 == cursor.header.generation else { throw MopError.vaultUntrusted }
                ancestors.append(parent); cursor = parent
            }
        }
        let ancestry = try ContentReconciliation.inspect(local: local, remote: remote, ancestors: ancestors, history: history)
        if ancestry == .keepLocal || ancestry == .acknowledgeDuplicate {
            try await repository.retireObsoleteContentBranch(expected,
                policy: GrantBackedContentStorage.recipientPolicy(history: history), permit: permit)
            AccessSyncTrace.event("obsolete conflict retired", item: local.header.item, detail: "reason=verifiedAncestry")
            return true
        }
        if ancestry == .acceptRemote {
            try await queueConflictChoice(expected, catalog: nil)
            return true
        }
        let grants = [local, remote].map { content in snapshot.grants.filter { $0.keyGeneration == content.header.keyGeneration } }
        var missing = false
        var legacyReaders: [UUID: ContentKeyGrant] = [:]
        for (index, content) in [local, remote].enumerated() {
            if grants[index].contains(where: { $0.recipient == identity.fingerprint }) { continue }
            let eligible = (try? history.verifyContentKeyPath(from: content.header.keyMembership)) != nil
            let source = legacy.flatMap { device in grants[index].first { $0.recipient == device.identity.fingerprint } }
            AccessSyncTrace.event("conflict key availability", item: content.header.item, generation: content.header.keyGeneration,
                recipient: identity.fingerprint, detail: "side=\(index == 0 ? "local" : "remote") currentGrant=false legacyKey=\(legacy != nil) legacyGrant=\(source != nil) retainedGrants=\(grants[index].count) keyPathEligible=\(eligible)")
            if eligible, let legacy, let source,
               WrappedDeviceMigration.canUseLegacySource(legacy.identity, replacement: identity, history: history),
               let stored = try await repository.contentVersion(scope: expected.local.scope, version: content.header.version) {
                let preparation = try ContentGrantPreparation(bytes: stored.version.ciphertext, item: content.header.item, history: history)
                let publication = try permit.withDevice {
                    try preparation.extendingAccess(to: identity, sourceGrantBytes: source.bytes, decryptor: legacy, signer: $0)
                }
                let grant = publication.grant
                let prepared = try PreparedContentGrant(scope: expected.local.scope, keyGeneration: grant.keyGeneration,
                    recipient: grant.recipient, identifier: grant.identifier, bytes: grant.encoded())
                try await repository.commitDeviceMigrationGrant(prepared, sourceVersion: stored,
                    expectedPolicy: GrantBackedContentStorage.recipientPolicy(history: history), authorization: permit)
                AccessSyncTrace.event("conflict grant recovered", item: content.header.item, generation: content.header.keyGeneration, detail: "source=legacy")
                continue
            }
            // An existing historical recipient may still read its own grant.
            // This is the same migration source gate used by rotation; it does
            // not extend the obsolete key to the replacement or to a peer.
            if let legacy, let source,
               WrappedDeviceMigration.canUseLegacySource(legacy.identity, replacement: identity, history: history) {
                legacyReaders[content.header.version] = try ContentKeyGrant.decode(source.bytes, content: content, history: history)
                continue
            }
            missing = true
            if eligible, let requestScope {
                let request = ContentGrantRequest(item: content.header.item, keyGeneration: content.header.keyGeneration, recipient: identity.fingerprint)
                let bytes = try setupEncode(request)
                let hash = Array(SHA256.hash(data: bytes).prefix(16))
                let id = UUID(uuid: (hash[0],hash[1],hash[2],hash[3],hash[4],hash[5],hash[6],hash[7],hash[8],hash[9],hash[10],hash[11],hash[12],hash[13],hash[14],hash[15]))
                _ = try await coordination(kind: .grantRequest, scope: requestScope, identity: id, payload: bytes)
            }
        }
        if missing {
            try permit.check()
            _ = try await repository.reviewedContentConflict(expected)
            try await repository.saveEngineState(observation, account: binding.account, database: marker, permit: permit)
            AccessSyncTrace.event("conflict waiting for key evidence", operation: expected.id, item: local.header.item,
                detail: "automaticRetry=false branchesPreserved=true")
            return true
        }
        let localGrant: ContentKeyGrant, remoteGrant: ContentKeyGrant
        if let retained = legacyReaders[local.header.version] { localGrant = retained }
        else { localGrant = try await grant(for: local) }
        if let retained = legacyReaders[remote.header.version] { remoteGrant = retained }
        else { remoteGrant = try await grant(for: remote) }
        let values: [String: SecretBytes]? = try permit.withDevice { device in
            let left = try local.open(components: Set(local.components.keys), grant: localGrant, history: history,
                device: legacyReaders[local.header.version] != nil ? legacy! : device)
            let right = try remote.open(components: Set(remote.components.keys), grant: remoteGrant, history: history,
                device: legacyReaders[remote.header.version] != nil ? legacy! : device)
            guard local.header.isTombstone == remote.header.isTombstone,
                  try ContentItemArchive.identical(left, right, item: local.header.item, preservingEditMetadata: true) else { return nil }
            return left
        }
        guard let values else {
            if !legacyReaders.isEmpty {
                // The ordinary editor cannot reveal a retired identity's branch.
                // Preserve the genuine difference without a repeated decrypt loop.
                _ = try await repository.reviewedContentConflict(expected)
                try await repository.saveEngineState(observation, account: binding.account, database: marker, permit: permit)
                AccessSyncTrace.event("legacy conflict requires review", operation: expected.id, item: local.header.item,
                    detail: "automaticRetry=false branchesPreserved=true")
                return true
            }
            return false
        }
        if legacyReaders[remote.header.version] == nil, (try? remote.verifyForPublication(history: history)) != nil {
            try await queueConflictChoice(expected, catalog: nil)
        } else {
            // Preserve the verified plaintext under a fresh CURRENT key. Never
            // publish the old key or replace a branch before cloud/CAS readback.
            guard remote.header.generation < UInt64(Int64.max) else { throw MopError.invalidVault }
            let publication = try permit.withDevice { device in
                try ContentEnvelope.seal(values, vault: binding.vaultID, item: local.header.item,
                    generation: remote.header.generation + 1, base: remote.header.version, history: history,
                    signer: device, isTombstone: local.header.isTombstone)
            }
            let prepared = try GrantBackedContentStorage.prepare(publication, scope: expected.local.scope, history: history)
            _ = try await repository.enqueueContentConflictDecision(expected, replacement: prepared,
                policy: GrantBackedContentStorage.recipientPolicy(history: history), permit: permit)
        }
        AccessSyncTrace.event("equivalent conflict queued", item: local.header.item, detail: "legacyRead=\(!legacyReaders.isEmpty)")
        return true
    }

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
        let local = try conflictContent(expected.local), remote = try conflictContent(expected.remote)
        guard local.header.isTombstone == remote.header.isTombstone else { return false }
        let localGrant = try await grant(for: local), remoteGrant = try await grant(for: remote)
        return try permit.withDevice { device in
            let left = try local.open(components: Set(local.components.keys), grant: localGrant, history: history, device: device)
            let right = try remote.open(components: Set(remote.components.keys), grant: remoteGrant, history: history, device: device)
            return try ContentItemArchive.identical(left, right, item: local.header.item, preservingEditMetadata: true)
        }
    }
    /// Queue only a fully authenticated, plaintext-equivalent branch through
    /// the normal durable resolution path. No cloud receipt or head is invented.
    func recoverEquivalentConflict(_ expected: EncryptedItemConflict) async throws -> Bool {
        guard try await isDuplicateConflict(expected) else { return false }
        try Task.checkCancellation()
        try permit.check()
        try await queueConflictChoice(expected, catalog: nil)
        AccessSyncTrace.event("equivalent conflict queued", item: expected.local.scope.itemID)
        return true
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
