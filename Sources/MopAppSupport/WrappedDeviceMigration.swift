import Foundation
import MopCore
import MopSync
import MopVaultNext

/// Resumable additive migration. The durable wrapped identity is created before
/// admission is journaled. Cloud-confirmed membership is the switch authority;
/// neither a local marker nor an unconfirmed proposal can authorize the new keys.
/// Legacy keys/grants are retained for offline devices and old key epochs, but
/// their membership is retired after replacement grant readiness.
struct WrappedDeviceMigration {
    static func open(repository: EncryptedItemRepository, trust: any ItemVaultMembershipTrustStore,
                     scope: ItemVaultSetupScope, legacy: any DeviceOperations,
                     replacement: any DeviceOperations, owner: any RepositoryWritePermit) async throws -> ItemVaultSession {
        guard legacy.identity.member == replacement.identity.member,
              legacy.identity.device != replacement.identity.device,
              let pin = try trust.load(scope: scope) else { throw MopError.invalidIdentity }
        let history = try ItemVaultMembershipAuthority.history(record: pin, trustStore: trust, allowingDeviceRemoval: true)
        guard !(history.current.membership.removedDevices ?? []).contains(replacement.identity.device) else {
            legacy.close(); replacement.close(); throw MopError.notVaultMember
        }
        if history.current.membership.role(of: replacement.identity) == .owner {
            let migrated = try await ItemVaultBootstrap(repository: repository, trustStore: trust, scope: scope, device: replacement).open()
            do {
                // A removed old identity is never restored or used as authority.
                if history.current.membership.role(of: legacy.identity) == .owner {
                    try await transferGrants(repository: repository, scope: scope, history: history,
                        legacy: legacy, replacement: migrated.contentSession, owner: owner)
                    try await retireLegacyIfReady(repository: repository, scope: scope, legacy: legacy.identity,
                        replacement: migrated.contentSession, owner: owner)
                }
                legacy.close()
                return migrated
            } catch { migrated.lock(); legacy.close(); throw error }
        }
        replacement.close()
        let previous = try await ItemVaultBootstrap(repository: repository, trustStore: trust, scope: scope, device: legacy).open()
        do {
            let current = history.current.membership
            guard current.accounts.count == 1, let member = current.accounts.first,
                  member.id == replacement.identity.member, member.role == .owner else { throw MopError.cloudPermission }
            let membership = try Membership(accounts: [AccountMember(id: member.id, role: member.role,
                devices: member.devices + [replacement.identity])], offlineRecovery: current.offlineRecovery,
                removedDevices: current.removedDevices)
            // prepareMembership reuses the exact durable proposal after restart.
            // Other membership work is allowed to complete before retrying migration.
            do {
                let operation = try await previous.contentSession.prepareMembership(membership, owner: owner)
                try await repository.enqueueDeviceMigration(operation,
                    authorization: ContentWorkPermit(owner: owner, session: previous.contentSession.permit))
            } catch ContentStoreError.staleAuthority { }
            return previous
        } catch { previous.lock(); throw error }
    }

    /// The retained private key belongs to the predecessor of this local wrapped
    /// identity. Both must have been independently pinned as owners together.
    /// Removal revokes its signing authority, not our ability to decrypt retained
    /// ciphertext and rotate it under the currently authorized replacement.
    static func canUseLegacySource(_ legacy: DevicePublicKey, replacement: DevicePublicKey,
                                   history: TrustedMembershipHistory) -> Bool {
        legacy.member == replacement.member && legacy != replacement
            && history.current.membership.role(of: replacement) == .owner
            && history.orderedStates.contains { $0.membership.role(of: legacy) == .owner && $0.membership.role(of: replacement) == .owner }
    }

    private static func retireLegacyIfReady(repository: EncryptedItemRepository, scope: ItemVaultSetupScope,
                                             legacy: DevicePublicKey, replacement: GrantBackedContentSession,
                                             owner: any RepositoryWritePermit) async throws {
        let current = replacement.history.current.membership
        guard current.role(of: legacy) == .owner else { return }
        let policy = try GrantBackedContentStorage.recipientPolicy(history: replacement.history)
        let index = try await repository.itemRevisionIndex(account: scope.binding.account, vaultID: scope.binding.vaultID,
            database: scope.binding.database, zoneOwner: scope.binding.zoneOwner)
        guard index[ItemVaultSession.metadataRecordID] != nil else { return }
        // Do not retire the only usable reader while a download or earlier
        // security rotation is incomplete. Reconsider after durable grant work.
        for (item, version) in index {
            guard let state = try await repository.contentState(scope: scope.binding.item(item)),
                  state.versionID == version, state.keyAuthority == policy.keyAuthority,
                  try await !repository.contentGrants(scope: scope.binding.item(item), keyGeneration: state.keyGeneration,
                    recipient: replacement.identity.fingerprint).isEmpty else { return }
            let (content, grant) = try await replacement.readable(item: item, expected: version)
            // Prove the replacement can unwrap and decrypt, not merely that a row
            // with its fingerprint exists. A tombstone still authenticates its grant.
            _ = try replacement.permit.withDevice {
                try content.open(components: Set(content.components.keys.prefix(1)), grant: grant,
                    history: replacement.history, device: $0)
            }
        }
        let accounts = current.accounts.map { AccountMember(id: $0.id, role: $0.role, devices: $0.devices.filter { $0 != legacy }) }
        let membership = try Membership(accounts: accounts, offlineRecovery: current.offlineRecovery,
            removedDevices: Array(Set(current.removedDevices ?? []).union([legacy.device])).sorted { $0.uuidString < $1.uuidString })
        do {
            let operation = try await replacement.prepareMembership(membership, owner: owner)
            try await repository.enqueueDeviceMigration(operation,
                authorization: ContentWorkPermit(owner: owner, session: replacement.permit))
        } catch ContentStoreError.staleAuthority { }
    }

    private static func transferGrants(repository: EncryptedItemRepository, scope: ItemVaultSetupScope,
                                       history: TrustedMembershipHistory, legacy: any DeviceOperations,
                                       replacement: GrantBackedContentSession, owner: any RepositoryWritePermit) async throws {
        let policy = try GrantBackedContentStorage.recipientPolicy(history: history)
        let authorization = ContentWorkPermit(owner: owner, session: replacement.permit)
        let index = try await repository.itemRevisionIndex(account: scope.binding.account, vaultID: scope.binding.vaultID,
            database: scope.binding.database, zoneOwner: scope.binding.zoneOwner)
        // History is immutable for this pass. Obsolete epochs fail identically
        // for every item; remember failures too, without changing trust decisions.
        var keyPathEligibility: [String: Bool] = [:]
        let replacementRecipient = replacement.identity.fingerprint
        let legacyRecipient = legacy.identity.fingerprint
        let items = Array(index.keys)
        for offset in stride(from: 0, to: items.count, by: 16) {
            try Task.checkCancellation(); try authorization.withWritePermission {}
            let batch = Array(items[offset..<min(offset + 16, items.count)])
            let snapshots = try await repository.contentMigrationReads(scopes: batch.map { scope.binding.item($0) },
                recipients: [replacementRecipient, legacyRecipient])
            for item in batch {
                try Task.checkCancellation(); try authorization.withWritePermission {}
                let itemScope = scope.binding.item(item)
                guard let snapshot = snapshots[itemScope] else { throw ContentStoreError.invalidRecord }
                let versions = snapshot.versions.sorted { left, right in
                    let leftIsHead = left.version.versionID == index[item]
                    let rightIsHead = right.version.versionID == index[item]
                    if leftIsHead != rightIsHead { return leftIsHead }
                    if left.version.generation != right.version.generation { return left.version.generation > right.version.generation }
                    return left.version.versionID.uuidString < right.version.versionID.uuidString
                }
                var generations = Set<UUID>()
                for version in versions {
                    guard generations.insert(version.keyGeneration).inserted else { continue }
                    if snapshot.grants.contains(where: { $0.keyGeneration == version.keyGeneration && $0.recipient == replacementRecipient }) { continue }
                    guard let source = snapshot.grants.filter({ $0.keyGeneration == version.keyGeneration && $0.recipient == legacyRecipient })
                        .min(by: { $0.identifier < $1.identifier }) else { continue }
                    let content = try ContentEnvelope.decode(version.version.ciphertext, history: history, item: item)
                    guard version.version.scope == itemScope, content.header.version == version.version.versionID,
                          content.header.base == version.version.baseVersionID, content.header.generation == version.version.generation,
                          content.header.isTombstone == version.version.isTombstone,
                          content.header.keyGeneration == version.keyGeneration, content.header.membership == version.membership else {
                        throw MopError.vaultUntrusted
                    }
                    // An obsolete security epoch must never be granted to a newly
                    // admitted identity. Keep its original grant and legacy key intact.
                    let membership = content.header.keyMembership
                    let eligible: Bool
                    if let cached = keyPathEligibility[membership] { eligible = cached }
                    else {
                        eligible = (try? history.verifyContentKeyPath(from: membership)) != nil
                        keyPathEligibility[membership] = eligible
                    }
                    guard eligible else { continue }
                    let preparation = try ContentGrantPreparation(bytes: version.version.ciphertext, item: item, history: history)
                    let publication = try replacement.permit.withDevice { signer in
                        try preparation.extendingAccess(to: signer.identity, sourceGrantBytes: source.bytes, decryptor: legacy, signer: signer)
                    }
                    let grant = publication.grant
                    let prepared = try PreparedContentGrant(scope: itemScope, keyGeneration: grant.keyGeneration,
                        recipient: grant.recipient, identifier: grant.identifier, bytes: grant.encoded())
                    try await repository.commitDeviceMigrationGrant(prepared, sourceVersion: version,
                        expectedPolicy: policy, authorization: authorization)
                }
            }
        }
    }
}

extension GrantBackedContentSession {
    /// Old-format clients may upload content after this device's first migration
    /// pass. Convert late legacy grants through the existing durable grant work.
    /// This bridge never re-admits a removed identity or serves another account.
    func prepareMigratedGrant(_ operation: SyncOperation, legacy: any DeviceOperations,
                               owner: any RepositoryWritePermit) async throws -> Bool {
        guard operation.kind == .prepareGrant, operation.account == binding.account,
              operation.database == binding.database, operation.zoneOwner == binding.zoneOwner,
              operation.vaultID == binding.vaultID,
              legacy.identity.member == identity.member, legacy.identity != identity,
              WrappedDeviceMigration.canUseLegacySource(legacy.identity, replacement: identity, history: history) else { return false }
        let missing = try JSONDecoder().decode(MissingContentGrant.self, from: operation.payload)
        guard missing.operationID == operation.id, missing.scope == binding.item(missing.scope.itemID),
              missing.recipient == identity.fingerprint,
              let snapshot = try await repository.contentGrantPreparation(missing, sourceRecipient: legacy.identity.fingerprint),
              let source = snapshot.sourceGrant else { return false }
        let content = try ContentEnvelope.decode(snapshot.version.ciphertext, history: history, item: missing.scope.itemID)
        guard (try? history.verifyContentKeyPath(from: content.header.keyMembership)) != nil else { return false }
        let verified = try ContentGrantPreparation(bytes: snapshot.version.ciphertext, item: missing.scope.itemID, history: history)
        guard verified.content.header.version == snapshot.version.versionID,
              verified.content.header.keyGeneration == missing.keyGeneration else { throw MopError.vaultUntrusted }
        let publication = try permit.withDevice {
            try verified.extendingAccess(to: identity, sourceGrantBytes: source.bytes, decryptor: legacy, signer: $0)
        }
        try await GrantBackedContentStorage(repository: repository).commitGrant(publication, scope: missing.scope,
            authorization: ContentWorkPermit(owner: owner, session: permit))
        return true
    }
}
