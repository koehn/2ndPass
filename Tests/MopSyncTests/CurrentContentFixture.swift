import Foundation
import CryptoKit
import Testing
@testable import MopSync

struct CurrentContentPermit: RepositoryWritePermit {
    func withWritePermission<T>(_ body: () throws -> T) throws -> T { try body() }
}

// Storage tests use opaque bytes at the same authenticated boundary as production.
// Crypto verification is covered separately by the content-envelope and inbox tests.
extension EncryptedItemRepository {
    private func fixturePolicy(_ scope: VaultScope) throws -> ContentRecipientPolicy {
        if let existing = try contentRecipients(scope: scope) { return existing }
        let digest = String(repeating: "c", count: 64)
        let policy = ContentRecipientPolicy(membership: digest, recipients: [String(repeating: "a", count: 64)], keyAuthority: digest)
        try setContentRecipients(scope: scope, expected: nil, policy: policy, authorization: CurrentContentPermit())
        return policy
    }
    private func fixturePublication(_ version: EncryptedItemVersion, policy: ContentRecipientPolicy) -> PreparedContentPublication {
        let key = version.scope.itemID
        let content = PreparedContentVersion(version: version, keyGeneration: key, contentRevision: version.versionID,
            membership: policy.membership, keyAuthority: policy.keyAuthority)
        let grants = policy.recipients.map { recipient in
            PreparedContentGrant(scope: version.scope, keyGeneration: key, recipient: recipient,
                identifier: SHA256.hash(data: Data((version.scope.storageKey + recipient).utf8)).map { String(format: "%02x", $0) }.joined(), bytes: Data([1]))
        }
        return PreparedContentPublication(content: content, grants: grants)
    }
    func commitTestContent(_ version: EncryptedItemVersion, authorization: any RepositoryWritePermit = CurrentContentPermit()) throws -> PendingItemMutation {
        let policy = try fixturePolicy(VaultScope(version.scope))
        let publication = fixturePublication(version, policy: policy)
        return try commitContent(publication.content, grants: publication.grants, expectedPolicy: policy, authorization: authorization)
    }
    func initializeTestContent(scope: VaultScope, versions: [EncryptedItemVersion], membershipState: Data, setupID: String,
                               authorization: any RepositoryWritePermit) throws -> VaultInitializationReceipt {
        let digest = String(repeating: "c", count: 64)
        let policy = ContentRecipientPolicy(membership: digest, recipients: [String(repeating: "a", count: 64)], keyAuthority: digest)
        let publications = versions.map { fixturePublication($0, policy: policy) }
        let provision = SyncOperation(account: scope.account, database: scope.database, vaultID: scope.vaultID, zoneOwner: scope.zoneOwner, kind: .provision, payload: Data([1]))
        return try initializeContentVault(scope: scope, publications: publications, policy: policy, membershipState: membershipState,
            setupID: setupID, provision: provision, authorization: authorization)
    }
    private func receiveTestVersion(_ version: EncryptedItemVersion, fields: Data, action: IncomingContentAction) throws {
        let policy = try fixturePolicy(VaultScope(version.scope))
        let content = try contentVersion(scope: version.scope, version: version.versionID) ?? fixturePublication(version, policy: policy).content
        let incoming = IncomingRecord(id: UUID().uuidString, account: version.scope.account, database: version.scope.database,
            zoneName: SyncStoreLayout.contentZone(vault: version.scope.vaultID), zoneOwner: version.scope.zoneOwner,
            recordName: version.scope.itemID.uuidString, recordType: ContentRecordKind.head.rawValue,
            bytes: version.ciphertext, systemFields: fields, vaultID: version.scope.vaultID)
        try stageIncomingBatch([incoming], checkpoint: Data([1]), account: version.scope.account, database: version.scope.database, permit: CurrentContentPermit())
        try receiveContent(content, from: incoming, action: action, expectedHead: item(version.scope)?.versionID,
            expectedPolicy: policy, permit: CurrentContentPermit())
    }
    func installTestContent(_ version: EncryptedItemVersion, serverSystemFields: Data) throws {
        try receiveTestVersion(version, fields: serverSystemFields, action: .install)
    }
    func branchTestContent(remote: EncryptedItemVersion, serverSystemFields: Data) throws -> EncryptedItemConflict {
        try receiveTestVersion(remote, fields: serverSystemFields, action: .branch)
        return try #require(try contentConflicts(account: remote.scope.account).first { $0.remote.versionID == remote.versionID })
    }
    func confirmTestMutation(mutationID: UUID, account: String, serverSystemFields: Data) throws {
        let pending = try #require(try pendingMutations(account: account).first { $0.id == mutationID })
        let head = try item(pending.version.scope)
        try receiveTestVersion(pending.version, fields: serverSystemFields,
            action: head?.versionID == pending.version.versionID ? .duplicate : .keepLocal)
    }
    func chooseRemoteTestContent(_ conflict: EncryptedItemConflict, authorization: any RepositoryWritePermit) throws -> EncryptedItemVersion {
        _ = try resolveContentConflict(conflict, replacement: nil, serverSystemFields: conflict.serverSystemFields,
            policy: fixturePolicy(VaultScope(conflict.local.scope)), permit: authorization)
        return conflict.remote
    }
    func resolveTestContent(_ conflict: EncryptedItemConflict, with version: EncryptedItemVersion,
                            authorization: any RepositoryWritePermit) throws -> PendingItemMutation {
        let policy = try fixturePolicy(VaultScope(version.scope))
        return try #require(try resolveContentConflict(conflict, replacement: fixturePublication(version, policy: policy),
            serverSystemFields: conflict.serverSystemFields, policy: policy, permit: authorization))
    }
}
