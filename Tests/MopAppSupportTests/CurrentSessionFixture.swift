@testable import MopSync
@testable import MopVaultNext
@testable import MopAppSupport

/// Every test session uses the production content/grant storage contract.
func currentTestSession(repository: EncryptedItemRepository, binding: ItemVaultBinding,
                        history: TrustedMembershipHistory, device: any DeviceOperations, isolation: isolated (any Actor)? = #isolation) async throws -> ItemVaultSession {
    try await currentTestSession(repository: repository, binding: binding, history: history, permit: ItemVaultPermit(device: device))
}

func currentTestSession(repository: EncryptedItemRepository, binding: ItemVaultBinding,
                        history: TrustedMembershipHistory, permit: ItemVaultPermit, isolation: isolated (any Actor)? = #isolation) async throws -> ItemVaultSession {
    let scope = VaultScope(account: binding.account, vaultID: binding.vaultID, database: binding.database, zoneOwner: binding.zoneOwner)
    if try await repository.contentRecipients(scope: scope) == nil {
        try await repository.setContentRecipients(scope: scope, expected: nil,
            policy: GrantBackedContentStorage.recipientPolicy(history: history), authorization: DomainAccountAuthorization())
    }
    return try ItemVaultSession(repository: repository, binding: binding, history: history, permit: permit)
}

import Foundation
import Testing

func confirmCurrentMutation(_ mutation: PendingItemMutation, repository: EncryptedItemRepository) async throws {
    let scope = mutation.version.scope
    let content = try #require(try await repository.contentVersion(scope: scope, version: mutation.version.versionID))
    let policy = try #require(try await repository.contentRecipients(scope: VaultScope(scope)))
    let incoming = IncomingRecord(id: UUID().uuidString, account: scope.account, database: scope.database,
        zoneName: SyncStoreLayout.contentZone(vault: scope.vaultID), zoneOwner: scope.zoneOwner,
        recordName: scope.itemID.uuidString, recordType: ContentRecordKind.head.rawValue,
        bytes: mutation.version.ciphertext, systemFields: Data([1]), vaultID: scope.vaultID)
    try await repository.stageIncomingBatch([incoming], checkpoint: Data([1]), account: scope.account, database: scope.database, permit: DomainAccountAuthorization())
    let head = try await repository.item(scope)
    try await repository.receiveContent(content, from: incoming,
        action: head?.versionID == mutation.version.versionID ? .duplicate : .keepLocal,
        expectedHead: head?.versionID, expectedPolicy: policy, permit: DomainAccountAuthorization())
}

func branchCurrentPublication(_ publication: ContentPublication, repository: EncryptedItemRepository,
                              scope: ItemScope, history: TrustedMembershipHistory, fields: Data) async throws -> EncryptedItemConflict {
    let content = publication.content
    let prepared = try PreparedContentVersion(version: EncryptedItemVersion(scope: scope, versionID: content.header.version,
        baseVersionID: content.header.base, ciphertext: content.encoded(), generation: content.header.generation),
        keyGeneration: content.header.keyGeneration, contentRevision: content.header.contentRevision,
        membership: content.header.membership, keyAuthority: GrantBackedContentStorage.keyAuthority(history: history, at: content.header.keyMembership))
    let policy = try #require(try await repository.contentRecipients(scope: VaultScope(scope)))
    let incoming = IncomingRecord(id: UUID().uuidString, account: scope.account, database: scope.database,
        zoneName: SyncStoreLayout.contentZone(vault: scope.vaultID), zoneOwner: scope.zoneOwner,
        recordName: scope.itemID.uuidString, recordType: ContentRecordKind.head.rawValue,
        bytes: prepared.version.ciphertext, systemFields: fields, vaultID: scope.vaultID)
    try await repository.stageIncomingBatch([incoming], checkpoint: Data([1]), account: scope.account, database: scope.database, permit: DomainAccountAuthorization())
    try await repository.receiveContent(prepared, from: incoming, action: .branch, expectedHead: repository.item(scope)?.versionID,
        expectedPolicy: policy, permit: DomainAccountAuthorization())
    for grant in publication.grants {
        let preparedGrant = try PreparedContentGrant(scope: scope, keyGeneration: grant.keyGeneration,
            recipient: grant.recipient, identifier: grant.identifier, bytes: grant.encoded())
        let record = try ContentRecordTransport.grant(preparedGrant)
        let grantIncoming = try ContentRecordTransport.materialize(record, account: scope.account)
        try await repository.stageIncomingBatch([grantIncoming], checkpoint: Data([1]), account: scope.account, database: scope.database, permit: DomainAccountAuthorization())
        try await repository.receiveContentGrant(preparedGrant, from: grantIncoming, expectedPolicy: policy, permit: DomainAccountAuthorization())
    }
    return try #require(try await repository.contentConflicts(account: scope.account).first { $0.remote.versionID == content.header.version })
}

func currentPublication(_ version: EncryptedItemVersion, repository: EncryptedItemRepository, history: TrustedMembershipHistory) async throws -> ContentPublication {
    let content = try ContentEnvelope.decode(version.ciphertext, history: history, item: version.scope.itemID)
    let grants = try await repository.contentGrants(scope: version.scope, keyGeneration: content.header.keyGeneration)
    return try ContentPublication(content: content, grants: grants.map { try ContentKeyGrant.decode($0.bytes, content: content, history: history) })
}

func transferCurrentVersion(_ version: EncryptedItemVersion, from source: EncryptedItemRepository,
                            to destination: EncryptedItemRepository) async throws {
    let scope = version.scope
    let prepared = try #require(try await source.contentVersion(scope: scope, version: version.versionID))
    let policy = try #require(try await destination.contentRecipients(scope: VaultScope(scope)))
    let incoming = IncomingRecord(id: UUID().uuidString, account: scope.account, database: scope.database,
        zoneName: SyncStoreLayout.contentZone(vault: scope.vaultID), zoneOwner: scope.zoneOwner,
        recordName: scope.itemID.uuidString, recordType: ContentRecordKind.head.rawValue,
        bytes: version.ciphertext, systemFields: Data([1]), vaultID: scope.vaultID)
    try await destination.stageIncomingBatch([incoming], checkpoint: Data([1]), account: scope.account, database: scope.database, permit: DomainAccountAuthorization())
    try await destination.receiveContent(prepared, from: incoming, action: .install, expectedHead: destination.item(scope)?.versionID,
        expectedPolicy: policy, permit: DomainAccountAuthorization())
    for grant in try await source.contentGrants(scope: scope, keyGeneration: prepared.keyGeneration) {
        let record = try ContentRecordTransport.grant(grant)
        let grantIncoming = try ContentRecordTransport.materialize(record, account: scope.account)
        try await destination.stageIncomingBatch([grantIncoming], checkpoint: Data([1]), account: scope.account, database: scope.database, permit: DomainAccountAuthorization())
        try await destination.receiveContentGrant(grant, from: grantIncoming, expectedPolicy: policy, permit: DomainAccountAuthorization())
    }
}
