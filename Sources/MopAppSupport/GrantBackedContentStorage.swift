import Foundation
import Synchronization
import MopCore
import MopSync
import MopVaultNext

/// The cryptographic boundary for the isolated preview store. History must come
/// from the independent account trust pin. Cloud discovery cannot call this to
/// install trust. Native GUI/CLI/AutoFill sessions share this isolated store.
public struct GrantBackedContentStorage: Sendable {
    private let repository: EncryptedItemRepository
    public init(repository: EncryptedItemRepository) { self.repository = repository }

    private struct DerivedMembership: Sendable {
        let policy: ContentRecipientPolicy
        let authorities: [String: String]
    }
    private static let derived = Mutex<[(UUID, DerivedMembership)]>([])

    public static func recipientPolicy(history: TrustedMembershipHistory) throws -> ContentRecipientPolicy {
        try derivedMembership(history: history).policy
    }

    private static func derivedMembership(history: TrustedMembershipHistory) throws -> DerivedMembership {
        if let cached = derived.withLock({ $0.first { $0.0 == history.cacheIdentity }?.1 }) { return cached }
        let states = history.orderedStates
        guard let first = states.first, history.current.membership.accounts.count == 1 else { throw MopError.vaultUntrusted }
        try history.verifyAccountPath(from: first.digest(), allowingDeviceRemoval: true)
        var authority = try first.digest()
        var authorities = [authority: authority]
        for (parent, successor) in zip(states, states.dropFirst()) {
            do { try history.verifyContentKeyPath(from: parent.digest(), to: successor.digest()) }
            catch { authority = try successor.digest() }
            authorities[try successor.digest()] = authority
        }
        let membership = history.current.membership
        let recipients = membership.devices + [membership.offlineRecovery].compactMap { $0 }
        let result = DerivedMembership(policy: ContentRecipientPolicy(membership: try history.current.digest(),
            recipients: Set(recipients.map(\.fingerprint)), keyAuthority: authority), authorities: authorities)
        derived.withLock { entries in
            if entries.count >= 16 { entries.removeFirst() }
            entries.append((history.cacheIdentity, result))
        }
        return result
    }

    static func keyAuthority(history: TrustedMembershipHistory, at membership: String) throws -> String {
        guard let authority = try derivedMembership(history: history).authorities[membership] else { throw MopError.vaultUntrusted }
        return authority
    }

    public static func validatePublication(_ upload: ContentUpload, history: TrustedMembershipHistory) throws {
        let prepared = upload.content, version = upload.content.version
        guard upload.scope.vaultID == history.vault, upload.scope.database == "private" else { throw MopError.vaultUntrusted }
        let content = try ContentEnvelope.decode(version.ciphertext, history: history, item: version.scope.itemID)
        let header = content.header
        guard header.version == version.versionID, header.base == version.baseVersionID,
              header.generation == version.generation, header.isTombstone == version.isTombstone,
              header.keyGeneration == prepared.keyGeneration, header.contentRevision == prepared.contentRevision,
              header.membership == prepared.membership, prepared.keyAuthority == (try recipientPolicy(history: history)).keyAuthority else {
            throw MopError.vaultUntrusted
        }
        try content.verifyForPublication(history: history)
        try Self.validateKind(content, history: history)
        if let grant = upload.grant {
            let decoded = try ContentKeyGrant.decode(grant.bytes, content: content, history: history)
            guard grant.scope == version.scope, grant.keyGeneration == header.keyGeneration,
                  grant.recipient == decoded.recipient, try grant.identifier == decoded.identifier else { throw MopError.vaultUntrusted }
            try decoded.verifyForPublication(content: content, history: history)
        }
    }

    public func setAuthority(scope: VaultScope, expected: TrustedMembershipHistory?, history: TrustedMembershipHistory,
                             authorization: any RepositoryWritePermit) async throws {
        guard scope.vaultID == history.vault, scope.database == "private" else { throw MopError.vaultUntrusted }
        if let expected {
            guard expected.vault == history.vault,
                  try history.state(forDigest: expected.current.digest()) == expected.current else { throw MopError.vaultUntrusted }
        }
        try await repository.setContentRecipients(scope: scope, expected: expected.map { try Self.recipientPolicy(history: $0) },
            policy: Self.recipientPolicy(history: history), authorization: authorization)
    }

    static func validateKind(_ content: ContentEnvelope, history: TrustedMembershipHistory) throws {
        if content.header.item == ItemVaultSession.metadataRecordID {
            let state = try history.state(forDigest: content.header.membership).membership
            guard !content.header.isTombstone,
                  Set(content.components.keys) == [ContentItemArchive.metadataComponent],
                  state.devices.contains(where: { $0.fingerprint == content.header.author && state.role(of: $0) == .owner }) else { throw MopError.vaultUntrusted }
        }
    }

    public static func prepare(_ publication: MopVaultNext.ContentPublication, scope: ItemScope,
                               history: TrustedMembershipHistory) throws -> PreparedContentPublication {
        let content = publication.content
        guard scope.vaultID == history.vault, scope.itemID == content.header.item, scope.database == "private" else { throw MopError.vaultUntrusted }
        try content.verifyForPublication(history: history)
        try Self.validateKind(content, history: history)
        let policy = try recipientPolicy(history: history)
        let prepared = try PreparedContentVersion(version: EncryptedItemVersion(scope: scope, versionID: content.header.version,
            baseVersionID: content.header.base, ciphertext: content.encoded(), isTombstone: content.header.isTombstone,
            generation: content.header.generation), keyGeneration: content.header.keyGeneration,
            contentRevision: content.header.contentRevision, membership: content.header.membership, keyAuthority: policy.keyAuthority)
        let grants = try publication.grants.map { grant in
            try grant.verifyForPublication(content: content, history: history)
            return try PreparedContentGrant(scope: scope, keyGeneration: grant.keyGeneration,
                recipient: grant.recipient, identifier: grant.identifier, bytes: grant.encoded())
        }
        return PreparedContentPublication(content: prepared, grants: grants)
    }

    public func commit(_ content: ContentEnvelope, grants: [ContentKeyGrant] = [], scope: ItemScope,
                       history: TrustedMembershipHistory, prerequisites: [SyncOperation] = [],
                       authorization: any RepositoryWritePermit) async throws -> PendingItemMutation {
        guard scope.vaultID == history.vault, scope.itemID == content.header.item, scope.database == "private" else { throw MopError.vaultUntrusted }
        try content.verifyForPublication(history: history)
        try Self.validateKind(content, history: history)
        let policy = try Self.recipientPolicy(history: history)
        let prepared = try PreparedContentVersion(version: EncryptedItemVersion(scope: scope, versionID: content.header.version,
            baseVersionID: content.header.base, ciphertext: content.encoded(), isTombstone: content.header.isTombstone,
            generation: content.header.generation), keyGeneration: content.header.keyGeneration,
            contentRevision: content.header.contentRevision, membership: content.header.membership, keyAuthority: policy.keyAuthority)
        let preparedGrants = try grants.map { grant in
            try grant.verifyForPublication(content: content, history: history)
            return try PreparedContentGrant(scope: scope, keyGeneration: grant.keyGeneration,
                recipient: grant.recipient, identifier: grant.identifier, bytes: grant.encoded())
        }
        return try await repository.commitContent(prepared, grants: preparedGrants, expectedPolicy: policy, prerequisites: prerequisites, authorization: authorization)
    }

    public func commitRotation(_ content: ContentEnvelope, grants: [ContentKeyGrant], scope: ItemScope,
                               expectedLocal: UUID, expectedAccepted: UUID?, history: TrustedMembershipHistory,
                               authorization: any RepositoryWritePermit) async throws -> PendingItemMutation {
        guard scope.vaultID == history.vault, scope.itemID == content.header.item else { throw MopError.vaultUntrusted }
        try content.verifyForPublication(history: history)
        try Self.validateKind(content, history: history)
        let policy = try Self.recipientPolicy(history: history)
        let prepared = try PreparedContentVersion(version: EncryptedItemVersion(scope: scope, versionID: content.header.version,
            baseVersionID: content.header.base, ciphertext: content.encoded(), isTombstone: content.header.isTombstone,
            generation: content.header.generation), keyGeneration: content.header.keyGeneration,
            contentRevision: content.header.contentRevision, membership: content.header.membership, keyAuthority: policy.keyAuthority)
        let preparedGrants = try grants.map { grant in
            try grant.verifyForPublication(content: content, history: history)
            return try PreparedContentGrant(scope: scope, keyGeneration: grant.keyGeneration, recipient: grant.recipient,
                identifier: grant.identifier, bytes: grant.encoded())
        }
        return try await repository.commitContentRotation(prepared, grants: preparedGrants, expectedLocal: expectedLocal,
            expectedAccepted: expectedAccepted, expectedPolicy: policy, authorization: authorization)
    }

    public func commitGrant(_ publication: VerifiedContentGrantPublication, scope: ItemScope,
                            authorization: any RepositoryWritePermit) async throws {
        let content = publication.content, grant = publication.grant, history = publication.history
        guard scope.vaultID == history.vault, scope.itemID == content.header.item, scope.database == "private" else { throw MopError.vaultUntrusted }
        let prepared = try PreparedContentGrant(scope: scope, keyGeneration: grant.keyGeneration,
            recipient: grant.recipient, identifier: grant.identifier, bytes: grant.encoded())
        try await repository.commitContentGrant(prepared, expectedPolicy: Self.recipientPolicy(history: history), authorization: authorization)
    }

    public func commitGrant(_ grant: ContentKeyGrant, for content: ContentEnvelope, scope: ItemScope,
                            history: TrustedMembershipHistory, authorization: any RepositoryWritePermit) async throws {
        guard scope.vaultID == history.vault, scope.itemID == content.header.item, scope.database == "private" else { throw MopError.vaultUntrusted }
        try grant.verifyForPublication(content: content, history: history)
        let prepared = try PreparedContentGrant(scope: scope, keyGeneration: grant.keyGeneration,
            recipient: grant.recipient, identifier: grant.identifier, bytes: grant.encoded())
        try await repository.commitContentGrant(prepared, expectedPolicy: Self.recipientPolicy(history: history), authorization: authorization)
    }
}
