import Foundation
import MopCore
import MopSync
import MopVaultNext

/// The closure runs inside the owning authorized session; it must obtain grants
/// and use that session's key provider. Its permit is checked again at commit.
public struct ContentComparisonSession: Sendable {
    public let authorization: any RepositoryWritePermit
    public let identical: @Sendable (ContentEnvelope, ContentEnvelope) async throws -> Bool
    public let rebase: (@Sendable (ContentEnvelope, ContentEnvelope, [ContentEnvelope]) async throws -> PreparedContentVersion?)?
    public init(authorization: any RepositoryWritePermit,
                identical: @escaping @Sendable (ContentEnvelope, ContentEnvelope) async throws -> Bool,
                rebase: (@Sendable (ContentEnvelope, ContentEnvelope, [ContentEnvelope]) async throws -> PreparedContentVersion?)? = nil) {
        self.authorization = authorization; self.identical = identical; self.rebase = rebase
    }
}
private struct ContentInboxCommitPermit: RepositoryWritePermit {
    let publication: any RepositoryWritePermit
    let authorization: any RepositoryWritePermit
    func withWritePermission<T>(_ body: () throws -> T) throws -> T {
        try publication.withWritePermission { try authorization.withWritePermission(body) }
    }
}

/// Public verification and inbox application require no secret key access.
/// The caller owns the account lease; its public-only permit must invalidate on
/// retirement. It must not nest the unlock permit: comparison combines the two.
/// Differing concurrent content waits for the authorized comparison session.
public struct GrantBackedContentInbox: Sendable {
    private let repository: EncryptedItemRepository
    private let account: String
    private let zoneOwner: String
    public init(repository: EncryptedItemRepository, account: String, zoneOwner: String = "__defaultOwner__") {
        self.repository = repository; self.account = account; self.zoneOwner = zoneOwner
    }
    private enum Failure: Error { case invalid; case missing(Set<SyncDependency>) }
    private func authenticate<T>(_ body: () throws -> T) throws -> T {
        do { return try body() } catch { throw Failure.invalid }
    }
    private func requireMembership(_ digests: [String], history: TrustedMembershipHistory) throws {
        for digest in digests {
            guard digest.utf8.count == 64, digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw Failure.invalid }
            if (try? history.state(forDigest: digest)) == nil {
                throw Failure.missing([SyncDependency(.membership, identifier: history.vault.uuidString + ":" + digest)])
            }
        }
    }
    private func contentDependency(_ scope: ItemScope, _ identity: String, kind: SyncDependency.Kind = .content) -> SyncDependency {
        SyncDependency(kind, identifier: scope.vaultID.uuidString + ":" + scope.itemID.uuidString + ":" + identity)
    }

    /// Plug into the existing account coordinator's applyIncoming handler. This
    /// does not create a second engine, lease, observer or independent retry loop.
    public func handle(_ operation: SyncOperation, history: TrustedMembershipHistory,
                       permit: any RepositoryWritePermit, comparison: ContentComparisonSession? = nil) async -> SyncOperationOutcome {
        guard operation.kind == .applyIncoming, operation.account == account, operation.database == "private",
              operation.vaultID == history.vault, operation.zoneOwner == zoneOwner,
              let id = String(data: operation.payload, encoding: .utf8) else { return .attention(.invalidAuthority) }
        do { return try await process(id: id, history: history, permit: permit, comparison: comparison) }
        catch SyncJournalError.staleOperation { return .retry(.dependency) }
        catch ItemRepositoryError.staleLocalVersion { return .retry(.dependency) }
        catch ContentStoreError.staleAuthority { return .retry(.dependency) }
        catch ContentStoreError.invalidRecord { return .attention(.invalidAuthority) }
        catch ItemRepositoryError.unresolvedConflict { return .attention(.conflict) }
        catch MopError.authentication { return .authorization }
        catch CloudSyncAdapterError.membershipUnavailable { return .retry(.dependency) }
        catch MopError.vaultUntrusted { return .attention(.invalidAuthority) }
        catch CloudSyncAdapterError.operationInterrupted { return .retry(.authorization) }
        catch { return .retry(.storagePressure) }
    }

    public func dependencyAvailable(_ dependency: SyncDependency, history: TrustedMembershipHistory) async throws -> Bool {
        let parts = dependency.identifier.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.first == Substring(history.vault.uuidString) else { return false }
        if dependency.kind == .membership, parts.count == 2 {
            return (try? history.state(forDigest: String(parts[1]))) != nil
        }
        if [.content, .contentKeyGeneration, .contentKeyState].contains(dependency.kind), parts.count == 3,
           let item = UUID(uuidString: String(parts[1])), let identity = UUID(uuidString: String(parts[2])) {
            let scope = ItemScope(account: account, vaultID: history.vault, itemID: item, zoneOwner: zoneOwner)
            if dependency.kind == .contentKeyState { return try await repository.contentKeyStateAvailable(scope: scope, keyGeneration: identity) }
            if dependency.kind == .content { return try await repository.contentVersion(scope: scope, version: identity) != nil }
            return try await repository.contentVersion(scope: scope, keyGeneration: identity) != nil
        }
        return false
    }

    public func process(id: String, history: TrustedMembershipHistory, permit: any RepositoryWritePermit, comparison: ContentComparisonSession? = nil) async throws -> SyncOperationOutcome {
        try permit.withWritePermission {}
        guard let incoming = try await repository.incomingRecord(id: id, account: account, database: "private") else { return .completed }
        do {
            let address = try authenticate { try ContentRecordAddress(recordType: incoming.recordType, zone: incoming.zoneName, record: incoming.recordName) }
            guard address.vault == history.vault, incoming.vaultID == history.vault, incoming.zoneOwner == zoneOwner else { throw Failure.invalid }
            let scope = ItemScope(account: account, vaultID: address.vault, itemID: address.item, database: "private", zoneOwner: incoming.zoneOwner)
            let vault = VaultScope(account: account, vaultID: scope.vaultID, zoneOwner: scope.zoneOwner)
            let policy = try authenticate { try GrantBackedContentStorage.recipientPolicy(history: history) }
            guard try await repository.contentRecipients(scope: vault) == policy else { throw ContentStoreError.staleAuthority }
            if address.kind == .grant {
                let grant = try authenticate { try JSONDecoder().decode(ContentKeyGrant.self, from: incoming.bytes) }
                try requireMembership([grant.membership], history: history)
                try authenticate {
                    guard grant.item == scope.itemID, try grant.identifier == address.identity,
                          try grant.encoded() == incoming.bytes else { throw MopError.vaultUntrusted }
                    try grant.verifySignature(history: history)
                }
                guard let stored = try await repository.contentVersion(scope: scope, keyGeneration: grant.keyGeneration) else {
                    throw Failure.missing([contentDependency(scope, grant.sourceVersion.uuidString)])
                }
                let content = try ContentEnvelope.decode(stored.version.ciphertext, history: history, item: scope.itemID)
                try authenticate { try grant.verify(content: content, history: history) }
                let prepared = try PreparedContentGrant(scope: scope, keyGeneration: grant.keyGeneration,
                    recipient: grant.recipient, identifier: grant.identifier, bytes: incoming.bytes)
                try await repository.receiveContentGrant(prepared, from: incoming, expectedPolicy: policy, permit: permit)
                AccessSyncTrace.event("grant applied", item: scope.itemID, generation: grant.keyGeneration,
                    recipient: grant.recipient, record: incoming.recordName)
                return .completed
            }
            let parsed = try authenticate { try JSONDecoder().decode(ContentEnvelope.self, from: incoming.bytes) }
            try requireMembership([parsed.header.membership, parsed.header.keyMembership], history: history)
            let content = try authenticate { try ContentEnvelope.decode(incoming.bytes, history: history, item: scope.itemID) }
            try authenticate { try GrantBackedContentStorage.validateKind(content, history: history) }
            if address.kind == .version, address.identity != content.header.version.uuidString { throw Failure.invalid }
            let prepared = try PreparedContentVersion(version: EncryptedItemVersion(scope: scope, versionID: content.header.version,
                baseVersionID: content.header.base, ciphertext: incoming.bytes, isTombstone: content.header.isTombstone, generation: content.header.generation),
                keyGeneration: content.header.keyGeneration, contentRevision: content.header.contentRevision, membership: content.header.membership,
                keyAuthority: GrantBackedContentStorage.keyAuthority(history: history, at: content.header.keyMembership))
            if address.kind == .version {
                try await repository.receiveContent(prepared, from: incoming, action: .archive, expectedHead: nil, expectedPolicy: policy, permit: permit)
                return .completed
            }
            try await repository.archiveIncomingContent(prepared, from: incoming, expectedPolicy: policy, permit: permit)
            guard let local = try await repository.item(scope) else {
                try await repository.receiveContent(prepared, from: incoming, action: .install, expectedHead: nil, expectedPolicy: policy, permit: permit)
                return .completed
            }
            let localContent = try ContentEnvelope.decode(local.ciphertext, history: history, item: scope.itemID)
            let ancestors = try await ancestry(local: localContent, remote: content, scope: scope, history: history)
            let decision = try authenticate { try ContentReconciliation.inspect(local: localContent, remote: content, ancestors: ancestors, history: history) }
            let publishable = (try? content.verifyForPublication(history: history)) != nil
            let action: EncryptedItemRepository.IncomingContentAction
            var commitPermit: any RepositoryWritePermit = permit
            switch decision {
            case .acknowledgeDuplicate: action = .duplicate
            case .keepLocal: action = .keepLocal
            case .acceptRemote: action = publishable ? .supersede : .branch
            case .preserveBranches: action = .branch
            case .compareContents:
                guard let comparison else {
                    AccessSyncTrace.event("incoming authorization blocked", item: scope.itemID,
                        record: incoming.recordName, detail: "reason=comparisonSessionUnavailable")
                    try await repository.deferIncoming(incoming, dependencies: [SyncDependency(.authorization, identifier: scope.vaultID.uuidString)], failure: .authorization, permit: permit)
                    return .authorization
                }
                try comparison.authorization.withWritePermission {}
                let identical = try await comparison.identical(localContent, content)
                commitPermit = ContentInboxCommitPermit(publication: permit, authorization: comparison.authorization)
                if !identical, publishable, let rebase = comparison.rebase,
                   let rebased = try await rebase(localContent, content, ancestors) {
                    let verified = try ContentEnvelope.decode(rebased.version.ciphertext, history: history, item: scope.itemID)
                    try verified.verifyForPublication(history: history)
                    guard rebased.version.scope == scope, verified.header.base == content.header.version,
                          verified.header.keyGeneration == content.header.keyGeneration,
                          verified.header.contentRevision == localContent.header.contentRevision,
                          verified.header.version == rebased.version.versionID,
                          verified.header.generation == rebased.version.generation,
                          verified.header.isTombstone == rebased.version.isTombstone,
                          verified.header.membership == rebased.membership,
                          verified.header.keyGeneration == rebased.keyGeneration,
                          verified.header.contentRevision == rebased.contentRevision else { throw ContentStoreError.invalidRecord }
                    try await repository.receiveRebasedContent(rebased, remote: prepared, from: incoming,
                        expectedHead: local.versionID, expectedPolicy: policy, permit: commitPermit)
                    return .completed
                }
                action = identical && publishable ? .supersede : .branch
            case .acceptRemoteSupersedingLocal: throw Failure.invalid // inspection never decrypts
            }
            try await repository.receiveContent(prepared, from: incoming, action: action, expectedHead: local.versionID, expectedPolicy: policy, permit: commitPermit)
            return action == .branch ? .attention(.conflict) : .completed
        } catch Failure.missing(let dependencies) {
            try await repository.deferContentIncoming(incoming, dependencies: dependencies, permit: permit)
            return .waiting(dependencies)
        } catch Failure.invalid {
            try await repository.quarantineIncoming(incoming, permit: permit)
            return .attention(.invalidAuthority)
        } catch ContentStoreError.identityCollision {
            try await repository.quarantineIncoming(incoming, permit: permit)
            return .attention(.invalidAuthority)
        }
    }

    /// Walk only the two relevant chains, fetching archived parents by identity.
    /// A missing notification produces a fetchable dependency, never a winner.
    private func ancestry(local: ContentEnvelope, remote: ContentEnvelope, scope: ItemScope,
                          history: TrustedMembershipHistory) async throws -> [ContentEnvelope] {
        var left = local, right = remote, result: [ContentEnvelope] = []
        while left.header.version != right.header.version {
            let advanceLeft = left.header.generation >= right.header.generation
            let cursor = advanceLeft ? left : right
            guard let predecessor = cursor.header.base else { break }
            guard let stored = try await repository.contentVersion(scope: scope, version: predecessor) else {
                throw Failure.missing([contentDependency(scope, predecessor.uuidString)])
            }
            let parent = try ContentEnvelope.decode(stored.version.ciphertext, history: history, item: scope.itemID)
            guard parent.header.generation == cursor.header.generation - 1 else { throw Failure.invalid }
            result.append(parent)
            if advanceLeft { left = parent } else { right = parent }
        }
        return result
    }
}
