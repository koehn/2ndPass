import Foundation
import CryptoKit
import MopAuth
import MopCore
import MopSync
import MopVaultNext

struct ContentWorkPermit: RepositoryWritePermit {
    let owner: any RepositoryWritePermit
    let session: any RepositoryWritePermit
    func withWritePermission<T>(_ body: () throws -> T) throws -> T {
        try owner.withWritePermission { try session.withWritePermission(body) }
    }
}

/// An authorized session for grant-backed content, including metadata components.
/// The provider is exclusively owned by the session; synchronous lock closes it
/// before returning. Independently pinned history is immutable for this session.
public final class GrantBackedContentSession: @unchecked Sendable {
    public let binding: ItemVaultBinding
    public let history: TrustedMembershipHistory
    let repository: EncryptedItemRepository
    private let storage: GrantBackedContentStorage
    let permit: ItemVaultPermit
    let identity: DevicePublicKey

    public convenience init(repository: EncryptedItemRepository, binding: ItemVaultBinding,
                history: TrustedMembershipHistory, device: any DeviceOperations) throws {
        try self.init(repository: repository, binding: binding, history: history, permit: ItemVaultPermit(device: device))
    }

    init(repository: EncryptedItemRepository, binding: ItemVaultBinding,
         history: TrustedMembershipHistory, permit: ItemVaultPermit) throws {
        let identity = try permit.withDevice { $0.identity }
        guard binding.database == "private", binding.vaultID == history.vault,
              history.current.membership.role(of: identity) != nil else { throw MopError.notVaultMember }
        self.repository = repository; self.binding = binding; self.history = history
        self.storage = GrantBackedContentStorage(repository: repository)
        self.identity = identity; self.permit = permit
    }
    public func lock() { permit.invalidate() }
    deinit { permit.invalidate() }

    public func create(item: UUID, components: [String: SecretBytes], prerequisites: [SyncOperation] = []) async throws -> PendingItemMutation {
        let publication = try permit.withDevice { try ContentEnvelope.seal(components, vault: binding.vaultID, item: item, history: history, signer: $0) }
        return try await storage.commit(publication.content, grants: publication.grants, scope: binding.item(item),
            history: history, prerequisites: prerequisites, authorization: permit)
    }

    public func edit(item: UUID, expected: UUID, components: [String: SecretBytes]) async throws -> PendingItemMutation {
        let (content, grant) = try await readable(item: item, expected: expected)
        let edited = try permit.withDevice { try content.editing(components, grant: grant, history: history, device: $0) }
        return try await storage.commit(edited, scope: binding.item(item), history: history, authorization: permit)
    }

    public func delete(item: UUID, expected: UUID) async throws -> PendingItemMutation {
        let (content, grant) = try await readable(item: item, expected: expected)
        let deleted = try permit.withDevice { try content.deleting(grant: grant, history: history, device: $0) }
        return try await storage.commit(deleted, scope: binding.item(item), history: history, authorization: permit)
    }

    public func open(item: UUID, component: String, expected: UUID) async throws -> SecretBytes {
        let (content, grant) = try await readable(item: item, expected: expected)
        return try permit.withDevice { try content.open(component: component, grant: grant, history: history, device: $0) }
    }

    func readable(item: UUID, expected: UUID) async throws -> (ContentEnvelope, ContentKeyGrant) {
        try permit.check()
        guard let stored = try await repository.item(binding.item(item)), stored.versionID == expected else {
            throw ItemRepositoryError.staleLocalVersion
        }
        return try await readable(stored: stored, item: item)
    }

    func readable(stored: EncryptedItemVersion, item: UUID) async throws -> (ContentEnvelope, ContentKeyGrant) {
        try permit.check()
        let content = try ContentEnvelope.decode(stored.ciphertext, history: history, item: item)
        guard content.header.version == stored.versionID, content.header.base == stored.baseVersionID,
              content.header.generation == stored.generation, content.header.isTombstone == stored.isTombstone,
              stored.healthItemID == nil else { throw MopError.vaultUntrusted }
        try GrantBackedContentStorage.validateKind(content, history: history)
        return try await (content, grant(for: content))
    }

    func grant(for content: ContentEnvelope) async throws -> ContentKeyGrant {
        let grants = try await repository.contentGrants(scope: binding.item(content.header.item), keyGeneration: content.header.keyGeneration, recipient: identity.fingerprint)
        for prepared in grants where prepared.recipient == identity.fingerprint {
            return try ContentKeyGrant.decode(prepared.bytes, content: content, history: history)
        }
        throw CloudSyncAdapterError.membershipUnavailable
    }

    /// Passed only the public account/lease permit. The session adds its own
    /// secret-key gate and checks it again at the final durable commit.
    public func handle(_ operation: SyncOperation, owner: any RepositoryWritePermit, recovery: (any DeviceOperations)? = nil, grantRequestScope: EnrollmentScope? = nil) async -> SyncOperationOutcome {
        guard operation.account == binding.account, operation.database == binding.database,
              operation.vaultID == binding.vaultID, operation.zoneOwner == binding.zoneOwner else { return .attention(.invalidAuthority) }
        do {
            try owner.withWritePermission {}; try permit.check()
            let authorization = ContentWorkPermit(owner: owner, session: permit)
            if operation.kind == .prepareGrant {
                let missing = try JSONDecoder().decode(MissingContentGrant.self, from: operation.payload)
                guard missing.operationID == operation.id, missing.scope == binding.item(missing.scope.itemID) else { return .attention(.invalidAuthority) }
                guard let snapshot = try await repository.contentGrantPreparation(missing, sourceRecipient: identity.fingerprint) else { return .completed }
                guard let existing = snapshot.sourceGrant else {
                    if let grantRequestScope { _ = try await requestOwnGrant(for: operation, scope: grantRequestScope, owner: owner) }
                    return .retry(.dependency)
                }
                let verified = try ContentGrantPreparation(bytes: snapshot.version.ciphertext, item: missing.scope.itemID, history: history)
                guard verified.content.header.version == snapshot.version.versionID,
                      verified.content.header.keyGeneration == missing.keyGeneration else { return .attention(.invalidAuthority) }
                try GrantBackedContentStorage.validateKind(verified.content, history: history)
                guard let recipient = (history.current.membership.devices + [history.current.membership.offlineRecovery].compactMap { $0 }).first(where: { $0.fingerprint == missing.recipient }) else {
                    return .retry(.dependency)
                }
                let prepared = try permit.withDevice {
                    try verified.extendingAccess(to: recipient, sourceGrantBytes: existing.bytes, decryptor: $0, signer: $0)
                }
                try await storage.commitGrant(prepared, scope: missing.scope, authorization: authorization)
                return .completed
            }
            if operation.kind == .rotateContent {
                let scope = try JSONDecoder().decode(ItemScope.self, from: operation.payload)
                guard scope == binding.item(scope.itemID) else { return .attention(.invalidAuthority) }
                guard let state = try await repository.contentState(scope: scope) else { return .completed }
                guard try await repository.contentBranches(scope: scope).isEmpty else { return .attention(.conflict) }
                let policy = try GrantBackedContentStorage.recipientPolicy(history: history)
                guard state.keyAuthority != policy.keyAuthority else { return .completed }
                guard let storedVersion = try await repository.item(scope), storedVersion.versionID == state.versionID else { return .retry(.dependency) }
                let content = try ContentEnvelope.decode(storedVersion.ciphertext, history: history, item: scope.itemID)
                let grant: ContentKeyGrant
                let decryptor: (any DeviceOperations)?
                do { grant = try await self.grant(for: content); decryptor = nil }
                catch CloudSyncAdapterError.membershipUnavailable {
                    guard let recovery, history.current.membership.offlineRecovery == recovery.identity,
                          let source = try await repository.contentGrants(scope: scope, keyGeneration: content.header.keyGeneration)
                            .first(where: { $0.recipient == recovery.identity.fingerprint }) else { return .retry(.dependency) }
                    grant = try ContentKeyGrant.decode(source.bytes, content: content, history: history); decryptor = recovery
                }
                let acceptedVersion = try await repository.acceptedVersion(scope)
                let accepted = try acceptedVersion.map { try ContentEnvelope.decode($0.ciphertext, history: history, item: scope.itemID) }
                var ancestors: [ContentEnvelope] = [], cursor = content
                while cursor.header.version != accepted?.header.version, let base = cursor.header.base {
                    guard let stored = try await repository.contentVersion(scope: scope, version: base) else { return .retry(.dependency) }
                    let parent = try ContentEnvelope.decode(stored.version.ciphertext, history: history, item: scope.itemID)
                    guard parent.header.generation + 1 == cursor.header.generation else { return .attention(.invalidAuthority) }
                    ancestors.append(parent); cursor = parent
                }
                let rotated = try permit.withDevice {
                    try content.rotatingUnpublishedEdits(accepted: accepted, ancestors: ancestors, grant: grant, history: history, device: $0, decryptor: decryptor)
                }
                _ = try await storage.commitRotation(rotated.content, grants: rotated.grants, scope: scope,
                    expectedLocal: state.versionID, expectedAccepted: accepted?.header.version, history: history, authorization: authorization)
                return .completed
            }
            return .attention(.invalidAuthority)
        } catch MopError.authentication { return .authorization }
        catch MopError.cloudPermission { return .authorization }
        catch CloudSyncAdapterError.membershipUnavailable { return .retry(.dependency) }
        catch CloudSyncAdapterError.operationInterrupted { return .retry(.authorization) }
        catch ContentStoreError.staleAuthority { return .retry(.dependency) }
        catch ItemRepositoryError.staleLocalVersion { return .retry(.dependency) }
        catch { return Authentication.requiresRenewal(error) ? .authorization : .attention(.invalidAuthority) }
    }

    /// Additive admission signs only membership and an approval. Existing
    /// content and pending user edits are never rewritten for a new recipient.
    /// The approval's outbox prerequisite is the exact committed membership.
    public func prepareEnrollment(_ request: DeviceEnrollmentRequest, scope: EnrollmentScope,
                                  owner: any RepositoryWritePermit) async throws -> PreparedCoordinationRecord {
        try permit.check(); try owner.withWritePermission {}
        guard request.scope == scope, scope.vault == binding.vaultID, scope.account == binding.account,
              scope.member == identity.member, history.current.membership.role(of: identity) == .owner else { throw MopError.cloudPermission }
        let inbox = GrantBackedCoordinationInbox(repository: repository, container: scope.container,
            environment: scope.environment, account: scope.account, member: scope.member)
        if let existing = try await repository.preparedCoordination(account: binding.account, vault: binding.vaultID,
                kind: .enrollmentApproval, identity: request.id) {
            let value = try inbox.verify(existing, history: history)
            guard try DeviceEnrollmentApproval.decode(value.payload).request == request else { throw MopError.vaultUntrusted }
            return existing
        }
        try request.verify()
        let pendingAuthority = try await repository.operations(account: binding.account, database: binding.database)
        guard !pendingAuthority.contains(where: { $0.kind == .membership && $0.vaultID == binding.vaultID && $0.state != .completed }) else { throw ContentStoreError.staleAuthority }
        let revisions = try await repository.itemRevisionIndex(account: binding.account, vaultID: binding.vaultID,
            database: binding.database, zoneOwner: binding.zoneOwner)
        let count = revisions.keys.filter { $0 != ItemVaultSession.metadataRecordID }.count
        let approval = try permit.withDevice { device in
            if history.current.membership.devices.contains(request.identity) {
                return try DeviceEnrollmentApproval.reconnect(request: request, history: history, owner: device, expectedItemCount: count)
            }
            return try DeviceEnrollmentApproval.create(request: request, history: history, owner: device, expectedItemCount: count)
        }
        let wrapper = try permit.withDevice { try CoordinationEnvelope.sign(kind: .enrollmentApproval, scope: scope,
            identity: request.id, payload: approval.encoded(), history: history, device: $0) }
        let record = try PreparedCoordinationRecord(account: binding.account, zoneOwner: binding.zoneOwner, vault: binding.vaultID,
            kind: .enrollmentApproval, identity: request.id, bytes: wrapper.encoded())
        let prerequisites = approval.isReconnect ? [] : [SyncOperation(account: binding.account, vaultID: binding.vaultID,
            zoneOwner: binding.zoneOwner, kind: .membership, payload: try approval.encoded())]
        let authorization = ContentWorkPermit(owner: owner, session: permit)
        do { _ = try await repository.enqueueCoordination(record, prerequisites: prerequisites, authorization: authorization) }
        catch SyncJournalError.identityCollision {
            // Another process may have prepared this request while encryption
            // ran. Reuse the durable winner after authenticating the exact request.
            guard let existing = try await repository.preparedCoordination(account: binding.account, vault: binding.vaultID,
                    kind: .enrollmentApproval, identity: request.id),
                  try DeviceEnrollmentApproval.decode(inbox.verify(existing, history: history).payload).request == request else { throw MopError.vaultUntrusted }
            return existing
        }
        return record
    }

    public func comparison() -> ContentComparisonSession {
        ContentComparisonSession(authorization: permit, identical: { [self] local, remote in
            let localGrant = try await grant(for: local), remoteGrant = try await grant(for: remote)
            return try permit.withDevice { device in
                guard local.header.isTombstone == remote.header.isTombstone else { return false }
                let left = try local.open(components: Set(local.components.keys), grant: localGrant, history: history, device: device)
                let right = try remote.open(components: Set(remote.components.keys), grant: remoteGrant, history: history, device: device)
                return try ContentItemArchive.identical(left, right, item: local.header.item)
            }
        }, rebase: { [self] local, remote, ancestors in
            guard local.header.keyGeneration != remote.header.keyGeneration,
                  !local.header.isTombstone, !remote.header.isTombstone else { return nil }
            var common: ContentEnvelope?
            for candidate in ancestors.sorted(by: { $0.header.generation > $1.header.generation }) {
                let left = try ContentReconciliation.inspect(local: candidate, remote: local, ancestors: ancestors, history: history)
                let right = try ContentReconciliation.inspect(local: candidate, remote: remote, ancestors: ancestors, history: history)
                if [.acceptRemote, .acknowledgeDuplicate].contains(left), [.acceptRemote, .acknowledgeDuplicate].contains(right) {
                    common = candidate; break
                }
            }
            guard let common else { return nil }
            let localGrant = try await grant(for: local), remoteGrant = try await grant(for: remote), baseGrant = try await grant(for: common)
            // A different server plaintext is a real content conflict. Never
            // treat matching logical revision IDs alone as access-only proof.
            let accessOnly = try permit.withDevice {
                try common.hasIdenticalContents(to: remote, grant: baseGrant, otherGrant: remoteGrant, history: history, device: $0)
            }
            guard accessOnly else { return nil }
            let rebased = try permit.withDevice {
                try local.rebasingEdit(onto: remote, commonBase: common, ancestors: ancestors, grant: localGrant,
                    baseGrant: baseGrant, rotatedGrant: remoteGrant, history: history, device: $0)
            }
            return try PreparedContentVersion(version: EncryptedItemVersion(scope: binding.item(local.header.item),
                versionID: rebased.header.version, baseVersionID: rebased.header.base, ciphertext: rebased.encoded(),
                isTombstone: rebased.header.isTombstone, generation: rebased.header.generation),
                keyGeneration: rebased.header.keyGeneration, contentRevision: rebased.header.contentRevision,
                membership: rebased.header.membership, keyAuthority: GrantBackedContentStorage.recipientPolicy(history: history).keyAuthority)
        })
    }
}

extension GrantBackedContentSession {
    func coordination(kind: CoordinationEnvelope.Kind, scope: EnrollmentScope, identity: UUID, payload: Data,
                      owner: any RepositoryWritePermit) async throws -> PreparedCoordinationRecord {
        guard let recordKind = CoordinationRecordKind(rawValue: kind.rawValue), scope.vault == binding.vaultID,
              scope.account == binding.account else { throw MopError.vaultUntrusted }
        if let existing = try await repository.preparedCoordination(account: binding.account, vault: binding.vaultID, kind: recordKind, identity: identity) {
            let decoded = try CoordinationEnvelope.decode(existing.bytes, scope: scope)
            try decoded.verifyAuthority(history: history)
            guard decoded.payload == payload else { throw MopError.vaultUntrusted }
            return existing
        }
        let envelope = try permit.withDevice { try CoordinationEnvelope.sign(kind: kind, scope: scope, identity: identity,
            payload: payload, history: history, device: $0) }
        let record = try PreparedCoordinationRecord(account: binding.account, vault: binding.vaultID, kind: recordKind,
            identity: identity, bytes: envelope.encoded())
        _ = try await repository.enqueueCoordination(record, authorization: ContentWorkPermit(owner: owner, session: permit))
        return record
    }
}

extension GrantBackedContentSession {
    func prepareMembership(_ membership: Membership, owner: any RepositoryWritePermit) async throws -> SyncOperation {
        let pending = try await repository.operations(account: binding.account, database: binding.database)
        for operation in pending where operation.kind == .membership && operation.vaultID == binding.vaultID && operation.state != .completed {
            if let commit = try? JSONDecoder().decode(ContentMembershipCommit.self, from: operation.payload), commit.successor.membership == membership { return operation }
            throw ContentStoreError.staleAuthority
        }
        let commit = try permit.withDevice { device in
            ContentMembershipCommit(history: history.orderedStates, successor: try MembershipEnvelope.successor(of: history.current, membership: membership, owner: device))
        }
        return try ContentWorkPermit(owner: owner, session: permit).withWritePermission {
            SyncOperation(account: binding.account, vaultID: binding.vaultID, kind: .membership, payload: try setupEncode(commit))
        }
    }

    func prepareRecoveryGrant(_ operation: SyncOperation, recovery: any DeviceOperations, owner: any RepositoryWritePermit) async throws {
        let missing = try JSONDecoder().decode(MissingContentGrant.self, from: operation.payload)
        guard missing.operationID == operation.id, missing.scope == binding.item(missing.scope.itemID),
              history.current.membership.offlineRecovery == recovery.identity else { throw MopError.invalidRecovery }
        guard let snapshot = try await repository.contentGrantPreparation(missing, sourceRecipient: recovery.identity.fingerprint) else { return }
        guard let source = snapshot.sourceGrant,
              let recipient = (history.current.membership.devices + [history.current.membership.offlineRecovery].compactMap { $0 }).first(where: { $0.fingerprint == missing.recipient }) else { throw CloudSyncAdapterError.membershipUnavailable }
        let verified = try ContentGrantPreparation(bytes: snapshot.version.ciphertext, item: missing.scope.itemID, history: history)
        guard verified.content.header.version == snapshot.version.versionID,
              verified.content.header.keyGeneration == missing.keyGeneration else { throw MopError.vaultUntrusted }
        try GrantBackedContentStorage.validateKind(verified.content, history: history)
        let prepared = try permit.withDevice { signer in
            try verified.extendingAccess(to: recipient, sourceGrantBytes: source.bytes, decryptor: recovery, signer: signer)
        }
        try await storage.commitGrant(prepared, scope: missing.scope,
            authorization: ContentWorkPermit(owner: owner, session: permit))
    }
}

extension GrantBackedContentSession {
    func requestOwnGrant(for operation: SyncOperation, scope: EnrollmentScope, owner: any RepositoryWritePermit) async throws -> Bool {
        guard operation.kind == .prepareGrant else { return false }
        let missing = try JSONDecoder().decode(MissingContentGrant.self, from: operation.payload)
        guard missing.scope == binding.item(missing.scope.itemID), let stored = try await repository.item(missing.scope) else { return false }
        let content = try ContentEnvelope.decode(stored.ciphertext, history: history, item: missing.scope.itemID)
        do { _ = try await grant(for: content); return false }
        catch CloudSyncAdapterError.membershipUnavailable { }
        let request = ContentGrantRequest(item: content.header.item, keyGeneration: content.header.keyGeneration, recipient: identity.fingerprint)
        let digest = Array(SHA256.hash(data: try setupEncode(request)).prefix(16))
        let id = UUID(uuid: (digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]))
        if try await repository.preparedCoordination(account: binding.account, vault: binding.vaultID, kind: .grantRequest, identity: id) == nil {
            _ = try await coordination(kind: .grantRequest, scope: scope, identity: id, payload: setupEncode(request), owner: owner)
        }
        return true
    }
}


extension GrantBackedContentSession {
    /// The randomized notice, publication and local intent commit atomically.
    /// Its authenticated history remains available after the item zone is gone.
    func prepareDeletion(scope: EnrollmentScope, owner: any RepositoryWritePermit) async throws {
        let inbox = GrantBackedCoordinationInbox(repository: repository, container: scope.container,
            environment: scope.environment, account: binding.account, member: identity.member)
        guard scope == inbox.scope(vault: binding.vaultID) else { throw MopError.vaultUntrusted }
        let record: PreparedCoordinationRecord
        if let existing = try await repository.preparedCoordination(account: binding.account, vault: binding.vaultID, kind: .deletion, identity: binding.vaultID) {
            _ = try inbox.verify(existing, history: history)
            record = existing
        } else {
            let envelope = try permit.withDevice { device in
                let notice = try VaultDeletionNotice.create(binding: inbox.deletionBinding(vault: binding.vaultID,
                    genesis: history.orderedStates[0].digest()), history: history, owner: device)
                return try CoordinationEnvelope.sign(kind: .deletion, scope: scope, identity: binding.vaultID,
                    payload: notice.encoded(), history: history, device: device)
            }
            record = try PreparedCoordinationRecord(account: binding.account, vault: binding.vaultID,
                kind: .deletion, identity: binding.vaultID, bytes: envelope.encoded())
        }
        _ = try await repository.saveDeletion(scope: VaultScope(account: binding.account, vaultID: binding.vaultID),
            notice: record.bytes, phase: .prepared, publication: record,
            authorization: ContentWorkPermit(owner: owner, session: permit))
    }
}
