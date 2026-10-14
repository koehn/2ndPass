import Foundation
import MopCore
import MopSync
import MopVaultNext

/// Persist the exact observations that caused a wait. Readiness is a hint only;
/// the request and all content are verified again by the normal worker.
struct GrantRequestWait: Codable, Equatable {
    let vault: UUID
    let item: UUID
    let version: UUID?
    let membership: String
    let missingVersion: UUID?

    func dependency() throws -> SyncDependency {
        .init(.grantRequestState, identifier: vault.uuidString + ":" + (try JSONEncoder().encode(self)).base64EncodedString())
    }
    init(vault: UUID, item: UUID, version: UUID?, membership: String, missingVersion: UUID? = nil) {
        self.vault = vault; self.item = item; self.version = version; self.membership = membership; self.missingVersion = missingVersion
    }
    init?(dependency: SyncDependency) {
        let parts = dependency.identifier.split(separator: ":", omittingEmptySubsequences: false)
        guard dependency.kind == .grantRequestState, parts.count == 2,
              let data = Data(base64Encoded: String(parts[1])),
              let value = try? JSONDecoder().decode(Self.self, from: data),
              parts[0] == Substring(value.vault.uuidString) else { return nil }
        self = value
    }
    func available(repository: EncryptedItemRepository, scope: ItemScope, history: TrustedMembershipHistory) async throws -> Bool {
        guard scope.vaultID == vault, scope.itemID == item, history.vault == vault else { return false }
        if try history.current.digest() != membership { return true }
        if try await repository.contentState(scope: scope)?.versionID != version { return true }
        if let missingVersion { return try await repository.contentVersion(scope: scope, version: missingVersion) != nil }
        return false
    }
}

struct GrantRequestPrerequisites {
    let repository: EncryptedItemRepository

    /// Caller has strictly verified the signed request, including its recipient.
    func reconcile(request: ContentGrantRequest, scope: ItemScope, history: TrustedMembershipHistory,
                   permit: any RepositoryWritePermit) async throws -> SyncOperationOutcome {
        guard request.item == scope.itemID, scope.vaultID == history.vault, scope.database == "private" else { throw MopError.vaultUntrusted }
        let policy = try GrantBackedContentStorage.recipientPolicy(history: history)
        let state = try await repository.contentState(scope: scope)
        func wait(missingVersion: UUID? = nil) async throws -> SyncOperationOutcome {
            AccessSyncTrace.event("grant request waiting", item: scope.itemID, generation: request.keyGeneration,
                recipient: request.recipient, detail: "reason=\(missingVersion != nil ? "missingAncestor" : state == nil ? "missingHead" : "unprovenGeneration") prerequisite=\(missingVersion.map { AccessSyncTrace.token($0.uuidString) } ?? "-")")
            if let missingVersion {
                let dependency = SyncDependency(.content, identifier: scope.vaultID.uuidString + ":" + scope.itemID.uuidString + ":" + missingVersion.uuidString)
                guard let fetch = ContentVersionFetch(dependency: dependency) else { throw MopError.vaultUntrusted }
                _ = try await repository.enqueuePrerequisite(fetch.operation(account: scope.account, owner: scope.zoneOwner), permit: permit)
            } else {
                // A local head can itself be behind the request. Refresh once
                // per observation, also when the requested generation is unknown.
                let fetch = ContentHeadFetch(vault: scope.vaultID, item: scope.itemID,
                    observedVersion: state?.versionID, membership: try history.current.digest())
                _ = try await repository.enqueuePrerequisite(fetch.operation(account: scope.account, owner: scope.zoneOwner), permit: permit)
            }
            return .waiting([try GrantRequestWait(vault: scope.vaultID, item: scope.itemID, version: state?.versionID,
                membership: history.current.digest(), missingVersion: missingVersion).dependency()])
        }
        guard let state else { return try await wait() }
        if state.keyGeneration == request.keyGeneration {
            if try await repository.reconcileContentGrantRequest(scope: scope, keyGeneration: request.keyGeneration,
                recipient: request.recipient, policy: policy, permit: permit) != nil { return try await wait() }
            return .completed
        }
        guard let stored = try await repository.contentVersion(scope: scope, version: state.versionID) else {
            return try await wait(missingVersion: state.versionID)
        }
        let current = try ContentEnvelope.decode(stored.version.ciphertext, history: history, item: scope.itemID)
        try current.verifyForPublication(history: history)
        var cursor = current
        var ancestors: [ContentEnvelope] = []
        var seen: Set<UUID> = [current.header.version]
        while let base = cursor.header.base {
            guard seen.insert(base).inserted else { throw MopError.vaultUntrusted }
            guard let parent = try await repository.contentVersion(scope: scope, version: base) else {
                return try await wait(missingVersion: base)
            }
            let verified = try ContentEnvelope.decode(parent.version.ciphertext, history: history, item: scope.itemID)
            guard verified.header.version == base, verified.header.generation == cursor.header.generation - 1 else { throw MopError.vaultUntrusted }
            ancestors.append(verified)
            if verified.header.keyGeneration == request.keyGeneration {
                guard try ContentReconciliation.inspect(local: current, remote: verified, ancestors: ancestors, history: history) == .keepLocal else {
                    throw MopError.vaultUntrusted
                }
                // Verify the observed head still owns the state; reconcile current
                // recipient requirements before retiring the superseded request.
                try await repository.reconcileSupersededGrantRequest(scope: scope, expected: state,
                    recipient: request.recipient, policy: policy, permit: permit)
                AccessSyncTrace.event("superseded grant request retired", item: scope.itemID, generation: request.keyGeneration,
                    recipient: request.recipient, detail: "reason=verifiedSuccessor")
                return .completed
            }
            cursor = verified
        }
        // Neither a generation mismatch nor an unknown cloud record proves
        // obsolescence. Retain the request without a hot retry loop.
        AccessSyncTrace.event("grant request awaiting evidence", item: scope.itemID, generation: request.keyGeneration,
            recipient: request.recipient, detail: "reason=noVerifiedSuccessor")
        return try await wait()
    }
}
