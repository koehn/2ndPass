import Foundation
import MopCore
import MopVault

public final class CloudSecretStore: AsyncSecretStore {
    public let vault: CloudVault
    private let session: VaultSession
    private let offline: Bool
    public var name: String { session.name }
    public var snapshot: Data { session.snapshot }

    public init(vault: CloudVault, snapshot: Data, opener: any VaultKeyOpener, offline: Bool = false,
                onClose: @escaping () -> Void = {}) throws {
        self.vault = vault; self.offline = offline
        session = try vault.authenticatedSession(snapshot: snapshot, opener: opener, offline: offline, onClose: onClose)
    }
    public func read(_ reference: SecretReference) throws -> SecretBytes { try session.read(reference) }
    public func list(vault: String?) throws -> [SecretReference] { try session.list(vault: vault) }
    public func catalog() throws -> ItemCatalog { try session.catalog() }
    public func saveItem(_ edit: ItemEdit) async throws { try await mutate { try session.saveItem(edit) } }
    public func recentlyDeleted(at date: Date) throws -> ItemCatalog { try session.recentlyDeleted(at: date) }
    public func trashItem(name: String, revision: String, at date: Date) async throws {
        try await mutate { try session.trashItem(name: name, revision: revision, at: date) }
    }
    public func restoreItem(id: UUID, revision: String, at date: Date) async throws {
        try await mutate { try session.restoreItem(id: id, revision: revision, at: date) }
    }
    public func purgeExpiredItems(at date: Date) async throws {
        // Avoid publishing a new revision when there is nothing to remove.
        let all = try session.recentlyDeleted(at: .distantPast).items
        guard all.contains(where: { $0.deletion?.isExpired(at: date) == true }) else { return }
        try await mutate { _ = try session.purgeExpiredItems(at: date) }
    }
    public var membership: VaultMembership? { session.membership }
    public func adoptOwner(_ owner: AccountIdentity, beforePublish: (() throws -> Void)? = nil) async throws {
        if session.membership?.owner == owner.identity {
            try session.adoptOwner(owner)
            return
        }
        try await mutate(rotation: true, beforePublish: beforePublish) { try session.adoptOwner(owner) }
    }
    public func fingerprint() throws -> String { try session.fingerprint() }

    private func mutate(rotation: Bool = false, beforePublish: (() throws -> Void)? = nil, _ body: () throws -> Void) async throws {
        guard !offline else { throw MopError.offlineWrite }
        let expected = session.snapshot
        do {
            try body()
            try await vault.commit(expected: expected, replacement: session.snapshot,
                                   rotationFingerprint: rotation ? session.fingerprint() : nil, beforePublish: beforePublish)
            try vault.finishCommittedSession(session, rotation: rotation)
        } catch { close(); throw error }
    }
    public func write(_ reference: SecretReference, value: SecretBytes, replace: Bool) async throws {
        try await mutate { try session.write(reference, value: value, replace: replace) }
    }
    public func delete(_ reference: SecretReference) async throws { try await mutate { try session.delete(reference) } }
    public func rename(_ name: String) async throws { try await mutate { try session.rename(name) } }
    public func restore(_ revision: String) async throws {
        guard !offline else { throw MopError.offlineWrite }
        guard try await vault.revisions().contains(revision) else { throw MopError.invalidVault }
        let bytes = try await vault.revision(revision)
        try await mutate { try session.restore(bytes) }
    }
    public func close() { session.close() }
    deinit { close() }
}

