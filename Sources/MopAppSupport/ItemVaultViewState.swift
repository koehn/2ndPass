import Foundation
import Observation
import MopCore
import MopSync
import MopVaultNext

/// Observable metadata for one authenticated item-store session. The lifecycle
/// owner must route lock/account/membership changes through lock()/invalidate(),
/// and separately pause/stop its sync adapter. Replace this object after unlock;
/// it never reopens private keys itself. No revealed values are retained here.
@MainActor @Observable public final class ItemVaultViewState {
    public enum Status: Equatable, Sendable { case loading, ready, locked, failed }
    public private(set) var entries: [ItemVaultCatalogEntry] = []
    public private(set) var conflictedItems: Set<UUID> = []
    /// Locally durable items still awaiting publication; absence does not assert
    /// that the entire remote inventory has been fetched.
    public private(set) var pendingItems: Set<UUID> = []
    public private(set) var status: Status = .loading
    public private(set) var failure: String?
    public private(set) var savingItems: Set<UUID> = []
    @ObservationIgnored private let repository: EncryptedItemRepository
    @ObservationIgnored private let session: ItemVaultSession
    @ObservationIgnored private var observation: Task<Void, Never>?
    @ObservationIgnored private var generation: UInt64 = 0
    @ObservationIgnored private var displayedVersions: [UUID: UUID]?
    @ObservationIgnored private var saveCounts: [UUID: Int] = [:]

    public init(repository: EncryptedItemRepository, session: ItemVaultSession) {
        self.repository = repository
        self.session = session
    }

    public func start() {
        guard observation == nil, status != .locked else { return }
        guard session.isUnlocked else { lock(); return }
        generation &+= 1
        let token = generation
        status = .loading; failure = nil
        observation = Task { [weak self, repository] in
            let changes = await repository.changes()
            for await _ in changes {
                guard !Task.isCancelled, let self, self.generation == token else { break }
                await self.refresh(token: token)
            }
        }
    }

    public func lock() {
        session.lock()
        clear(status: .locked)
    }

    public func invalidate() {
        session.invalidate()
        clear(status: .locked)
    }

    /// Completion means the encrypted mutation is durably saved locally. Cloud
    /// delivery is tracked separately by its receipt; no network wait blocks the
    /// editor. Expected versions keep overlapping edits from overwriting changes.
    @discardableResult
    public func edit(itemID: UUID, expectedBase: UUID, catalog: ItemEnvelopeCatalog,
                     changedRecords: [String: SecretBytes] = [:], removedRecords: Set<String> = []) async throws -> PendingItemMutation {
        guard session.isUnlocked, status == .ready else { throw MopError.authentication }
        let token = generation
        saveCounts[itemID, default: 0] += 1
        savingItems.insert(itemID)
        defer {
            if generation == token {
                let remaining = (saveCounts[itemID] ?? 1) - 1
                if remaining == 0 { saveCounts[itemID] = nil; savingItems.remove(itemID) }
                else { saveCounts[itemID] = remaining }
            }
        }
        return try await session.edit(itemID: itemID, expectedBase: expectedBase, catalog: catalog,
            changedRecords: changedRecords, removedRecords: removedRecords)
    }

    private func refresh(token: UInt64) async {
        let binding = session.binding
        do {
            let versions = try await repository.itemRevisionIndex(account: binding.account,
                vaultID: binding.vaultID, database: binding.database, zoneOwner: binding.zoneOwner)
                .filter { $0.key != ItemVaultSession.metadataRecordID }
            let conflicts = try await repository.conflictedItemIDs(account: binding.account,
                vaultID: binding.vaultID, database: binding.database, zoneOwner: binding.zoneOwner)
            let pending = try await repository.pendingScopes(account: binding.account).filter {
                $0.vaultID == binding.vaultID && $0.database == binding.database && $0.zoneOwner == binding.zoneOwner
            }
            guard generation == token, !Task.isCancelled else { return }
            guard session.isUnlocked else { lock(); return }
            if versions != displayedVersions {
                let catalog = try await session.catalog()
                guard generation == token, !Task.isCancelled else { return }
                guard session.isUnlocked else { lock(); return }
                entries = catalog
                displayedVersions = Dictionary(uniqueKeysWithValues: catalog.map { ($0.itemID, $0.versionID) })
            }
            conflictedItems = conflicts.intersection(Set(versions.keys))
            pendingItems = Set(pending.map(\.itemID)).intersection(Set(versions.keys))
            status = .ready
        } catch {
            guard generation == token, !Task.isCancelled else { return }
            if error as? MopError == .authentication { lock(); return }
            session.invalidate()
            clear(status: .failed)
            // Framework diagnostics may contain sensitive paths or data.
            failure = "The vault's local item state could not be loaded and verified."
        }
    }

    private func clear(status: Status) {
        generation &+= 1
        observation?.cancel(); observation = nil
        entries = []; conflictedItems = []; pendingItems = []; displayedVersions = nil
        savingItems = []; saveCounts = [:]
        failure = nil; self.status = status
    }

    deinit { observation?.cancel(); session.lock() }
}
