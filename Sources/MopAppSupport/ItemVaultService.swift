@preconcurrency import CloudKit
import Foundation
import OSLog
import Synchronization
import MopCore
import MopSync
import MopVaultNext

public protocol ItemVaultServiceBackend: Sendable {
    func inventory() async throws -> [VaultDescriptor]
    func discover() async throws -> ItemVaultDiscovery
    func invalidateDiscovery()
    func enrollment(_ action: VaultManagement, vaultID: UUID) async throws -> VaultResult
    func open(_ vaultID: UUID) async throws -> ItemVaultSession
    func open(_ vaultID: UUID, offline: Bool) async throws -> ItemVaultSession
    func inventory(offline: Bool) async throws -> [VaultDescriptor]
    func create(name: String, id: UUID, archiveData: Data?, recoveryKey: SecretBytes?) async throws -> ItemVaultSession
    func requestSync() async throws
    func conflictAdapter() async throws -> CloudKitSyncAdapter
    func waitForDelivery(_ mutationIDs: [UUID], timeout: Duration) async throws -> Bool
    func creationMutations(_ vaultID: UUID) async throws -> [UUID]
    func lock()
    func changes() async -> AsyncStream<Void>
    func existing(_ vaultID: UUID) async -> ItemVaultSession?
    func resolveVault(named name: String, offline: Bool) async throws -> UUID?
}
public extension ItemVaultServiceBackend {
    func conflictAdapter() async throws -> CloudKitSyncAdapter { throw ItemVaultServiceFailure.unavailable }
    func discover() async throws -> ItemVaultDiscovery { try await ItemVaultDiscovery(vaults: inventory(), complete: true) }
    func invalidateDiscovery() {}
    func enrollment(_ action: VaultManagement, vaultID: UUID) async throws -> VaultResult { throw ItemVaultServiceFailure.unavailable }
    func resolveVault(named name: String, offline: Bool) async throws -> UUID? {
        let matches = try await inventory(offline: offline).filter { $0.name == name }
        guard matches.count <= 1 else { throw ItemVaultServiceFailure.ambiguousVault }
        return matches.first.flatMap { UUID(uuidString: $0.id) }
    }
    func existing(_ vaultID: UUID) async -> ItemVaultSession? { nil }
    func open(_ vaultID: UUID, offline: Bool) async throws -> ItemVaultSession { try await open(vaultID) }
    func inventory(offline: Bool) async throws -> [VaultDescriptor] { try await inventory() }
    func waitForDelivery(_ mutationIDs: [UUID], timeout: Duration) async throws -> Bool { false }
    func creationMutations(_ vaultID: UUID) async throws -> [UUID] { [] }
    func changes() async -> AsyncStream<Void> { AsyncStream { $0.finish() } }
}

public enum ItemVaultServiceFailure: Error, LocalizedError, Equatable {
    case awaitingAdmission, enrollmentExpired, unavailable, ambiguousVault, incompleteCloudBackup, invalidRevision, isolatedStateUnsupported, localStorageUnavailable, synchronizationUnavailable
    public var errorDescription: String? {
        switch self {
        case .awaitingAdmission: "Waiting for encrypted items from another enrolled device. Synchronization will finish in the background."
        case .enrollmentExpired: "This access request expired. Start a new request from the device you are connecting."
        case .localStorageUnavailable: "The local encrypted vault store or device trust is unavailable. Unlock this device and try again."
        case .synchronizationUnavailable: "Synchronization is unavailable. Previously saved local changes remain durable; try sync again when cloud access is restored."
        case .isolatedStateUnsupported: "Cloud vaults use the shared app-group database. A separate state directory is not supported."
        case .unavailable: "This feature is not available in the item-level vault backend yet. No legacy vault was changed."
        case .ambiguousVault: "Choose a vault by UUID; more than one vault has this name."
        case .incompleteCloudBackup: "Only the locally stored inventory is available. A complete cloud backup cannot yet be verified."
        case .invalidRevision: "Reload the item before saving; its edit version is unavailable."
        }
    }
}

/// The app, CLI and AutoFill share this item-level service. Revision tokens carry
/// independent item bases, so saving one item does not conflict with another.
public enum ItemVaultDelivery: Sendable { case local, cloudConfirmed(timeout: Duration) }

public final class ItemVaultService: VaultService, @unchecked Sendable {
    private let backend: any ItemVaultServiceBackend
    private let delivery: ItemVaultDelivery
    private let allowsAttachments: Bool
    private let publisher: (any AutoFillPublishing)?
    private let idleWork: IdleWorkQueue
    private let catalogGate = OperationGate()
    private struct CatalogUpdate: Sendable { let id: UUID; let task: Task<Void, Never> }
    private let catalogUpdates = Mutex<[UUID: CatalogUpdate]>([:])
    private let catalogUpdateFailures = Mutex<[UUID: [UUID: UUID]]>([:])
    private let displayListeners = Mutex<[UUID: AsyncStream<Void>.Continuation]>([:])
    private let state = Mutex<(generation: Int, authenticated: TimeInterval?)>((0, nil))
    private struct CachedCatalog: Sendable {
        let session: ObjectIdentifier
        let versions: [UUID: UUID]
        let catalog: ItemCatalog
        let entries: [UUID: ItemVaultCatalogEntry]
        let waiting: [UUID: UUID]
        let metadata: VaultEnvelopeMetadata
    }
    private let catalogCache = Mutex<[UUID: CachedCatalog]>([:])
    private var accountObserver: NSObjectProtocol?

    public init(backend: any ItemVaultServiceBackend, delivery: ItemVaultDelivery = .local, allowsAttachments: Bool = true,
                publisher: (any AutoFillPublishing)? = nil,
                idleDelay: Duration = .seconds(3), idleSpacing: Duration = .milliseconds(100)) {
        self.backend = backend; self.delivery = delivery; self.allowsAttachments = allowsAttachments; self.publisher = publisher
        self.idleWork = IdleWorkQueue(delay: idleDelay, spacing: idleSpacing)
        accountObserver = NotificationCenter.default.addObserver(forName: .CKAccountChanged, object: nil, queue: nil) { [weak self] _ in self?.lock() }
    }
    public convenience init(state: URL? = nil, allowsAttachments: Bool = true, delivery: ItemVaultDelivery = .local) {
        self.init(backend: NativeItemVaultServiceBackend(state: state), delivery: delivery, allowsAttachments: allowsAttachments,
            publisher: state == nil && Bundle.main.object(forInfoDictionaryKey: "MopPublishesAutoFill") as? Bool == true ? AutoFillPublisher.shared : nil)
    }
    public var capabilities: Set<VaultServiceCapability> { [.portableBackup, .enrollment, .passwordCheckCache] }
    public func userActivity() { idleWork.activity() }
    public func setMaintenanceActive(_ active: Bool) { idleWork.setActive(active) }
    public func invalidateDiscovery() { backend.invalidateDiscovery() }
    public func requestSynchronization() async throws {
        guard authenticatedAt != nil else { return }
        let token = sessionGeneration
        // Do not resolve/open a vault or request biometric authorization here.
        try await backend.requestSync()
        try checked(token)
    }
    public var sessionGeneration: Int { state.withLock { $0.generation } }
    public var authenticatedAt: TimeInterval? { state.withLock { $0.authenticated } }
    public func changes() async -> AsyncStream<Void> {
        let id = UUID(), pair = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        displayListeners.withLock { $0[id] = pair.continuation }
        let backend = self.backend
        let pump = Task {
            for await _ in await backend.changes() {
                guard !Task.isCancelled else { break }
                pair.continuation.yield(())
            }
        }
        pair.continuation.onTermination = { [weak self] _ in
            pump.cancel(); self?.displayListeners.withLock { $0[id] = nil }
        }
        pair.continuation.yield(())
        return pair.stream
    }
    private func displayChanged() { displayListeners.withLock { Array($0.values) }.forEach { $0.yield(()) } }
    public func lock() {
        idleWork.activity()
        state.withLock { value in
            value.generation += 1; value.authenticated = nil
            catalogCache.withLock { $0.removeAll() }
        }
        let loads = catalogUpdates.withLock { values in let current = Array(values.values); values.removeAll(); return current }
        loads.forEach { $0.task.cancel() }
        catalogUpdateFailures.withLock { $0.removeAll() }
        backend.lock()
    }
    deinit {
        if let accountObserver { NotificationCenter.default.removeObserver(accountObserver) }
        catalogUpdates.withLock { $0.values.forEach { $0.task.cancel() } }
        displayListeners.withLock { $0.values.forEach { $0.finish() } }
        backend.lock()
    }
    private func checked(_ token: Int) throws {
        guard sessionGeneration == token else { throw MopError.authentication }
        try Task.checkCancellation()
    }
    private func opened(_ id: UUID, token: Int, offline: Bool) async throws -> ItemVaultSession {
        let opening = authenticatedAt == nil
        let session = try await backend.open(id, offline: offline)
        if opening { idleWork.activity() }
        try checked(token)
        state.withLock { value in if value.generation == token, value.authenticated == nil { value.authenticated = ProcessInfo.processInfo.systemUptime } }
        return session
    }
    public func conflicts(vault: String) async throws -> [ItemVaultConflictPreview] {
        let token = sessionGeneration
        guard let id = UUID(uuidString: vault), let session = await backend.existing(id), session.isUnlocked else { return [] }
        let previews = try await session.conflictPreviews()
        try checked(token)
        return previews
    }

    public func revealConflict(_ preview: ItemVaultConflictPreview, side: ItemVaultConflictSide, path: String) async throws -> SecretBytes {
        let token = sessionGeneration
        guard let session = await backend.existing(preview.conflict.local.scope.vaultID), session.isUnlocked else { throw MopError.authentication }
        let catalog = side == .local ? preview.local : preview.remote
        guard let record = catalog.references[SecretReference.encode(catalog.item.name) + "/" + path] else { throw MopError.notFound }
        let value = try await session.revealConflict(preview.conflict, side: side, recordID: record)
        try checked(token)
        return value
    }

    public func resolve(_ preview: ItemVaultConflictPreview, choice: ItemConflictChoice) async throws {
        let token = sessionGeneration
        guard let session = await backend.existing(preview.conflict.local.scope.vaultID), session.isUnlocked else { throw MopError.authentication }
        let adapter = try await backend.conflictAdapter()
        try checked(token)
        switch choice {
        case .remote:
            _ = try await session.resolveConflictUsingRemote(preview.conflict, coordinator: adapter)
        case .local:
            _ = try await session.resolveConflict(preview.conflict, catalog: preview.local, coordinator: adapter)
        case .combine(let metadata, let fields):
            let patch = try await session.combinedConflict(preview.conflict, metadata: metadata, fields: fields)
            _ = try await session.resolveConflict(preview.conflict, catalog: patch.catalog,
                changedRecords: patch.changedRecords, removedRecords: patch.removedRecords, coordinator: adapter)
        }
        try checked(token)
    }

    public func cachedCatalog(vault: String) async throws -> VaultResult? {
        try CloudVaultBoundary.requireCloud(vault)
        guard authenticatedAt != nil else { return nil }
        let token = sessionGeneration, id = try await select(vault, offline: true, authenticate: false)
        guard let session = await backend.existing(id), session.isUnlocked else { return nil }
        guard let cached = catalogCache.withLock({ $0[id] }), cached.session == ObjectIdentifier(session) else { return nil }
        let index = try await session.revisionIndex()
        try checked(token)
        return try await displayResult(cached, index: index, session: session)
    }
    public func readLocal(_ reference: SecretReference, vault: String?) async throws -> VaultResult {
        try CloudVaultBoundary.requireCloud(vault)
        try CloudVaultBoundary.requireCloud(reference.vault)
        guard authenticatedAt != nil else { throw MopError.authentication }
        let token = sessionGeneration, id = try await select(vault ?? reference.vault, offline: true, authenticate: false)
        guard let session = await backend.existing(id), session.isUnlocked else { throw MopError.authentication }
        let result = try await read(reference, session: session)
        try checked(token)
        return result
    }
    /// Reuse the persistent local projection immediately. Only missing or changed
    /// rows need bounded background preparation; partial views are never AutoFill
    /// inventories or authoritative complete command results.
    public func displayCatalog(vault: String) async throws -> VaultResult {
        try CloudVaultBoundary.requireCloud(vault)
        let token = sessionGeneration, id = try await select(vault, offline: false)
        let session = try await opened(id, token: token, offline: false)
        let index = try await session.revisionIndex()
        if catalogUpdateFailures.withLock({ $0[id] }) == index { throw ItemVaultServiceFailure.localStorageUnavailable }
        catalogUpdateFailures.withLock { $0[id] = nil }
        if catalogUpdates.withLock({ $0[id] != nil }),
           let cached = catalogCache.withLock({ $0[id] }), cached.session == ObjectIdentifier(session) {
            try checked(token)
            return try await displayResult(cached, index: index, session: session)
        }
        if let cached = catalogCache.withLock({ $0[id] }), cached.session == ObjectIdentifier(session), cached.versions == index {
            try checked(token)
            startCatalogUpdater(session, token: token)
            return try await displayResult(cached, index: index, session: session)
        }
        _ = try await catalog(session, limit: 0)
        try checked(token)
        let current = try await session.revisionIndex()
        guard let cached = catalogCache.withLock({ $0[id] }), cached.session == ObjectIdentifier(session) else { throw MopError.authentication }
        let result = try await displayResult(cached, index: current, session: session)
        startCatalogUpdater(session, token: token)
        try checked(token)
        return result
    }

    /// Priority reveal from a displayed storage identity. It cannot trigger a
    /// full-vault name scan or wait for the progressive catalog loader.
    public func readLocal(_ reference: SecretReference, vault: String?, itemID: String?) async throws -> VaultResult {
        guard let itemID else { return try await readLocal(reference, vault: vault) }
        try CloudVaultBoundary.requireCloud(vault); try CloudVaultBoundary.requireCloud(reference.vault)
        guard let item = UUID(uuidString: itemID) else { throw MopError.invalidReference }
        guard authenticatedAt != nil else { throw MopError.authentication }
        let token = sessionGeneration, id = try await select(vault ?? reference.vault, offline: true, authenticate: false)
        guard let session = await backend.existing(id), session.isUnlocked else { throw MopError.authentication }
        let index = try await session.revisionIndex()
        let entry: ItemVaultCatalogEntry
        if let cached = catalogCache.withLock({ $0[id] }), cached.session == ObjectIdentifier(session),
           let existing = cached.entries[item], existing.versionID == index[item] { entry = existing }
        else { entry = try await session.catalog(itemID: item) }
        let result = try await read(reference, entry: entry, session: session)
        try checked(token)
        return result
    }

    private func displaySettled(_ cached: CachedCatalog, index: [UUID: UUID]) -> Bool {
        cached.versions.merging(cached.waiting, uniquingKeysWith: { first, _ in first }) == index
    }
    private func displayResult(_ cached: CachedCatalog, index: [UUID: UUID], session: ItemVaultSession) async throws -> VaultResult {
        var result = VaultResult(); assignCatalog(cached.catalog, to: &result)
        if cached.versions != index {
            result.catalogTotalCount = index.keys.filter { $0 != ItemVaultSession.metadataRecordID }.count
            result.catalogLoadedCount = cached.entries.values.filter { index[$0.itemID] == $0.versionID }.count
            result.catalogWaitingCount = cached.waiting.filter { index[$0.key] == $0.value }.count
        }
        if let expected = try await session.initialDownloadExpectedCount() {
            result.catalogDownloading = true
            result.catalogTotalCount = max(expected, result.catalogTotalCount ?? 0)
            result.catalogLoadedCount = cached.entries.values.filter { index[$0.itemID] == $0.versionID }.count
        }
        return result
    }
    private func startCatalogUpdater(_ session: ItemVaultSession, token: Int) {
        let vault = session.binding.vaultID, identifier = UUID()
        catalogUpdates.withLock { values in
            guard values[vault] == nil else { return }
            let task = Task(priority: .utility) { [weak self] in
                do {
                    var staleRetries = 0
                    while !Task.isCancelled {
                        do {
                            guard let self else { break }
                            let complete = try await self.idleWork.run {
                                try await self.advanceCatalogProjection(session, token: token)
                            }
                            staleRetries = 0
                            if complete { break }
                        } catch ItemRepositoryError.staleLocalVersion where staleRetries < 2 {
                            // An edit during this chunk invalidates its snapshot,
                            // not the vault. Resnapshot at most twice, never spin.
                            staleRetries += 1
                        }
                        await Task.yield()
                    }
                } catch {
                    if !Task.isCancelled, session.isUnlocked, self?.sessionGeneration == token,
                       let index = try? await session.revisionIndex() {
                        if let self {
                            let accepted = self.state.withLock { current in
                                guard current.generation == token, session.isUnlocked, !Task.isCancelled else { return false }
                                self.catalogUpdateFailures.withLock { $0[vault] = index }
                                return true
                            }
                            if accepted { self.displayChanged() }
                        }
                    }
                }
                self?.catalogUpdates.withLock { current in
                    if current[vault]?.id == identifier { current[vault] = nil }
                }
            }
            values[vault] = CatalogUpdate(id: identifier, task: task)
        }
    }
    private func advanceCatalogProjection(_ session: ItemVaultSession, token: Int) async throws -> Bool {
        try checked(token)
        let previous = catalogCache.withLock { $0[session.binding.vaultID] }
        _ = try await catalog(session, limit: 1)
        let index = try await session.revisionIndex()
        try checked(token)
        guard let cached = catalogCache.withLock({ $0[session.binding.vaultID] }), cached.session == ObjectIdentifier(session) else { throw MopError.authentication }
        let complete = cached.versions == index
        let settled = complete || displaySettled(cached, index: index)
        var changed = previous?.versions != cached.versions || previous?.waiting != cached.waiting
        if settled {
            let enriched = try await withHealth(cached.catalog, session: session)
            try checked(token)
            changed = changed || enriched.security != cached.catalog.security
            try state.withLock { state in
                guard state.generation == token, session.isUnlocked else { throw MopError.authentication }
                catalogCache.withLock { values in
                    guard let current = values[session.binding.vaultID], current.session == cached.session,
                          current.versions == cached.versions else { return }
                    values[session.binding.vaultID] = CachedCatalog(session: cached.session, versions: cached.versions,
                        catalog: enriched, entries: cached.entries, waiting: cached.waiting, metadata: cached.metadata)
                }
            }
            let downloading = try await session.initialDownloadExpectedCount() != nil
            _ = await publish(enriched, session: session, token: token, complete: complete && !downloading)
        } else {
            _ = await publish(cached.catalog, session: session, token: token, complete: false)
        }
        if changed { displayChanged() }
        return settled
    }

    public func execute(_ operation: VaultOperation, vault: String?, offline: Bool = false) async throws -> VaultResult {
        try CloudVaultBoundary.requireCloud(vault)
        switch operation {
        case .read(let reference), .write(let reference, _, _), .delete(let reference):
            try CloudVaultBoundary.requireCloud(reference.vault)
        case .create(let name), .rename(let name), .restorePortable(_, _, let name):
            try CloudVaultBoundary.requireCloud(name)
        default: break
        }
        switch operation {
        case .manage(.automaticEnrollment), .manage(.requestEnrollment), .manage(.restartEnrollment), .manage(.checkEnrollment), .manage(.enrollmentInbox), .manage(.approveEnrollment), .manage(.confirmEnrollment), .manage(.cancelEnrollment), .manage(.rejectEnrollment), .manage(.devices): break
        case .discover, .catalog, .recentlyDeleted, .read, .save, .write, .delete, .create, .restorePortable,
             .trashItem, .restoreItem, .rename, .exportPortable, .sync, .readHistory, .restoreHistory, .clearHistory, .passwordQuality, .savePasswordChecks: break
        default: throw ItemVaultServiceFailure.unavailable
        }
        do { return try await executeCore(operation, vault: vault, offline: offline) }
        catch ItemVaultBootstrapFailure.committedButLocked(let receipt) {
            var result = VaultResult()
            result.defaultVault = receipt.scope.vaultID.uuidString; result.mutationIDs = receipt.mutationIDs
            if case .cloudConfirmed = delivery { result.saveStatus = .pending }
            else { result.saveStatus = .local }
            result.message = "Vault saved on this device. Reopen it to finish unlocking and synchronization; do not repeat the import."
            return result
        }
        catch ItemVaultSessionFailure.pendingAdmission { throw ItemVaultServiceFailure.awaitingAdmission }
        catch let error as DeviceEnrollmentFailure {
            if error == .expired { throw ItemVaultServiceFailure.enrollmentExpired }
            throw MopError.vaultUntrusted
        }
        catch let error as ItemRepositoryError {
            switch error {
            case .staleLocalVersion, .staleConflict, .unresolvedConflict, .remoteVersionConflict: throw MopError.vaultConflict
            default: throw ItemVaultServiceFailure.localStorageUnavailable
            }
        } catch is CloudSyncAdapterError { throw ItemVaultServiceFailure.synchronizationUnavailable }
        catch is VaultProvisioningError { throw ItemVaultServiceFailure.synchronizationUnavailable }
        catch is KeychainItemVaultTrustFailure { throw ItemVaultServiceFailure.localStorageUnavailable }
    }
    private func executeCore(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult {
        try CloudVaultBoundary.requireCloud(vault)
        let token = sessionGeneration
        switch operation {
        case .discover:
            var result = VaultResult()
            if offline { result.vaults = try await backend.inventory(offline: true); result.discoveryComplete = false }
            else { let discovery = try await backend.discover(); result.vaults = discovery.vaults; result.discoveryComplete = discovery.complete }
            try checked(token)
            result.defaultVault = result.vaults.count == 1 ? result.vaults.first?.id : nil
            return result
        case .manage(.devices) where vault == nil:
            guard !offline else { throw MopError.offlineWrite }
            var result = VaultResult()
            for descriptor in try await backend.inventory(offline: false) where descriptor.enrolled {
                guard let id = UUID(uuidString: descriptor.id) else { continue }
                let listed = try await backend.enrollment(.devices, vaultID: id)
                result.devices += listed.devices.map { device in
                    var device = device; device.vaultNames[descriptor.id] = descriptor.name ?? descriptor.id; return device
                }
                try checked(token)
            }
            return result
        case .manage(let action):
            guard !offline, let vault, let id = UUID(uuidString: vault) else { throw MopError.vaultMissing }
            let result = try await backend.enrollment(action, vaultID: id)
            try checked(token)
            return result
        case .create(let name), .restorePortable(_, _, let name):
            guard !offline else { throw MopError.offlineWrite }
            try VaultName.validate(name)
            let id: UUID
            if let vault { guard let parsed = UUID(uuidString: vault) else { throw MopError.invalidVault }; id = parsed }
            else { id = UUID() }
            let session: ItemVaultSession
            if case .restorePortable(let data, let key, _) = operation {
                session = try await backend.create(name: name, id: id, archiveData: data, recoveryKey: key)
            } else { session = try await backend.create(name: name, id: id, archiveData: nil, recoveryKey: nil) }
            var result = VaultResult(); result.message = "Vault saved on this device. Cloud synchronization is queued."
            result.defaultVault = id.uuidString
            result.mutationIDs = (try? await backend.creationMutations(id)) ?? []
            result.saveStatus = .local
            await delivered(&result)
            if session.isUnlocked, sessionGeneration == token {
                state.withLock { value in
                    if value.generation == token, value.authenticated == nil { value.authenticated = ProcessInfo.processInfo.systemUptime }
                }
                if let value = try? await catalog(session) { assignCatalog(value, to: &result) }
            }
            startCatalogUpdater(session, token: token)
            result.autoFillStatus = await publisher?.status()
            if sessionGeneration != token || !session.isUnlocked { result.catalog = nil; result.deletedCatalog = nil }
            return result
        default: break
        }
        let referenceVault: String?
        switch operation {
        case .read(let ref), .write(let ref, _, _), .delete(let ref): referenceVault = ref.vault
        default: referenceVault = nil
        }
        let selected = try await select(vault ?? referenceVault, offline: offline)
        let session = try await opened(selected, token: token, offline: offline)
        var result = VaultResult()
        switch operation {
        case .catalog, .recentlyDeleted:
            assignCatalog(try await catalog(session), to: &result)
        case .read(let reference):
            result = try await read(reference, session: session)
        case .passwordQuality(let name):
            let entry = try await entry(named: name, session: session)
            for field in entry.catalog.item.fields where field.type == .password {
                guard let id = entry.catalog.references[SecretReference.encode(name) + "/" + field.path] else { throw MopError.invalidVault }
                let value = try await session.reveal(itemID: entry.itemID, recordID: id, expectedVersion: entry.versionID)
                result.passwordQuality[field.path] = PasswordEstimator.estimate(String(decoding: try value.validatedUTF8(), as: UTF8.self), userInputs: [name])
            }
        case .savePasswordChecks(let checks, let expectedRevision):
            let entries = try await metadataEntries(session)
            guard try revision(entries) == expectedRevision else { throw MopError.vaultConflict }
            let live = Set(entries.filter { !$0.catalog.item.isArchived && $0.catalog.item.deletion == nil }.flatMap { entry in
                entry.catalog.item.fields.filter { $0.type == .password || ($0.path == entry.catalog.item.autoFill?.password && [.concealed, .text, .username, .email].contains($0.type)) }
                    .compactMap { entry.catalog.references[SecretReference.encode(entry.catalog.item.name) + "/" + $0.path] }
            })
            guard Set(checks.map(\.record)).count == checks.count, checks.allSatisfy({ live.contains($0.record) }) else { throw MopError.vaultConflict }
            for check in checks { try check.validate() }
            var mutations: [UUID] = []
            let storedChecks = Dictionary(uniqueKeysWithValues: try await session.healthChecks().map { ($0.record, $0) })
            for entry in entries {
                let ids = Set(entry.catalog.references.values)
                let subset = checks.filter { ids.contains($0.record) }
                if !subset.isEmpty && subset.allSatisfy({ storedChecks[$0.record] == $0 }) { continue }
                if let mutation = try await session.saveHealthChecks(subset, itemID: entry.itemID, expectedItemVersion: entry.versionID) {
                    mutations.append(mutation.id)
                }
            }
            if !mutations.isEmpty { return await saved(session, token: token, mutations: mutations) }
            assignCatalog(try await catalog(session), to: &result)
        case .save(let edit):
            let mutation = try await save(edit, session: session); return await saved(session, token: token, mutations: [mutation])
        case .write(let reference, let value, let replace):
            let mutation: UUID
            let entries = try await metadataEntries(session)
            let path = [reference.section, reference.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
            let matching = entries.filter { $0.catalog.item.name == reference.item && $0.catalog.item.deletion == nil }
            guard matching.count <= 1 else { throw MopError.duplicate }
            if let entry = matching.first {
                if entry.catalog.item.fields.contains(where: { $0.path == path }) {
                    guard replace else { throw MopError.duplicate }
                    mutation = try await session.replaceField(itemID: entry.itemID, expectedBase: entry.versionID, path: path, value: value).id
                } else {
                    guard !replace else { throw MopError.notFound }
                    var item = entry.catalog.item; item.fields.append(ItemField(path: path, value: String(decoding: try value.validatedUTF8(), as: UTF8.self)))
                    mutation = try await save(ItemEdit(revision: revision(entries), item: item, create: false, originalName: item.name), session: session)
                }
            } else {
                guard !replace else { throw MopError.notFound }
                let item = VaultItem(name: reference.item, fields: [ItemField(path: path, value: String(decoding: try value.validatedUTF8(), as: UTF8.self))])
                mutation = try await save(ItemEdit(revision: revision(entries), item: item, create: true), session: session)
            }
            return await saved(session, token: token, mutations: [mutation])
        case .delete(let reference):
            let entries = try await metadataEntries(session), entry = try find(reference.item, entries)
            var item = entry.catalog.item
            let path = [reference.section, reference.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
            guard item.fields.contains(where: { $0.path == path }) else { throw MopError.notFound }
            if item.fields.count == 1 {
                var projection = entry.catalog
                projection = trashed(projection)
                let mutation = try await session.edit(itemID: entry.itemID, expectedBase: entry.versionID, catalog: projection)
                return await saved(session, token: token, mutations: [mutation.id])
            }
            item.fields.removeAll { $0.path == path }
            let mutation = try await save(ItemEdit(revision: revision(entries), item: item, create: false, originalName: item.name), session: session)
            return await saved(session, token: token, mutations: [mutation])
        case .trashItem(let name, let revision):
            let entry = try await entry(named: name, session: session)
            let projection = trashed(entry.catalog)
            let mutation = try await session.edit(itemID: entry.itemID, expectedBase: base(revision, id: entry.itemID), catalog: projection)
            return await saved(session, token: token, mutations: [mutation.id])
        case .restoreItem(let id, let revision):
            guard let entry = try await metadataEntries(session).first(where: { $0.catalog.item.deletion?.id == id }) else { throw MopError.notFound }
            guard let original = entry.catalog.item.deletion?.originalName else { throw MopError.notFound }
            guard !(try await metadataEntries(session).contains { $0.itemID != entry.itemID && $0.catalog.item.name == original }) else { throw MopError.duplicate }
            var projection = renamed(entry.catalog, to: original); projection.item.deletion = nil
            let mutation = try await session.edit(itemID: entry.itemID, expectedBase: base(revision, id: entry.itemID), catalog: projection)
            return await saved(session, token: token, mutations: [mutation.id])
        case .rename(let name):
            try VaultName.validate(name)
            let current = try await session.vaultMetadata(); var metadata = current.value; metadata.name = name
            let mutation = try await session.saveMetadata(metadata, expectedBase: current.versionID)
            return await saved(session, token: token, mutations: [mutation.id])
        case .exportPortable(let url):
            // This explicit export is labelled a local snapshot until the runtime
            // can certify a completed initial inventory fetch on every device.
            let document = try await session.exportPortableLocalSnapshot()
            let archive = try PortableArchive.seal(document)
            try checked(token)
            try DocumentAccess.write(to: url) { target in
                try OutputFile(url: target, force: false, mode: 0o600, protectedFiles: [], protectedDirectories: []).write(archive.data)
                _ = try PortableArchive.open(LocalFile.read(target, limit: PortableArchive.maximumSize), recoveryKey: archive.recoveryKey)
            }
            result.value = archive.recoveryKey; result.message = "Encrypted local snapshot exported and verified. It includes saved local changes; cloud inventory completeness is not certified. Save the backup key separately."
        case .sync:
            guard !offline else { throw MopError.offlineWrite }
            try await backend.requestSync(); result.message = "Synchronization requested. Saved changes remain durable until iCloud confirms them."
        case .readHistory(let id, let revision):
            let entries = try await metadataEntries(session)
            guard let entry = entries.first(where: { $0.catalog.histories.contains { $0.entries.contains { $0.id == id } } }) else { throw MopError.notFound }
            guard entry.versionID == (try base(revision, id: entry.itemID)) else { throw MopError.vaultConflict }
            result.value = try await session.reveal(itemID: entry.itemID, recordID: id)
        case .restoreHistory(let id, let revision):
            let entries = try await metadataEntries(session)
            guard let entry = entries.first(where: { $0.catalog.histories.contains { $0.entries.contains { $0.id == id } } }),
                  let history = entry.catalog.histories.first(where: { $0.entries.contains { $0.id == id } }) else { throw MopError.notFound }
            let value = try await session.reveal(itemID: entry.itemID, recordID: id)
            let mutation = try await session.replaceField(itemID: entry.itemID, expectedBase: base(revision, id: entry.itemID), path: history.path, value: value)
            return await saved(session, token: token, mutations: [mutation.id])
        case .clearHistory(let field, let revision):
            guard let entry = try await metadataEntries(session).first(where: { $0.catalog.histories.contains { $0.id == field } }) else { throw MopError.notFound }
            var projection = entry.catalog
            let removed = Set(projection.histories.filter { $0.id == field }.flatMap { $0.entries.map(\.id) })
            projection.histories.removeAll { $0.id == field }
            let mutation = try await session.edit(itemID: entry.itemID, expectedBase: base(revision, id: entry.itemID), catalog: projection, removedRecords: removed)
            return await saved(session, token: token, mutations: [mutation.id])
        default: throw ItemVaultServiceFailure.unavailable
        }
        if let catalog = result.catalog { result.autoFillStatus = await publish(catalog, session: session, token: token) }
        try checked(token)
        return result
    }
    private func read(_ reference: SecretReference, session: ItemVaultSession) async throws -> VaultResult {
        let entry = try await entry(named: reference.item, session: session)
        return try await read(reference, entry: entry, session: session)
    }
    private func read(_ reference: SecretReference, entry: ItemVaultCatalogEntry, session: ItemVaultSession) async throws -> VaultResult {
        guard entry.catalog.item.name == reference.item, entry.catalog.item.deletion == nil else { throw MopError.notFound }
        let path = [reference.section, reference.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
        guard let record = entry.catalog.references[reference.relativePath], let field = entry.catalog.item.fields.first(where: { $0.path == path }) else { throw MopError.notFound }
        guard allowsAttachments || field.type != .attachment else { throw ItemVaultServiceFailure.unavailable }
        let secret = try await session.reveal(itemID: entry.itemID, recordID: record, expectedVersion: entry.versionID)
        var result = VaultResult()
        if field.type == .otp {
            let otp = try TimeBasedOTP(String(decoding: secret.validatedUTF8(), as: UTF8.self)), now = Date()
            result.value = SecretBytes(utf8: try otp.code(at: now)); result.otpExpiresAt = otp.expires(at: now); result.otpPeriod = otp.period
        } else { result.value = secret }
        result.valueIsConcealed = field.type.concealed
        result.usageIdentity = ItemUsageIdentity(account: session.memberID.uuidString, vault: session.binding.vaultID.uuidString, item: entry.itemID.uuidString)
        return result
    }
    private func select(_ selection: String?, offline: Bool, authenticate: Bool = true) async throws -> UUID {
        if let selection, let id = UUID(uuidString: selection) { return id }
        if authenticate, let selection {
            guard let id = try await backend.resolveVault(named: selection, offline: offline) else { throw MopError.vaultMissing }
            return id
        }
        let inventory = try await backend.inventory(offline: offline)
        let matches = selection.map { name in inventory.filter { $0.name == name } } ?? inventory
        guard matches.count == 1, let value = matches.first, let id = UUID(uuidString: value.id) else {
            if matches.isEmpty { throw MopError.vaultMissing }; throw ItemVaultServiceFailure.ambiguousVault
        }
        return id
    }
    private func revision(_ entries: [ItemVaultCatalogEntry]) throws -> String {
        try setupEncode(Dictionary(uniqueKeysWithValues: entries.map { ($0.itemID.uuidString, $0.versionID.uuidString) })).base64EncodedString()
    }
    private func base(_ revision: String, id: UUID) throws -> UUID {
        guard let data = Data(base64Encoded: revision), let versions = try? JSONDecoder().decode([String: String].self, from: data),
              let string = versions[id.uuidString], let version = UUID(uuidString: string) else { throw ItemVaultServiceFailure.invalidRevision }
        return version
    }
    private func find(_ name: String, _ entries: [ItemVaultCatalogEntry]) throws -> ItemVaultCatalogEntry {
        let matches = entries.filter { $0.catalog.item.name == name && $0.catalog.item.deletion == nil }
        guard matches.count == 1, let value = matches.first else { if matches.isEmpty { throw MopError.notFound }; throw MopError.duplicate }
        return value
    }
    private func entry(named name: String, session: ItemVaultSession) async throws -> ItemVaultCatalogEntry {
        let index = try await session.revisionIndex()
        if let cached = catalogCache.withLock({ $0[session.binding.vaultID] }),
           cached.session == ObjectIdentifier(session), cached.versions == index {
            return try find(name, Array(cached.entries.values))
        }
        return try await session.catalog(named: name)
    }
    private func metadataEntries(_ session: ItemVaultSession) async throws -> [ItemVaultCatalogEntry] {
        _ = try await catalog(session)
        guard session.isUnlocked,
              let cached = catalogCache.withLock({ $0[session.binding.vaultID] }),
              cached.session == ObjectIdentifier(session) else { throw MopError.authentication }
        return Array(cached.entries.values)
    }
    private func catalog(_ session: ItemVaultSession, limit: Int? = nil) async throws -> ItemCatalog {
        if limit == nil {
            let previous = catalogUpdates.withLock { $0.removeValue(forKey: session.binding.vaultID) }
            previous?.task.cancel()
            if let previous { await previous.task.value }
        }
        try await catalogGate.enter(vault: session.binding.vaultID.uuidString)
        do {
            let result = try await projectCatalog(session, limit: limit)
            await catalogGate.leave(vault: session.binding.vaultID.uuidString)
            return result
        } catch {
            await catalogGate.leave(vault: session.binding.vaultID.uuidString)
            throw error
        }
    }
    private static let catalogSignposter = OSSignposter(subsystem: "com.koehn.mop", category: "Catalog")
    private func projectCatalog(_ session: ItemVaultSession, limit: Int?) async throws -> ItemCatalog {
        let interval = Self.catalogSignposter.beginInterval("Build display catalog")
        defer { Self.catalogSignposter.endInterval("Build display catalog", interval) }
        let token = sessionGeneration
        let index = try await session.revisionIndex()
        let previous = catalogCache.withLock { $0[session.binding.vaultID] }.flatMap {
            $0.session == ObjectIdentifier(session) ? $0 : nil
        }
        if let previous, previous.versions == index {
            try checked(token)
            guard session.isUnlocked else { throw MopError.authentication }
            return limit == nil ? try await withHealth(previous.catalog, session: session) : previous.catalog
        }
        let itemIDs = Set(index.keys).subtracting([ItemVaultSession.metadataRecordID])
        var waiting = (previous?.waiting ?? [:]).filter { itemIDs.contains($0.key) && index[$0.key] == $0.value }
        var entries = (previous?.entries ?? [:]).filter { itemIDs.contains($0.key) && previous?.versions[$0.key] == index[$0.key] }
        var visible = Dictionary(uniqueKeysWithValues: (previous?.catalog.items ?? []).compactMap { item -> (UUID, VaultItem)? in
            guard let id = item.storageID.flatMap(UUID.init(uuidString:)), entries[id] != nil else { return nil }
            return (id, item)
        })
        if previous == nil {
            let cachedRows = try await session.cachedDisplayRows(expectedVersions: index)
            for row in cachedRows where index[row.entry.itemID] == row.entry.versionID {
                entries[row.entry.itemID] = row.entry
                var item = row.item; item.storageID = row.entry.itemID.uuidString
                for field in item.fields.indices {
                    item.fields[field].recordVersion = row.entry.catalog.references[SecretReference.encode(item.name) + "/" + item.fields[field].path]
                }
                visible[row.entry.itemID] = item
            }
        }
        let allChanged = itemIDs.filter { entries[$0] == nil && (limit == nil || waiting[$0] != index[$0]) }.sorted { $0.uuidString < $1.uuidString }
        let changed = Set(limit.map { Array(allChanged.prefix($0)) } ?? allChanged)
        // One item-key unwrap hydrates metadata and its visible fields. Unchanged
        // item projections survive other item edits and receipt-only notifications.
        let rows: [ItemVaultDisplayEntry]
        if limit != nil {
            let batch = try await session.admissionAwareDisplayCatalogBatch(expectedVersions: Dictionary(uniqueKeysWithValues: changed.compactMap { id in index[id].map { (id, $0) } }))
            rows = batch.rows
            waiting.merge(batch.waiting, uniquingKeysWith: { _, latest in latest })
        } else {
            // CLI/export callers need complete coverage, using the same bounded
            // projector as the UI rather than the old whole-vault decrypt path.
            let ids = Array(changed).sorted { $0.uuidString < $1.uuidString }
            var projected: [ItemVaultDisplayEntry] = []
            for offset in stride(from: 0, to: ids.count, by: 64) {
                let batch = ids[offset..<min(offset + 64, ids.count)]
                projected += try await session.displayCatalogBatch(expectedVersions: Dictionary(uniqueKeysWithValues:
                    batch.compactMap { id in index[id].map { (id, $0) } }))
            }
            rows = projected
        }
        do { try await session.cacheDisplayRows(rows) }
        catch {
            // Local cache availability never decides whether an item save/read
            // succeeded. Lock still prevents publishing plaintext below.
            try checked(token)
            guard session.isUnlocked else { throw MopError.authentication }
        }
        for row in rows {
            waiting[row.entry.itemID] = nil
            entries[row.entry.itemID] = row.entry
            var item = row.item; item.storageID = row.entry.itemID.uuidString
            for field in item.fields.indices {
                item.fields[field].recordVersion = row.entry.catalog.references[SecretReference.encode(item.name) + "/" + item.fields[field].path]
            }
            visible[row.entry.itemID] = item
        }
        if limit == nil {
            guard Set(entries.keys) == itemIDs, Set(visible.keys) == itemIDs else { throw MopError.vaultConflict }
        }
        let metadata: VaultEnvelopeMetadata
        let metadataVersion: UUID
        if let previous, let version = index[ItemVaultSession.metadataRecordID], previous.versions[ItemVaultSession.metadataRecordID] == version {
            metadata = previous.metadata; metadataVersion = version
        } else {
            let current = try await session.vaultMetadata()
            metadata = current.value; metadataVersion = current.versionID
        }
        let ordered = entries.values.sorted {
            ($0.catalog.item.name, $0.itemID.uuidString) < ($1.catalog.item.name, $1.itemID.uuidString)
        }
        var result = ItemCatalog(vault: metadata.name, revision: try revision(ordered), items: ordered.compactMap { visible[$0.itemID] })
        result.canEdit = true; result.security = metadata.security ?? VaultSecurityMetadata()
        result.security?.histories = ordered.flatMap { $0.catalog.histories }
        if limit == nil { result = try await withHealth(result, session: session) }
        result.securityEnabled = true; result.canUpgradeSecurity = false
        result.usageScope = session.memberID.uuidString
        var versions = Dictionary(uniqueKeysWithValues: ordered.map { ($0.itemID, $0.versionID) })
        versions[ItemVaultSession.metadataRecordID] = metadataVersion
        // Seed only complete authenticated projections. Receipt-only refreshes
        // return above, so they do not reseal or sign an unchanged index.
        if versions == index && !rows.isEmpty { try? await session.seedNameIndex(ordered, versions: versions) }
        try state.withLock { current in
            guard current.generation == token, session.isUnlocked else { throw MopError.authentication }
            catalogCache.withLock {
                $0[session.binding.vaultID] = CachedCatalog(session: ObjectIdentifier(session), versions: versions,
                    catalog: result, entries: entries, waiting: waiting, metadata: metadata)
            }
        }
        return result
    }
    private func withHealth(_ catalog: ItemCatalog, session: ItemVaultSession) async throws -> ItemCatalog {
        // Preserve the latest successful timestamp for each independent check.
        let conflicts = try await session.healthConflicts()
        if !conflicts.isEmpty {
            let adapter = try await backend.conflictAdapter()
            for conflict in conflicts { try await session.resolveHealthConflict(conflict, coordinator: adapter) }
        }
        var result = catalog
        if result.security == nil { result.security = VaultSecurityMetadata() }
        let live = Set(catalog.items.filter { !$0.isArchived && $0.deletion == nil }.flatMap { $0.fields.compactMap(\.recordVersion) })
        result.security?.passwordChecks = try await session.healthChecks().filter { live.contains($0.record) }
        let checks = Dictionary((result.security?.passwordChecks ?? []).map { ($0.record, $0) }, uniquingKeysWith: { _, value in value })
        for itemIndex in result.items.indices {
            let item = result.items[itemIndex]
            let context = [item.name, item.fields.first { [.username, .email].contains($0.type) }?.value ?? ""]
            for fieldIndex in item.fields.indices where item.fields[fieldIndex].type == .password {
                result.items[itemIndex].fields[fieldIndex].passwordQuality = nil
                guard let record = item.fields[fieldIndex].recordVersion,
                      let strength = checks[record]?.strengthResult, strength.context == context,
                      strength.evaluator == 1 else { continue }
                result.items[itemIndex].fields[fieldIndex].passwordQuality = strength.quality
            }
        }
        return result
    }

    private func assignCatalog(_ catalog: ItemCatalog, to result: inout VaultResult) {
        var active = catalog, deleted = catalog
        active.items.removeAll { $0.deletion != nil }
        deleted.items.removeAll { $0.deletion == nil }
        result.catalog = active; result.deletedCatalog = deleted
    }
    private func saved(_ session: ItemVaultSession, token: Int, mutations: [UUID]) async -> VaultResult {
        var result = VaultResult(); result.message = "Saved on this device. Cloud synchronization is queued."
        result.mutationIDs = mutations
        result.saveStatus = .local
        await delivered(&result)
        if sessionGeneration == token, session.isUnlocked, let value = try? await catalog(session) { assignCatalog(value, to: &result) }
        startCatalogUpdater(session, token: token)
        result.autoFillStatus = await publisher?.status()
        if sessionGeneration != token || !session.isUnlocked { result.catalog = nil; result.deletedCatalog = nil }
        return result
    }
    private func publish(_ catalog: ItemCatalog?, session: ItemVaultSession, token: Int, complete: Bool = true) async -> AutoFillPublicationStatus? {
        guard let publisher, let catalog, sessionGeneration == token, session.isUnlocked else { return nil }
        // Suggestions intentionally survive lock, but contain only eligible public
        // metadata. Every credential use still authenticates in the extension.
        do { try await publisher.publish(catalog: catalog, vaultID: session.binding.vaultID.uuidString, complete: complete, removing: []) }
        catch { return await publisher.status() }
        return await publisher.status()
    }
    private func delivered(_ result: inout VaultResult) async {
        guard case .cloudConfirmed(let timeout) = delivery else { return }
        result.saveStatus = .pending
        guard !result.mutationIDs.isEmpty else {
            result.message = "Saved on this device; iCloud confirmation is unavailable."
            return
        }
        do {
            if try await backend.waitForDelivery(result.mutationIDs, timeout: timeout) {
                result.saveStatus = .cloudConfirmed
                result.message = "Saved and confirmed by iCloud."
            } else { result.message = "Saved on this device; iCloud confirmation is pending. The durable save will retry automatically." }
        } catch {
            result.message = "Saved on this device; iCloud confirmation is pending. Run sync when cloud access is available."
        }
    }
    private func renamed(_ catalog: ItemEnvelopeCatalog, to name: String) -> ItemEnvelopeCatalog {
        var result = catalog
        let old = SecretReference.encode(catalog.item.name) + "/"
        result.references = Dictionary(uniqueKeysWithValues: catalog.references.map { key, value in
            (SecretReference.encode(name) + "/" + key.dropFirst(old.count), value)
        })
        result.item.name = name
        return result
    }
    private func trashed(_ catalog: ItemEnvelopeCatalog) -> ItemEnvelopeCatalog {
        let deletion = ItemDeletion(originalName: catalog.item.name, deletedAt: Date())
        var result = renamed(catalog, to: "trashed-" + deletion.id.uuidString)
        result.item.deletion = deletion
        return result
    }
    private func save(_ edit: ItemEdit, session: ItemVaultSession) async throws -> UUID {
        let entries = try await metadataEntries(session)
        guard !edit.item.fields.isEmpty, Set(edit.item.fields.map(\.path)).count == edit.item.fields.count,
              edit.item.autoFill?.validationError(in: edit.item.fields) == nil else { throw MopError.invalidVault }
        if edit.create {
            guard !entries.contains(where: { $0.catalog.item.name == edit.item.name }) else { throw MopError.duplicate }
            let id = UUID(), metadata = try await session.vaultMetadata()
            var item = edit.item, records: [String: PortableArchiveRecord] = [:], references: [String: String] = [:]
            item.storageID = nil; item.deletion = nil
            for index in item.fields.indices {
                let field = item.fields[index], recordID = UUID().uuidString
                records[recordID] = PortableArchiveRecord(itemID: id.uuidString, bytes: SecretBytes(utf8: field.value ?? ""))
                references[SecretReference.encode(item.name) + "/" + field.path] = recordID
                item.fields[index].historyID = nil; item.fields[index].recordVersion = nil
                if field.type.concealed { item.fields[index].value = nil }
            }
            return try await session.save(PortableVaultArchive(name: metadata.value.name, items: [item], itemIDs: [item.name: id.uuidString],
                references: references, records: records), expectedBase: nil).id
        }
        let current: ItemVaultCatalogEntry
        if let id = edit.item.storageID.flatMap(UUID.init(uuidString:)), let entry = entries.first(where: { $0.itemID == id }) { current = entry }
        else { current = try find(edit.originalName ?? edit.item.name, entries) }
        let expected = try base(edit.revision, id: current.itemID)
        guard current.versionID == expected else { throw MopError.vaultConflict }
        guard !entries.contains(where: { $0.itemID != current.itemID && $0.catalog.item.name == edit.item.name }) else { throw MopError.duplicate }
        var projection = current.catalog
        var changed: [String: SecretBytes] = [:], removed: Set<String> = []
        let wanted = Set(edit.item.fields.map(\.path)), oldName = projection.item.name
        for field in projection.item.fields where !wanted.contains(field.path) {
            if let id = projection.references.removeValue(forKey: SecretReference.encode(oldName) + "/" + field.path) { removed.insert(id) }
            removed.formUnion(projection.histories.filter { $0.path == field.path }.flatMap { $0.entries.map(\.id) })
            projection.histories.removeAll { $0.path == field.path }
        }
        projection.item.fields.removeAll { !wanted.contains($0.path) }
        projection.projectedValuePaths.removeAll { !wanted.contains($0) }
        for field in edit.item.fields {
            if projection.item.fields.contains(where: { $0.path == field.path }) {
                if let value = field.value {
                    if !field.type.concealed,
                       projection.item.fields.first(where: { $0.path == field.path })?.type == field.type,
                       let record = projection.references[SecretReference.encode(oldName) + "/" + field.path],
                       try await session.reveal(itemID: current.itemID, recordID: record) == SecretBytes(utf8: value) {
                        continue
                    }
                    let patch = try projection.replacingField(field.path, value: SecretBytes(utf8: value), itemID: current.itemID)
                    projection = patch.catalog; changed.merge(patch.changedRecords) { _, new in new }; removed.formUnion(patch.removedRecords)
                }
            } else {
                let id = UUID().uuidString
                changed[id] = SecretBytes(utf8: field.value ?? "")
                projection.references[SecretReference.encode(oldName) + "/" + field.path] = id
                var added = field; added.value = nil; added.historyID = nil; added.recordVersion = nil
                projection.item.fields.append(added)
            }
        }
        var updated = edit.item
        updated.storageID = nil; updated.deletion = current.catalog.item.deletion
        for index in updated.fields.indices {
            updated.fields[index].value = nil; updated.fields[index].recordVersion = nil
            updated.fields[index].historyID = projection.item.fields.first(where: { $0.path == updated.fields[index].path })?.historyID
            if ![FieldType.password, .concealed].contains(updated.fields[index].type) {
                let path = updated.fields[index].path
                removed.formUnion(projection.histories.filter { $0.path == path }.flatMap { $0.entries.map(\.id) })
                projection.histories.removeAll { $0.path == path }; updated.fields[index].historyID = nil
            }
        }
        projection.item = updated
        projection.projectedValuePaths = updated.fields.filter { !$0.type.concealed }.map(\.path)
        if oldName != updated.name {
            projection.references = Dictionary(uniqueKeysWithValues: updated.fields.map { field in
                (SecretReference.encode(updated.name) + "/" + field.path, projection.references[SecretReference.encode(oldName) + "/" + field.path]!)
            })
        }
        return try await session.edit(itemID: current.itemID, expectedBase: expected, catalog: projection, changedRecords: changed, removedRecords: removed).id
    }
}
