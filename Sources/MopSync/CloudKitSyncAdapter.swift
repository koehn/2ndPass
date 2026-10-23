@preconcurrency import CloudKit
import Foundation
import MopCore
import OSLog
import CryptoKit

/// Engine-local bookkeeping, not evidence that a zone exists or is trusted.
/// CloudKit owns retries after registration. Re-adding a completed zone save on
/// every checkpoint wake can keep database changes ahead of record uploads.
struct GrantZoneRegistration {
    private var submitted: Set<CKRecordZone.ID> = []

    mutating func newlyRequired(_ zones: Set<CKRecordZone.ID>) -> Set<CKRecordZone.ID> {
        let added = zones.subtracting(submitted)
        submitted.formUnion(added)
        return added
    }

    mutating func invalidate(_ zone: CKRecordZone.ID) { submitted.remove(zone) }
}

/// Whitelist numeric diagnostics only. CloudKit descriptions, partial-error
/// dictionary keys and userInfo may contain private record identifiers/data.
func cloudFailureSummary(_ errors: [CKError]) -> String {
    var counts: [Int: Int] = [:]
    var retryAfter: TimeInterval = 0
    func collect(_ error: CKError, depth: Int) {
        counts[error.code.rawValue, default: 0] += 1
        if let delay = error.retryAfterSeconds, delay.isFinite, delay > retryAfter { retryAfter = delay }
        if depth < 4, let partial = error.partialErrorsByItemID {
            for nested in partial.values {
                if let cloud = nested as? CKError { collect(cloud, depth: depth + 1) }
            }
        }
    }
    for error in errors { collect(error, depth: 0) }
    let codes = counts.keys.sorted().map { "\($0):\(counts[$0]!)" }.joined(separator: ",")
    return "CKError codes(counts)=\(codes) retryAfterSeconds=\(retryAfter)"
}

/// An authority barrier interrupts preparation without failing durable work.
/// Call before any retry bookkeeping or removal from CKSyncEngine's pending set.
func checkUploadPreparation(_ error: (any Error)? = nil) throws {
    try Task.checkCancellation()
    if let error, error is CancellationError
        || (error as? CKError)?.code == .operationCancelled
        || error as? CloudSyncAdapterError == .operationInterrupted {
        throw CancellationError()
    }
}

func publicationFailure(_ error: any Error) -> SyncFailure {
    switch error {
    case CloudSyncAdapterError.accountChanged, MopError.cloudAccount: return .accountChanged
    case CloudSyncAdapterError.membershipUnavailable, ContentStoreError.staleAuthority: return .dependency
    case MopError.authentication, MopError.vaultUntrusted, MopError.cloudPermission: return .authorization
    case is CKError, MopError.cloudUnavailable, MopError.cloudThrottled, is CancellationError: return .transport
    case SyncJournalError.inboxFull, CloudSyncAdapterError.inboxFull: return .inboxFull
    default:
        let native = error as NSError
        if (native.domain == NSCocoaErrorDomain && native.code == NSFileWriteOutOfSpaceError)
            || (native.domain == NSPOSIXErrorDomain && native.code == 28) { return .storagePressure }
        return .processing
    }
}

public struct VaultCloudAddress: Equatable, Codable, Sendable {
    public let vaultID: UUID
    public let zoneName: String
    public let ownerName: String

    public init(vaultID: UUID, zoneName: String, ownerName: String) {
        self.vaultID = vaultID
        self.zoneName = zoneName
        self.ownerName = ownerName
    }

    var zoneID: CKRecordZone.ID { CKRecordZone.ID(zoneName: zoneName, ownerName: ownerName) }
    var storageKey: String { vaultID.uuidString + ":" + ownerName }
}

public enum CloudRecordDirection: Sendable { case receiving, sending, cached }

public typealias CloudAccountValidator = @Sendable () async throws -> Bool

/// Transport for the isolated content store with public publication authority checks.
/// The handler receives the engine owner's public account/lease permit; it must
/// authenticate with pinned membership, never with CloudKit routing hints.
public struct CloudCoordinationTransport: Sendable {
    public let validate: @Sendable (PreparedCoordinationRecord, PublicationAuthorityChecks) async throws -> Void
    public let discovered: @Sendable ([VaultCloudAddress]) async throws -> Void
    public init(validate: @escaping @Sendable (PreparedCoordinationRecord, PublicationAuthorityChecks) async throws -> Void,
                discovered: @escaping @Sendable ([VaultCloudAddress]) async throws -> Void) {
        self.validate = validate; self.discovered = discovered
    }
}

public struct CloudContentReception: Sendable {
    public let prepareGrantRouting: (@Sendable (any RepositoryWritePermit) async throws -> [String])?
    public let coordination: CloudCoordinationTransport?
    public let publicationValidator: ContentPublicationValidator?
    public let authorizedWork: (@Sendable (SyncOperation, any RepositoryWritePermit) async -> SyncOperationOutcome)?
    public let apply: @Sendable (SyncOperation, any RepositoryWritePermit) async -> SyncOperationOutcome
    public let dependencyAvailable: @Sendable (SyncDependency) async throws -> Bool
    public init(apply: @escaping @Sendable (SyncOperation, any RepositoryWritePermit) async -> SyncOperationOutcome,
                dependencyAvailable: @escaping @Sendable (SyncDependency) async throws -> Bool,
                publicationValidator: ContentPublicationValidator? = nil,
                coordination: CloudCoordinationTransport? = nil,
                authorizedWork: (@Sendable (SyncOperation, any RepositoryWritePermit) async -> SyncOperationOutcome)? = nil,
                prepareGrantRouting: (@Sendable (any RepositoryWritePermit) async throws -> [String])? = nil) {
        self.prepareGrantRouting = prepareGrantRouting
        self.coordination = coordination
        self.apply = apply; self.dependencyAvailable = dependencyAvailable
        self.publicationValidator = publicationValidator; self.authorizedWork = authorizedWork
    }
}

// Cancellation is transport interruption, not evidence of invalid ciphertext or
// a failed disk write. Keep both Swift and CloudKit cancellation paths equivalent.
func cloudSyncFailure(_ error: any Error, fallback: CloudSyncAdapterError) -> CloudSyncAdapterError {
    if error as? SyncJournalError == .inboxFull { return .inboxFull }
    if error is CancellationError || (error as? CKError)?.code == .operationCancelled {
        return .operationInterrupted
    }
    return error as? CloudSyncAdapterError ?? fallback
}

/// A delivered event must finish its local processing before its delegate returns,
/// even when cancelOperations cancels the transport task that delivered it.
/// Lifecycle/account validation remains the event processor's responsibility.
func completeCloudSyncEvent(_ process: @escaping @Sendable () async -> Void) async {
    await Task { await process() }.value
}

/// CKSyncEngine owns transfer scheduling and retries; this adapter owns no retry timer.
/// Construct one adapter per account/container/environment/database binding with a
/// distinct lease URL. Initialization performs no cloud calls; start is explicit.
public actor CloudKitSyncAdapter: CKSyncEngineDelegate {
    public static let maximumInlineBytes = 512 * 1024
    public static let assetChunkBytes = 16 * 1024 * 1024
    private let repository: EncryptedItemRepository
    private let database: CKDatabase
    private let account: String
    private let stateNamespace: String
    private let leaseURL: URL
    private let assetDirectory: URL
    private let accountValidator: CloudAccountValidator
    private let accountAuthorization: any RepositoryWritePermit
    private let contentReception: CloudContentReception?
    private var contentPermit: ConflictPublicationPermit?
    private var addresses: [String: VaultCloudAddress]
    private var pendingAddressRegistration: UUID?
    private var coordinationZoneID: CKRecordZone.ID { CKRecordZone.ID(zoneName: SyncStoreLayout.contentCoordinationZone, ownerName: CKCurrentUserDefaultName) }
    private var recipientZoneIDs: [CKRecordZone.ID] = []
    private var receiveZoneIDs: [CKRecordZone.ID] {
        addresses.values.map(\.zoneID) + recipientZoneIDs + (contentReception?.coordination == nil ? [] : [coordinationZoneID])
    }

    private func refreshGrantRouting() async throws {
        guard let prepare = contentReception?.prepareGrantRouting, let contentPermit else { return }
        let names = try await prepare(contentPermit)
        recipientZoneIDs = try names.map { name in
            let zone = try RecipientGrantZone(name: name)
            guard addresses.values.contains(where: { $0.vaultID == zone.vault }) else { throw CloudSyncAdapterError.invalidBinding }
            return CKRecordZone.ID(zoneName: name, ownerName: CKCurrentUserDefaultName)
        }
    }

    /// Adding independently trusted addresses updates the existing engine. Cloud
    /// discovery alone must never call this method or install a trust pin.
    private static func contentAddressHints(_ zones: [CKRecordZone.ID]) -> [VaultCloudAddress] {
        zones.compactMap { zone in
            let prefix = "MopContent3-"
            guard zone.ownerName == CKCurrentUserDefaultName, zone.zoneName.hasPrefix(prefix),
                  let id = UUID(uuidString: String(zone.zoneName.dropFirst(prefix.count))),
                  zone.zoneName == SyncStoreLayout.contentZone(vault: id) else { return nil }
            return VaultCloudAddress(vaultID: id, zoneName: zone.zoneName, ownerName: zone.ownerName)
        }
    }

    public func hasTrustedContentAddress(_ vault: UUID) -> Bool {
        addresses.values.contains { $0.vaultID == vault && $0.zoneName == SyncStoreLayout.contentZone(vault: vault) && $0.ownerName == CKCurrentUserDefaultName }
    }

    public func addContentAddresses(_ added: [VaultCloudAddress]) async throws {
        guard contentReception != nil, added.allSatisfy({ $0.zoneName == SyncStoreLayout.contentZone(vault: $0.vaultID) && $0.ownerName == CKCurrentUserDefaultName }) else { throw CloudSyncAdapterError.invalidBinding }
        for address in added where addresses[address.storageKey] != address {
            addresses[address.storageKey] = address
            pendingAddressRegistration = UUID()
        }
        guard engine != nil, let revision = pendingAddressRegistration else { return }
        try await registerPendingChanges()
        // Keep failed registration retryable, and don't consume a newer address
        // update that arrived while registration awaited repository work.
        if pendingAddressRegistration == revision { pendingAddressRegistration = nil }
    }

    public func removeContentAddress(_ address: VaultCloudAddress) async throws {
        guard contentReception != nil, address.zoneName == SyncStoreLayout.contentZone(vault: address.vaultID) else { throw CloudSyncAdapterError.invalidBinding }
        addresses.removeValue(forKey: address.storageKey)
        recipientZoneIDs.removeAll { ContentZoneRouting.belongs($0, to: address) }
        if let engine {
            let changes = engine.state.pendingRecordZoneChanges.filter { ContentZoneRouting.belongs($0, to: address) }
            let zones = engine.state.pendingDatabaseChanges.filter { ContentZoneRouting.belongs($0, to: address) }
            engine.state.remove(pendingRecordZoneChanges: changes)
            engine.state.remove(pendingDatabaseChanges: zones)
        }
    }

    private var engine: CKSyncEngine?
    private var lease: SynchronizationLease?
    private var uploadsAllowed = false
    private var lastIncomingBlockDiagnostic: String?
    private var suspension = CloudSyncSuspension()
    private var suspended: Bool { suspension.failure != nil }
    private var stopping = false
    private var resolutionInProgress = false
    private var resolutionPermit: ConflictPublicationPermit?
    private var generation = 0
    private var identityGeneration = 0
    private var activeAssetVersions: Set<UUID> = []
    private var activeContentAssets: [String: UUID] = [:]
    // Diagnostic only, bounded and intentionally not persisted. Measures latest
    // engine handoff to server acknowledgement, not end-to-end durable latency.
    private var submissionTimes: [CKRecord.ID: ContinuousClock.Instant] = [:]
    private var grantZoneRegistration = GrantZoneRegistration()
    private var lastUploadStateTrace = Date.distantPast
    private var networkPhases: [UUID: (name: String, started: ContinuousClock.Instant)] = [:]
    private var lastRetentionPrune = Date.distantPast
    private var recoveryOperation: UUID?
    private var activeDataEvents = 0
    private var deferredEngineState: Data?
    private var databaseName: String { database.databaseScope == .shared ? "shared" : "private" }
    private static let logger = Logger(subsystem: "com.koehn.mop", category: "CloudSync")
    public private(set) var lastFailure: CloudSyncAdapterError? {
        didSet {
            guard let lastFailure, lastFailure != oldValue else { return }
            // Enum cases contain no item names, record contents or account IDs.
            Self.logger.error("Sync adapter failure: \(String(describing: lastFailure), privacy: .public)")
        }
    }

    public init(repository: EncryptedItemRepository, database: CKDatabase, account: String,
                stateNamespace: String, leaseURL: URL, addresses: [VaultCloudAddress],
                accountValidator: @escaping CloudAccountValidator,
                accountAuthorization: any RepositoryWritePermit,
                contentReception: CloudContentReception) throws {
        guard !account.isEmpty, !stateNamespace.isEmpty,
              database.databaseScope == .private || database.databaseScope == .shared,
              Set(addresses.map(\.storageKey)).count == addresses.count,
              Set(addresses.map { $0.ownerName + ":" + $0.zoneName }).count == addresses.count else {
            throw CloudSyncAdapterError.invalidBinding
        }

        do {
            guard database.databaseScope == .private,
                  addresses.allSatisfy({ $0.zoneName == SyncStoreLayout.contentZone(vault: $0.vaultID) }) else {
                throw CloudSyncAdapterError.invalidBinding
            }
        }
        self.contentReception = contentReception
        self.repository = repository
        self.database = database
        self.account = account
        self.stateNamespace = stateNamespace + ":content-v3" + ":" + (database.databaseScope == .shared ? "shared" : "private")
        self.leaseURL = leaseURL
        self.assetDirectory = leaseURL.deletingLastPathComponent().appendingPathComponent("EncryptedAssets", isDirectory: true)
        self.addresses = Dictionary(uniqueKeysWithValues: addresses.map { ($0.storageKey, $0) })
        self.accountValidator = accountValidator
        self.accountAuthorization = accountAuthorization
    }

    public func start(automaticallySync: Bool = true) async throws {
        try Task.checkCancellation()
        guard !stopping else { throw CloudSyncAdapterError.operationInterrupted }
        try checkSuspension()
        guard engine == nil else {
            Self.logger.notice("Sync trace: engine startup skipped; existing engine reused")
            return
        }
        let expectedGeneration = identityGeneration
        let acquired = try SynchronizationLease(url: leaseURL)
        guard try await accountValidator() else { throw CloudSyncAdapterError.accountChanged }
        try await cleanupUploadAssets(holding: acquired)
        try await repository.pruneCompletedOperations(account: account, database: databaseName)
        try await repository.pruneHistory(permit: ConflictPublicationPermit(lease: acquired, authorization: accountAuthorization))
        lastRetentionPrune = Date()
        // Log checkpoint availability, never its contents or account/vault identifiers.
        let data: Data?
        do {
            data = try await repository.engineState(account: account, database: stateNamespace)
        } catch {
            let native = error as NSError
            Self.logger.error("Sync trace: startup checkpoint read failed; domain=\(native.domain, privacy: .public) code=\(native.code)")
            throw error
        }
        Self.logger.notice("Sync trace: startup checkpoint loaded; present=\(data != nil) bytes=\(data?.count ?? 0)")
        let state: CKSyncEngine.State.Serialization?
        do {
            state = try data.map { try JSONDecoder().decode(CKSyncEngine.State.Serialization.self, from: $0) }
        } catch {
            let native = error as NSError
            Self.logger.error("Sync trace: startup checkpoint decode failed; domain=\(native.domain, privacy: .public) code=\(native.code); startup aborted")
            throw error
        }
        try Task.checkCancellation()
        guard expectedGeneration == identityGeneration, !suspended, !stopping else { throw CloudSyncAdapterError.operationInterrupted }
        var configuration = CKSyncEngine.Configuration(database: database, stateSerialization: state, delegate: self)
        configuration.automaticallySync = automaticallySync
        configuration.subscriptionID = SyncStoreLayout.contentSubscriptionID
        lease = acquired
        if contentReception != nil { contentPermit = ConflictPublicationPermit(lease: acquired, authorization: accountAuthorization) }
        try await refreshGrantRouting()
        let deletedAddresses = try await repository.deletions(account: account).map {
            VaultCloudAddress(vaultID: $0.scope.vaultID, zoneName: SyncStoreLayout.contentZone(vault: $0.scope.vaultID), ownerName: $0.scope.zoneOwner)
        }
        let startedEngine = CKSyncEngine(configuration)
        // Scrub restored transport work before yielding to any engine callback.
        // Keep the account coordination zone and its signed deletion notices.
        for address in deletedAddresses {
            addresses.removeValue(forKey: address.storageKey)
            recipientZoneIDs.removeAll { ContentZoneRouting.belongs($0, to: address) }
            startedEngine.state.remove(pendingRecordZoneChanges: startedEngine.state.pendingRecordZoneChanges.filter { ContentZoneRouting.belongs($0, to: address) })
            startedEngine.state.remove(pendingDatabaseChanges: startedEngine.state.pendingDatabaseChanges.filter { ContentZoneRouting.belongs($0, to: address) })
        }
        engine = startedEngine
        grantZoneRegistration = GrantZoneRegistration()
        Self.logger.notice("Sync trace: engine created; checkpointRestored=\(state != nil) zones=\(self.addresses.count) automaticallySync=\(automaticallySync)")
        if contentReception?.coordination != nil { startedEngine.state.add(pendingDatabaseChanges: [.saveZone(CKRecordZone(zoneID: coordinationZoneID))]) }
        do {
            // A restored checkpoint is not a current inventory. Zone-scoped
            // fetches need not rediscover vaults created since this device last
            // participated. Refresh routing hints once per engine startup; this
            // lists zone metadata only, never other recipients' grant records.
            if let coordination = contentReception?.coordination {
                let zones = try await database.allRecordZones()
                try await validateAccount(generation: expectedGeneration)
                let hints = Self.contentAddressHints(zones.map(\.zoneID))
                try await coordination.discovered(hints)
                Self.logger.notice("Sync trace: cloud vault inventory refreshed; candidates=\(hints.count)")
                try await validateAccount(generation: expectedGeneration)
                try await repository.saveEngineState(Data([1]), account: account, database: stateNamespace + ":inventory")
            }
            try await registerPendingChanges()
            guard expectedGeneration == identityGeneration, engine === startedEngine, suspension.allowsLocalProcessing, !stopping else {
                throw CloudSyncAdapterError.operationInterrupted
            }
        } catch {
            // Automatic reception may fill the inbox before registration returns.
            // Retain this adapter/lease so startup can hand off to the consumer.
            if error as? CloudSyncAdapterError == .inboxFull,
               suspension.failure == .inboxFull, expectedGeneration == identityGeneration,
               engine === startedEngine, !stopping { return }
            if engine === startedEngine { await stop() }
            throw error
        }
    }

    public func stop() async {
        guard !stopping else { return }
        stopping = true
        contentPermit?.invalidate(); contentPermit = nil
        resolutionPermit?.invalidate()
        resolutionPermit = nil
        resolutionInProgress = false
        uploadsAllowed = false
        generation += 1
        identityGeneration += 1
        deferredEngineState = nil
        activeDataEvents = 0
        let oldEngine = engine
        engine = nil
        if let oldEngine {
            Self.logger.notice("Sync trace: cancelling operations; reason=engine stop")
            await oldEngine.cancelOperations()
        }
        lease = nil
        activeAssetVersions = []; activeContentAssets = [:]; submissionTimes = [:]
        stopping = false
    }

    public func setUploadsAllowed(_ allowed: Bool) async {
        let next = allowed && !suspended && (contentReception == nil || contentReception?.publicationValidator != nil)
        // Reapplying the read-only startup policy must not cancel downloads.
        // Only a transition from allowed to disallowed revokes active sends.
        guard next != uploadsAllowed else { return }
        uploadsAllowed = next
        generation += 1
        if !uploadsAllowed, let engine {
            Self.logger.notice("Sync trace: cancelling operations; reason=uploads disabled")
            await engine.cancelOperations()
        }
        if uploadsAllowed {
            do { try await registerPendingChanges() }
            catch { lastFailure = suspension.failure ?? cloudSyncFailure(error, fallback: .storageFailure) }
        }
    }

    private func finishResolution(engine owner: CKSyncEngine, generation expectedGeneration: Int) async {
        guard identityGeneration == expectedGeneration, engine === owner else { return }
        resolutionInProgress = false
        guard !suspended, !stopping else { return }
        do {
            try await registerPendingChanges()
            _ = try await repository.requestSync(account: account, database: databaseName, reason: .manual)
        } catch {
            // The choice is already durable. Do not turn a scheduling error into
            // a false report that the local transaction failed.
            lastFailure = cloudSyncFailure(error, fallback: .storageFailure)
        }
    }

    public func requestSync() async throws {
        let traceID = UUID()
        let started = ContinuousClock.now
        networkPhases[traceID] = ("preparing", started)
        AccessSyncTrace.event("network reconciliation started", operation: traceID)
        defer {
            networkPhases.removeValue(forKey: traceID)
            AccessSyncTrace.elapsed("network reconciliation exited", since: started, operation: traceID)
        }
        try Task.checkCancellation()
        try checkSuspension()
        guard let engine else { throw CloudSyncAdapterError.engineNotStarted }
        let expectedGeneration = identityGeneration
        try await validateAccount(generation: expectedGeneration)
        guard self.engine === engine else { throw CloudSyncAdapterError.operationInterrupted }
        try Task.checkCancellation()
        // Refresh BEFORE constructing the explicit scope. The delegate can
        // narrow that scope but cannot add an identity absent from it.
        try await refreshGrantRouting()
        guard self.engine === engine, expectedGeneration == identityGeneration else { throw CloudSyncAdapterError.operationInterrupted }
        let pendingCount = try await repository.pendingScopes(account: account).count
        let conflictCount = try await repository.conflictedScopes(account: account).count
        Self.logger.notice("Sync trace: fetch starting; zones=\(self.addresses.count) pendingItems=\(pendingCount) conflicts=\(conflictCount) uploadsAllowed=\(self.uploadsAllowed)")
        networkPhases[traceID] = ("fetching", .now)
        AccessSyncTrace.event("network fetch started", operation: traceID,
            detail: "zones=\(receiveZoneIDs.count) uploadsAllowed=\(uploadsAllowed)")
        try await engine.fetchChanges(.init(scope: .zoneIDs(receiveZoneIDs)))
        networkPhases[traceID] = ("registering", .now)
        AccessSyncTrace.event("network fetch returned", operation: traceID)
        Self.logger.notice("Sync trace: fetch returned; suspended=\(self.suspended)")
        guard expectedGeneration == identityGeneration, self.engine === engine, !suspended else {
            throw CloudSyncAdapterError.operationInterrupted
        }
        if uploadsAllowed && !resolutionInProgress {
            try await registerPendingChanges()
            guard expectedGeneration == identityGeneration, self.engine === engine, !suspended, uploadsAllowed, !resolutionInProgress else {
                throw CloudSyncAdapterError.operationInterrupted
            }
            try Task.checkCancellation()
            Self.logger.notice("Sync trace: send starting")
            networkPhases[traceID] = ("sending", .now)
            AccessSyncTrace.event("network send started", operation: traceID)
            try await engine.sendChanges()
            AccessSyncTrace.event("network send returned", operation: traceID)
            Self.logger.notice("Sync trace: send returned")
        }
        guard expectedGeneration == identityGeneration, self.engine === engine, !suspended else {
            throw CloudSyncAdapterError.operationInterrupted
        }
        recoveryOperation = nil
    }

    /// Call after a durable local transaction; restart reconstructs this list from Core Data.
    public func registerPendingChanges() async throws {
        try checkSuspension()
        // Long-lived foreground owners also age out completed receipts/history.
        // Reuse reconciliation opportunities rather than adding a cleanup timer.
        if Date().timeIntervalSince(lastRetentionPrune) >= 86400, let lease {
            lastRetentionPrune = Date()
            do {
                let permit = ConflictPublicationPermit(lease: lease, authorization: accountAuthorization)
                try permit.withWritePermission {}
                try await repository.pruneCompletedOperations(account: account, database: databaseName)
                try await repository.pruneHistory(permit: permit)
            } catch {
                lastRetentionPrune = .distantPast
                Self.logger.error("Deferred completed sync history cleanup")
            }
        }
            guard let engine else { throw CloudSyncAdapterError.engineNotStarted }
            let expected = identityGeneration
            try await refreshGrantRouting()
            let candidates = try await repository.contentPublications(account: account)
            guard expected == identityGeneration, self.engine === engine, !suspended else { throw CloudSyncAdapterError.operationInterrupted }
            let coordination = contentReception?.coordination == nil ? [] : try await repository.coordinationPublications(account: account)
            let removals = try await repository.coordinationRemovals(account: account).compactMap { operation -> CKSyncEngine.PendingRecordZoneChange? in
                guard let name = String(data: operation.payload, encoding: .utf8) else { throw ContentStoreError.invalidRecord }
                return .deleteRecord(CKRecord.ID(recordName: name, zoneID: coordinationZoneID))
            }
            guard expected == identityGeneration, self.engine === engine, !suspended else { throw CloudSyncAdapterError.operationInterrupted }
            if !removals.isEmpty { engine.state.add(pendingRecordZoneChanges: removals) }
            let ids = Set(candidates.filter { address(for: $0.scope) != nil }.map(\.recordID) + coordination.map(\.recordID))
            let registered = Set(engine.state.pendingRecordZoneChanges.compactMap { change -> CKRecord.ID? in
                if case .saveRecord(let id) = change { return id }; return nil
            })
            if ids != registered || Date().timeIntervalSince(lastUploadStateTrace) >= 30 {
                lastUploadStateTrace = Date()
                let phases = networkPhases.values.map {
                    "\($0.name):\($0.started.duration(to: .now))"
                }.sorted().joined(separator: ",")
                AccessSyncTrace.event("upload transport state",
                    detail: "candidates=\(candidates.count) coordination=\(coordination.count) trustedRecords=\(ids.count) registered=\(registered.count) uploadsAllowed=\(uploadsAllowed) suspended=\(suspended) resolving=\(resolutionInProgress) network=\(phases.isEmpty ? "idle" : phases)")
            }
            if ids != registered {
                Self.logger.notice("Sync trace: upload registration; contentCandidates=\(candidates.count) coordinationCandidates=\(coordination.count) untrustedZoneCandidates=\(candidates.filter { address(for: $0.scope) == nil }.count) added=\(ids.subtracting(registered).count) removed=\(registered.subtracting(ids).count)")
            }
            let grantZones = Set(candidates.filter { $0.grant != nil && address(for: $0.scope) != nil }.map { $0.recordID.zoneID })
            let newZones = grantZoneRegistration.newlyRequired(grantZones)
            if !newZones.isEmpty {
                AccessSyncTrace.event("grant zones registered", detail: "count=\(newZones.count)")
                engine.state.add(pendingDatabaseChanges: newZones.map { .saveZone(CKRecordZone(zoneID: $0)) })
            }
            let added = ids.subtracting(registered), removed = registered.subtracting(ids)
            if !added.isEmpty { engine.state.add(pendingRecordZoneChanges: added.map { .saveRecord($0) }) }
            if !removed.isEmpty { engine.state.remove(pendingRecordZoneChanges: removed.map { .saveRecord($0) }) }

    }

    /// The account coordinator retries this same durable operation until lease
    /// reacquisition and upload restoration both succeed. No nested wake/pump.
    public func resumeAutomaticSync() async throws {
        if suspension.failure == .inboxFull {
            // Return to the durable scheduler so applyIncoming can drain. Never
            // wait here for the consumer running on that same scheduler.
            let expected = identityGeneration
            let ready = try await repository.inboxReadyToResume(account: account)
            guard expected == identityGeneration, !stopping else { throw CloudSyncAdapterError.operationInterrupted }
            guard ready else { throw CloudSyncAdapterError.inboxFull }
            Self.logger.notice("Sync trace: inbox capacity available; resuming from durable checkpoint")
        }
        if suspended {
            guard try await accountValidator() else { throw CloudSyncAdapterError.accountChanged }
            await stop()
            suspension = CloudSyncSuspension(); lastFailure = nil
        }
        try await start()
        await setUploadsAllowed(true)
        try checkSuspension()
        guard engine != nil, lease != nil, uploadsAllowed else { throw CloudSyncAdapterError.engineNotStarted }
        recoveryOperation = nil
    }

    public func handleEvent(_ event: CKSyncEngine.Event, syncEngine: CKSyncEngine) async {
        await completeCloudSyncEvent { [self] in
            await processEvent(event, syncEngine: syncEngine)
        }
    }

    private func processEvent(_ event: CKSyncEngine.Event, syncEngine: CKSyncEngine) async {
        guard engine === syncEngine else { return }
        if suspended {
            // Capacity suspension retains the local permit. Account revocation
            // must still invalidate it even while transport callbacks are ignored.
            guard case .accountChange = event else { return }
        }
        let expectedGeneration = identityGeneration
        let dataEvent: Bool
        switch event {
        case .fetchedRecordZoneChanges, .sentRecordZoneChanges, .fetchedDatabaseChanges: dataEvent = true
        default: dataEvent = false
        }
        if dataEvent { activeDataEvents += 1 }
        do {
            switch event {
            case .stateUpdate(let update):
                deferredEngineState = try JSONEncoder().encode(update.stateSerialization)
            case .accountChange(let change):
                if case .signIn = change.changeType, try await accountValidator() { break }
                guard expectedGeneration == identityGeneration, engine === syncEngine else {
                    throw CloudSyncAdapterError.operationInterrupted
                }
                suspend(.accountChanged)
                generation += 1
                identityGeneration += 1
                lastFailure = .accountChanged
                // Do not delete/rebind the outbox or reuse this engine under another account.
            case .fetchedRecordZoneChanges(let changes):
                Self.logger.notice("Sync trace: fetched records=\(changes.modifications.count) deletions=\(changes.deletions.count)")
                do { try await receiveBatch(changes.modifications.map(\.record)) }
                catch let error as CloudSyncAdapterError { suspend(error); throw error }
                catch { suspend(cloudSyncFailure(error, fallback: .storageFailure)); throw error }
                for deletion in changes.deletions where deletion.recordType == ContentRecordKind.grant.rawValue {
                    if let zone = try? RecipientGrantZone(name: deletion.recordID.zoneID.zoneName),
                       let address = try? ContentRecordAddress(recordType: deletion.recordType,
                            zone: deletion.recordID.zoneID.zoneName, record: deletion.recordID.recordName) {
                        try await repairGrantDestination(deletion.recordID.zoneID, zone: zone, identifier: address.identity)
                    }
                }
                for deletion in changes.deletions where deletion.recordType == NativeVaultProvisioningTransport.recordType {
                    try await validateAccount(generation: expectedGeneration)
                    try await blockZone(deletion.recordID.zoneID)
                }
                if let contentPermit {
                    for deletion in changes.deletions where deletion.recordID.zoneID == coordinationZoneID {
                        if let hint = try? PreparedCoordinationRecord.address(recordType: deletion.recordType, zone: coordinationZoneID.zoneName, record: deletion.recordID.recordName), hint.kind == .discovery {
                            try await repository.removeContentDiscovery(account: account, vault: hint.vault, publishRemoval: false, permit: contentPermit)
                        }
                    }
                }
                if changes.deletions.contains(where: { $0.recordID.zoneID != coordinationZoneID }) {
                    // Only authenticated tombstones authorize deletion of local data.
                    lastFailure = .unexpectedRemoteDeletion
                }
            case .didFetchRecordZoneChanges(let completion):
                if let error = completion.error, error.code == .zoneNotFound || error.code == .userDeletedZone,
                   let zone = try? RecipientGrantZone(name: completion.zoneID.zoneName) {
                    try await repairGrantDestination(completion.zoneID, zone: zone)
                }
                if completion.error == nil, recipientZoneIDs.contains(completion.zoneID), let contentPermit {
                    try await validateAccount(generation: expectedGeneration)
                    try await repository.saveEngineState(Data([1]), account: account,
                        database: "grant-initial-fetch4:" + completion.zoneID.zoneName, permit: contentPermit)
                }
                if contentReception != nil, completion.error == nil,
                   let address = addresses.values.first(where: { $0.zoneID == completion.zoneID }), let contentPermit {
                    try await validateAccount(generation: expectedGeneration)
                    try await repository.saveEngineState(Data([1]), account: account, database: "content-initial-fetch:" + address.vaultID.uuidString, permit: contentPermit)
                }
            case .fetchedDatabaseChanges(let changes):
                if let coordination = contentReception?.coordination {
                    try await validateAccount(generation: expectedGeneration)
                    try await coordination.discovered(Self.contentAddressHints(changes.modifications.map(\.zoneID)))
                }
                for deletion in changes.deletions {
                    try await validateAccount(generation: expectedGeneration)
                    try await blockZone(deletion.zoneID)
                }
                if !changes.deletions.isEmpty { lastFailure = .unexpectedRemoteDeletion }
            case .sentRecordZoneChanges(let changes):
                Self.logger.notice("Sync trace: sent records=\(changes.savedRecords.count) failed=\(changes.failedRecordSaves.count)")
                if !changes.failedRecordSaves.isEmpty {
                    let summary = cloudFailureSummary(changes.failedRecordSaves.map(\.error))
                    Self.logger.error("Cloud record saves failed: \(summary, privacy: .public)")
                }
                for saved in changes.savedRecords {
                    AccessSyncTrace.event("record saved by cloud", record: saved.recordID.recordName, detail: "type=\(saved.recordType)")
                    if let start = submissionTimes.removeValue(forKey: saved.recordID) {
                        AccessSyncTrace.elapsed("publication acknowledgment latency", since: start,
                            detail: "basis=latestSubmission type=\(saved.recordType)")
                    }
                    try await acknowledge(saved)
                }
                if contentReception != nil, let contentPermit {
                    for id in changes.deletedRecordIDs where id.zoneID == coordinationZoneID {
                        try await repository.acknowledgeCoordinationRemoval(account: account, record: id.recordName, permit: contentPermit)
                    }
                }
                for failure in changes.failedRecordSaves {
                    AccessSyncTrace.event("record save failed", record: failure.record.recordID.recordName,
                        detail: "type=\(failure.record.recordType) code=\(failure.error.code.rawValue)")
                    if failure.error.code == .serverRecordChanged {
                        // A conflict response is not an asset download. Fetch the
                        // complete current record before validating its ciphertext;
                        // error.serverRecord may contain asset references only.
                        try await validateAccount(generation: expectedGeneration)
                        let remote = try await database.record(for: failure.record.recordID)
                        guard remote.recordID == failure.record.recordID, remote.recordType == failure.record.recordType else {
                            throw CloudSyncAdapterError.invalidBinding
                        }
                        guard expectedGeneration == identityGeneration, engine === syncEngine, !suspended else {
                            throw CloudSyncAdapterError.operationInterrupted
                        }
                        if failure.record.recordType == ContentRecordKind.grant.rawValue {
                            let sent = try ContentRecordTransport.materialize(failure.record, account: account)
                            let fetched = try ContentRecordTransport.materialize(remote, account: account)
                            guard sent.bytes == fetched.bytes else { throw ContentStoreError.identityCollision }
                            try await acknowledge(remote)
                        } else { try await receive(remote) }
                    } else if failure.error.code == .unknownItem || failure.error.code == .zoneNotFound {
                        try await blockZone(failure.record.recordID.zoneID)
                        lastFailure = .unexpectedRemoteDeletion
                    }
                }
                try await registerPendingChanges()
                for record in changes.savedRecords + changes.failedRecordSaves.map(\.record) {
                    if contentReception != nil, let incoming = try? (record.recordID.zoneID == coordinationZoneID ? PreparedCoordinationRecord.materialize(record, account: account) : ContentRecordTransport.materialize(record, account: account)) {
                        let key = record.recordID.recordName + ":" + SHA256.hash(data: incoming.bytes).map { String(format: "%02x", $0) }.joined()
                        if let version = activeContentAssets.removeValue(forKey: key), !activeContentAssets.values.contains(version) {
                            activeAssetVersions.remove(version)
                        }
                    }
                }
                if let lease {
                    do { try await cleanupUploadAssets(holding: lease) }
                    catch { Self.logger.error("Deferred encrypted upload asset cleanup") }
                }
            default: break
            }
        } catch {
            if expectedGeneration == identityGeneration, engine === syncEngine {
                // Never log localized descriptions/userInfo: CloudKit and Core
                // Data can include record payloads there. Domain/code identify the
                // underlying failure without exposing item contents.
                let native = error as NSError
                Self.logger.error("Sync event failed: domain=\(native.domain, privacy: .public) code=\(native.code)")
                if let repositoryError = error as? ItemRepositoryError {
                    Self.logger.error("Repository failure: \(String(describing: repositoryError), privacy: .public)")
                }
                if let underlying = native.userInfo[NSUnderlyingErrorKey] as? NSError {
                    Self.logger.error("Underlying sync failure: domain=\(underlying.domain, privacy: .public) code=\(underlying.code)")
                }
                suspend(cloudSyncFailure(error, fallback: .storageFailure))
            }
        }
        if dataEvent, expectedGeneration == identityGeneration { activeDataEvents -= 1 }
        guard activeDataEvents == 0, !suspended, expectedGeneration == identityGeneration,
              engine === syncEngine, let state = deferredEngineState else { return }
        deferredEngineState = nil
        do {
            if let contentPermit {
                try await repository.saveEngineState(state, account: account, database: stateNamespace, permit: contentPermit)
            } else {
                try await repository.saveEngineState(state, account: account, database: stateNamespace)
            }
            AccessSyncTrace.event("checkpoint persisted", detail: "bytes=\(state.count)")
        }
        catch {
            let native = error as NSError
            Self.logger.error("Sync trace: checkpoint save failed; domain=\(native.domain, privacy: .public) code=\(native.code)")
            if expectedGeneration == identityGeneration, engine === syncEngine {
                suspend(.storageFailure)
            }
        }
    }

    public func nextFetchChangesOptions(_ context: CKSyncEngine.FetchChangesContext,
                                        syncEngine: CKSyncEngine) async -> CKSyncEngine.FetchChangesOptions {
        guard engine === syncEngine, !suspended else { return .init(scope: .zoneIDs([])) }
        var options = context.options
        do { try await refreshGrantRouting() } catch { return .init(scope: .zoneIDs([])) }
        guard engine === syncEngine, !suspended, !stopping else { return .init(scope: .zoneIDs([])) }
        options.scope = .zoneIDs(receiveZoneIDs.filter { context.options.scope.contains($0) })
        return options
    }

    public func nextRecordZoneChangeBatch(_ context: CKSyncEngine.SendChangesContext,
                                         syncEngine: CKSyncEngine) async -> CKSyncEngine.RecordZoneChangeBatch? {
        guard uploadsAllowed, !suspended, !resolutionInProgress, engine === syncEngine else {
            Self.logger.notice("Sync trace: send batch blocked; uploadsAllowed=\(self.uploadsAllowed) suspended=\(self.suspended) resolutionInProgress=\(self.resolutionInProgress) currentEngine=\(self.engine === syncEngine)")
            return nil
        }
        return await nextContentBatch(context, syncEngine: syncEngine)
    }

    private func nextContentBatch(_ context: CKSyncEngine.SendChangesContext, syncEngine: CKSyncEngine) async -> CKSyncEngine.RecordZoneChangeBatch? {
        guard let validate = contentReception?.publicationValidator, let contentPermit else { return nil }
        let expected = identityGeneration, expectedUploads = generation
        var pending: [(UUID, CKRecord.ID)] = []
        do {
            try checkUploadPreparation()
            let candidates = try await repository.contentPublications(account: account)
            let controls = try await repository.coordinationPublications(account: account)
            Self.logger.notice("Sync trace: send batch candidates; content=\(candidates.count) coordination=\(controls.count)")
            pending = candidates.map { ($0.operationID, $0.recordID) } + controls.map { ($0.operationID, $0.recordID) }
            try await validateAccount(generation: expected)
            var records: [CKRecord] = [], selected: [ContentUpload] = [], bytes = 0
            var selectedCoordination: [PreparedCoordinationRecord] = []
            let preparationAuthority = PublicationAuthorityChecks()
            if let coordination = contentReception?.coordination {
                for candidate in controls {
                    try checkUploadPreparation()
                    guard records.count < 100, context.options.scope.contains(.saveRecord(candidate.recordID)) else { continue }
                    if !records.isEmpty, candidate.bytes.count > Self.assetChunkBytes - min(bytes, Self.assetChunkBytes) { break }
                    do {
                        try await coordination.validate(candidate, preparationAuthority)
                    }
                    catch {
                        try await deferUpload(candidate.operationID, recordID: candidate.recordID, error: error, permit: contentPermit, engine: syncEngine)
                        continue
                    }
                    records.append(try candidate.record(assetDirectory: assetDirectory))
                    selectedCoordination.append(candidate); bytes += candidate.bytes.count
                }
            }
            for candidate in candidates {
                try checkUploadPreparation()
                guard records.count < 100 else { break }
                guard address(for: candidate.scope) != nil, context.options.scope.contains(.saveRecord(candidate.recordID)) else { continue }
                // Authority failures are scoped to this operation, not the engine.
                do {
                    try await validate(candidate, preparationAuthority)
                } catch {
                    try await deferUpload(candidate.operationID, recordID: candidate.recordID, error: error, permit: contentPermit, engine: syncEngine)
                    continue
                }
                if !records.isEmpty, candidate.byteCount > Self.assetChunkBytes - min(bytes, Self.assetChunkBytes) { break }
                let record = try candidate.record(assetDirectory: assetDirectory)
                records.append(record); selected.append(candidate); bytes += candidate.byteCount
                if records.count == 100 || bytes >= Self.assetChunkBytes { break }
            }
            let removals = try await repository.coordinationRemovals(account: account).prefix(max(0, 100 - records.count)).compactMap { operation -> CKRecord.ID? in
                guard let name = String(data: operation.payload, encoding: .utf8) else { throw ContentStoreError.invalidRecord }
                let id = CKRecord.ID(recordName: name, zoneID: coordinationZoneID)
                return context.options.scope.contains(.deleteRecord(id)) ? id : nil
            }
            var rejected: Set<CKRecord.ID> = []
            // Assets may have taken time to prepare. Read authority afresh for
            // this phase, sharing only within this batch and exact pinned head.
            let submissionAuthority = PublicationAuthorityChecks()
            for candidate in selected {
                try checkUploadPreparation()
                do {
                    try await validate(candidate, submissionAuthority)
                    try await repository.setContentUploadBlocked(candidate.operationID, account: account, blocked: false, permit: contentPermit)
                }
                catch {
                    try await deferUpload(candidate.operationID, recordID: candidate.recordID, error: error, permit: contentPermit, engine: syncEngine)
                    rejected.insert(candidate.recordID)
                }
            }
            if let coordination = contentReception?.coordination {
                for candidate in selectedCoordination {
                    try checkUploadPreparation()
                    do {
                        try await coordination.validate(candidate, submissionAuthority)
                        try await repository.setContentUploadBlocked(candidate.operationID, account: account, blocked: false, permit: contentPermit)
                    }
                    catch {
                        try await deferUpload(candidate.operationID, recordID: candidate.recordID, error: error, permit: contentPermit, engine: syncEngine)
                        rejected.insert(candidate.recordID)
                    }
                }
            }
            records.removeAll { rejected.contains($0.recordID) }
            selected.removeAll { rejected.contains($0.recordID) }
            selectedCoordination.removeAll { rejected.contains($0.recordID) }
            try checkUploadPreparation()
            try contentPermit.withWritePermission {}
            guard expected == identityGeneration, expectedUploads == generation, engine === syncEngine,
                  !suspended, uploadsAllowed, (!records.isEmpty || !removals.isEmpty) else {
                Self.logger.notice("Sync trace: send batch withheld; records=\(records.count) removals=\(removals.count) rejected=\(rejected.count) identityChanged=\(expected != self.identityGeneration) uploadsChanged=\(expectedUploads != self.generation) suspended=\(self.suspended) uploadsAllowed=\(self.uploadsAllowed)")
                return nil
            }
            for candidate in selectedCoordination {
                activeAssetVersions.insert(candidate.operationID)
                activeContentAssets[candidate.recordName + ":" + SHA256.hash(data: candidate.bytes).map { String(format: "%02x", $0) }.joined()] = candidate.operationID
            }
            for candidate in selected where candidate.grant == nil {
                let key = candidate.recordID.recordName + ":" + SHA256.hash(data: candidate.content.version.ciphertext).map { String(format: "%02x", $0) }.joined()
                activeContentAssets[key] = candidate.content.version.versionID
                activeAssetVersions.insert(candidate.content.version.versionID)
            }
            for candidate in selectedCoordination where !rejected.contains(candidate.recordID) {
                AccessSyncTrace.event("coordination submitted", operation: candidate.operationID,
                    record: candidate.recordName, detail: "kind=\(candidate.kind.rawValue) payloadBytes=\(candidate.bytes.count)")
            }
            for candidate in selected where !rejected.contains(candidate.recordID) {
                AccessSyncTrace.event("content submitted", operation: candidate.operationID, item: candidate.scope.itemID,
                    generation: candidate.content.keyGeneration, recipient: candidate.grant?.recipient,
                    record: candidate.recordID.recordName, detail: "kind=\(candidate.kind.rawValue) payloadBytes=\(candidate.byteCount)")
            }
            if submissionTimes.count + records.count > 1_024 { submissionTimes.removeAll(keepingCapacity: true) }
            for record in records { submissionTimes[record.recordID] = .now }
            let submittedBytes = selected.reduce(0) { $0 + $1.byteCount } + selectedCoordination.reduce(0) { $0 + $1.bytes.count }
            AccessSyncTrace.event("batch submitted", detail: "records=\(records.count) payloadBytes=\(submittedBytes) deletions=\(removals.count)")
            return CKSyncEngine.RecordZoneChangeBatch(recordsToSave: records, recordIDsToDelete: removals, atomicByZone: false)
        } catch {
            do { try checkUploadPreparation(error) } catch { return nil }
            lastFailure = cloudSyncFailure(error, fallback: .storageFailure)
            do {
                for (id, recordID) in pending {
                    try await deferUpload(id, recordID: recordID, error: error, permit: contentPermit, engine: syncEngine)
                }
            } catch {
                do { try checkUploadPreparation(error) } catch { return nil }
                suspend(.storageFailure)
            }
            return nil
        }
    }

    private func deferUpload(_ id: UUID, recordID: CKRecord.ID, error: any Error,
                             permit: ConflictPublicationPermit, engine owner: CKSyncEngine) async throws {
        try checkUploadPreparation(error)
        if error as? CloudSyncAdapterError == .accountChanged || error as? MopError == .cloudAccount {
            suspend(.accountChanged); throw CloudSyncAdapterError.accountChanged
        }
        let failure = publicationFailure(error)
        AccessSyncTrace.failure("upload deferred", operation: id, error: error)
        AccessSyncTrace.event("upload deferred", operation: id, record: recordID.recordName, detail: "failure=\(failure.rawValue)")
        let retryAfter = (error as? CKError)?.retryAfterSeconds
        let native = error as NSError
        // Only error type and numeric code; never descriptions, payloads or IDs.
        let typeName = String(reflecting: type(of: error))
        Self.logger.error("Upload preparation deferred: classification=\(failure.rawValue, privacy: .public) type=\(typeName, privacy: .public) code=\(native.code)")
        try await repository.deferContentUpload(id, account: account, failure: failure, retryAfter: retryAfter,
            jitter: Double.random(in: -1...1), permit: permit)
        // Re-add at the persisted deadline. Returning an empty batch otherwise
        // leaves the engine unaware that application preflight needs another try.
        if engine === owner { owner.state.remove(pendingRecordZoneChanges: [.saveRecord(recordID)]) }
    }

    /// Public for deterministic transport tests without CloudKit network execution.
    public func receive(_ record: CKRecord) async throws {
        try await receiveBatch([record])
    }

    private func receiveBatch(_ records: [CKRecord]) async throws {
        try checkSuspension()
        let token = identityGeneration, owner = engine
        try await validateAccount(generation: token)
        guard let contentPermit, owner != nil else { throw CloudSyncAdapterError.engineNotStarted }
        var chunk: [IncomingRecord] = [], bytes = 0
        for record in records where receiveZoneIDs.contains(record.recordID.zoneID) {
            let incoming = try record.recordID.zoneID == coordinationZoneID
                ? PreparedCoordinationRecord.materialize(record, account: account)
                : record.recordType == NativeVaultProvisioningTransport.recordType
                    ? ContentMembershipTransport.materialize(record, account: account)
                    : ContentRecordTransport.materialize(record, account: account, database: databaseName)
            let size = incoming.bytes.count + incoming.systemFields.count
            if !chunk.isEmpty && (chunk.count >= 200 || bytes + size > 8 * 1024 * 1024) {
                try await commitIncomingChunk(chunk, token: token, owner: owner, permit: contentPermit); chunk.removeAll(keepingCapacity: true); bytes = 0
            }
            chunk.append(incoming); bytes += size
        }
        if !chunk.isEmpty { try await commitIncomingChunk(chunk, token: token, owner: owner, permit: contentPermit) }
    }

    private func commitIncomingChunk(_ chunk: [IncomingRecord], token: Int, owner: CKSyncEngine?, permit: ConflictPublicationPermit) async throws {
        guard token == identityGeneration, engine === owner, !suspended else { throw CloudSyncAdapterError.operationInterrupted }
        try await repository.stageIncomingRecords(chunk, permit: permit)
        for incoming in chunk {
            AccessSyncTrace.event("record staged locally", record: incoming.recordName, detail: "type=\(incoming.recordType) payloadBytes=\(incoming.bytes.count) systemFieldBytes=\(incoming.systemFields.count)")
        }
    }

    public func processIncomingOperation(_ operation: SyncOperation) async -> SyncOperationOutcome {
        if let contentReception {
            AccessSyncTrace.event("incoming operation", operation: operation.id, detail: "kind=\(operation.kind.rawValue)")
            guard operation.account == account, operation.database == databaseName,
                  operation.vaultID != nil, operation.zoneOwner == CKCurrentUserDefaultName else { return .attention(.invalidAuthority) }
            guard engine != nil, suspension.allowsLocalProcessing, !stopping, let contentPermit else {
                let reason = "engine=\(engine != nil) suspended=\(suspended) stopping=\(stopping) permit=\(contentPermit != nil) cause=\(suspension.failure.map { String(describing: $0) } ?? "none") recoveryQueued=\(recoveryOperation != nil)"
                if lastIncomingBlockDiagnostic != reason {
                    lastIncomingBlockDiagnostic = reason
                    AccessSyncTrace.event("incoming application blocked", operation: operation.id, detail: reason)
                }
                return .retry(.transport)
            }
            lastIncomingBlockDiagnostic = nil
            let expected = identityGeneration
            do { try await validateAccount(generation: expected, allowingInboxDrain: true) }
            catch { return .retry(.authorization) }
            if operation.kind == .fetchContentVersion {
                let fetcher = ContentVersionFetcher(repository: repository, account: account) { [weak self] id in
                    guard let self else { throw CloudSyncAdapterError.operationInterrupted }
                    return try await self.fetchContentVersionRecord(id)
                }
                return await fetcher.handle(operation, permit: contentPermit)
            }
            if operation.kind == .fetchContentHead {
                let fetcher = ContentHeadFetcher(repository: repository, account: account) { [weak self] id in
                    guard let self else { throw CloudSyncAdapterError.operationInterrupted }
                    return try await self.fetchContentVersionRecord(id)
                }
                return await fetcher.handle(operation, permit: contentPermit)
            }
            if operation.kind == .fetchMembership {
                let fetcher = ContentMembershipFetcher(repository: repository, account: account, fetch: { [weak self] id in
                    guard let self else { throw CloudSyncAdapterError.operationInterrupted }
                    return try await self.fetchContentVersionRecord(id)
                }, available: contentReception.dependencyAvailable)
                return await fetcher.handle(operation, permit: contentPermit)
            }
            if [.prepareGrant, .rotateContent, .provision, .membership, .enrollment, .deletion, .recovery, .resolveConflict].contains(operation.kind) {
                guard let work = contentReception.authorizedWork else { return .authorization }
                if operation.kind == .rotateContent {
                    return await processContentRotations([operation]).first ?? .retry(.processing)
                }
                if operation.kind == .membership {
                    guard let owner = engine, !resolutionInProgress else { return .retry(.dependency) }
                    resolutionInProgress = true; generation += 1
                    let token = identityGeneration
                    await owner.cancelOperations()
                    do { try await checkContentRotationOwner(owner, generation: token) }
                    catch { await finishResolution(engine: owner, generation: token); return .retry(.authorization) }
                    let outcome = await work(operation, contentPermit)
                    await finishResolution(engine: owner, generation: token)
                    return outcome
                }
                return await work(operation, contentPermit)
            }
            guard operation.kind == .applyIncoming else { return .attention(.invalidAuthority) }
            return await contentReception.apply(operation, contentPermit)
        }
        return .attention(.invalidAuthority)
    }

    /// A security transition needs a bounded send barrier, not an engine
    /// restart. Read back the head after cancellation before superseding an old
    /// outbox: a lost acknowledgment must not be mistaken for an unsent edit.
    /// Called only with a bounded group that the durable scheduler has already
    /// checked for retry floors and dependencies. No speculative work is fetched.
    public func processContentRotations(_ operations: [SyncOperation]) async -> [SyncOperationOutcome] {
        func repeated(_ outcome: SyncOperationOutcome) -> [SyncOperationOutcome] { operations.map { _ in outcome } }
        guard !operations.isEmpty, operations.count <= DurableSyncCoordinator.rotationBatchLimit,
              Set(operations.map(\.id)).count == operations.count else { return repeated(.attention(.invalidAuthority)) }
        guard let owner = engine, !resolutionInProgress, let reception = contentReception,
              let work = reception.authorizedWork, let permit = contentPermit,
              !stopping, !suspended else { return repeated(.retry(.authorization)) }
        var pending: [(Int, SyncOperation, ItemScope)] = []
        var outcomes = repeated(.completed)
        for (index, operation) in operations.enumerated() {
            guard operation.kind == .rotateContent, operation.account == account, operation.database == databaseName,
                  let scope = try? JSONDecoder().decode(ItemScope.self, from: operation.payload),
                  scope.account == account, scope.database == databaseName, scope.database == "private",
                  scope.vaultID == operation.vaultID, scope.zoneOwner == operation.zoneOwner,
                  address(for: scope) != nil else { return repeated(.attention(.invalidAuthority)) }
            do {
                if try await repository.contentRotationSatisfied(scope: scope) {
                    AccessSyncTrace.event("rotation already satisfied", operation: operation.id, item: scope.itemID)
                } else { pending.append((index, operation, scope)) }
            } catch { outcomes[index] = .retry(.storagePressure) }
        }
        guard !pending.isEmpty else { return outcomes }
        guard Set(pending.map { $0.2.storageKey }).count == pending.count else { return repeated(.attention(.invalidAuthority)) }
        // Repository reads above can reenter this actor. Recheck before owning
        // the publication barrier, including engine identity.
        guard engine === owner, !resolutionInProgress, !stopping, !suspended else { return repeated(.retry(.authorization)) }
        resolutionInProgress = true; generation += 1
        let expected = identityGeneration
        let batchStart = ContinuousClock.now
        do {
            let cancelStart = ContinuousClock.now
            await owner.cancelOperations()
            AccessSyncTrace.elapsed("rotation engine cancellation", since: cancelStart, detail: "items=\(pending.count)")
            try await validateAccount(generation: expected)
            guard engine === owner, !stopping else { throw CloudSyncAdapterError.operationInterrupted }
            let readback = ContentRotationBatchReadback(repository: repository, account: account) { [database] ids in
                try await database.records(for: ids)
            }
            let byScope = Dictionary(uniqueKeysWithValues: pending.map { ($0.2.storageKey, $0.1) })
            for (_, operation, scope) in pending {
                AccessSyncTrace.event("rotation readback requested", operation: operation.id, item: scope.itemID)
            }
            let results = try await readback.perform(scopes: pending.map { $0.2 }, permit: permit, check: { [self] in
                try await checkContentRotationOwner(owner, generation: expected)
            }, apply: reception.apply, rotate: { scope in
                guard let operation = byScope[scope.storageKey] else { return .attention(.invalidAuthority) }
                return await work(operation, permit)
            })
            for (entry, outcome) in zip(pending, results) { outcomes[entry.0] = outcome }
        } catch {
            let outcome: SyncOperationOutcome
            if let cloud = error as? CKError { outcome = .retry(.transport, retryAfter: cloud.retryAfterSeconds) }
            else if case CloudSyncAdapterError.operationInterrupted = error { outcome = .retry(.authorization) }
            else { outcome = .retry(.transport) }
            for entry in pending { outcomes[entry.0] = outcome }
        }
        if expected == identityGeneration, engine === owner {
            resolutionInProgress = false
            let registrationStart = ContinuousClock.now
            do { try await registerPendingChanges() }
            catch { lastFailure = cloudSyncFailure(error, fallback: .storageFailure) }
            AccessSyncTrace.elapsed("rotation upload registration", since: registrationStart)
            // Give registered publications a send opportunity before the next
            // rotation batch cancels engine work for its readback barrier.
            // Failure leaves the durable publications pending for normal retry.
            if engine === owner, expected == identityGeneration, !stopping, !suspended, uploadsAllowed, !resolutionInProgress {
                let sendStart = ContinuousClock.now
                do {
                    try await validateAccount(generation: expected)
                    guard engine === owner, expected == identityGeneration, !stopping, !suspended, uploadsAllowed, !resolutionInProgress else {
                        throw CloudSyncAdapterError.operationInterrupted
                    }
                    try await owner.sendChanges()
                    AccessSyncTrace.elapsed("rotation send opportunity", since: sendStart, detail: "success=true")
                } catch {
                    lastFailure = cloudSyncFailure(error, fallback: .storageFailure)
                    AccessSyncTrace.failure("rotation send deferred", operation: pending[0].1.id, error: error)
                }
            }
        }
        AccessSyncTrace.elapsed("rotation batch total", since: batchStart, detail: "items=\(pending.count)")
        return outcomes
    }

    public func resolveContentConflict<T: Sendable>(_ expected: EncryptedItemConflict, authorization: any RepositoryWritePermit,
            commit: @Sendable (Data, any RepositoryWritePermit) async throws -> T) async throws -> T {
        guard let owner = engine, contentReception != nil, let contentPermit, !resolutionInProgress else { throw CloudSyncAdapterError.engineNotStarted }
        try authorization.withWritePermission {}; try contentPermit.withWritePermission {}
        resolutionInProgress = true; generation += 1
        let token = identityGeneration
        do {
            await owner.cancelOperations()
            try await checkContentRotationOwner(owner, generation: token)
            let scope = expected.remote.scope
            let record = try await database.record(for: CKRecord.ID(recordName: scope.itemID.uuidString,
                zoneID: CKRecordZone.ID(zoneName: SyncStoreLayout.contentZone(vault: scope.vaultID), ownerName: scope.zoneOwner)))
            let incoming = try ContentRecordTransport.materialize(record, account: account)
            guard incoming.bytes == expected.remote.ciphertext else {
                try await repository.stageIncoming(incoming, permit: contentPermit)
                throw ItemRepositoryError.staleConflict
            }
            try await checkContentRotationOwner(owner, generation: token)
            try authorization.withWritePermission {}; try contentPermit.withWritePermission {}
            let result = try await commit(incoming.systemFields, contentPermit)
            await finishResolution(engine: owner, generation: token)
            return result
        } catch {
            await finishResolution(engine: owner, generation: token)
            throw error
        }
    }

    private func checkContentRotationOwner(_ owner: CKSyncEngine, generation expected: Int) async throws {
        try await validateAccount(generation: expected)
        guard engine === owner, !stopping, resolutionInProgress else { throw CloudSyncAdapterError.operationInterrupted }
    }

    private func fetchContentVersionRecord(_ id: CKRecord.ID) async throws -> CKRecord {
        let expected = identityGeneration
        // Targeted dependencies can unblock staged records while bulk fetching
        // is paused. Their normal scope, signature, and inbox bounds still apply.
        try await validateAccount(generation: expected, allowingInboxDrain: true)
        guard engine != nil, !stopping, contentReception != nil else { throw CloudSyncAdapterError.engineNotStarted }
        guard addresses.values.contains(where: { $0.zoneID == id.zoneID }) else {
            guard let address = Self.contentAddressHints([id.zoneID]).first else { throw CloudSyncAdapterError.invalidBinding }
            AccessSyncTrace.event("direct fetch waiting for trusted zone", record: id.recordName,
                detail: "vault=\(AccessSyncTrace.token(address.vaultID.uuidString))")
            throw CloudSyncAdapterError.contentZoneUnavailable(address.vaultID)
        }
        AccessSyncTrace.event("direct fetch requested", record: id.recordName)
        let record = try await database.record(for: id)
        AccessSyncTrace.event("direct fetch returned", record: id.recordName, detail: "type=\(record.recordType)")
        try await validateAccount(generation: expected, allowingInboxDrain: true)
        return record
    }

    private func acknowledge(_ record: CKRecord) async throws {
        if record.recordType == ContentRecordKind.grant.rawValue {
            try await validateAccount(generation: identityGeneration)
            // A send receipt is targeted evidence, not a subscription to the
            // recipient's history. Apply the normal strict inbox verification.
            guard let contentPermit else { throw CloudSyncAdapterError.engineNotStarted }
            let incoming = try ContentRecordTransport.materialize(record, account: account)
            guard addresses.values.contains(where: { $0.vaultID == incoming.vaultID && $0.ownerName == incoming.zoneOwner }) else { throw CloudSyncAdapterError.invalidBinding }
            try await repository.stageIncoming(incoming, permit: contentPermit)
        } else { try await receive(record) }
    }

    private func checkSuspension() throws {
        try suspension.check()
    }

    private func suspend(_ failure: CloudSyncAdapterError) {
        // Preserve the first cause even if subsequent callbacks fail because the
        // engine is suspended. A confirmed account change always takes priority.
        let newlyFull = failure == .inboxFull && suspension.failure == nil
        suspension.record(failure)
        if !suspension.allowsLocalProcessing { contentPermit?.invalidate() }
        resolutionPermit?.invalidate()
        uploadsAllowed = false
        lastFailure = suspension.failure
        if newlyFull, let owner = engine {
            let expected = identityGeneration
            Self.logger.notice("Sync trace: inbox full; pausing transfers while local records drain")
            // Do not await cancellation inside the callback being cancelled.
            // Keep the lease and local permit until recovery restarts the engine
            // from its last durable (pre-overflow) checkpoint.
            Task {
                guard identityGeneration == expected, engine === owner, suspension.failure == .inboxFull else { return }
                await owner.cancelOperations()
            }
        }
        if failure != .accountChanged, recoveryOperation == nil {
            let operation = SyncOperation(account: account, database: databaseName, kind: .recoverTransport)
            recoveryOperation = operation.id
            let repository = repository
            Task { try? await repository.enqueue(operation) }
        }
    }

    private func validateAccount(generation expected: Int, allowingInboxDrain: Bool = false) async throws {
        guard expected == identityGeneration else { throw CloudSyncAdapterError.operationInterrupted }
        let validationStart = ContinuousClock.now
        let authorized: Bool
        do { authorized = try await accountValidator() }
        catch {
            AccessSyncTrace.elapsed("account validation", since: validationStart, detail: "success=false")
            throw error
        }
        AccessSyncTrace.elapsed("account validation", since: validationStart, detail: "success=\(authorized)")
        guard expected == identityGeneration else { throw CloudSyncAdapterError.operationInterrupted }
        guard authorized else {
            suspend(.accountChanged)
            throw CloudSyncAdapterError.accountChanged
        }
        // A callback can suspend the engine while account validation awaits.
        // A valid account must not turn that failure into an account mismatch.
        if allowingInboxDrain { try suspension.checkLocalProcessing() }
        else { try checkSuspension() }
    }

    private func repairGrantDestination(_ id: CKRecordZone.ID, zone: RecipientGrantZone, identifier: String? = nil) async throws {
        guard let contentPermit, let engine,
              let address = addresses.values.first(where: { $0.vaultID == zone.vault && $0.ownerName == id.ownerName }) else { return }
        try await validateAccount(generation: identityGeneration)
        let scope = VaultScope(account: account, vaultID: zone.vault, database: databaseName, zoneOwner: address.ownerName)
        try await repository.invalidateGrantDestination(scope: scope, recipient: zone.recipient, identifier: identifier, permit: contentPermit)
        if identifier == nil {
            // Remote deletion/missing-zone recovery must be allowed to recreate a
            // previously registered destination. This does not authorize grants.
            grantZoneRegistration.invalidate(id)
            let zones = grantZoneRegistration.newlyRequired([id])
            engine.state.add(pendingDatabaseChanges: zones.map { .saveZone(CKRecordZone(zoneID: $0)) })
        }
        _ = try await repository.requestSync(account: account, database: databaseName, reason: .manual)
    }

    private func blockZone(_ zone: CKRecordZone.ID) async throws {
        if let recipient = try? RecipientGrantZone(name: zone.zoneName) {
            try await repairGrantDestination(zone, zone: recipient)
            return
        }
        for address in addresses.values where address.zoneID == zone {
            let scope = VaultScope(account: account, vaultID: address.vaultID, database: databaseName, zoneOwner: address.ownerName)
            // A newly created vault may be discovered locally before its
            // journaled commissioning creates the zone. Do not poison that work.
            if let state = try await repository.provisioning(scope), state.phase == .controlConfirmed {
                try await repository.blockProvisioning(scope)
            }
        }
    }

    private func address(for scope: ItemScope) -> VaultCloudAddress? {
        addresses[scope.vaultID.uuidString + ":" + scope.zoneOwner]
    }

    /// The caller owns the publication lease. Never remove an asset referenced by
    /// the outbox or an outstanding native batch, including failed/conflicted work.
    private func cleanupUploadAssets(holding lease: SynchronizationLease) async throws {
        defer { withExtendedLifetime(lease) {} }
        let accountDirectory = SHA256.hash(data: Data(account.utf8)).map { String(format: "%02x", $0) }.joined()
        let root = assetDirectory.appendingPathComponent(accountDirectory)
        guard FileManager.default.fileExists(atPath: root.path) else { return }
        var pending = try await repository.pendingAssetVersions(account: account, database: databaseName)
        if contentReception?.coordination != nil {
            pending.formUnion(try await repository.pendingCoordinationAssetOperations(account: account, database: databaseName))
        }
        let keep = pending.union(activeAssetVersions)
        let directories = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        for directory in directories {
            let attributes = try directory.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            guard UUID(uuidString: directory.lastPathComponent) != nil, attributes.isDirectory == true, attributes.isSymbolicLink != true else { continue }
            let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            for file in files where file.pathExtension == "ciphertext" {
                guard let id = UUID(uuidString: String(file.lastPathComponent.prefix(36))), !keep.contains(id) else { continue }
                let values = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
                guard values.isRegularFile == true, values.isSymbolicLink != true else { continue }
                try FileManager.default.removeItem(at: file)
            }
        }
    }

}
