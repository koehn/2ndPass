@preconcurrency import CloudKit
import Foundation
import MopCore
import OSLog
import CryptoKit

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

func publicationFailure(_ error: any Error) -> SyncFailure {
    switch error {
    case CloudSyncAdapterError.accountChanged, MopError.cloudAccount: return .accountChanged
    case CloudSyncAdapterError.membershipUnavailable, ContentStoreError.staleAuthority: return .dependency
    case MopError.authentication, MopError.vaultUntrusted, MopError.cloudPermission: return .authorization
    case is CKError, MopError.cloudUnavailable, MopError.cloudThrottled, is CancellationError: return .transport
    case SyncJournalError.inboxFull: return .storagePressure
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
    public let coordination: CloudCoordinationTransport?
    public let publicationValidator: ContentPublicationValidator?
    public let authorizedWork: (@Sendable (SyncOperation, any RepositoryWritePermit) async -> SyncOperationOutcome)?
    public let apply: @Sendable (SyncOperation, any RepositoryWritePermit) async -> SyncOperationOutcome
    public let dependencyAvailable: @Sendable (SyncDependency) async throws -> Bool
    public init(apply: @escaping @Sendable (SyncOperation, any RepositoryWritePermit) async -> SyncOperationOutcome,
                dependencyAvailable: @escaping @Sendable (SyncDependency) async throws -> Bool,
                publicationValidator: ContentPublicationValidator? = nil,
                coordination: CloudCoordinationTransport? = nil,
                authorizedWork: (@Sendable (SyncOperation, any RepositoryWritePermit) async -> SyncOperationOutcome)? = nil) {
        self.coordination = coordination
        self.apply = apply; self.dependencyAvailable = dependencyAvailable
        self.publicationValidator = publicationValidator; self.authorizedWork = authorizedWork
    }
}

// Cancellation is transport interruption, not evidence of invalid ciphertext or
// a failed disk write. Keep both Swift and CloudKit cancellation paths equivalent.
func cloudSyncFailure(_ error: any Error, fallback: CloudSyncAdapterError) -> CloudSyncAdapterError {
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
    private var receiveZoneIDs: [CKRecordZone.ID] {
        addresses.values.map(\.zoneID) + (contentReception?.coordination == nil ? [] : [coordinationZoneID])
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
        if let engine {
            let changes = engine.state.pendingRecordZoneChanges.filter {
                switch $0 { case .saveRecord(let id), .deleteRecord(let id): return id.zoneID == address.zoneID; @unknown default: return false }
            }
            engine.state.remove(pendingRecordZoneChanges: changes)
        }
    }

    private var engine: CKSyncEngine?
    private var lease: SynchronizationLease?
    private var uploadsAllowed = false
    private var suspension = CloudSyncSuspension()
    private var suspended: Bool { suspension.failure != nil }
    private var stopping = false
    private var resolutionInProgress = false
    private var resolutionPermit: ConflictPublicationPermit?
    private var generation = 0
    private var identityGeneration = 0
    private var activeAssetVersions: Set<UUID> = []
    private var activeContentAssets: [String: UUID] = [:]
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
        guard repository.layout == .contentPreview3 else {
            throw ContentStoreError.wrongLayout
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
        guard engine == nil else { return }
        let expectedGeneration = identityGeneration
        let acquired = try SynchronizationLease(url: leaseURL)
        guard try await accountValidator() else { throw CloudSyncAdapterError.accountChanged }
        try await cleanupUploadAssets(holding: acquired)
        try await repository.pruneCompletedOperations(account: account, database: databaseName)
        try await repository.pruneHistory(permit: ConflictPublicationPermit(lease: acquired, authorization: accountAuthorization))
        lastRetentionPrune = Date()
        let data = try await repository.engineState(account: account, database: stateNamespace)
        let state = try data.map { try JSONDecoder().decode(CKSyncEngine.State.Serialization.self, from: $0) }
        try Task.checkCancellation()
        guard expectedGeneration == identityGeneration, !suspended, !stopping else { throw CloudSyncAdapterError.operationInterrupted }
        var configuration = CKSyncEngine.Configuration(database: database, stateSerialization: state, delegate: self)
        configuration.automaticallySync = automaticallySync
        configuration.subscriptionID = SyncStoreLayout.contentSubscriptionID
        lease = acquired
        if contentReception != nil { contentPermit = ConflictPublicationPermit(lease: acquired, authorization: accountAuthorization) }
        let startedEngine = CKSyncEngine(configuration)
        engine = startedEngine
        if contentReception?.coordination != nil { startedEngine.state.add(pendingDatabaseChanges: [.saveZone(CKRecordZone(zoneID: coordinationZoneID))]) }
        do {
            if let coordination = contentReception?.coordination,
               try await repository.engineState(account: account, database: stateNamespace + ":inventory") == nil {
                let zones = try await database.allRecordZones()
                try await validateAccount(generation: expectedGeneration)
                try await coordination.discovered(Self.contentAddressHints(zones.map(\.zoneID)))
                try await validateAccount(generation: expectedGeneration)
                try await repository.saveEngineState(Data([1]), account: account, database: stateNamespace + ":inventory")
            }
            try await registerPendingChanges()
            guard expectedGeneration == identityGeneration, engine === startedEngine, !suspended, !stopping else {
                throw CloudSyncAdapterError.operationInterrupted
            }
        } catch {
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
        activeAssetVersions = []; activeContentAssets = [:]
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
        try Task.checkCancellation()
        try checkSuspension()
        guard let engine else { throw CloudSyncAdapterError.engineNotStarted }
        let expectedGeneration = identityGeneration
        try await validateAccount(generation: expectedGeneration)
        guard self.engine === engine else { throw CloudSyncAdapterError.operationInterrupted }
        try Task.checkCancellation()
        let pendingCount = try await repository.pendingScopes(account: account).count
        let conflictCount = try await repository.conflictedScopes(account: account).count
        Self.logger.notice("Sync trace: fetch starting; zones=\(self.addresses.count) pendingItems=\(pendingCount) conflicts=\(conflictCount) uploadsAllowed=\(self.uploadsAllowed)")
        try await engine.fetchChanges(.init(scope: .zoneIDs(receiveZoneIDs)))
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
            try await engine.sendChanges()
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
            let candidates = try await repository.contentPublications(account: account)
            guard expected == identityGeneration, self.engine === engine, !suspended else { throw CloudSyncAdapterError.operationInterrupted }
            let coordination = contentReception?.coordination == nil ? [] : try await repository.coordinationPublications(account: account)
            let removals = try await repository.coordinationRemovals(account: account).compactMap { operation -> CKSyncEngine.PendingRecordZoneChange? in
                guard let name = String(data: operation.payload, encoding: .utf8) else { throw ContentStoreError.invalidRecord }
                return .deleteRecord(CKRecord.ID(recordName: name, zoneID: coordinationZoneID))
            }
            engine.state.add(pendingRecordZoneChanges: removals)
            let ids = Set(candidates.filter { address(for: $0.scope) != nil }.map(\.recordID) + coordination.map(\.recordID))
            let registered = Set(engine.state.pendingRecordZoneChanges.compactMap { change -> CKRecord.ID? in
                if case .saveRecord(let id) = change { return id }; return nil
            })
            engine.state.add(pendingRecordZoneChanges: ids.subtracting(registered).map { .saveRecord($0) })
            engine.state.remove(pendingRecordZoneChanges: registered.subtracting(ids).map { .saveRecord($0) })

    }

    /// The account coordinator retries this same durable operation until lease
    /// reacquisition and upload restoration both succeed. No nested wake/pump.
    public func resumeAutomaticSync() async throws {
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
        guard !suspended, engine === syncEngine else { return }
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
                for change in changes.modifications {
                    guard expectedGeneration == identityGeneration, engine === syncEngine, !suspended else {
                        throw CloudSyncAdapterError.operationInterrupted
                    }
                    do { try await receive(change.record) }
                    catch let error as CloudSyncAdapterError {
                        suspend(error); throw error
                    }
                    catch {
                        suspend(cloudSyncFailure(error, fallback: .storageFailure))
                        throw error
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
                for saved in changes.savedRecords { try await acknowledge(saved) }
                if contentReception != nil, let contentPermit {
                    for id in changes.deletedRecordIDs where id.zoneID == coordinationZoneID {
                        try await repository.acknowledgeCoordinationRemoval(account: account, record: id.recordName, permit: contentPermit)
                    }
                }
                for failure in changes.failedRecordSaves {
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
                        try await receive(remote)
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
        }
        catch {
            if expectedGeneration == identityGeneration, engine === syncEngine {
                suspend(.storageFailure)
            }
        }
    }

    public func nextFetchChangesOptions(_ context: CKSyncEngine.FetchChangesContext,
                                        syncEngine: CKSyncEngine) async -> CKSyncEngine.FetchChangesOptions {
        guard engine === syncEngine, !suspended else { return .init(scope: .zoneIDs([])) }
        var options = context.options
        options.scope = .zoneIDs(receiveZoneIDs.filter { context.options.scope.contains($0) })
        return options
    }

    public func nextRecordZoneChangeBatch(_ context: CKSyncEngine.SendChangesContext,
                                         syncEngine: CKSyncEngine) async -> CKSyncEngine.RecordZoneChangeBatch? {
        guard uploadsAllowed, !suspended, !resolutionInProgress, engine === syncEngine else { return nil }
        return await nextContentBatch(context, syncEngine: syncEngine)
    }

    private func nextContentBatch(_ context: CKSyncEngine.SendChangesContext, syncEngine: CKSyncEngine) async -> CKSyncEngine.RecordZoneChangeBatch? {
        guard let validate = contentReception?.publicationValidator, let contentPermit else { return nil }
        let expected = identityGeneration, expectedUploads = generation
        var pending: [(UUID, CKRecord.ID)] = []
        do {
            let candidates = try await repository.contentPublications(account: account)
            let controls = try await repository.coordinationPublications(account: account)
            pending = candidates.map { ($0.operationID, $0.recordID) } + controls.map { ($0.operationID, $0.recordID) }
            try await validateAccount(generation: expected)
            var records: [CKRecord] = [], selected: [ContentUpload] = [], bytes = 0
            var selectedCoordination: [PreparedCoordinationRecord] = []
            let preparationAuthority = PublicationAuthorityChecks()
            if let coordination = contentReception?.coordination {
                for candidate in controls {
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
            try contentPermit.withWritePermission {}
            guard expected == identityGeneration, expectedUploads == generation, engine === syncEngine,
                  !suspended, uploadsAllowed, (!records.isEmpty || !removals.isEmpty) else { return nil }
            for candidate in selectedCoordination {
                activeAssetVersions.insert(candidate.operationID)
                activeContentAssets[candidate.recordName + ":" + SHA256.hash(data: candidate.bytes).map { String(format: "%02x", $0) }.joined()] = candidate.operationID
            }
            for candidate in selected where candidate.grant == nil {
                let key = candidate.recordID.recordName + ":" + SHA256.hash(data: candidate.content.version.ciphertext).map { String(format: "%02x", $0) }.joined()
                activeContentAssets[key] = candidate.content.version.versionID
                activeAssetVersions.insert(candidate.content.version.versionID)
            }
            return CKSyncEngine.RecordZoneChangeBatch(recordsToSave: records, recordIDsToDelete: removals, atomicByZone: false)
        } catch {
            lastFailure = cloudSyncFailure(error, fallback: .storageFailure)
            do {
                for (id, recordID) in pending {
                    try await deferUpload(id, recordID: recordID, error: error, permit: contentPermit, engine: syncEngine)
                }
            } catch { suspend(.storageFailure) }
            return nil
        }
    }

    private func deferUpload(_ id: UUID, recordID: CKRecord.ID, error: any Error,
                             permit: ConflictPublicationPermit, engine owner: CKSyncEngine) async throws {
        if error as? CloudSyncAdapterError == .accountChanged || error as? MopError == .cloudAccount {
            suspend(.accountChanged); throw CloudSyncAdapterError.accountChanged
        }
        let failure = publicationFailure(error)
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
        try checkSuspension()
        try await validateAccount(generation: identityGeneration)
        guard receiveZoneIDs.contains(record.recordID.zoneID) else { return }
            guard let contentPermit, engine != nil else { throw CloudSyncAdapterError.engineNotStarted }
            let incoming = try record.recordID.zoneID == coordinationZoneID
                ? PreparedCoordinationRecord.materialize(record, account: account)
                : record.recordType == NativeVaultProvisioningTransport.recordType
                    ? ContentMembershipTransport.materialize(record, account: account)
                    : ContentRecordTransport.materialize(record, account: account, database: databaseName)
            try await repository.stageIncoming(incoming, permit: contentPermit)

    }

    public func processIncomingOperation(_ operation: SyncOperation) async -> SyncOperationOutcome {
        if let contentReception {
            guard operation.account == account, operation.database == databaseName,
                  operation.vaultID != nil, operation.zoneOwner == CKCurrentUserDefaultName else { return .attention(.invalidAuthority) }
            guard engine != nil, !suspended, !stopping, let contentPermit else { return .retry(.transport) }
            let expected = identityGeneration
            do { try await validateAccount(generation: expected) }
            catch { return .retry(.authorization) }
            if operation.kind == .fetchContentVersion {
                let fetcher = ContentVersionFetcher(repository: repository, account: account) { [weak self] id in
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
                    return await performContentRotation(operation, permit: contentPermit, work: work)
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
    private func performContentRotation(_ operation: SyncOperation, permit: ConflictPublicationPermit,
        work: @Sendable (SyncOperation, any RepositoryWritePermit) async -> SyncOperationOutcome) async -> SyncOperationOutcome {
        guard let owner = engine, !resolutionInProgress, let reception = contentReception,
              let scope = try? JSONDecoder().decode(ItemScope.self, from: operation.payload),
              scope.account == account, scope.database == databaseName, scope.vaultID == operation.vaultID,
              scope.zoneOwner == operation.zoneOwner, address(for: scope) != nil else { return .retry(.dependency) }
        resolutionInProgress = true; generation += 1
        let expected = identityGeneration
        let outcome: SyncOperationOutcome
        do {
            await owner.cancelOperations()
            try await validateAccount(generation: expected)
            guard engine === owner, !stopping else { throw CloudSyncAdapterError.operationInterrupted }
            let readback = ContentRotationReadback(repository: repository, account: account) { [database] id in
                try await database.record(for: id)
            }
            outcome = try await readback.perform(scope: scope, permit: permit, check: { [self] in
                try await checkContentRotationOwner(owner, generation: expected)
            }, apply: reception.apply, rotate: {
                await work(operation, permit)
            })
        } catch let error as CKError { outcome = .retry(.transport, retryAfter: error.retryAfterSeconds) }
        catch CloudSyncAdapterError.operationInterrupted { outcome = .retry(.authorization) }
        catch { outcome = .retry(.transport) }
        if expected == identityGeneration, engine === owner {
            resolutionInProgress = false
            do { try await registerPendingChanges() }
            catch { lastFailure = cloudSyncFailure(error, fallback: .storageFailure) }
        }
        return outcome
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
        try await validateAccount(generation: expected)
        guard engine != nil, !stopping, contentReception != nil,
              addresses.values.contains(where: { $0.zoneID == id.zoneID }) else { throw CloudSyncAdapterError.invalidBinding }
        let record = try await database.record(for: id)
        try await validateAccount(generation: expected)
        return record
    }

    private func acknowledge(_ record: CKRecord) async throws {
        try await receive(record)
    }

    private func checkSuspension() throws {
        try suspension.check()
    }

    private func suspend(_ failure: CloudSyncAdapterError) {
        // Preserve the first cause even if subsequent callbacks fail because the
        // engine is suspended. A confirmed account change always takes priority.
        suspension.record(failure)
        contentPermit?.invalidate()
        resolutionPermit?.invalidate()
        uploadsAllowed = false
        lastFailure = suspension.failure
        if failure != .accountChanged, recoveryOperation == nil {
            let operation = SyncOperation(account: account, database: databaseName, kind: .recoverTransport)
            recoveryOperation = operation.id
            let repository = repository
            Task { try? await repository.enqueue(operation) }
        }
    }

    private func validateAccount(generation expected: Int) async throws {
        guard expected == identityGeneration else { throw CloudSyncAdapterError.operationInterrupted }
        let authorized = try await accountValidator()
        guard expected == identityGeneration else { throw CloudSyncAdapterError.operationInterrupted }
        guard authorized else {
            suspend(.accountChanged)
            throw CloudSyncAdapterError.accountChanged
        }
        // A callback can suspend the engine while account validation awaits.
        // A valid account must not turn that failure into an account mismatch.
        try checkSuspension()
    }

    private func blockZone(_ zone: CKRecordZone.ID) async throws {
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
