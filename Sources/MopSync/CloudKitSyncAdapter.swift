@preconcurrency import CloudKit
import Foundation
import OSLog
import CryptoKit
import MopCore

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

/// Verification must authenticate the ciphertext envelope AND bind its signed identity,
/// version, predecessor and membership to every outer EncryptedItemVersion field.
/// Outgoing authorization must also refresh membership and reject stale key generations.
public typealias CloudItemValidator = @Sendable (EncryptedItemVersion, CloudRecordDirection) async throws -> Void
public typealias CloudAccountValidator = @Sendable () async throws -> Bool
public typealias CloudVaultUploadEligibility = @Sendable (VaultScope) async -> Bool

/// Local account namespaces never travel in shared records. Every recipient binds
/// the authenticated wire identity to its own account/container/database namespace.
private struct CloudItemWireEnvelope: Codable {
    let vaultID: UUID
    let itemID: UUID
    let versionID: UUID
    let baseVersionID: UUID?
    let ciphertext: Data
    let isTombstone: Bool
    let healthItemID: UUID?
    let generation: UInt64
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
    public static let recordType = "MopEncryptedItemV1"
    public static let maximumInlineBytes = 512 * 1024
    public static let assetChunkBytes = 16 * 1024 * 1024
    private static let maximumWireBytes = (EncryptedItemRepository.maximumCiphertextBytes * 4 / 3) + 16_384
    private let repository: EncryptedItemRepository
    private let database: CKDatabase
    private let account: String
    private let stateNamespace: String
    private let leaseURL: URL
    private let assetDirectory: URL
    private let validator: CloudItemValidator
    private let accountValidator: CloudAccountValidator
    private let controlValidator: CloudControlValidator?
    private let uploadEligibility: CloudVaultUploadEligibility
    private var addresses: [String: VaultCloudAddress]
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
    private var requestPump: Task<Void, Never>?
    private var lastAttemptedRequest: Int64?
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
                validator: @escaping CloudItemValidator,
                controlValidator: CloudControlValidator? = nil,
                uploadEligibility: @escaping CloudVaultUploadEligibility = { _ in true }) throws {
        guard !account.isEmpty, !stateNamespace.isEmpty,
              database.databaseScope == .private || database.databaseScope == .shared,
              Set(addresses.map(\.storageKey)).count == addresses.count,
              Set(addresses.map { $0.ownerName + ":" + $0.zoneName }).count == addresses.count else {
            throw CloudSyncAdapterError.invalidBinding
        }
        self.repository = repository
        self.database = database
        self.account = account
        self.stateNamespace = stateNamespace + ":" + (database.databaseScope == .shared ? "shared" : "private")
        self.leaseURL = leaseURL
        self.assetDirectory = leaseURL.deletingLastPathComponent().appendingPathComponent("EncryptedAssets", isDirectory: true)
        self.addresses = Dictionary(uniqueKeysWithValues: addresses.map { ($0.storageKey, $0) })
        self.validator = validator
        self.controlValidator = controlValidator
        self.uploadEligibility = uploadEligibility
        self.accountValidator = accountValidator
    }

    public func start(automaticallySync: Bool = true) async throws {
        try Task.checkCancellation()
        guard !stopping else { throw CloudSyncAdapterError.operationInterrupted }
        try checkSuspension()
        guard engine == nil else { return }
        let expectedGeneration = identityGeneration
        let acquired = try SynchronizationLease(url: leaseURL)
        guard try await accountValidator() else { throw CloudSyncAdapterError.accountChanged }
        let data = try await repository.engineState(account: account, database: stateNamespace)
        let state = try data.map { try JSONDecoder().decode(CKSyncEngine.State.Serialization.self, from: $0) }
        try Task.checkCancellation()
        guard expectedGeneration == identityGeneration, !suspended, !stopping else { throw CloudSyncAdapterError.operationInterrupted }
        var configuration = CKSyncEngine.Configuration(database: database, stateSerialization: state, delegate: self)
        configuration.automaticallySync = automaticallySync
        lease = acquired
        let startedEngine = CKSyncEngine(configuration)
        engine = startedEngine
        do {
            try await registerPendingChanges()
            let stream = await repository.changes()
            guard expectedGeneration == identityGeneration, engine === startedEngine, !suspended, !stopping else {
                throw CloudSyncAdapterError.operationInterrupted
            }
            requestPump = Task { [weak self] in
                for await _ in stream {
                    guard !Task.isCancelled else { break }
                    await self?.processDurableRequests()
                }
            }
        } catch {
            if engine === startedEngine { await stop() }
            throw error
        }
    }

    public func stop() async {
        guard !stopping else { return }
        stopping = true
        resolutionPermit?.invalidate()
        resolutionPermit = nil
        resolutionInProgress = false
        uploadsAllowed = false
        generation += 1
        identityGeneration += 1
        requestPump?.cancel()
        requestPump = nil
        lastAttemptedRequest = nil
        deferredEngineState = nil
        activeDataEvents = 0
        let oldEngine = engine
        engine = nil
        if let oldEngine { await oldEngine.cancelOperations() }
        lease = nil
        stopping = false
    }

    public func setUploadsAllowed(_ allowed: Bool) async {
        uploadsAllowed = allowed && !suspended
        generation += 1
        if !uploadsAllowed, let engine { await engine.cancelOperations() }
        if uploadsAllowed {
            do { try await registerPendingChanges() }
            catch { lastFailure = suspension.failure ?? cloudSyncFailure(error, fallback: .storageFailure) }
        }
    }

    /// Production conflict choices execute only in the process holding this
    /// database's publication lease. A requester in another process must contact
    /// that owner or start an adapter after acquiring the lease; direct repository
    /// resolution is not a substitute for quiescing outstanding publication.
    public func resolveConflictUsingRemote(_ expected: EncryptedItemConflict,
                                           authorization: any RepositoryWritePermit) async throws -> EncryptedItemVersion {
        let owner = try claimResolution(expected)
        guard let lease else { throw CloudSyncAdapterError.engineNotStarted }
        let permit = ConflictPublicationPermit(lease: lease, authorization: authorization)
        resolutionPermit = permit
        defer {
            permit.invalidate()
            if resolutionPermit === permit { resolutionPermit = nil; resolutionInProgress = false }
        }
        let expectedGeneration = identityGeneration
        try await quiesceResolution(expected, engine: owner, generation: expectedGeneration)
        let result = try await repository.resolveConflictUsingRemote(expected, authorization: permit)
        await finishResolution(engine: owner, generation: expectedGeneration)
        return result
    }

    public func resolveConflict(_ expected: EncryptedItemConflict, with resolved: EncryptedItemVersion,
                                authorization: any RepositoryWritePermit) async throws -> PendingItemMutation {
        let owner = try claimResolution(expected)
        guard let lease else { throw CloudSyncAdapterError.engineNotStarted }
        let permit = ConflictPublicationPermit(lease: lease, authorization: authorization)
        resolutionPermit = permit
        defer {
            permit.invalidate()
            if resolutionPermit === permit { resolutionPermit = nil; resolutionInProgress = false }
        }
        let expectedGeneration = identityGeneration
        try await quiesceResolution(expected, engine: owner, generation: expectedGeneration)
        try await validator(resolved, .sending)
        try await validateAccount(generation: expectedGeneration)
        guard engine === owner, resolutionInProgress, !stopping else { throw CloudSyncAdapterError.operationInterrupted }
        let result = try await repository.resolveConflict(expected, with: resolved, authorization: permit)
        await finishResolution(engine: owner, generation: expectedGeneration)
        return result
    }

    private func claimResolution(_ expected: EncryptedItemConflict) throws -> CKSyncEngine {
        guard let engine, lease != nil else { throw CloudSyncAdapterError.engineNotStarted }
        guard !suspended, !stopping, !resolutionInProgress else { throw CloudSyncAdapterError.operationInterrupted }
        guard expected.local.scope == expected.remote.scope, expected.local.scope.account == account,
              expected.local.scope.database == databaseName, address(for: expected.local.scope) != nil else {
            throw CloudSyncAdapterError.invalidBinding
        }
        resolutionInProgress = true
        generation += 1
        return engine
    }

    private func quiesceResolution(_ expected: EncryptedItemConflict, engine owner: CKSyncEngine,
                                   generation expectedGeneration: Int) async throws {
        await owner.cancelOperations()
        try await validateAccount(generation: expectedGeneration)
        guard engine === owner, resolutionInProgress, !stopping else { throw CloudSyncAdapterError.operationInterrupted }
        try await validator(expected.local, .cached)
        try await validator(expected.remote, .receiving)
        try await validateAccount(generation: expectedGeneration)
        guard engine === owner, resolutionInProgress, !stopping else { throw CloudSyncAdapterError.operationInterrupted }
        // Cancellation cannot revoke an already-submitted server write. Superseded
        // receipt/version tracking keeps a later result from silently undoing the choice.
    }

    private func finishResolution(engine owner: CKSyncEngine, generation expectedGeneration: Int) async {
        resolutionInProgress = false
        guard identityGeneration == expectedGeneration, engine === owner, !suspended, !stopping else { return }
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
        try await engine.fetchChanges(.init(scope: .zoneIDs(addresses.values.map(\.zoneID))))
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
    }

    /// Call after a durable local transaction; restart reconstructs this list from Core Data.
    public func registerPendingChanges() async throws {
        try checkSuspension()
        guard let engine else { throw CloudSyncAdapterError.engineNotStarted }
        let expectedGeneration = identityGeneration
        let pending = try await repository.pendingScopes(account: account, excludingConflicts: true)
        guard expectedGeneration == identityGeneration, self.engine === engine, !suspended else {
            throw CloudSyncAdapterError.operationInterrupted
        }
        var ids = Set<CKRecord.ID>()
        var readiness: [VaultScope: Bool] = [:]
        for scope in pending {
            // Conflict resolution re-registers the chosen durable mutation. Until
            // then keep both versions locally, not an unsendable engine entry.
            let vault = VaultScope(scope)
            if readiness[vault] == nil { readiness[vault] = try await isPublicationReady(vault) }
            if let address = address(for: scope),
               scope.database == databaseName, scope.zoneOwner == address.ownerName,
               readiness[vault] == true {
                ids.insert(CKRecord.ID(recordName: scope.itemID.uuidString, zoneID: address.zoneID))
            }
        }
        guard expectedGeneration == identityGeneration, self.engine === engine, !suspended else { throw CloudSyncAdapterError.operationInterrupted }
        let registered = Set(engine.state.pendingRecordZoneChanges.compactMap { change -> CKRecord.ID? in
            if case .saveRecord(let id) = change { return id }
            return nil
        })
        let added = ids.subtracting(registered)
        let removed = registered.subtracting(ids)
        if !added.isEmpty { engine.state.add(pendingRecordZoneChanges: added.map { .saveRecord($0) }) }
        if !removed.isEmpty { engine.state.remove(pendingRecordZoneChanges: removed.map { .saveRecord($0) }) }
    }

    /// Requesters persist a wake-up even when another process owns the engine lease.
    /// A caller may retry start after foregrounding/owner exit; there is no lease timer.
    public func requestForegroundSync() async throws -> DurableSyncRequest {
        try Task.checkCancellation()
        Self.logger.notice("Sync trace: foreground wake; enginePresent=\(self.engine != nil) suspended=\(self.suspended)")
        lastAttemptedRequest = nil
        let request = try await repository.requestSync(account: account, database: databaseName, reason: .foreground)
        if suspended {
            // Recreate from the last DURABLE token after unavailable protected
            // storage or an unreadable asset. Never resume under a different account.
            guard try await accountValidator() else { throw CloudSyncAdapterError.accountChanged }
            await stop()
            suspension = CloudSyncSuspension()
            lastFailure = nil
        }
        if engine == nil {
            do { try await start() }
            catch CloudSyncAdapterError.engineAlreadyOwned {
                // The other process observes the same durable request through
                // Core Data notifications. This result is not upload confirmation.
            }
        }
        return request
    }

    private func processDurableRequests() async {
        guard !suspended, engine != nil else { return }
        let expectedGeneration = identityGeneration
        do {
            try await registerPendingChanges()
            let requests = try await repository.pendingSyncRequests(account: account, database: databaseName)
            for request in requests {
                guard expectedGeneration == identityGeneration, !suspended, !Task.isCancelled else { return }
                guard request.generation != lastAttemptedRequest else { continue }
                lastAttemptedRequest = request.generation
                try await requestSync()
                guard expectedGeneration == identityGeneration, !suspended, !Task.isCancelled else { return }
                try await repository.markSyncRequestHandled(request)
            }
        } catch {
            // A delegate may already have suspended the adapter with a precise
            // cause. The enclosing send can then throw a generic partialFailure;
            // do not replace that diagnosis or mutate a retired engine's state.
            if expectedGeneration == identityGeneration, !suspended {
                lastFailure = cloudSyncFailure(error, fallback: .storageFailure)
            }
            // CKSyncEngine owns network retry. A new explicit request or restart
            // retries this wake-up; unrelated store events must not create a loop.
        }
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
                    catch let error as CloudSyncAdapterError { lastFailure = error }
                    catch {
                        suspend(cloudSyncFailure(error, fallback: .storageFailure))
                        throw error
                    }
                }
                for deletion in changes.deletions where deletion.recordType == NativeVaultProvisioningTransport.recordType {
                    try await validateAccount(generation: expectedGeneration)
                    try await blockZone(deletion.recordID.zoneID)
                }
                if !changes.deletions.isEmpty {
                    // Only authenticated tombstones authorize deletion of local data.
                    lastFailure = .unexpectedRemoteDeletion
                }
            case .fetchedDatabaseChanges(let changes):
                for deletion in changes.deletions {
                    try await validateAccount(generation: expectedGeneration)
                    try await blockZone(deletion.zoneID)
                }
                if !changes.deletions.isEmpty { lastFailure = .unexpectedRemoteDeletion }
            case .sentRecordZoneChanges(let changes):
                Self.logger.notice("Sync trace: sent records=\(changes.savedRecords.count) failed=\(changes.failedRecordSaves.count)")
                for saved in changes.savedRecords { try await acknowledge(saved) }
                for failure in changes.failedRecordSaves {
                    if failure.error.code == .serverRecordChanged {
                        // A conflict response is not an asset download. Fetch the
                        // complete current record before validating its ciphertext;
                        // error.serverRecord may contain asset references only.
                        try await validateAccount(generation: expectedGeneration)
                        let remote = try await Self.fetchConflictRecord(failure.record.recordID) { [database] id in
                            try await database.record(for: id)
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
        do { try await repository.saveEngineState(state, account: account, database: stateNamespace) }
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
        options.scope = .zoneIDs(addresses.values.map(\.zoneID).filter { context.options.scope.contains($0) })
        return options
    }

    public func nextRecordZoneChangeBatch(_ context: CKSyncEngine.SendChangesContext,
                                         syncEngine: CKSyncEngine) async -> CKSyncEngine.RecordZoneChangeBatch? {
        guard uploadsAllowed, !suspended, !resolutionInProgress, engine === syncEngine else { return nil }
        let expectedGeneration = generation
        do {
            guard try await accountValidator(), expectedGeneration == generation, !suspended else { return nil }
            var blocked = try await repository.conflictedScopes(account: account)
            var readiness: [VaultScope: Bool] = [:]
            for scope in try await repository.pendingScopes(account: account) {
                guard let address = address(for: scope) else { blocked.insert(scope); continue }
                let id = CKRecord.ID(recordName: scope.itemID.uuidString, zoneID: address.zoneID)
                let vault = VaultScope(scope)
                if readiness[vault] == nil {
                    let allowed = await uploadEligibility(vault)
                    readiness[vault] = allowed ? try await isPublicationReady(vault) : false
                }
                if !context.options.scope.contains(.saveRecord(id)) || readiness[vault] != true { blocked.insert(scope) }
            }
            let pending = try await repository.pendingMutationHeads(account: account, database: databaseName, excluding: blocked)
            var seen = Set<ItemScope>()
            var records: [CKRecord] = []
            var publicationVaults = Set<VaultScope>()
            var payloadBytes = 0
            for mutation in pending {
                let version = mutation.version
                guard !blocked.contains(version.scope), seen.insert(version.scope).inserted,
                      let address = address(for: version.scope), version.scope.database == databaseName,
                      version.scope.zoneOwner == address.ownerName else { continue }
                let id = CKRecord.ID(recordName: version.scope.itemID.uuidString, zoneID: address.zoneID)
                guard context.options.scope.contains(.saveRecord(id)) else { continue }
                // One large item is permitted, but never accumulate many maximum-
                // sized assets in a single batch. Small records still cap at 100.
                if !records.isEmpty, version.ciphertext.count > Self.assetChunkBytes - min(payloadBytes, Self.assetChunkBytes) { break }
                try await validator(version, .sending)
                let fields = try await repository.serverSystemFields(version.scope)
                let record = try Self.makeRecord(version, address: address, serverSystemFields: fields, assetDirectory: assetDirectory)
                records.append(record)
                publicationVaults.insert(VaultScope(version.scope))
                payloadBytes += version.ciphertext.count
                if records.count == 100 || payloadBytes >= Self.assetChunkBytes { break }
            }
            for vault in publicationVaults {
                guard await uploadEligibility(vault), try await isPublicationReady(vault) else { return nil }
            }
            guard expectedGeneration == generation, uploadsAllowed, !suspended, !resolutionInProgress, engine === syncEngine, !records.isEmpty else { return nil }
            return CKSyncEngine.RecordZoneChangeBatch(recordsToSave: records, atomicByZone: false)
        } catch {
            lastFailure = cloudSyncFailure(error, fallback: .untrustedRecord)
            return nil
        }
    }

    /// Public for deterministic transport tests without CloudKit network execution.
    public func receive(_ record: CKRecord) async throws {
        try checkSuspension()
        let expectedGeneration = identityGeneration
        try await validateAccount(generation: expectedGeneration)
        // Enrollment relay zones are outside this engine's trusted item inventory.
        guard addresses.values.contains(where: { $0.zoneID == record.recordID.zoneID }) else { return }
        if record.recordType == NativeVaultProvisioningTransport.recordType
            || record.recordID.recordName == "membership-head"
            || record.recordID.recordName.hasPrefix("membership-") {
            try await receiveControl(record, generation: expectedGeneration)
            return
        }
        let wireBytes: Data
        do { wireBytes = try Self.wireBytes(record) }
        catch {
            suspend(.unreadableRemoteRecord)
            throw CloudSyncAdapterError.unreadableRemoteRecord
        }
        let version: EncryptedItemVersion
        do {
            version = try decode(record, bytes: wireBytes)
            try await validator(version, .receiving)
        }
        catch CloudSyncAdapterError.membershipUnavailable {
            suspend(.membershipUnavailable)
            throw CloudSyncAdapterError.membershipUnavailable
        } catch CloudSyncAdapterError.operationInterrupted {
            suspend(.operationInterrupted)
            throw CloudSyncAdapterError.operationInterrupted
        } catch CloudSyncAdapterError.storageFailure {
            suspend(.storageFailure)
            throw CloudSyncAdapterError.storageFailure
        } catch where cloudSyncFailure(error, fallback: .untrustedRecord) == .operationInterrupted {
            // An interrupted validator has not established whether this record
            // is trustworthy. Do not quarantine it or advance the durable token.
            suspend(.operationInterrupted)
            throw CloudSyncAdapterError.operationInterrupted
        } catch {
            // Persist opaque invalid input for recovery rather than applying it or dropping
            // it while CKSyncEngine advances its change token.
            try await repository.saveEngineState(wireBytes, account: account,
                database: stateNamespace + ":quarantine:" + UUID().uuidString)
            throw CloudSyncAdapterError.untrustedRecord
        }
        try await validateAccount(generation: expectedGeneration)
        // Legacy devices may still publish signed health envelopes. They are
        // optional derived data: authenticate above, retire old local uploads,
        // and consume the cloud event without importing or merging the result.
        if version.healthItemID != nil {
            try await repository.retireHealthSynchronization(version)
            return
        }
        if let accepted = try await repository.acceptedVersion(version.scope) {
            // Authenticate the stored watermark too; an editable database column
            // alone must not decide whether a signed remote version is fresh.
            try await validator(accepted, .cached)
        }
        try await validateAccount(generation: expectedGeneration)
        let fields = Self.systemFields(record)
        let matching = try await repository.pendingMutation(matching: version)
        let firstPending = try await repository.oldestPendingMutation(scope: version.scope)
        guard expectedGeneration == identityGeneration, !suspended else { throw CloudSyncAdapterError.operationInterrupted }
        if let matching {
            do { try await repository.acknowledge(mutationID: matching.id, account: account, serverSystemFields: fields) }
            catch ItemRepositoryError.outOfOrderAcknowledgement {
                try await repository.recordConflict(remote: version, serverSystemFields: fields)
            }
        } else if firstPending?.version.baseVersionID == version.versionID {
            do { try await repository.rememberAcceptedVersion(version, serverSystemFields: fields) }
            catch ItemRepositoryError.remoteVersionConflict {
                try await repository.recordConflict(remote: version, serverSystemFields: fields)
            }
        } else if firstPending != nil {
            try await repository.recordConflict(remote: version, serverSystemFields: fields)
        } else {
            do { try await repository.applyRemote(version, serverSystemFields: fields) }
            catch ItemRepositoryError.remoteVersionConflict {
                // A valid signature does not prove freshness. Preserve replays and
                // equal-generation forks; higher signed generations allow catch-up
                // when CloudKit coalesces intermediate item versions.
                try await repository.recordConflict(remote: version, serverSystemFields: fields)
            } catch ItemRepositoryError.pendingLocalChanges {
                // A local save may have committed during the repository await.
                try await repository.recordConflict(remote: version, serverSystemFields: fields)
            } catch ItemRepositoryError.unresolvedConflict {
                try await repository.recordConflict(remote: version, serverSystemFields: fields)
            }
        }
    }

    private func acknowledge(_ record: CKRecord) async throws {
        let expectedGeneration = identityGeneration
        try await validateAccount(generation: expectedGeneration)
        let version = try decode(record)
        if let mutation = try await repository.pendingMutation(matching: version) {
            guard expectedGeneration == identityGeneration, !suspended else { throw CloudSyncAdapterError.operationInterrupted }
            do { try await repository.acknowledge(mutationID: mutation.id, account: account, serverSystemFields: Self.systemFields(record)) }
            catch ItemRepositoryError.outOfOrderAcknowledgement {
                try await repository.recordConflict(remote: version, serverSystemFields: Self.systemFields(record))
            }
        }
    }

    private func checkSuspension() throws {
        try suspension.check()
    }

    private func suspend(_ failure: CloudSyncAdapterError) {
        // Preserve the first cause even if subsequent callbacks fail because the
        // engine is suspended. A confirmed account change always takes priority.
        suspension.record(failure)
        resolutionPermit?.invalidate()
        uploadsAllowed = false
        lastFailure = suspension.failure
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

    private func decode(_ record: CKRecord, bytes: Data? = nil) throws -> EncryptedItemVersion {
        guard record.recordType == Self.recordType else { throw CloudSyncAdapterError.malformedRecord }
        let wire = try JSONDecoder().decode(CloudItemWireEnvelope.self, from: bytes ?? Self.wireBytes(record))
        let version = EncryptedItemVersion(scope: ItemScope(account: account, vaultID: wire.vaultID, itemID: wire.itemID,
            database: databaseName, zoneOwner: record.recordID.zoneID.ownerName),
            versionID: wire.versionID, baseVersionID: wire.baseVersionID, ciphertext: wire.ciphertext,
            isTombstone: wire.isTombstone, generation: wire.generation, healthItemID: wire.healthItemID)
        guard let address = address(for: version.scope),
              record.recordID.zoneID == address.zoneID,
              record.recordID.recordName == version.scope.itemID.uuidString else { throw CloudSyncAdapterError.invalidBinding }
        return version
    }

    /// Missing provisioning or verifier always denies publication. Native setup
    /// confirms both history and head before this gate can open.
    public func isPublicationReady(_ scope: VaultScope) async throws -> Bool {
        try await VaultPublicationGate.isReady(scope, repository: repository, account: account,
            database: databaseName, addresses: Array(addresses.values), validator: controlValidator)
    }

    private func blockZone(_ zone: CKRecordZone.ID) async throws {
        for address in addresses.values where address.zoneID == zone {
            try await repository.blockProvisioning(VaultScope(account: account, vaultID: address.vaultID,
                database: databaseName, zoneOwner: address.ownerName))
        }
    }

    private func receiveControl(_ record: CKRecord, generation expected: Int) async throws {
        guard let address = addresses.values.first(where: { $0.zoneID == record.recordID.zoneID }) else {
            throw CloudSyncAdapterError.invalidBinding
        }
        let scope = VaultScope(account: account, vaultID: address.vaultID, database: databaseName, zoneOwner: address.ownerName)
        do {
            guard let controlValidator, let state = try await repository.provisioning(scope),
                  state.binding.address == address, state.phase == .controlConfirmed else { throw CloudSyncAdapterError.operationInterrupted }
            guard record.recordType == NativeVaultProvisioningTransport.recordType,
                  let bytes = record["membership"] as? Data, !bytes.isEmpty, bytes.count <= 512 * 1024 else {
                throw VaultProvisioningError.controlMismatch
            }
            if record.recordID.recordName != "membership-head" {
                let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
                guard record.recordID.recordName == "membership-" + digest else { throw VaultProvisioningError.controlMismatch }
            }
            try await controlValidator(state.binding, bytes)
            try await validateAccount(generation: expected)
        } catch {
            if record.recordID.recordName != "membership-head",
               (error as? CloudSyncAdapterError) == .membershipUnavailable {
                // Immutable proposals can precede the conditional head update.
                // The eventual head fetch retrieves its entire chain by digest;
                // merely observing a proposal neither grants authority nor blocks
                // fetching the head that will establish whether it was accepted.
                return
            }
            let provenMismatch = (error as? VaultProvisioningError) == .controlMismatch
                || (error as? CloudSyncAdapterError) == .untrustedRecord
            if !provenMismatch {
                // Protected storage, account retirement, and unavailable local
                // trust are not evidence that a remote authority is invalid.
                suspend(cloudSyncFailure(error, fallback: .storageFailure))
                throw suspension.failure ?? .storageFailure
            }
            do {
                try await validateAccount(generation: expected)
                if let bytes = record["membership"] as? Data {
                    try await repository.saveEngineState(bytes, account: account, database: stateNamespace + ":control-quarantine:" + UUID().uuidString)
                }
                try await repository.blockProvisioning(scope)
            } catch {
                suspend(cloudSyncFailure(error, fallback: .storageFailure))
                throw error
            }
            throw CloudSyncAdapterError.untrustedRecord
        }
    }

    private func address(for scope: ItemScope) -> VaultCloudAddress? {
        addresses[scope.vaultID.uuidString + ":" + scope.zoneOwner]
    }

    public static func makeRecord(_ version: EncryptedItemVersion, address: VaultCloudAddress,
                                  serverSystemFields: Data? = nil, assetDirectory: URL? = nil) throws -> CKRecord {
        guard address.vaultID == version.scope.vaultID, address.ownerName == version.scope.zoneOwner else { throw CloudSyncAdapterError.invalidBinding }
        guard version.ciphertext.count <= EncryptedItemRepository.maximumCiphertextBytes else { throw ItemRepositoryError.oversizedCiphertext }
        let id = CKRecord.ID(recordName: version.scope.itemID.uuidString, zoneID: address.zoneID)
        let record: CKRecord
        if let serverSystemFields {
            let decoder = try NSKeyedUnarchiver(forReadingFrom: serverSystemFields)
            decoder.requiresSecureCoding = true
            guard let existing = CKRecord(coder: decoder), existing.recordID == id,
                  existing.recordType == recordType else { throw CloudSyncAdapterError.invalidBinding }
            decoder.finishDecoding()
            record = existing
        } else { record = CKRecord(recordType: recordType, recordID: id) }
        let wire = CloudItemWireEnvelope(vaultID: version.scope.vaultID, itemID: version.scope.itemID,
            versionID: version.versionID, baseVersionID: version.baseVersionID, ciphertext: version.ciphertext,
            isTombstone: version.isTombstone, healthItemID: version.healthItemID, generation: version.generation)
        let data = try JSONEncoder().encode(wire)
        guard data.count <= maximumWireBytes else { throw ItemRepositoryError.oversizedCiphertext }
        if data.count <= maximumInlineBytes {
            record["envelope"] = data as CKRecordValue
            record["envelopeAssets"] = nil
        } else {
            guard var assetDirectory else { throw CloudSyncAdapterError.assetDirectoryRequired }
            let accountDirectory = SHA256.hash(data: Data(version.scope.account.utf8)).map { String(format: "%02x", $0) }.joined()
            assetDirectory = assetDirectory.appendingPathComponent(accountDirectory, isDirectory: true)
                .appendingPathComponent(version.scope.vaultID.uuidString, isDirectory: true)
            try LocalFile.privateDirectory(assetDirectory)
            var protection = URLResourceValues()
            protection.isExcludedFromBackup = true
            try assetDirectory.setResourceValues(protection)
            var assets: [CKAsset] = []
            for start in stride(from: 0, to: data.count, by: assetChunkBytes) {
                let chunk = data.subdata(in: start..<min(start + assetChunkBytes, data.count))
                let digest = SHA256.hash(data: chunk).map { String(format: "%02x", $0) }.joined()
                let path = assetDirectory.appendingPathComponent(version.versionID.uuidString + "-" + digest + ".ciphertext")
                if FileManager.default.fileExists(atPath: path.path) {
                    guard try LocalFile.read(path, privateFile: true, limit: assetChunkBytes) == chunk else {
                        throw CloudSyncAdapterError.invalidBinding
                    }
                } else {
                    do { try LocalFile.write(chunk, to: path) }
                    catch MopError.duplicate {
                        guard try LocalFile.read(path, privateFile: true, limit: assetChunkBytes) == chunk else {
                            throw CloudSyncAdapterError.invalidBinding
                        }
                    }
                }
                assets.append(CKAsset(fileURL: path))
            }
            record["envelope"] = nil
            record["envelopeAssets"] = assets as CKRecordValue
        }
        return record
    }

    /// Decode transport bytes only. Never apply the returned version before signature,
    /// membership, predecessor and scope validation by the application's verifier.
    public static func unverifiedVersion(from record: CKRecord, account: String, database: String,
                                         address: VaultCloudAddress) throws -> EncryptedItemVersion {
        guard record.recordType == recordType else { throw CloudSyncAdapterError.malformedRecord }
        let wire = try JSONDecoder().decode(CloudItemWireEnvelope.self, from: wireBytes(record))
        guard wire.vaultID == address.vaultID, record.recordID.zoneID == address.zoneID,
              record.recordID.recordName == wire.itemID.uuidString else { throw CloudSyncAdapterError.invalidBinding }
        return EncryptedItemVersion(scope: ItemScope(account: account, vaultID: wire.vaultID, itemID: wire.itemID,
            database: database, zoneOwner: address.ownerName), versionID: wire.versionID,
            baseVersionID: wire.baseVersionID, ciphertext: wire.ciphertext, isTombstone: wire.isTombstone,
            generation: wire.generation, healthItemID: wire.healthItemID)
    }

    /// Conflict error records are not guaranteed to carry downloaded asset files.
    /// Always retrieve the current record, including all fields/assets. A newer
    /// version arriving during the fetch is handled by normal authenticated receive.
    static func fetchConflictRecord(_ id: CKRecord.ID,
                                    fetch: (CKRecord.ID) async throws -> CKRecord) async throws -> CKRecord {
        let record = try await fetch(id)
        guard record.recordID == id, record.recordType == recordType else {
            throw CloudSyncAdapterError.invalidBinding
        }
        return record
    }

    private static func wireBytes(_ record: CKRecord) throws -> Data {
        if let data = record["envelope"] as? Data {
            guard record["envelopeAssets"] == nil, data.count <= maximumInlineBytes else { throw CloudSyncAdapterError.malformedRecord }
            return data
        }
        guard let assets = record["envelopeAssets"] as? [CKAsset], !assets.isEmpty,
              assets.count <= (maximumWireBytes + assetChunkBytes - 1) / assetChunkBytes else {
            throw CloudSyncAdapterError.malformedRecord
        }
        var result = Data()
        for asset in assets {
            guard let url = asset.fileURL else { throw CloudSyncAdapterError.malformedRecord }
            // CloudKit owns downloaded temporary files; ownership/mode is not an
            // authentication signal. LocalFile still rejects symlinks/nonregular files.
            let bytes = try LocalFile.read(url, limit: assetChunkBytes)
            guard !bytes.isEmpty, result.count <= maximumWireBytes - bytes.count else { throw CloudSyncAdapterError.malformedRecord }
            result.append(bytes)
        }
        return result
    }

    private static func systemFields(_ record: CKRecord) -> Data {
        let encoder = NSKeyedArchiver(requiringSecureCoding: true)
        record.encodeSystemFields(with: encoder)
        encoder.finishEncoding()
        return encoder.encodedData
    }
}
