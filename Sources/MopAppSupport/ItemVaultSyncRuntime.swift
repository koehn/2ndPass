@preconcurrency import CloudKit
import Foundation
import OSLog
import Synchronization
import MopCore
import MopSync
import MopVaultNext

public protocol ItemVaultRuntimeDriver: Sendable {
    func start(automaticallySync: Bool) async throws
    func stop() async
    func setUploadsAllowed(_ allowed: Bool) async
    func requestForegroundSync() async throws -> DurableSyncRequest
}
extension CloudKitSyncAdapter: ItemVaultRuntimeDriver {}
public typealias ItemVaultRuntimeDriverFactory = @Sendable ([VaultCloudAddress], @escaping CloudItemValidator,
    @escaping CloudControlValidator, @escaping CloudVaultUploadEligibility) throws -> any ItemVaultRuntimeDriver

public struct ItemVaultRuntimeContext: Sendable {
    public let container: String
    public let environment: String
    public let account: String
    public let memberID: UUID
    public let leaseURL: URL
    public init(container: String, environment: String, account: String, memberID: UUID, leaseURL: URL) {
        self.container = container; self.environment = environment; self.account = account
        self.memberID = memberID; self.leaseURL = leaseURL
    }
}

/// One private-database engine for every locally trusted vault in an account.
/// Inventory comes from independent Keychain pins, never an untrusted cloud list.
/// Adding a vault pauses/rebuilds the same engine from its durable state. Public
/// verification continues while individual vault sessions are locked or unopened.
public actor ItemVaultSyncRuntime {
    private static let logger = Logger(subsystem: "com.koehn.mop", category: "CloudSync")
    private let context: ItemVaultRuntimeContext
    private let repository: EncryptedItemRepository
    private let trustStore: any ItemVaultInventoryStore
    private let accountValidator: CloudAccountValidator
    private let factory: ItemVaultRuntimeDriverFactory
    private let membershipTransport: (any VaultMembershipTransport)?
    private let accountAuthorization: any RepositoryWritePermit
    private let coordinator: VaultProvisioningCoordinator
    nonisolated private let routes: ItemVaultRuntimeRoutes
    private var activeAdmissionPermit: ConflictPublicationPermit?
    private var driver: (any ItemVaultRuntimeDriver)?
    private var addresses: [VaultCloudAddress] = []
    private var busy = false
    private var operationWaiters: [(UUID, CheckedContinuation<Void, Error>)] = []
    private var generation = 0
    private var retired = false
    private var accountObserver: RuntimeAccountObserver?
    private var requestPump: Task<Void, Never>?
    private var pendingMembershipCatchUp: Set<UUID> = []
    private var lastSetupAttempt: Int64?
    private var backgroundSyncEnabled = false
    private var sessionLoader: (@Sendable (ItemVaultSetupRecord) async throws -> ItemVaultSession?)?

    public init(context: ItemVaultRuntimeContext, repository: EncryptedItemRepository,
                trustStore: any ItemVaultInventoryStore, transport: any VaultProvisioningTransport,
                accountValidator: @escaping CloudAccountValidator,
                accountAuthorization: any RepositoryWritePermit,
                membershipTransport: (any VaultMembershipTransport)? = nil,
                driverFactory: @escaping ItemVaultRuntimeDriverFactory) throws {
        guard !context.container.isEmpty, ["Development", "Production"].contains(context.environment),
              !context.account.isEmpty else { throw ItemVaultBootstrapFailure.invalidScope }
        self.context = context; self.repository = repository; self.trustStore = trustStore
        self.accountValidator = accountValidator; factory = driverFactory
        self.membershipTransport = membershipTransport; self.accountAuthorization = accountAuthorization
        routes = ItemVaultRuntimeRoutes(account: context.account, authorization: accountAuthorization)
        coordinator = VaultProvisioningCoordinator(repository: repository, transport: transport,
            leaseURL: context.leaseURL, accountValidator: accountValidator, accountAuthorization: accountAuthorization)
    }

    public init(account: NativeItemCloudAccount, repository: EncryptedItemRepository) throws {
        let lease = try account.leaseURL(database: "private")
        let context = ItemVaultRuntimeContext(container: account.containerIdentifier, environment: account.environment,
            account: account.accountNamespace, memberID: account.memberID, leaseURL: lease)
        try self.init(context: context, repository: repository, trustStore: KeychainItemVaultTrustStore(),
            transport: NativeVaultProvisioningTransport(database: account.container.privateCloudDatabase),
            accountValidator: account.validator, accountAuthorization: account,
            membershipTransport: NativeVaultMembershipTransport(database: account.container.privateCloudDatabase)) { addresses, items, control, eligible in
                try CloudKitSyncAdapter(repository: repository, database: account.container.privateCloudDatabase,
                    account: account.accountNamespace, stateNamespace: "MopItems1", leaseURL: lease,
                    addresses: addresses, accountValidator: account.validator, validator: items,
                    controlValidator: control, uploadEligibility: eligible)
            }
    }

    /// Explicit owner approval from the authenticated same-account private relay.
    /// A crash resumes the same signed operation rather than inventing a new head.
    public func approveEnrollment(_ request: DeviceEnrollmentRequest) async throws -> DeviceEnrollmentApproval {
        let operation = try await begin(); defer { end() }
        return try await performAdmission(request, operation: operation)
    }
    private func performAdmission(_ request: DeviceEnrollmentRequest, operation: Int) async throws -> DeviceEnrollmentApproval {
        guard request.scope.container == context.container, request.scope.environment == context.environment,
              request.scope.account == context.account, request.scope.member == context.memberID,
              let transport = membershipTransport,
              let membershipStore = trustStore as? any ItemVaultMembershipTrustStore else { throw DeviceEnrollmentFailure.invalidRequest }
        let inventory = try await committedInventory()
        guard let record = inventory.first(where: { $0.scope.binding.vaultID == request.scope.vault }) else { throw MopError.notFound }
        let scope = record.scope.repositoryScope
        let session = try routes.session(request.scope.vault)
        let existingAdmission = try await repository.admission(scope: scope)
        // An exact retry must finish/replay its original durable admission, not
        // replace it with a reconnect grant after membership became visible.
        if existingAdmission?.requestID != request.id,
           let approval = try await session.reconnectApproval(request) {
            try check(operation)
            return approval
        }
        // Drain predecessors before constructing per-item successor versions.
        if let driver { _ = try await driver.requestForegroundSync(); try check(operation) }
        let previousDriver = driver; driver = nil
        await previousDriver?.stop(); try check(operation)
        let lease = try SynchronizationLease(url: context.leaseURL)
        let permission = ConflictPublicationPermit(lease: lease,
            authorization: RuntimeAdmissionAuthorization(account: accountAuthorization, session: session))
        activeAdmissionPermit = permission
        defer { permission.invalidate(); activeAdmissionPermit = nil; withExtendedLifetime(lease) {} }
        try await checkAdmission(operation, permission)
        let plan: VaultAdmissionPlan
        if let existing = try await repository.admission(scope: scope), existing.requestID == request.id {
            guard try DeviceEnrollmentApproval.decode(existing.approval).request == request else { throw DeviceEnrollmentFailure.invalidRequest }
            plan = existing
        } else {
            try request.verify()
            let prepared = try await session.prepareAdmission(request: request)
            try await checkAdmission(operation, permission)
            guard let parent = prepared.approval.history.last else { throw DeviceEnrollmentFailure.invalidApproval }
            plan = try await repository.prepareAdmission(scope: scope, requestID: request.id,
                approval: prepared.approval.encoded(), parentControl: parent.encoded(),
                successorControl: prepared.approval.successor.encoded(), expectedVersions: prepared.expectedVersions,
                versions: prepared.versions, authorization: permission)
        }
        let approval = try DeviceEnrollmentApproval.decode(plan.approval)
        guard let genesis = approval.history.first, try genesis.digest() == record.pinnedDigest else { throw DeviceEnrollmentFailure.invalidApproval }
        if plan.phase == .complete { return approval }
        guard let provisioned = try await repository.provisioning(scope), provisioned.phase == .controlConfirmed else {
            throw VaultProvisioningError.staleState
        }
        try await checkAdmission(operation, permission)
        var head = try await transport.readHead(binding: provisioned.binding)
        try await checkAdmission(operation, permission)
        if head.bytes != plan.successorControl {
            guard head.bytes == plan.parentControl else { throw VaultProvisioningError.staleState }
            try await transport.createMembership(binding: provisioned.binding, digest: approval.successor.digest(), bytes: plan.successorControl)
            try await checkAdmission(operation, permission)
            do { _ = try await transport.compareAndSwapHead(binding: provisioned.binding, bytes: plan.successorControl, expected: head) }
            catch {
                // A network error may follow a committed head update. Only exact
                // readback recovers it; a competing signed head is not overwritten.
                try await checkAdmission(operation, permission)
                let readback = try await transport.readHead(binding: provisioned.binding)
                guard readback.bytes == plan.successorControl else { throw error }
            }
            try await checkAdmission(operation, permission)
            head = try await transport.readHead(binding: provisioned.binding)
        }
        guard head.bytes == plan.successorControl else { throw VaultProvisioningError.controlMismatch }
        try await checkAdmission(operation, permission)
        let descendants = try Array(approval.history.dropFirst()).map { try $0.encoded() } + [plan.successorControl]
        try permission.withWritePermission { try membershipStore.reserveMembership(scope: record.scope, successors: descendants) }
        _ = try await repository.completeAdmission(plan, headSystemFields: head.systemFields, authorization: permission)
        // The completed local operation is durable. Old sessions may never upload
        // under the superseded membership, even if a later reopen is interrupted.
        session.invalidate()
        permission.invalidate()
        let authority = try ItemVaultPinnedAuthority(record: record, memberID: context.memberID,
            successors: membershipStore.membershipHistory(scope: record.scope))
        try routes.replaceAuthority(authority)
        if let sessionLoader, let reopened = try await sessionLoader(record) {
            try routes.register(reopened, expectedLockGeneration: routes.lockGeneration, authority: authority)
        }
        lastSetupAttempt = nil
        _ = try await repository.requestSync(account: context.account, database: "private", reason: .manual)
        return approval
    }
    private func checkAdmission(_ operation: Int, _ permission: any RepositoryWritePermit) async throws {
        try check(operation); try permission.withWritePermission {}
        guard try await accountValidator() else { throw MopError.cloudAccount }
        try check(operation); try permission.withWritePermission {}
    }

    public func changes() async -> AsyncStream<Void> { await repository.changes() }

    /// The owner may reuse an existing authenticated device context to service a
    /// newly committed vault from another process. This callback must never prompt
    /// or call back into the runtime. Returning nil defers until explicit unlock.
    public func setSessionLoader(_ loader: @escaping @Sendable (ItemVaultSetupRecord) async throws -> ItemVaultSession?) throws {
        try routes.check()
        sessionLoader = loader
    }

    public func inventory() async throws -> [ItemVaultSetupRecord] {
        try await committedInventory()
    }

    private var localRegistrationRevision = 0
    private func committedInventory() async throws -> [ItemVaultSetupRecord] {
        var complete: [ItemVaultSetupRecord] = []
        for record in try trustedRecords() {
            if let receipt = try await repository.vaultInitialization(record.scope.repositoryScope) {
                guard receipt.scope == record.scope.repositoryScope, receipt.setupID == (try record.setupID),
                      receipt.membershipState == record.genesis else { throw ItemVaultBootstrapFailure.invalidTrust }
                complete.append(record)
            }
            try routes.check(); try Task.checkCancellation()
        }
        return complete
    }

    /// Reserved but uncommitted setup pins remain recoverable with their original
    /// source archive; they never enter the sync engine's address inventory.
    public func incompleteSetups() async throws -> [ItemVaultSetupRecord] {
        let operation = try await begin(); defer { end() }
        var result: [ItemVaultSetupRecord] = []
        for record in try trustedRecords() {
            if try await repository.vaultInitialization(record.scope.repositoryScope) == nil { result.append(record) }
            try check(operation)
        }
        return result
    }

    /// Local access never queues behind commissioning or a CloudKit callback.
    public func register(session: ItemVaultSession, synchronize: Bool = false) async throws {
        let lockGeneration = routes.lockGeneration
        let inventory = try await committedInventory()
        guard let record = inventory.first(where: { $0.scope.binding == session.binding }),
              session.memberID == context.memberID else { throw ItemVaultBootstrapFailure.invalidTrust }
        try session.validateMembershipAuthority(digest: ItemVaultMembershipAuthority.history(record: record, trustStore: trustStore).current.digest())
        let wasEligible = routes.isUploadEligible(VaultScope(account: session.binding.account, vaultID: session.binding.vaultID,
            database: session.binding.database, zoneOwner: session.binding.zoneOwner))
        try routes.register(session, expectedLockGeneration: lockGeneration,
            authority: ItemVaultPinnedAuthority(record: record, memberID: context.memberID,
                successors: membershipSuccessors(record)))
        localRegistrationRevision += 1
        Task { [weak self] in await self?.updateUploadPolicy() }
        if synchronize {
            let resumed = !backgroundSyncEnabled || !wasEligible
            if resumed { lastSetupAttempt = nil }
            backgroundSyncEnabled = true
            if resumed {
                _ = try await repository.requestSync(account: context.account, database: "private", reason: .foreground)
                try routes.check()
            }
            await ensureRequestPump()
            Task { [weak self] in await self?.reconcileRequests() }
        }
    }

    public func session(vaultID: UUID) throws -> ItemVaultSession { try routes.session(vaultID) }

    public func provision(vaultID: UUID) async throws -> VaultProvisioningState {
        let operation = try await begin(); defer { end() }
        let inventory = try await refresh(operation)
        guard let record = inventory.first(where: { $0.scope.binding.vaultID == vaultID }) else { throw MopError.notFound }
        let session = try routes.session(vaultID)
        if let driver { await driver.stop(); self.driver = nil }
        try check(operation)
        let provisioner = try ItemVaultProvisioner(repository: repository, trustStore: trustStore,
            scope: record.scope, session: session, coordinator: coordinator)
        // A successful result means durable commissioning even if a later engine
        // restart fails. Starting/retrying sync is a separate explicit operation.
        return try await provisioner.provision(address: Self.address(record))
    }

    public func start() async throws {
        backgroundSyncEnabled = true
        let operation = try await begin(); defer { end() }
        let inventory = try await refresh(operation)
        try await commissionPending(inventory, operation: operation)
        _ = try await refresh(operation)
        try await catchUpMembership(inventory, operation: operation)
        try await startDriver(operation)
        await ensureRequestPump()
    }

    @discardableResult public func requestSync() async throws -> DurableSyncRequest {
        Self.logger.notice("Sync trace: runtime wake requested")
        backgroundSyncEnabled = true
        let operation = try await begin(); defer { end() }
        let wake = try await repository.requestSync(account: context.account, database: "private", reason: .manual)
        try check(operation)
        do {
            let inventory = try await refresh(operation)
            try await commissionPending(inventory, operation: operation)
            _ = try await refresh(operation)
            try await catchUpMembership(inventory, operation: operation)
            // An existing adapter may be suspended after protected storage or
            // membership was unavailable. Its foreground entry point can recover
            // from the durable token; start() deliberately rejects suspension.
            if driver == nil { try await startDriver(operation) }
            await ensureRequestPump()
            try check(operation)
            guard let driver else { throw CloudSyncAdapterError.engineNotStarted }
            Self.logger.notice("Sync trace: runtime setup complete; handing wake to driver")
            let request = try await driver.requestForegroundSync()
            try check(operation)
            await driver.setUploadsAllowed(routes.hasUnlockedSessions)
            try check(operation)
            lastSetupAttempt = request.generation
            return request
        } catch CloudSyncAdapterError.engineAlreadyOwned {
            // The owning process observes the durable request through Core Data.
            // Returning this receipt never claims CloudKit accepted the items.
            Self.logger.notice("Sync trace: runtime lease owned by another process")
            return wake
        }
    }

    /// Existing conflict resolution methods require the one lease-owning native
    /// adapter. Fake drivers intentionally cannot masquerade as a CloudKit owner.
    public func cloudAdapter() throws -> CloudKitSyncAdapter {
        try routes.check()
        guard let value = driver as? CloudKitSyncAdapter else { throw CloudSyncAdapterError.engineNotStarted }
        return value
    }

    public nonisolated func lock(vaultID: UUID? = nil) {
        routes.lock(vaultID)
        Task { await self.updateUploadPolicy() }
    }

    public nonisolated func invalidate() {
        routes.invalidate()
        Task { await self.stop() }
    }

    /// Explicit offline mode pauses transfer without retiring local sessions.
    public func pauseNetwork() async {
        backgroundSyncEnabled = false; lastSetupAttempt = nil; generation += 1
        activeAdmissionPermit?.invalidate()
        await coordinator.stop()
        let old = driver; driver = nil
        await old?.stop()
    }

    public func stop() async {
        retired = true; generation += 1; routes.invalidate()
        activeAdmissionPermit?.invalidate()
        requestPump?.cancel(); requestPump = nil
        sessionLoader = nil
        let waiting = operationWaiters; operationWaiters = []
        waiting.forEach { $0.1.resume(throwing: CloudSyncAdapterError.operationInterrupted) }
        await coordinator.stop()
        let old = driver; driver = nil
        await old?.stop()
        accountObserver = nil
    }

    private func begin() async throws -> Int {
        let requestedGeneration = generation
        var acquired = false
        defer {
            if !acquired, !busy, !operationWaiters.isEmpty { operationWaiters.removeFirst().1.resume() }
        }
        while busy {
            try routes.check(); try Task.checkCancellation()
            let id = UUID()
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { operationWaiters.append((id, $0)) }
            } onCancel: { Task { await self.cancelWaiter(id) } }
        }
        try routes.check(); try Task.checkCancellation()
        guard !retired, generation == requestedGeneration else { throw CloudSyncAdapterError.operationInterrupted }
        busy = true; acquired = true
        if accountObserver == nil {
            accountObserver = RuntimeAccountObserver { [weak self, routes] in
                routes.invalidate()
                Task { await self?.stop() }
            }
        }
        return generation
    }
    private func cancelWaiter(_ id: UUID) {
        guard let index = operationWaiters.firstIndex(where: { $0.0 == id }) else { return }
        operationWaiters.remove(at: index).1.resume(throwing: CancellationError())
    }
    private func end() {
        busy = false
        if !operationWaiters.isEmpty { operationWaiters.removeFirst().1.resume() }
        if backgroundSyncEnabled { Task { [weak self] in await self?.reconcileRequests() } }
    }
    private func check(_ expected: Int) throws {
        try routes.check(); try Task.checkCancellation()
        guard generation == expected, !retired else { throw CloudSyncAdapterError.operationInterrupted }
    }
    private func membershipSuccessors(_ record: ItemVaultSetupRecord) throws -> [Data] {
        try (trustStore as? any ItemVaultMembershipTrustStore)?.membershipHistory(scope: record.scope) ?? []
    }

    private func trustedRecords() throws -> [ItemVaultSetupRecord] {
        try routes.check()
        let records = try trustStore.records(container: context.container, environment: context.environment, account: context.account)
        guard Set(records.map { $0.scope.binding.vaultID }).count == records.count else { throw ItemVaultBootstrapFailure.invalidTrust }
        for record in records {
            guard record.scope.container == context.container, record.scope.environment == context.environment,
                  record.scope.binding.account == context.account, record.scope.binding.database == "private",
                  record.scope.binding.zoneOwner == "__defaultOwner__",
                  try trustStore.load(scope: record.scope) == record else { throw ItemVaultBootstrapFailure.invalidTrust }
            _ = try ItemVaultPinnedAuthority(record: record, memberID: context.memberID,
                successors: membershipSuccessors(record))
        }
        return records.sorted { $0.scope.binding.vaultID.uuidString < $1.scope.binding.vaultID.uuidString }
    }
    private func refresh(_ operation: Int) async throws -> [ItemVaultSetupRecord] {
        while true {
            let registrationRevision = localRegistrationRevision
            let complete = try await committedInventory()
            try check(operation)
            var next: [VaultCloudAddress] = []
            for record in complete {
                if let state = try await repository.provisioning(record.scope.repositoryScope) {
                    guard state.binding.scope == record.scope.repositoryScope,
                          state.binding.address == Self.address(record), state.binding.setupID == (try record.setupID) else { throw ItemVaultBootstrapFailure.invalidTrust }
                    let history = try ItemVaultMembershipAuthority.history(record: record, trustStore: trustStore)
                    let currentBytes = try history.current.encoded()
                    if state.controlBytes != currentBytes {
                        let old = try MembershipEnvelope.decode(state.controlBytes)
                        guard try history.state(forDigest: old.digest()) == old else { throw ItemVaultBootstrapFailure.invalidTrust }
                        // Recover a crash between immutable Keychain checkpoint
                        // and local activation. Prepared owner journals activate
                        // their ciphertext batch together in completeAdmission.
                        if state.phase == .controlConfirmed,
                           try await repository.admission(scope: record.scope.repositoryScope)?.phase != .prepared {
                            try await repository.acceptMembershipHead(scope: record.scope.repositoryScope,
                                expectedControl: state.controlBytes, control: currentBytes, headSystemFields: nil,
                                authorization: routes.authorizationPermit)
                        }
                    }
                    if state.phase == .controlConfirmed { next.append(state.binding.address) }
                }
                try check(operation)
            }
            guard registrationRevision == localRegistrationRevision else { continue }
            if next != addresses {
                if let driver { await driver.stop(); self.driver = nil }
                try check(operation)
                addresses = next
            }
            guard registrationRevision == localRegistrationRevision else { continue }
            try routes.install(complete.map { try ItemVaultPinnedAuthority(record: $0, memberID: context.memberID,
                successors: membershipSuccessors($0)) })
            return complete
        }
    }
    private func commissionPending(_ inventory: [ItemVaultSetupRecord], operation: Int) async throws {
        var pending = Set(try await repository.pendingScopes(account: context.account)
            .filter { $0.database == "private" && $0.zoneOwner == "__defaultOwner__" }.map(\.vaultID))
        var admissions: [DeviceEnrollmentRequest] = []
        for record in inventory {
            if let plan = try await repository.admission(scope: record.scope.repositoryScope), plan.phase == .prepared {
                pending.insert(record.scope.binding.vaultID)
                admissions.append(try DeviceEnrollmentApproval.decode(plan.approval).request)
            }
        }
        try check(operation)
        if let sessionLoader {
            for record in inventory where pending.contains(record.scope.binding.vaultID) {
                if let existing = try? routes.session(record.scope.binding.vaultID), existing.isUnlocked { continue }
                let lockGeneration = routes.lockGeneration
                if let session = try await sessionLoader(record) {
                    do {
                        try check(operation)
                        guard session.binding == record.scope.binding, session.memberID == context.memberID else {
                            throw ItemVaultBootstrapFailure.invalidTrust
                        }
                        try session.validateMembershipAuthority(digest: ItemVaultMembershipAuthority.history(record: record, trustStore: trustStore).current.digest())
                        try routes.register(session, expectedLockGeneration: lockGeneration)
                    } catch { session.invalidate(); throw error }
                }
                try check(operation)
            }
        }
        for request in admissions {
            if let session = try? routes.session(request.scope.vault), session.isUnlocked {
                _ = try await performAdmission(request, operation: operation)
                try check(operation)
            }
        }
        var candidates: [(ItemVaultSetupRecord, ItemVaultSession)] = []
        for record in inventory {
            let phase = try await repository.provisioning(record.scope.repositoryScope)?.phase
            try check(operation)
            if phase != .controlConfirmed && phase != .blocked,
               let session = try? routes.session(record.scope.binding.vaultID), session.isUnlocked {
                candidates.append((record, session))
            }
        }
        guard !candidates.isEmpty else { return }
        if let driver { await driver.stop(); self.driver = nil }
        try check(operation)
        for (record, session) in candidates {
            let provisioner = try ItemVaultProvisioner(repository: repository, trustStore: trustStore,
                scope: record.scope, session: session, coordinator: coordinator)
            _ = try await provisioner.provision(address: Self.address(record))
            try check(operation)
        }
    }
    private func catchUpMembership(_ inventory: [ItemVaultSetupRecord], operation: Int) async throws {
        var candidates: [ItemVaultSetupRecord] = []
        for record in inventory {
            guard try !membershipSuccessors(record).isEmpty,
                  let session = try? routes.session(record.scope.binding.vaultID), session.isUnlocked else { continue }
            let scope = record.scope.repositoryScope
            let items = try await repository.items(account: scope.account, vaultID: scope.vaultID,
                database: scope.database, zoneOwner: scope.zoneOwner)
            try check(operation)
            if try items.contains(where: { try session.requiresMembershipCatchUp($0) }) {
                candidates.append(record)
            } else {
                pendingMembershipCatchUp.remove(record.scope.binding.vaultID)
            }
        }
        // Enrollment history persists forever; it is not evidence of outstanding
        // work. Keep the live engine when all local envelopes are already current.
        // The actual preparation and commit still run under the exclusive lease.
        guard !candidates.isEmpty else { return }
        // Complete every upload callback before replacing obsolete queued versions.
        if let active = driver { driver = nil; await active.stop(); try check(operation) }
        let lease = try SynchronizationLease(url: context.leaseURL)
        defer { withExtendedLifetime(lease) {} }
        for record in candidates {
            guard let session = try? routes.session(record.scope.binding.vaultID), session.isUnlocked else { continue }
            let permission = ConflictPublicationPermit(lease: lease,
                authorization: RuntimeAdmissionAuthorization(account: accountAuthorization, session: session))
            defer { permission.invalidate() }
            try await checkAdmission(operation, permission)
            let versions = try await session.prepareMembershipCatchUp()
            for version in versions {
                try check(operation); try permission.withWritePermission {}
                do { _ = try await repository.commitMembershipCatchUp(version, authorization: permission) }
                catch ItemRepositoryError.staleLocalVersion { continue }
                catch ItemRepositoryError.unresolvedConflict { continue }
            }
            pendingMembershipCatchUp.remove(record.scope.binding.vaultID)
        }
    }
    private func ensureRequestPump() async {
        guard requestPump == nil, !retired else { return }
        let stream = await repository.changes()
        guard requestPump == nil, !retired else { return }
        requestPump = Task { [weak self] in
            for await _ in stream {
                guard !Task.isCancelled else { break }
                await self?.reconcileRequests()
            }
        }
    }
    private func reconcileRequests() async {
        guard backgroundSyncEnabled, !busy, !retired, routes.hasUnlockedSessions else { return }
        do {
            let latest = try await repository.latestSyncRequest(account: context.account, database: "private")
            guard backgroundSyncEnabled, !busy, !retired, let request = latest,
                  request.generation != lastSetupAttempt || !pendingMembershipCatchUp.isEmpty else { return }
            lastSetupAttempt = request.generation
            // The engine owns delivery/retries. This wake only resumes durable
            // commissioning before handing the same database lease to the engine.
            try await start()
        } catch {
            // Retain the durable item/outbox state, but consume this transient
            // wake. A held lease or unavailable cloud must not make end() spin.
            pendingMembershipCatchUp.removeAll()
            // A foreground request, fresh local save, or new process retries.
            // Do not turn engine-state/history commits into a polling loop.
        }
    }

    private func validateIncoming(_ version: EncryptedItemVersion, direction: CloudRecordDirection) async throws {
        do { try routes.verify(version, direction: direction) }
        catch CloudSyncAdapterError.membershipUnavailable {
            guard direction != .sending,
                  let record = try trustedRecords().first(where: { $0.scope.binding.vaultID == version.scope.vaultID }),
                  let state = try await repository.provisioning(record.scope.repositoryScope) else { throw CloudSyncAdapterError.membershipUnavailable }
            do { try await synchronizeMembership(record: record, binding: state.binding) }
            catch let error as CloudSyncAdapterError { throw error }
            catch {
                let native = error as NSError
                Self.logger.error("Membership synchronization failed: domain=\(native.domain, privacy: .public) code=\(native.code)")
                throw CloudSyncAdapterError.storageFailure
            }
            try routes.verify(version, direction: direction)
        }
        if direction != .sending, let session = try? routes.session(version.scope.vaultID),
           (try? session.requiresMembershipCatchUp(version)) == true {
            pendingMembershipCatchUp.insert(version.scope.vaultID)
        }
    }
    private func validateControl(_ binding: VaultProvisioningBinding, bytes: Data) async throws {
        try routes.check()
        guard let record = try trustedRecords().first(where: { $0.scope.repositoryScope == binding.scope }),
              binding.address == Self.address(record), binding.setupID == (try record.setupID),
              binding.controlDigest == record.pinnedDigest else { throw CloudSyncAdapterError.untrustedRecord }
        var history = try ItemVaultMembershipAuthority.history(record: record, trustStore: trustStore)
        let candidate = try MembershipEnvelope.decode(bytes)
        let digest = try candidate.digest()
        if (try? history.state(forDigest: digest)) == nil {
            try await synchronizeMembership(record: record, binding: binding)
            history = try ItemVaultMembershipAuthority.history(record: record, trustStore: trustStore)
        }
        guard let known = try? history.state(forDigest: digest), try known.encoded() == bytes else {
            // An immutable proposed successor can arrive before its CAS head.
            // Retain the engine token and retry; it has not become authority yet.
            throw CloudSyncAdapterError.membershipUnavailable
        }
        guard let state = try await repository.provisioning(binding.scope), state.binding == binding,
              state.phase == .controlConfirmed else { throw CloudSyncAdapterError.operationInterrupted }
        try routes.check()
        let current = try history.current.encoded()
        if state.controlBytes != current {
            try await repository.acceptMembershipHead(scope: binding.scope, expectedControl: state.controlBytes,
                control: current, headSystemFields: nil, authorization: routes.authorizationPermit)
        }
    }
    /// Head discovery is an ordered public-key operation. Unknown item epochs
    /// never become permanent quarantine merely because callbacks arrived first.
    private func synchronizeMembership(record: ItemVaultSetupRecord, binding: VaultProvisioningBinding) async throws {
        let operation = generation
        guard let transport = membershipTransport,
              let membershipStore = trustStore as? any ItemVaultMembershipTrustStore else { throw CloudSyncAdapterError.membershipUnavailable }
        try check(operation)
        guard try await accountValidator() else { throw MopError.cloudAccount }
        try check(operation)
        let descendants = try membershipStore.membershipHistory(scope: record.scope)
        var history = try ItemVaultMembershipAuthority.history(record: record, successors: descendants)
        let currentDigest = try history.current.digest()
        let head = try await transport.readHead(binding: binding)
        try check(operation)
        var next = try MembershipEnvelope.decode(head.bytes)
        var reversed: [MembershipEnvelope] = []
        while try next.digest() != currentDigest {
            guard next.header.generation > history.current.header.generation, reversed.count < 127,
                  let parent = next.header.parent else { throw CloudSyncAdapterError.operationInterrupted }
            reversed.append(next)
            if parent == currentDigest { break }
            let bytes = try await transport.readMembership(binding: binding, digest: parent)
            try check(operation)
            next = try MembershipEnvelope.decode(bytes)
            guard try next.digest() == parent else { throw CloudSyncAdapterError.untrustedRecord }
        }
        let additions = reversed.reversed()
        for state in additions {
            try ItemVaultMembershipAuthority.validateAddition(previous: history.current, next: state)
            try history.append(state)
        }
        let complete = try descendants + additions.map { try $0.encoded() }
        guard try history.current.encoded() == head.bytes else { throw CloudSyncAdapterError.untrustedRecord }
        guard try await accountValidator() else { throw MopError.cloudAccount }
        try check(operation)
        try routes.authorizationPermit.withWritePermission {
            try membershipStore.reserveMembership(scope: record.scope, successors: complete)
        }
        if let state = try await repository.provisioning(binding.scope) {
            // A prepared owner operation completes its journal atomically instead.
            if try await repository.admission(scope: binding.scope)?.phase != .prepared {
                try await repository.acceptMembershipHead(scope: binding.scope, expectedControl: state.controlBytes,
                    control: head.bytes, headSystemFields: head.systemFields, authorization: routes.authorizationPermit)
            }
        }
        try check(operation)
        let authority = try ItemVaultPinnedAuthority(record: record, memberID: context.memberID, successors: complete)
        if !additions.isEmpty {
            pendingMembershipCatchUp.insert(record.scope.binding.vaultID)
            let lockGeneration = routes.lockGeneration
            try routes.replaceAuthority(authority)
            if let sessionLoader, let reopened = try await sessionLoader(record) {
                do { try check(operation); try routes.register(reopened, expectedLockGeneration: lockGeneration, authority: authority) }
                catch { reopened.invalidate(); throw error }
            }
        }
    }

    private func startDriver(_ operation: Int) async throws {
        guard try await accountValidator() else { throw MopError.cloudAccount }
        try check(operation)
        if driver == nil {
            let routes = self.routes
            driver = try factory(addresses, { [weak self] version, direction in
                guard let self else { throw CloudSyncAdapterError.operationInterrupted }
                try await self.validateIncoming(version, direction: direction)
            }, { [weak self] binding, bytes in
                guard let self else { throw CloudSyncAdapterError.operationInterrupted }
                try await self.validateControl(binding, bytes: bytes)
            },
                { scope in routes.isUploadEligible(scope) })
        }
        guard let current = driver else { throw CloudSyncAdapterError.engineNotStarted }
        do {
            try await current.start(automaticallySync: true)
            try check(operation)
            await current.setUploadsAllowed(routes.hasUnlockedSessions)
            try check(operation)
        } catch {
            await current.stop()
            driver = nil
            throw error
        }
    }
    private func updateUploadPolicy() async { await driver?.setUploadsAllowed(routes.hasUnlockedSessions) }
    private static func address(_ record: ItemVaultSetupRecord) -> VaultCloudAddress {
        VaultCloudAddress(vaultID: record.scope.binding.vaultID, zoneName: "MopItems-" + record.scope.binding.vaultID.uuidString,
            ownerName: record.scope.binding.zoneOwner)
    }
    deinit {
        routes.invalidate()
        requestPump?.cancel()
        let driver = driver, coordinator = coordinator
        Task { await coordinator.stop(); await driver?.stop() }
    }
}

private final class ItemVaultRuntimeRoutes: @unchecked Sendable {
    struct State { var valid = true; var lockGeneration = 0; var authorities: [UUID: ItemVaultPinnedAuthority] = [:]; var sessions: [UUID: ItemVaultSession] = [:] }
    private let state = Mutex(State())
    private let account: String
    private let authorization: RuntimeAuthorityPermit
    var authorizationPermit: any RepositoryWritePermit { authorization }
    init(account: String, authorization: any RepositoryWritePermit) {
        self.account = account; self.authorization = RuntimeAuthorityPermit(account: authorization)
    }
    func check() throws {
        try authorization.withWritePermission {}
        guard state.withLock({ $0.valid }) else { throw CloudSyncAdapterError.operationInterrupted }
    }
    func install(_ authorities: [ItemVaultPinnedAuthority]) throws {
        try check()
        let old = try state.withLock { value -> [ItemVaultSession] in
            guard value.valid else { throw CloudSyncAdapterError.operationInterrupted }
            let next = Dictionary(uniqueKeysWithValues: authorities.map { ($0.record.scope.binding.vaultID, $0) })
            let retained = value.sessions.filter { entry in
                guard let authority = next[entry.key] else { return false }
                return value.authorities[entry.key]?.history.current == authority.history.current
            }
            let removed = value.sessions.filter { retained[$0.key] == nil }.map(\.value)
            value.sessions = retained
            value.authorities = next
            return removed
        }
        old.forEach { $0.invalidate() }
    }
    func replaceAuthority(_ authority: ItemVaultPinnedAuthority) throws {
        try check()
        let removed = state.withLock { value -> ItemVaultSession? in
            value.authorities[authority.record.scope.binding.vaultID] = authority
            return value.sessions.removeValue(forKey: authority.record.scope.binding.vaultID)
        }
        removed?.invalidate()
    }
    var lockGeneration: Int { state.withLock { $0.lockGeneration } }
    func register(_ session: ItemVaultSession, expectedLockGeneration: Int, authority: ItemVaultPinnedAuthority? = nil) throws {
        try check()
        let previous = try state.withLock { value -> ItemVaultSession? in
            guard value.valid, value.lockGeneration == expectedLockGeneration else { throw MopError.authentication }
            if let authority {
                guard authority.record.scope.binding == session.binding,
                      value.authorities[session.binding.vaultID].map({ $0.record == authority.record }) ?? true else {
                    throw ItemVaultBootstrapFailure.invalidTrust
                }
                value.authorities[session.binding.vaultID] = authority
            }
            guard value.authorities[session.binding.vaultID]?.record.scope.binding == session.binding else {
                session.invalidate()
                throw ItemVaultBootstrapFailure.invalidTrust
            }
            return value.sessions.updateValue(session, forKey: session.binding.vaultID)
        }
        if let previous, previous !== session { previous.invalidate() }
    }
    func session(_ id: UUID) throws -> ItemVaultSession {
        try check()
        guard let session = state.withLock({ $0.sessions[id] }) else { throw MopError.authentication }
        return session
    }
    var hasUnlockedSessions: Bool { state.withLock { $0.valid && $0.sessions.values.contains(where: \.isUnlocked) } }
    func isUploadEligible(_ scope: VaultScope) -> Bool {
        guard scope.account == account, scope.database == "private", scope.zoneOwner == "__defaultOwner__",
              (try? check()) != nil else { return false }
        return state.withLock { $0.valid && $0.sessions[scope.vaultID]?.isUnlocked == true }
    }
    func lock(_ id: UUID?) {
        let sessions = state.withLock { value in value.lockGeneration += 1; return id.flatMap { value.sessions[$0].map { [$0] } } ?? (id == nil ? Array(value.sessions.values) : []) }
        sessions.forEach { $0.lock() }
    }
    func invalidate() {
        authorization.invalidate()
        let sessions = state.withLock { value in value.valid = false; return Array(value.sessions.values) }
        sessions.forEach { $0.invalidate() }
    }
    func verify(_ version: EncryptedItemVersion, direction: CloudRecordDirection) throws {
        try check()
        guard let authority = state.withLock({ $0.authorities[version.scope.vaultID] }) else { throw CloudSyncAdapterError.untrustedRecord }
        try authority.verify(version)
        if case .sending = direction { try session(version.scope.vaultID).validate(version, direction: .sending) }
        try check()
    }
    func verifyControl(_ binding: VaultProvisioningBinding, bytes: Data, repository: EncryptedItemRepository) async throws {
        try check()
        guard let authority = state.withLock({ $0.authorities[binding.scope.vaultID] }),
              authority.record.scope.repositoryScope == binding.scope,
              binding.setupID == (try authority.record.setupID), binding.controlDigest == authority.record.pinnedDigest,
              bytes == authority.record.genesis else { throw CloudSyncAdapterError.untrustedRecord }
        let current: VaultProvisioningState?
        do { current = try await repository.provisioning(binding.scope) }
        catch { throw CloudSyncAdapterError.storageFailure }
        try check()
        guard let current else { throw CloudSyncAdapterError.storageFailure }
        guard current.binding == binding, current.controlBytes == bytes, current.phase == .controlConfirmed else {
            throw CloudSyncAdapterError.operationInterrupted
        }
    }
}

private final class RuntimeAccountObserver: @unchecked Sendable {
    let observer: NSObjectProtocol
    init(_ action: @escaping @Sendable () -> Void) {
        observer = NotificationCenter.default.addObserver(forName: .CKAccountChanged, object: nil, queue: nil) { _ in action() }
    }
    deinit { NotificationCenter.default.removeObserver(observer) }
}

private struct RuntimeAdmissionAuthorization: RepositoryWritePermit {
    let account: any RepositoryWritePermit
    let session: ItemVaultSession
    func withWritePermission<T>(_ body: () throws -> T) throws -> T {
        try account.withWritePermission { try session.withAdmissionPermission(body) }
    }
}

private final class RuntimeAuthorityPermit: RepositoryWritePermit, @unchecked Sendable {
    private let gate = NSLock()
    private var valid = true
    private let account: any RepositoryWritePermit
    init(account: any RepositoryWritePermit) { self.account = account }
    func invalidate() { gate.lock(); valid = false; gate.unlock() }
    func withWritePermission<T>(_ body: () throws -> T) throws -> T {
        gate.lock(); defer { gate.unlock() }
        guard valid else { throw CloudSyncAdapterError.operationInterrupted }
        return try account.withWritePermission(body)
    }
}
