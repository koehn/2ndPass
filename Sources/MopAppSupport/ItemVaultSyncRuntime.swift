@preconcurrency import CloudKit
import Foundation
import OSLog
import Synchronization
import MopCore
import MopAuth
import MopSync
import MopVaultNext

/// The native account's sole scheduler. All app-owned work, including lease
/// acquisition, runs through the durable journal; CKSyncEngine owns transport.
actor ItemVaultSyncRuntime {
    private static let logger = Logger(subsystem: "com.koehn.mop", category: "CloudSync")
    typealias Enrollment = @Sendable (UUID, PreparedCoordinationRecord?, any RepositoryWritePermit) async throws -> Void
    private let account: NativeItemCloudAccount
    private let repository: EncryptedItemRepository
    private let trust: KeychainItemVaultTrustStore
    private var adapter: CloudKitSyncAdapter?
    private var adapterStartup: Task<CloudKitSyncAdapter, Error>?
    private var adapterStartupID: UUID?
    private var coordinator: DurableSyncCoordinator?
    private var loader: (@Sendable (ItemVaultSetupRecord) async throws -> ItemVaultSession?)?
    private var enrollment: Enrollment?
    private var recoveryWork: (@Sendable (SyncOperation, any RepositoryWritePermit) async -> SyncOperationOutcome)?
    private var recoveryGrant: (@Sendable (SyncOperation, GrantBackedContentSession, any RepositoryWritePermit) async -> SyncOperationOutcome?)?
    private var observers: ContentRuntimeObservers?
    private var startupRequested = false
    private var enabled = true
    private var retired = false
    nonisolated private let sessions = Mutex<[UUID: ItemVaultSession]>([:])

    init(account: NativeItemCloudAccount, repository: EncryptedItemRepository) throws {
        guard repository.layout == .contentPreview3 else { throw ContentStoreError.wrongLayout }
        self.account = account; self.repository = repository
        trust = try KeychainItemVaultTrustStore(namespace: .contentPreview3)
    }
    func setSessionLoader(_ value: @escaping @Sendable (ItemVaultSetupRecord) async throws -> ItemVaultSession?) { loader = value }
    func setEnrollmentHandler(_ value: @escaping Enrollment) { enrollment = value }
    func setRecoveryHandlers(work: @escaping @Sendable (SyncOperation, any RepositoryWritePermit) async -> SyncOperationOutcome,
                             grant: @escaping @Sendable (SyncOperation, GrantBackedContentSession, any RepositoryWritePermit) async -> SyncOperationOutcome?) {
        recoveryWork = work; recoveryGrant = grant
    }
    func refreshTrustedAddresses() async throws {
        if let adapter { try await adapter.addContentAddresses(try await inventory().map { address($0.scope.binding.vaultID) }) }
        try await wake(reason: .unlocked)
    }
    func authorizedSession(_ vault: UUID) async throws -> ItemVaultSession { try await unlocked(vault) }
    func inventory() async throws -> [ItemVaultSetupRecord] {
        try account.withWritePermission {}
        var result: [ItemVaultSetupRecord] = []
        for record in try trust.records(container: account.containerIdentifier, environment: account.environment, account: account.accountNamespace) {
            if let deletion = try await repository.deletion(record.scope.repositoryScope), deletion.phase != .prepared { continue }
            guard let receipt = try await repository.vaultInitialization(record.scope.repositoryScope) else { continue }
            guard receipt.setupID == (try record.setupID), receipt.membershipState == record.genesis else { throw MopError.vaultUntrusted }
            result.append(record)
        }
        return result
    }
    private func pin(_ id: UUID) throws -> ItemVaultSetupRecord? { try trust.load(scope: account.setupScope(vaultID: id)) }
    private func history(_ id: UUID) throws -> TrustedMembershipHistory? {
        try pin(id).map { try ItemVaultMembershipAuthority.history(record: $0, trustStore: trust, allowingDeviceRemoval: true) }
    }
    private func address(_ id: UUID) -> VaultCloudAddress { VaultCloudAddress(vaultID: id, zoneName: SyncStoreLayout.contentZone(vault: id), ownerName: CKCurrentUserDefaultName) }
    func register(session: ItemVaultSession, synchronize: Bool = false) async throws {
        guard let history = try history(session.binding.vaultID), session.contentSession != nil else { throw MopError.vaultUntrusted }
        try session.validateMembershipAuthority(digest: history.current.digest())
        let old = sessions.withLock { $0.updateValue(session, forKey: session.binding.vaultID) }
        if let old, old !== session { old.invalidate() }
        if let adapter { try await adapter.addContentAddresses([address(session.binding.vaultID)]) }
        if synchronize { try await wake(reason: .unlocked) }
    }
    func session(vaultID: UUID) throws -> ItemVaultSession {
        try account.withWritePermission {}
        guard !retired, let value = sessions.withLock({ $0[vaultID] }), value.isUnlocked else { throw MopError.authentication }
        return value
    }
    private func unlocked(_ id: UUID) async throws -> ItemVaultSession {
        if let session = try? session(vaultID: id) { return session }
        guard let record = try pin(id), let loader, let loaded = try await loader(record) else { throw MopError.authentication }
        try await register(session: loaded)
        return loaded
    }
    nonisolated func lock(vaultID: UUID? = nil) {
        let selected = sessions.withLock { values -> [ItemVaultSession] in
            if let vaultID { return values.removeValue(forKey: vaultID).map { [$0] } ?? [] }
            let result = Array(values.values); values.removeAll(); return result
        }
        selected.forEach { $0.lock() }
    }
    nonisolated func invalidate() { lock(); Task { await self.stop() } }
    func pauseNetwork() async {
        startupRequested = false
        enabled = false; adapterStartup?.cancel(); adapterStartup = nil; adapterStartupID = nil
        await adapter?.stop(); adapter = nil
    }
    func stop() async {
        retired = true; enabled = false; observers = nil; lock()
        adapterStartup?.cancel(); adapterStartup = nil; adapterStartupID = nil
        await coordinator?.stop(); coordinator = nil
        await adapter?.stop(); adapter = nil; loader = nil; enrollment = nil
    }
    private func automaticWake(_ reason: SyncWakeReason) async {
        guard enabled, !retired else { return }
        try? await wake(reason: reason)
    }
    private func ensureCoordinator() async {
        guard coordinator == nil, !retired else { return }
        observers = try? ContentRuntimeObservers(leaseURL: account.leaseURL(database: "private"), wake: { [weak self] reason in
            Task { await self?.automaticWake(reason) }
        }, retire: { [weak self] in self?.invalidate() })
        let value = DurableSyncCoordinator(repository: repository, account: account.accountNamespace,
            kinds: [.publishItem, .grant, .publishCoordination, .removeCoordination, .reconcile, .recoverTransport, .applyIncoming, .fetchContentVersion, .fetchMembership, .provision, .membership, .enrollment, .deletion, .recovery, .prepareGrant, .rotateContent, .resolveConflict],
            allowsConcurrentReconciliation: true, coalescesPublicationRegistration: true,
            dependencyAvailable: { [weak self] dependency in try await self?.dependency(dependency) ?? false }) { [weak self] operation in
                guard let self else { return .retry(.accountChanged) }
                return await self.handle(operation)
            }
        coordinator = value
        // Start asynchronously: a handler can reenter runtime during callbacks.
        Task { await value.start() }
    }
    /// Online discovery may reuse a context created by an offline status read.
    /// Ensure one durable startup request without making every discovery a wake.
    func start() async throws {
        guard !retired else { throw CloudSyncAdapterError.accountChanged }
        guard !startupRequested else { return }
        startupRequested = true
        Self.logger.notice("Sync trace: starting account coordinator for online discovery")
        do { try await wake(reason: .startup) }
        catch { startupRequested = false; throw error }
    }
    /// A bounded OS-granted execution opportunity can move public, prepared work
    /// without constructing an authenticated device or opening any secret keys.
    func runAvailableWork() async throws {
        try await wake(reason: .startup)
        guard let coordinator else { return }
        await coordinator.start()
        await coordinator.wake(reason: .foreground)
        await coordinator.waitUntilIdle()
    }

    @discardableResult func requestSync() async throws -> DurableSyncRequest {
        guard !retired else { throw CloudSyncAdapterError.accountChanged }
        enabled = true
        let request = try await repository.requestSync(account: account.accountNamespace, database: "private", reason: .manual)
        await ensureCoordinator()
        let coordinator = coordinator
        Task { await coordinator?.wake(reason: .foreground) }
        return request
    }
    func wake(reason: SyncWakeReason) async throws {
        guard !retired else { throw CloudSyncAdapterError.accountChanged }
        enabled = true
        _ = try await repository.requestSync(account: account.accountNamespace, database: "private",
            reason: reason == .networkRestored ? .networkRestored : .foreground)
        await ensureCoordinator()
        let coordinator = coordinator
        Task { await coordinator?.wake(reason: reason) }
    }
    func health() async -> AsyncStream<SyncHealthSnapshot> {
        await ensureCoordinator()
        guard let coordinator else { return AsyncStream { $0.finish() } }
        return await coordinator.health()
    }
    private func ensureAdapter() async throws -> CloudKitSyncAdapter {
        guard enabled, !retired else { throw CloudSyncAdapterError.accountChanged }
        if let startup = adapterStartup { return try await startup.value }
        if let adapter { return adapter }
        let id = UUID(), startup = Task { try await self.createAdapter() }
        adapterStartup = startup; adapterStartupID = id
        defer { if adapterStartupID == id { adapterStartup = nil; adapterStartupID = nil } }
        return try await startup.value
    }
    private func createAdapter() async throws -> CloudKitSyncAdapter {
        if let adapter { return adapter }
        let records = try await inventory()
        let reception = CloudContentReception(apply: { [weak self] operation, permit in
            guard let self else { return .retry(.accountChanged) }; return await self.apply(operation, permit: permit)
        }, dependencyAvailable: { [weak self] dependency in try await self?.dependency(dependency) ?? false },
        publicationValidator: { [weak self] upload, authority in
            guard let self else { throw CloudSyncAdapterError.accountChanged }; try await self.validate(upload, authority: authority)
        }, coordination: CloudCoordinationTransport(validate: { [weak self] record, authority in
            guard let self else { throw CloudSyncAdapterError.accountChanged }; try await self.validate(record, authority: authority)
        }, discovered: { [weak self] addresses in
            guard let self else { throw CloudSyncAdapterError.accountChanged }; try await self.discovered(addresses)
        }), authorizedWork: { [weak self] operation, permit in
            guard let self else { return .retry(.accountChanged) }; return await self.work(operation, permit: permit)
        })
        let value = try CloudKitSyncAdapter(repository: repository, database: account.container.privateCloudDatabase,
            account: account.accountNamespace, stateNamespace: "MopContent3", leaseURL: account.leaseURL(database: "private"),
            addresses: records.map { address($0.scope.binding.vaultID) }, accountValidator: account.validator, accountAuthorization: account,
            contentReception: reception)
        // Set before awaiting start so a callback can add a newly admitted zone.
        adapter = value
        do {
            try await value.start(automaticallySync: true)
            await value.setUploadsAllowed(true)
            return value
        } catch {
            await value.stop(); if adapter === value { adapter = nil }; throw error
        }
    }
    private func handle(_ operation: SyncOperation) async -> SyncOperationOutcome {
        guard enabled, !retired else { return .retry(.authorization) }
        do {
            try account.withWritePermission {}
            let engine = try await ensureAdapter()
            if [.publishItem, .grant, .publishCoordination, .removeCoordination].contains(operation.kind) {
                try await engine.registerPendingChanges()
                return .transportOwned
            }
            if [.reconcile, .recoverTransport].contains(operation.kind) {
                if operation.kind == .recoverTransport { try await engine.resumeAutomaticSync() }
                else { try await engine.requestSync() }
                if let request = try? JSONDecoder().decode(DurableSyncRequest.self, from: operation.payload) { try await repository.markSyncRequestHandled(request) }
                return .completed
            }
            return await engine.processIncomingOperation(operation)
        } catch CloudSyncAdapterError.accountChanged { await stop(); return .attention(.accountChanged) }
        catch MopError.cloudAccount { await stop(); return .attention(.accountChanged) }
        catch let error as CKError { return .retry(.transport, retryAfter: error.retryAfterSeconds) }
        catch { return .retry(.transport) }
    }
    private func dependency(_ dependency: SyncDependency) async throws -> Bool {
        if dependency.kind == .operation, let id = UUID(uuidString: dependency.identifier) {
            return try await repository.operationIsDelivered(id, account: account.accountNamespace)
        }
        guard let text = dependency.identifier.split(separator: ":").first, let id = UUID(uuidString: String(text)) else { return false }
        if dependency.kind == .authorization { return (try? session(vaultID: id)) != nil }
        guard let history = try history(id) else { return false }
        return try await GrantBackedContentInbox(repository: repository, account: account.accountNamespace).dependencyAvailable(dependency, history: history)
    }
    private func validate(_ upload: ContentUpload, authority: PublicationAuthorityChecks) async throws {
        try account.withWritePermission {}
        guard let history = try history(upload.scope.vaultID), try await repository.deletion(VaultScope(account: account.accountNamespace, vaultID: history.vault)) == nil else { throw MopError.vaultUntrusted }
        try await checkRemoteAuthority(history, checks: authority)
        try GrantBackedContentStorage.validatePublication(upload, history: history)
    }
    private func checkRemoteAuthority(_ pinned: TrustedMembershipHistory, checks: PublicationAuthorityChecks) async throws {
        let encoded = try pinned.current.encoded()
        try await checks.check(vault: pinned.vault, authority: encoded) { [weak self] in
            guard let self else { throw CloudSyncAdapterError.accountChanged }
            try await self.checkRemoteAuthority(pinned)
        }
        // Actor reentrancy can change the local pin while a read is pending.
        // A cached remote result never authorizes records against a replaced pin.
        try account.withWritePermission {}
        guard !retired, enabled else { throw CloudSyncAdapterError.accountChanged }
        guard let current = try history(pinned.vault), try current.current.encoded() == encoded else {
            throw CloudSyncAdapterError.membershipUnavailable
        }
    }
    private func checkRemoteAuthority(_ history: TrustedMembershipHistory) async throws {
        guard let provisioned = try await repository.provisioning(VaultScope(account: account.accountNamespace, vaultID: history.vault)),
              provisioned.phase == .controlConfirmed else { throw CloudSyncAdapterError.membershipUnavailable }
        let head = try await NativeVaultMembershipTransport(database: account.container.privateCloudDatabase).readHead(binding: provisioned.binding)
        try account.withWritePermission {}
        if head.bytes != (try history.current.encoded()) {
            let incoming = IncomingRecord(id: setupHash(Data((account.accountNamespace + history.vault.uuidString + "head").utf8) + head.bytes + head.systemFields),
                account: account.accountNamespace, database: "private", zoneName: SyncStoreLayout.contentZone(vault: history.vault), zoneOwner: CKCurrentUserDefaultName,
                recordName: "membership-head", recordType: NativeVaultProvisioningTransport.recordType, bytes: head.bytes, systemFields: head.systemFields, vaultID: history.vault)
            try await repository.stageIncoming(incoming, permit: account)
            throw CloudSyncAdapterError.membershipUnavailable
        }
    }
    private var coordinationInbox: GrantBackedCoordinationInbox {
        GrantBackedCoordinationInbox(repository: repository, container: account.containerIdentifier,
            environment: account.environment, account: account.accountNamespace, member: account.memberID)
    }
    private func validate(_ record: PreparedCoordinationRecord, authority: PublicationAuthorityChecks) async throws {
        try account.withWritePermission {}
        let current = try history(record.vault)
        if record.kind != .enrollmentRequest, let current { try await checkRemoteAuthority(current, checks: authority) }
        _ = try coordinationInbox.verify(record, history: current)
    }
    private func discovered(_ addresses: [VaultCloudAddress]) async throws {
        try await repository.retainContentDiscovery(account: account.accountNamespace, addresses: addresses, authorization: account)
    }
    #if DEBUG
    func debugVerifyRemoval(vault: UUID, head: Data, removed: Set<UUID>) throws -> Bool {
        guard let trusted = try history(vault) else { return false }
        let envelope = try MembershipEnvelope.decode(head)
        guard try trusted.state(forDigest: envelope.digest()) == envelope else { return false }
        return removed.isSubset(of: Set(envelope.membership.removedDevices ?? []))
    }
    #endif

    private func changedMembership(_ history: TrustedMembershipHistory) async throws {
        let coordinator = coordinator
        Task { await coordinator?.wake(reason: .dependenciesChanged) }
        if let existing = sessions.withLock({ $0[history.vault] }),
           (try? existing.validateMembershipAuthority(digest: history.current.digest())) != nil { return }
        lock(vaultID: history.vault)
        do {
            if let pin = try pin(history.vault), let loader, let loaded = try await loader(pin) {
                try await register(session: loaded)
                let coordinator = coordinator; Task { await coordinator?.wake(reason: .unlocked) }
            }
        } catch MopError.notVaultMember {
            // Revocation is successfully applied even though this device can no
            // longer open a session under the newly pinned membership.
        }
    }
    private func apply(_ operation: SyncOperation, permit: any RepositoryWritePermit) async -> SyncOperationOutcome {
        do {
            guard let id = String(data: operation.payload, encoding: .utf8),
                  let incoming = try await repository.incomingRecord(id: id, account: account.accountNamespace, database: "private"),
                  let vault = incoming.vaultID else { return .completed }
            if incoming.zoneName == SyncStoreLayout.contentCoordinationZone {
                return didApply(await coordinationInbox.handle(operation, history: try history(vault), permit: permit))
            }
            guard let record = try pin(vault), let history = try history(vault) else { return .retry(.dependency) }
            if incoming.recordType == NativeVaultProvisioningTransport.recordType {
                return didApply(await GrantBackedMembershipInbox(repository: repository, trustStore: trust, record: record,
                    committed: { [weak self] history in try await self?.changedMembership(history) }).handle(operation, permit: permit))
            }
            let comparison = (try? await unlocked(vault))?.contentSession?.comparison()
            return didApply(await GrantBackedContentInbox(repository: repository, account: account.accountNamespace)
                .handle(operation, history: history, permit: permit, comparison: comparison))
        } catch { return .retry(.dependency) }
    }
    private func didApply(_ outcome: SyncOperationOutcome) -> SyncOperationOutcome {
        // Unlike arbitrary store events, an authenticated inbox application is
        // evidence that deferred dependencies may now be available.
        if case .completed = outcome {
            let coordinator = coordinator
            Task { await coordinator?.wake(reason: .dependenciesChanged) }
        }
        return outcome
    }
    private func work(_ operation: SyncOperation, permit: any RepositoryWritePermit) async -> SyncOperationOutcome {
        do {
            guard let vault = operation.vaultID else { return .attention(.invalidAuthority) }
            switch operation.kind {
            case .provision:
                return await JournaledContentProvisioner(repository: repository, trustStore: trust,
                    transport: NativeVaultProvisioningTransport(database: account.container.privateCloudDatabase), accountValidator: account.validator).handle(operation, permit: permit)
            case .membership:
                if let current = try history(vault) {
                    let proposed: TrustedMembershipHistory
                    if let approval = try? DeviceEnrollmentApproval.decode(operation.payload) { proposed = try approval.verifiedHistory() }
                    else { proposed = try JSONDecoder().decode(ContentMembershipCommit.self, from: operation.payload).verified() }
                    if (try? current.state(forDigest: proposed.current.digest())) == nil,
                       proposed.orderedStates.dropLast().last != current.current {
                        let session = try await unlocked(vault).contentSession!
                        if try await session.reconcileMembership(operation, scope: coordinationInbox.scope(vault: vault), owner: permit) { return .retry(.dependency) }
                    }
                }
                return await JournaledContentMembership(repository: repository, trustStore: trust,
                    transport: NativeVaultMembershipTransport(database: account.container.privateCloudDatabase), scope: try account.setupScope(vaultID: vault),
                    accountValidator: account.validator, committed: { [weak self] history in try await self?.changedMembership(history) }).handle(operation, permit: permit)
            case .enrollment:
                if operation.payload.isEmpty {
                    if try await repository.vaultInitialization(account.setupScope(vaultID: vault).repositoryScope) != nil { return .completed }
                    guard let enrollment else { return .authorization }
                    try await enrollment(vault, nil, permit)
                    // Keep this request live until admission. The coordinator's
                    // bounded retry also replaces an expired signed request.
                    return .retry(.dependency)
                } else {
                    let record = try JSONDecoder().decode(PreparedCoordinationRecord.self, from: operation.payload)
                    let envelope = try coordinationInbox.verify(record, history: history(vault))
                    if [.enrollmentRequest, .enrollmentApproval, .enrollmentAcknowledgment].contains(record.kind),
                       try await repository.enrollmentReceipt(account: account.accountNamespace, vault: vault, request: record.identity) != nil { return .completed }
                    switch record.kind {
                    case .enrollmentRequest:
                        guard try pin(vault) != nil else { return .completed }
                        let session = try await unlocked(vault)
                        _ = try await session.contentSession!.prepareEnrollment(DeviceEnrollmentRequest.decode(envelope.payload),
                            scope: coordinationInbox.scope(vault: vault), owner: permit)
                    case .enrollmentApproval:
                        guard let enrollment else { return .authorization }
                        try await enrollment(vault, record, permit)
                        if try pin(vault) != nil { try await adapter?.addContentAddresses([address(vault)]) }
                    case .enrollmentAcknowledgment:
                        let acknowledgment = try JSONDecoder().decode(EnrollmentAcknowledgment.self, from: envelope.payload)
                        guard let approvalRecord = try await repository.preparedCoordination(account: account.accountNamespace, vault: vault,
                            kind: .enrollmentApproval, identity: record.identity) else { return .retry(.dependency) }
                        let approval = try DeviceEnrollmentApproval.decode(coordinationInbox.verify(approvalRecord, history: history(vault)).payload)
                        guard approval.request.identity == envelope.author, acknowledgment.approvalDigest == setupHash(approvalRecord.bytes) else { return .attention(.invalidAuthority) }
                        try permit.withWritePermission {
                            try ItemEnrollmentRequestStore(directory: account.directory.appendingPathComponent("ContentPreview3"), scope: coordinationInbox.scope(vault: vault)).removeCompleted(record.identity)
                        }
                        try await repository.completeContentEnrollment(CompletedEnrollmentReceipt(request: record.identity, vault: vault,
                            approvalDigest: acknowledgment.approvalDigest), account: account.accountNamespace, permit: permit)
                    case .grantRequest:
                        // Grant requirements are indexed against the current
                        // policy whenever content arrives or authority advances.
                        guard let history = try history(vault) else { return .retry(.dependency) }
                        let policy = try GrantBackedContentStorage.recipientPolicy(history: history)
                        let request = try JSONDecoder().decode(ContentGrantRequest.self, from: envelope.payload)
                        try await repository.reconcileContentGrantRequest(scope: account.setupScope(vaultID: vault).binding.item(request.item),
                            keyGeneration: request.keyGeneration, recipient: request.recipient, policy: policy, permit: permit)
                    default: break
                    }
                }
                return .completed
            case .deletion:
                let record = try JSONDecoder().decode(PreparedCoordinationRecord.self, from: operation.payload)
                let envelope = try coordinationInbox.verify(record, history: history(vault))
                guard let pin = try pin(vault), try VaultDeletionNotice.decode(envelope.payload).binding.genesis == pin.pinnedDigest, record.identity == vault else { return .attention(.invalidAuthority) }
                let scope = pin.scope.repositoryScope
                var state = try await repository.deletion(scope)
                if state == nil || state?.phase == .prepared || state?.phase == .publishing {
                    state = try await repository.saveDeletion(scope: scope, notice: record.bytes, phase: .committed, authorization: permit)
                }
                lock(vaultID: vault)
                try await adapter?.removeContentAddress(address(vault))
                if state?.phase == .committed {
                    try await repository.removeContentDiscovery(account: account.accountNamespace, vault: vault, publishRemoval: true, permit: permit)
                    try permit.withWritePermission {}
                    do { _ = try await account.container.privateCloudDatabase.deleteRecordZone(withID: CKRecordZone.ID(zoneName: SyncStoreLayout.contentZone(vault: vault), ownerName: CKCurrentUserDefaultName)) }
                    catch let error as CKError where error.code == .zoneNotFound || error.code == .unknownItem { }
                    try permit.withWritePermission {}
                    state = try await repository.saveDeletion(scope: scope, notice: record.bytes, phase: .cloudDeleted, authorization: permit)
                }
                if state?.phase == .cloudDeleted {
                    try permit.withWritePermission {
                        let keyScope = account.containerIdentifier + "/" + account.environment + "/content3/" + account.accountNamespace + "/" + vault.uuidString
                        try DeviceKeychain.remove(scope: keyScope, member: account.memberID)
                        try ItemEnrollmentRequestStore(directory: account.directory.appendingPathComponent("ContentPreview3"), scope: coordinationInbox.scope(vault: vault)).purge()
                    }
                    try await AutoFillPublisher().remove(vaultID: vault.uuidString)
                    _ = try await repository.saveDeletion(scope: scope, notice: record.bytes, phase: .complete, authorization: permit)
                }
                return .completed
            case .resolveConflict:
                do {
                    let (expected, replacement) = try await repository.contentConflictDecision(operation)
                    guard let history = try history(vault), let adapter else { return .retry(.dependency) }
                    let policy = try GrantBackedContentStorage.recipientPolicy(history: history)
                    if let replacement {
                        try GrantBackedContentStorage.validatePublication(ContentUpload(operationID: operation.id,
                            content: replacement.content, grant: nil, kind: .head, systemFields: nil), history: history)
                        for grant in replacement.grants {
                            try GrantBackedContentStorage.validatePublication(ContentUpload(operationID: operation.id,
                                content: replacement.content, grant: grant, kind: .grant, systemFields: nil), history: history)
                        }
                    } else {
                        try ContentEnvelope.decode(expected.remote.ciphertext, history: history, item: expected.remote.scope.itemID)
                            .verifyForPublication(history: history)
                    }
                    try await adapter.resolveContentConflict(expected, authorization: permit) { [repository] fields, owner in
                        _ = try await repository.resolveContentConflict(expected, replacement: replacement, serverSystemFields: fields,
                            policy: policy, decision: operation, permit: owner)
                    }
                    return .completed
                } catch SyncJournalError.staleOperation { return .completed }
                catch ItemRepositoryError.staleConflict { return .attention(.conflict) }
                catch ContentStoreError.staleAuthority { return .attention(.conflict) }
                catch MopError.vaultUntrusted { return .attention(.conflict) }
                catch let error as CKError { return .retry(.transport, retryAfter: error.retryAfterSeconds) }
            case .recovery:
                guard let recoveryWork else { return .authorization }
                return await recoveryWork(operation, permit)
            case .prepareGrant, .rotateContent:
                let session = try await unlocked(vault).contentSession!
                if let recoveryGrant, let result = await recoveryGrant(operation, session, permit) { return result }
                return await session.handle(operation, owner: permit, grantRequestScope: coordinationInbox.scope(vault: vault))
            default: return .attention(.invalidAuthority)
            }
        } catch MopError.authentication { return .authorization }
        catch DeviceEnrollmentFailure.expired { return .completed }
        catch { return Authentication.requiresRenewal(error) ? .authorization : .retry(.dependency) }
    }
    func reconcileDeletions() async throws { try await wake(reason: .foreground) }
    func deleteVault(_ vault: UUID) async throws -> VaultDeletionPhase {
        let scope = try account.setupScope(vaultID: vault).repositoryScope
        if let existing = try await repository.deletion(scope) { try await wake(reason: .foreground); return existing.phase }
        guard try pin(vault) != nil else { throw MopError.vaultMissing }
        let session = try await unlocked(vault)
        try await session.contentSession!.prepareDeletion(scope: coordinationInbox.scope(vault: vault), owner: account)
        try await wake(reason: .storeChanged)
        return .prepared
    }
    func approveEnrollment(_ request: DeviceEnrollmentRequest) async throws -> DeviceEnrollmentApproval {
        let session = try await unlocked(request.scope.vault)
        let record = try await session.contentSession!.prepareEnrollment(request, scope: coordinationInbox.scope(vault: request.scope.vault), owner: account)
        try await wake(reason: .unlocked)
        return try DeviceEnrollmentApproval.decode(coordinationInbox.verify(record, history: history(record.vault)).payload)
    }
}
