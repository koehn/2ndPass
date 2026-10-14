import CryptoKit
import Foundation
import OSLog
import LocalAuthentication
import Synchronization
import MopAuth
import MopCore
import MopKeychain
import MopSync
import MopVaultNext

/// Native access to the shared item store. No legacy registry or snapshot path is
/// consulted. User presence authorizes a shared context until explicit lock.
public final class NativeItemVaultServiceBackend: ItemVaultServiceBackend, @unchecked Sendable {
    private static let logger = Logger(subsystem: "com.koehn.mop", category: "Enrollment")
    private struct Context: Sendable {
        let account: NativeItemCloudAccount
        let repository: EncryptedItemRepository
        let runtime: ItemVaultSyncRuntime
        let recovery: ContentRecoveryCoordinator
    }
    private struct State: @unchecked Sendable {
        var generation = 0
        #if DEBUG
        var resettingEnrollment = false
        #endif
        var context: Context?
        var authorization: ContextInvalidator?
        var pendingAuthorization: ContextInvalidator?
        var listeners: [UUID: AsyncStream<Void>.Continuation] = [:]
        var changePump: Task<Void, Never>?
        var provisionalBootstraps: [UUID: ItemVaultBootstrap] = [:]
    }
    private let state = Mutex(State())
    private let directory: URL?
    private let gate = OperationGate()
    public init(state: URL? = nil) { directory = state }
    public func lock() {
        let resources = state.withLock { value in
            value.generation += 1
            value.authorization?.invalidate(); value.authorization = nil
            value.pendingAuthorization?.invalidate(); value.pendingAuthorization = nil
            let bootstraps = Array(value.provisionalBootstraps.values)
            value.provisionalBootstraps.removeAll()
            return (value.context, bootstraps)
        }
        resources.1.forEach { $0.lock() }
        resources.0?.recovery.lock()
        resources.0?.runtime.lock()
    }
    deinit {
        lock()
        state.withLock { $0.changePump?.cancel(); $0.listeners.values.forEach { $0.finish() } }
        if let context = state.withLock({ $0.context }) { context.runtime.invalidate() }
    }
    private func serialized<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T {
        try await gate.enter()
        do { try Task.checkCancellation(); let result = try await body(); await gate.leave(); return result }
        catch { await gate.leave(); throw error }
    }
    private func connected(offline: Bool = false) async throws -> Context {
        guard directory == nil else { throw ItemVaultServiceFailure.isolatedStateUnsupported }
        if let existing = state.withLock({ $0.context }) {
            do {
                try existing.account.withWritePermission {}
                if !offline { try await existing.runtime.start() }
                return existing
            } catch MopError.cloudAccount {
                // A retired account is never rebound in place. Drop only live
                // handles and observers; its scoped ciphertext/outbox stays put.
                let retired = state.withLock { value -> (ContextInvalidator?, ContextInvalidator?, Task<Void, Never>?, [ItemVaultBootstrap])? in
                    guard value.context?.account === existing.account else { return nil }
                    let resources = (value.authorization, value.pendingAuthorization, value.changePump, Array(value.provisionalBootstraps.values))
                    value.provisionalBootstraps.removeAll()
                    value.generation += 1
                            value.context = nil; value.authorization = nil
                    value.pendingAuthorization = nil; value.changePump = nil
                    return resources
                }
                if let retired {
                    retired.0?.invalidate(); retired.1?.invalidate(); retired.2?.cancel()
                    retired.3.forEach { $0.lock() }
                    existing.recovery.lock()
                    existing.runtime.invalidate()
                }
            }
        }
        let generation = state.withLock { $0.generation }
        let account: NativeItemCloudAccount
        if offline { account = try await NativeItemCloudAccount.connect(offline: true) }
        else {
            do { account = try await NativeItemCloudAccount.connect(offline: true) }
            catch MopError.cloudAccount { account = try await NativeItemCloudAccount.connect() }
        }
        let root = account.directory
        let repository = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root), layout: .contentPreview3)
        let runtime = try ItemVaultSyncRuntime(account: account, repository: repository)
        let context = Context(account: account, repository: repository, runtime: runtime, recovery: try ContentRecoveryCoordinator(account: account, repository: repository, runtime: runtime))
        let accepted = state.withLock { value in
            guard value.generation == generation else { return false }
            value.context = context; return true
        }
        guard accepted else { runtime.invalidate(); throw MopError.authentication }
        // Subscribe before startup can commit discovery/inventory records.
        let stream = await repository.changes()
        let pump = Task { [weak self] in
            for await _ in stream {
                guard !Task.isCancelled, let self else { break }
                _ = try? await context.recovery.progress()
                let listeners = self.state.withLock { Array($0.listeners.values) }
                listeners.forEach { $0.yield(()) }
            }
        }
        state.withLock { $0.changePump = pump }
        try await runtime.setSessionLoader { [weak self] record in
            guard let self else { return nil }
            return try await self.loadWithoutPrompt(record, account: account, repository: repository)
        }
        await runtime.setRecoveryHandlers(work: { [weak recovery = context.recovery] operation, permit in
            guard let recovery else { return .authorization }; return await recovery.handle(operation, permit: permit)
        }, grant: { [weak recovery = context.recovery] operation, session, permit in
            guard let recovery else { return nil }; return await recovery.grant(operation, session: session, permit: permit)
        })
        await runtime.setEnrollmentHandler { [weak self] vault, record, permit in
            guard let self else { throw MopError.authentication }
            try await self.progressEnrollment(vault, record: record, context: context, permit: permit)
        }
        guard state.withLock({ $0.generation == generation && $0.context?.account === account }) else { throw MopError.authentication }
        if !offline { try await runtime.start() }
        return context
    }
    public func changes() async -> AsyncStream<Void> {
        let id = UUID()
        let pair = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        state.withLock { $0.listeners[id] = pair.continuation }
        pair.continuation.onTermination = { [weak self] _ in self?.state.withLock { $0.listeners[id] = nil } }
        pair.continuation.yield(())
        return pair.stream
    }
    public func existing(_ vaultID: UUID) async -> ItemVaultSession? {
        if let context = state.withLock({ $0.context }), (try? requireNoRecovery(context)) == nil { return nil }
        guard let context = state.withLock({ $0.context }) else { return nil }
        return try? await context.runtime.session(vaultID: vaultID)
    }
    public func invalidateDiscovery() {

    }
    public var vaultDeletionAvailable: Bool {
        guard let configuration = try? SigningIdentity.cloudConfiguration() else { return false }
        if configuration.environment == "Development" { return true }
        #if MOP_VAULT_DELETION
        return true
        #else
        return false
        #endif
    }
    public func deleteVault(_ vaultID: UUID) async throws -> VaultDeletionPhase {
        guard vaultDeletionAvailable else { throw ItemVaultServiceFailure.unavailable }
        let context = try await serialized { try await self.connected() }
        let scope = try context.account.setupScope(vaultID: vaultID)
        if try await context.repository.deletion(scope.repositoryScope) == nil { _ = try await open(vaultID) }
        let phase = try await context.runtime.deleteVault(vaultID)
        invalidateDiscovery()
        return phase
    }
    public func deletionStates() async throws -> [UUID: VaultDeletionPhase] {
        guard let context = state.withLock({ $0.context }) else { return [:] }
        return Dictionary(uniqueKeysWithValues: try await context.repository.deletions(account: context.account.accountNamespace).map { ($0.scope.vaultID, $0.phase) })
    }
    public func resumeDeletions() async throws -> [UUID: VaultDeletionPhase] {
        let context = try await serialized { try await self.connected() }
        do { try await context.runtime.reconcileDeletions() }
        catch {
            let states = try await context.repository.deletions(account: context.account.accountNamespace)
            guard states.contains(where: { $0.phase != .complete }) else { throw error }
        }
        return Dictionary(uniqueKeysWithValues: try await context.repository.deletions(account: context.account.accountNamespace).map { ($0.scope.vaultID, $0.phase) })
    }
    public func discover() async throws -> ItemVaultDiscovery {
        #if DEBUG
        // A timed-out reset may have committed removal after the UI returned.
        // Resume before inventory can try opening the now-revoked identity.
        let pendingResetContext = try await serialized { try await self.connected() }
        if FileManager.default.fileExists(atPath: pendingResetContext.account.directory
            .appendingPathComponent("ContentPreview3/debug-enrollment-reset.json").path) {
            try await debugResetEnrollment()
        }
        #endif
        let local = try await inventory(offline: false)
        let context = try await serialized { try await self.connected() }
        // Discovery is also invoked for repository notifications. It must remain
        // a read: enqueueing reconciliation here feeds its own commits back into
        // discovery and keeps the locked UI perpetually busy. connected() starts
        // the account runtime; explicit lifecycle/unlock requests wake it.
        let deleted = Set(try await context.repository.deletions(account: context.account.accountNamespace).map { $0.scope.vaultID })
        let remote = try await context.repository.contentDiscovery(account: context.account.accountNamespace).filter { !deleted.contains($0.vaultID) }.map {
            VaultDescriptor(id: $0.vaultID.uuidString, name: nil, format: "mop-content-v3", enrolled: false)
        }
        let seeded = try await context.repository.engineState(account: context.account.accountNamespace, database: "MopContent3:content-v3:private:inventory") != nil
        return ItemVaultDiscovery(vaults: mergeDiscovery(local, remote), complete: seeded)
    }
    private func mergeDiscovery(_ local: [VaultDescriptor], _ remote: [VaultDescriptor]) -> [VaultDescriptor] {
        let ids = Set(local.map(\.id))
        return local + remote.filter { !ids.contains($0.id) }
    }
    public func inventory() async throws -> [VaultDescriptor] { try await inventory(offline: false) }
    public func inventory(offline: Bool) async throws -> [VaultDescriptor] {
        try await serialized { [self] in
            let context = try await connected(offline: offline)
            let records = try await context.runtime.inventory()
            var result: [VaultDescriptor] = []
            for record in records {
                let id = record.scope.binding.vaultID
                var name = record.name
                guard try await context.repository.vaultInitialization(record.scope.repositoryScope) != nil else {
                    result.append(VaultDescriptor(id: id.uuidString, name: name, format: "mop-content-v3", enrolled: false))
                    continue
                }
                if let existing = try? await context.runtime.session(vaultID: id), existing.isUnlocked {
                    do { name = try await existing.vaultMetadata().value.name }
                    catch ItemVaultSessionFailure.missingVaultMetadata { }
                    catch CloudSyncAdapterError.membershipUnavailable { }
                    catch MopError.authentication where !existing.isUnlocked {
                        // Membership replacement can retire a name read in flight.
                        // The independently pinned name remains a valid discovery label.
                    }
                } else if let session = try await loadWithoutPrompt(record, account: context.account, repository: context.repository) {
                    do { name = try await session.vaultMetadata().value.name }
                    catch ItemVaultSessionFailure.missingVaultMetadata { }
                    catch CloudSyncAdapterError.membershipUnavailable { }
                    try await context.runtime.register(session: session)
                }
                result.append(VaultDescriptor(id: id.uuidString, name: name, format: "mop-content-v3", enrolled: true))
            }
            return result.sorted { ($0.name ?? "", $0.id) < ($1.name ?? "", $1.id) }
        }
    }
    /// Explicit user selection may authenticate to resolve an encrypted current
    /// name. Discovery and cached reads never call this method.
    public func resolveVault(named name: String, offline: Bool) async throws -> UUID? {
        try await serialized { [self] in
            let context = try await connected(offline: offline)
            try requireNoRecovery(context)
            if offline { await context.runtime.pauseNetwork() }
            var matches: [UUID] = []
            for record in try await context.runtime.inventory() {
                let id = record.scope.binding.vaultID
                let session: ItemVaultSession
                if let existing = try? await context.runtime.session(vaultID: id), existing.isUnlocked { session = existing }
                else {
                    let device = try await device(context, vaultID: id, create: false)
                    let bootstrap = try ItemVaultBootstrap(repository: context.repository, trustStore: KeychainItemVaultTrustStore(namespace: .contentPreview3), scope: record.scope, device: device)
                    session = try await context.runtime.register(session: bootstrap.open(), synchronize: !offline)
                }
                if try await session.vaultMetadata().value.name == name { matches.append(id) }
            }
            guard matches.count <= 1 else { throw ItemVaultServiceFailure.ambiguousVault }
            return matches.first
        }
    }
    private func enrollmentScope(_ account: NativeItemCloudAccount, vaultID: UUID) -> EnrollmentScope {
        EnrollmentScope(container: account.containerIdentifier, environment: account.environment,
            account: account.accountNamespace, vault: vaultID, member: account.memberID)
    }
    private func checkEnrollment(_ context: Context, generation: Int, requireAuthorization: Bool = false) throws {
        try Task.checkCancellation()
        guard state.withLock({ $0.generation == generation && $0.context?.account === context.account
            && (!requireAuthorization || $0.authorization != nil) }) else { throw MopError.authentication }
        try context.account.withWritePermission {}
    }
    public func enrollment(_ action: VaultManagement, vaultID: UUID) async throws -> VaultResult {
        try await enrollment(action, vaultID: vaultID, allowPrompt: true)
    }
    private func enrollment(_ action: VaultManagement, vaultID: UUID, allowPrompt: Bool) async throws -> VaultResult {
        let context = try await serialized { try await self.connected() }
        var result = VaultResult()
        if case .removeDevice(let id) = action {
            let session = try await open(vaultID), content = session.contentSession!
            let current = content.history.current.membership
            guard let member = current.accounts.first, current.accounts.count == 1,
                  member.devices.count > 1, member.devices.contains(where: { $0.device == id }) else { throw MopError.cloudPermission }
            let updated = try Membership(accounts: [AccountMember(id: member.id, role: member.role, devices: member.devices.filter { $0.device != id })],
                offlineRecovery: current.offlineRecovery, removedDevices: Array(Set((current.removedDevices ?? []) + [id])).sorted { $0.uuidString < $1.uuidString })
            let operation = try await content.prepareMembership(updated, owner: context.account)
            _ = try await context.repository.enqueue(operation)
            try await context.runtime.wake(reason: .unlocked)
            result.deviceRemovalIncomplete = true
            result.message = "Device removal is saved. Key rotation continues automatically."
            return result
        }
        if case .devices = action {
            let session = try await open(vaultID), current = try session.currentDeviceID
            result.devices = try session.enrolledDevices.map {
                VaultDeviceRecord(id: $0.device, name: $0.device == current ? "This device" : "Device " + $0.device.uuidString.prefix(8), isCurrent: $0.device == current)
            }
            return result
        }
        switch action {
        case .automaticEnrollment, .requestEnrollment, .checkEnrollment: break
        default: throw ItemVaultServiceFailure.unavailable
        }
        if try await context.repository.vaultInitialization(context.account.setupScope(vaultID: vaultID).repositoryScope) != nil {
            result.enrollmentCompleted = true; return result
        }
        try await progressEnrollment(vaultID, record: nil, context: context, permit: context.account, allowPrompt: allowPrompt)
        try await context.runtime.wake(reason: .unlocked)
        result.message = "Waiting for an existing unlocked device to share this vault’s keys. Connection continues automatically."
        return result
    }
    private func progressEnrollment(_ vault: UUID, record: PreparedCoordinationRecord?, context: Context,
                                    permit: any RepositoryWritePermit, allowPrompt: Bool = false) async throws {
        let generation = state.withLock { $0.generation }
        try checkEnrollment(context, generation: generation, requireAuthorization: !allowPrompt)
        let scope = enrollmentScope(context.account, vaultID: vault)
        let store = ItemEnrollmentRequestStore(directory: context.account.directory.appendingPathComponent("ContentPreview3"), scope: scope)
        if let record {
            let envelope = try CoordinationEnvelope.decode(record.bytes, scope: scope)
            let approval = try DeviceEnrollmentApproval.decode(envelope.payload)
            let requests = try [store.load()].compactMap { $0 } + store.history()
            guard let request = requests.first(where: { $0.id == approval.request.id }) else { return }
            guard approval.request == request else { throw MopError.vaultUntrusted }
            let provider = try await device(context, vaultID: vault, create: false, allowPrompt: allowPrompt)
            let bootstrap = try ItemVaultBootstrap(repository: context.repository, trustStore: KeychainItemVaultTrustStore(namespace: .contentPreview3),
                scope: context.account.setupScope(vaultID: vault), device: provider)
            var session = try await bootstrap.acceptContentEnrollment(approval: approval, request: request)
            do {
                try checkEnrollment(context, generation: generation, requireAuthorization: true)
                session = try await context.runtime.register(session: session, synchronize: true)
                let acknowledgment = EnrollmentAcknowledgment(request: request.id, approvalDigest: setupHash(record.bytes))
                _ = try await session.contentSession!.coordination(kind: .enrollmentAcknowledgment, scope: scope, identity: request.id,
                    payload: setupEncode(acknowledgment), owner: permit)
            } catch { session.invalidate(); throw error }
            return
        }
        if try await context.repository.vaultInitialization(context.account.setupScope(vaultID: vault).repositoryScope) != nil { return }
        let provider = try await device(context, vaultID: vault, create: true, allowPrompt: allowPrompt)
        defer { provider.close() }
        let request: DeviceEnrollmentRequest
        if let saved = try store.load(), saved.expiresAt > Date() { request = saved }
        else {
            request = try permit.withWritePermission {
                try store.clear()
                return try store.reserve(DeviceEnrollmentRequest.create(scope: scope, device: provider))
            }
        }
        if try await context.repository.preparedCoordination(account: scope.account, vault: vault, kind: .enrollmentRequest, identity: request.id) == nil {
            let envelope = try CoordinationEnvelope.sign(kind: .enrollmentRequest, scope: scope, identity: request.id, payload: request.encoded(), device: provider)
            try checkEnrollment(context, generation: generation, requireAuthorization: true)
            _ = try await context.repository.enqueueCoordination(PreparedCoordinationRecord(account: scope.account, vault: vault,
                kind: .enrollmentRequest, identity: request.id, bytes: envelope.encoded()), authorization: permit)
        }
    }
    public func endRecoverySession() {
        guard let context = state.withLock({ $0.context }) else { return }
        context.recovery.lock()
        if var progress = try? context.recovery.store.load(), progress.phase == .preview {
            progress.phase = .complete
            try? context.recovery.store.save(progress)
        }
    }
    private let recoveryActivity = Mutex<String?>(nil)
    public var operationProgress: String? { state.withLock { $0.context }?.recovery.operationProgress ?? recoveryActivity.withLock { $0 } }
    public var operationFraction: Double? { state.withLock { $0.context }?.recovery.operationFraction }
    public var recoveryAvailable: Bool { true }
    public var deviceRemovalAvailable: Bool { true }
    public func recoveryState() async throws -> ItemRecoveryState? {
        do {
            let context = try await connected(offline: true)
            return try await context.recovery.progress()
        } catch MopError.cloudAccount { return nil }
    }
    public func recovery(_ action: VaultManagement) async throws -> VaultResult {
        try await serialized { [self] in
            let context = try await connected()
            let generation = state.withLock { $0.generation }
            return try await context.recovery.execute(action, device: { [self] id, create in
                try await device(context, vaultID: id, create: create)
            }, check: { [self] in
                try context.account.withWritePermission {}
                guard state.withLock({ $0.generation == generation }) else { throw MopError.authentication }
            })
        }
    }
    private func requireNoRecovery(_ context: Context) throws {
        guard try context.recovery.store.load()?.blocksRegularAccess != true else { throw ItemRecoveryFailure.recoveryInProgress }
    }

    public func open(_ vaultID: UUID) async throws -> ItemVaultSession { try await open(vaultID, offline: false) }
    public func open(_ vaultID: UUID, offline: Bool) async throws -> ItemVaultSession {
        // Revealing an already open vault never waits for commissioning, another
        // vault's authentication, or the cloud delivery queue.
        let snapshot = state.withLock { ($0.generation, $0.context) }
        if let context = snapshot.1, (try? context.account.withWritePermission {}) != nil {
            try requireNoRecovery(context)
            if let session = try? await context.runtime.session(vaultID: vaultID), session.isUnlocked {
                guard state.withLock({ $0.generation == snapshot.0 }) else { throw MopError.authentication }
                if offline { await context.runtime.pauseNetwork() }
                return session
            }
        }
        return try await serialized { [self] in
            let context = try await connected(offline: offline)
            if offline { await context.runtime.pauseNetwork() }
            if let session = try? await context.runtime.session(vaultID: vaultID), session.isUnlocked { return session }
            let scope = try context.account.setupScope(vaultID: vaultID)
            if let deletion = try await context.repository.deletion(scope.repositoryScope), deletion.phase != .prepared { throw VaultDeletionFailure.deleted }
            let trust = try KeychainItemVaultTrustStore(namespace: .contentPreview3)
            guard try trust.load(scope: scope) != nil else { throw MopError.vaultMissing }
            let device = try await device(context, vaultID: vaultID, create: false)
            let bootstrap = try ItemVaultBootstrap(repository: context.repository, trustStore: trust, scope: scope, device: device)
            let session = try await bootstrap.open()
            return try await context.runtime.register(session: session, synchronize: !offline)
        }
    }
    public func create(name: String, id: UUID, archiveData: Data?, recoveryKey: SecretBytes?) async throws -> ItemVaultSession {
        try await serialized { [self] in
            let context = try await connected(), scope = try context.account.setupScope(vaultID: id)
            try requireNoRecovery(context)
            let recoveryConfiguration = try await context.recovery.configuration()
            guard !recoveryConfiguration.incomplete else { throw ItemRecoveryFailure.configurationBusy }
            guard try await context.repository.deletion(scope.repositoryScope) == nil else { throw VaultDeletionFailure.deleted }
            let device = try await device(context, vaultID: id, create: true)
            let bootstrap = try ItemVaultBootstrap(repository: context.repository, trustStore: KeychainItemVaultTrustStore(namespace: .contentPreview3), scope: scope, device: device, recovery: recoveryConfiguration.active)
            var session: ItemVaultSession
            if let archiveData, let recoveryKey { session = try await bootstrap.restore(archiveData: archiveData, recoveryKey: recoveryKey, name: name) }
            else if archiveData == nil, recoveryKey == nil { session = try await bootstrap.create(name: name) }
            else { throw PortableArchiveFailure.invalid }
            do {
                session = try await context.runtime.register(session: session, synchronize: true)
                _ = try await session.contentSession!.coordination(kind: .discovery, scope: enrollmentScope(context.account, vaultID: id),
                    identity: id, payload: Data(id.uuidString.utf8), owner: context.account)
            }
            catch {
                // Bootstrap has already durably committed. Registration/lock is
                // a separate delivery outcome, never evidence of a lost create.
                if let receipt = try? await context.repository.vaultInitialization(scope.repositoryScope) {
                    throw ItemVaultBootstrapFailure.committedButLocked(receipt)
                }
                return session
            }
            return session
        }
    }
    public func requestSync() async throws {
        try Task.checkCancellation()
        let context = try await serialized { [self] in
            try Task.checkCancellation()
            return try await connected()
        }
        // Connection/authentication serialization protects local handles only.
        // A cloud request may outlive its caller and must not hold that gate.
        _ = try await context.runtime.requestSync()
    }
    public func enrollmentProgress() async throws -> [String: VaultEnrollmentProgress] {
        guard let context = state.withLock({ $0.context }) else { return [:] }
        try context.account.withWritePermission {}
        var result: [String: VaultEnrollmentProgress] = [:]
        for record in try await context.runtime.inventory() {
            let vault = record.scope.binding.vaultID
            let store = ItemEnrollmentRequestStore(directory: context.account.directory.appendingPathComponent("ContentPreview3"), scope: enrollmentScope(context.account, vaultID: vault))
            let savedRecipient = try await context.repository.enrollmentProgressRecipient(scope: record.scope.repositoryScope)
            guard let recipient = try savedRecipient ?? store.load()?.identity.fingerprint else { continue }
            if let progress = try await context.repository.enrollmentDownloadProgress(scope: record.scope.repositoryScope,
                recipient: recipient, metadata: ItemVaultSession.metadataRecordID) {
                result[vault.uuidString] = VaultEnrollmentProgress(ready: progress.ready, total: progress.total)
            }
        }
        return result
    }

    public func synchronizationHealth() async throws -> SyncHealthSnapshot? {
        guard let context = state.withLock({ $0.context }) else { return nil }
        try context.account.withWritePermission {}
        return try await context.repository.syncHealth(account: context.account.accountNamespace, database: "private")
    }
    public func pendingDeliveryReceipts(vault: UUID?) async throws -> [UUID] {
        let context = try await serialized { try await self.connected() }
        return try await context.repository.pendingMutations(account: context.account.accountNamespace)
            .filter { vault == nil || $0.version.scope.vaultID == vault }.map(\.id)
    }
    public func creationMutations(_ vaultID: UUID) async throws -> [UUID] {
        guard let context = state.withLock({ $0.context }) else { throw MopError.authentication }
        let scope = try context.account.setupScope(vaultID: vaultID).repositoryScope
        guard let receipt = try await context.repository.vaultInitialization(scope) else { throw ItemVaultBootstrapFailure.incompleteSetup }
        return receipt.mutationIDs
    }
    public func waitForDelivery(_ mutationIDs: [UUID], timeout: Duration) async throws -> Bool {
        guard !mutationIDs.isEmpty else { return false }
        guard let context = state.withLock({ $0.context }) else { throw MopError.authentication }
        return try await DeliveryConfirmationWaiter.wait(timeout: timeout,
            request: { [self] in try await requestSync() },
            observe: {
                try await withThrowingTaskGroup(of: Bool.self) { receipts in
                    for id in mutationIDs {
                        receipts.addTask {
                            try await MutationDeliveryWaiter.wait(repository: context.repository, mutationID: id,
                                account: context.account.accountNamespace, timeout: timeout).status == .cloudConfirmed
                        }
                    }
                    for try await confirmed in receipts {
                        if !confirmed { receipts.cancelAll(); return false }
                    }
                    return true
                }
            })
    }
    /// Called by the shared lease owner only with a locally pinned setup. It must
    /// never initiate authentication while responding to a background save.
    private func loadWithoutPrompt(_ record: ItemVaultSetupRecord, account: NativeItemCloudAccount, repository: EncryptedItemRepository) async throws -> ItemVaultSession? {
        guard let snapshot = state.withLock({ value -> (Int, ContextInvalidator)? in
            value.authorization.map { (value.generation, $0) }
        }) else { return nil }
        try account.withWritePermission {}
        let device = try openDevice(account, vaultID: record.scope.binding.vaultID, context: snapshot.1.context, create: false)
        let bootstrap = try ItemVaultBootstrap(repository: repository, trustStore: KeychainItemVaultTrustStore(namespace: .contentPreview3), scope: record.scope, device: device)
        let session = try await bootstrap.open()
        guard state.withLock({ $0.generation == snapshot.0 }) else { session.lock(); return nil }
        return session
    }
    #if DEBUG
    private struct DebugReset: Codable {
        let account: String
        let scopes: [ItemVaultSetupScope]
        let removals: [SyncOperation]
        var revoked = false
    }
    public func debugResetEnrollment() async throws {
        guard state.withLock({ value in
            if value.resettingEnrollment { return false }
            value.resettingEnrollment = true; return true
        }) else { throw DebugEnrollmentResetFailure.waiting }
        defer { state.withLock { $0.resettingEnrollment = false } }
        let context = try await serialized {
            if let context = self.state.withLock({ $0.context }) { return context }
            return try await self.connected()
        }
        let resetLease: SynchronizationLease
        do { resetLease = try SynchronizationLease(url: context.account.directory.appendingPathComponent("ContentPreview3/debug-enrollment-reset.lock")) }
        catch CloudSyncAdapterError.engineAlreadyOwned { throw DebugEnrollmentResetFailure.waiting }
        defer { withExtendedLifetime(resetLease) {} }
        let location = context.account.directory.appendingPathComponent("ContentPreview3/debug-enrollment-reset.json")
        var reset: DebugReset
        if FileManager.default.fileExists(atPath: location.path) {
            reset = try JSONDecoder().decode(DebugReset.self, from: LocalFile.read(location, privateFile: true, limit: 16 * 1024 * 1024))
            guard reset.account == context.account.accountNamespace else { throw MopError.cloudAccount }
        } else {
            guard try await context.repository.pendingMutations(account: context.account.accountNamespace).isEmpty,
                  try await context.repository.contentConflicts(account: context.account.accountNamespace, includePendingDecisions: true).isEmpty,
                  try await context.recovery.progress()?.blocksRegularAccess != true else {
                throw DebugEnrollmentResetFailure.pendingWork
            }
            let records = try await context.runtime.inventory()
            guard !records.isEmpty else { throw DebugEnrollmentResetFailure.noVaults }
            var removals: [SyncOperation] = []
            for record in records {
                let session = try await open(record.scope.binding.vaultID)
                guard let content = session.contentSession else { throw MopError.vaultUntrusted }
                let current = content.history.current.membership, id = try session.currentDeviceID
                let membership = try DebugEnrollmentResetFailure.removing(id, from: current)
                removals.append(try await content.prepareMembership(membership, owner: context.account))
            }
            reset = DebugReset(account: context.account.accountNamespace, scopes: records.map(\.scope), removals: removals)
            // Persist randomized signed proposals before any cloud publication.
            try LocalFile.write(JSONEncoder().encode(reset), to: location, replace: false)
        }
        if !reset.revoked {
            let existing = try await context.repository.operations(account: reset.account, database: "private")
            for operation in reset.removals where !existing.contains(where: { $0.id == operation.id }) {
                _ = try await context.repository.enqueue(operation)
            }
            try await context.runtime.wake(reason: .unlocked)
            let deadline = ContinuousClock.now.advanced(by: .seconds(30))
            while true {
                // The signed cloud head, verified against pinned history, is the
                // completion evidence. A receipt can be lost after self-removal
                // invalidates the session; do not require it before readback.
                var verified = true
                for scope in reset.scopes {
                    guard let operation = reset.removals.first(where: { $0.vaultID == scope.binding.vaultID }) else {
                        throw MopError.invalidVault
                    }
                    let proposal = try JSONDecoder().decode(ContentMembershipCommit.self, from: operation.payload)
                    let head = try await NativeVaultMembershipTransport(database: context.account.container.privateCloudDatabase)
                        .readHead(binding: NativeContentHistoryReader(account: context.account).binding(scope.binding.vaultID))
                    if try await !context.runtime.debugVerifyRemoval(vault: scope.binding.vaultID, head: head.bytes,
                        removed: Set(proposal.successor.membership.removedDevices ?? [])) { verified = false; break }
                }
                if verified { break }
                guard ContinuousClock.now < deadline else { throw DebugEnrollmentResetFailure.waiting }
                try await Task.sleep(for: .seconds(2))
            }
            reset.revoked = true
            try LocalFile.write(JSONEncoder().encode(reset), to: location, replace: true)
        }
        await context.runtime.stop()
        let lease = try SynchronizationLease(url: context.account.leaseURL(database: "private"))
        defer { withExtendedLifetime(lease) {} }
        guard try await context.repository.pendingMutations(account: reset.account).isEmpty,
              try await context.repository.contentConflicts(account: reset.account, includePendingDecisions: true).isEmpty else {
            throw DebugEnrollmentResetFailure.pendingWork
        }
        lock()
        // Recheck pending work inside the clearing transaction before deleting keys.
        // The durable manifest makes a crash during subsequent Keychain cleanup resumable.
        try await context.repository.debugClearEnrollmentStore(authorization: context.account)
        let trust = try KeychainItemVaultTrustStore(namespace: .contentPreview3)
        for scope in reset.scopes {
            let vault = scope.binding.vaultID
            let keyScope = context.account.containerIdentifier + "/" + context.account.environment + "/content3/" + reset.account + "/" + vault.uuidString
            try DeviceKeychain.remove(scope: keyScope, member: context.account.memberID)
            try trust.removeDeletedVault(scope: scope)
            try ItemEnrollmentRequestStore(directory: context.account.directory.appendingPathComponent("ContentPreview3"),
                scope: enrollmentScope(context.account, vaultID: vault)).purge()
        }
        state.withLock { value in
            value.changePump?.cancel(); value.changePump = nil; value.context = nil
            value.provisionalBootstraps.removeAll()
        }
        try FileManager.default.removeItem(at: location)
    }
    #endif

    private func openDevice(_ account: NativeItemCloudAccount, vaultID: UUID, context: LAContext, create: Bool) throws -> any DeviceOperations {
        let keyScope = account.containerIdentifier + "/" + account.environment + "/content3/" + account.accountNamespace + "/" + vaultID.uuidString
        return SharedAuthorizationDevice(try DeviceKeychain.open(scope: keyScope, member: account.memberID, context: context, create: create))
    }
    private func device(_ context: Context, vaultID: UUID, create: Bool, allowPrompt: Bool = true) async throws -> any DeviceOperations {
        let generation = state.withLock { $0.generation }
        let authorization: LAContext
        if let existing = state.withLock({ $0.authorization }) { authorization = existing.context }
        else {
            guard allowPrompt else { throw MopError.authentication }
            authorization = try await Authentication.authorizeAsync(reason: "open your 2ndPass vault") { [self] value in
                let accepted = state.withLock { current in
                    guard current.generation == generation else { return false }
                    current.pendingAuthorization = ContextInvalidator(value); return true
                }
                guard accepted else { value.invalidate(); throw MopError.authentication }
            }
        }
        let accepted = state.withLock { current in
            guard current.generation == generation else { return false }
            // Only completed, interaction-disabled contexts are visible to the
            // no-prompt background loader. Pending authentication is separate.
            current.authorization = ContextInvalidator(authorization)
            current.pendingAuthorization = nil
            return true
        }
        guard accepted else { authorization.invalidate(); throw MopError.authentication }
        let device = try openDevice(context.account, vaultID: vaultID, context: authorization, create: create)
        guard state.withLock({ $0.generation == generation }) else { device.close(); throw MopError.authentication }
        return device
    }
}

/// Each session exclusively owns its key handles. The backend owns the shared
/// authorization context and invalidates it on global lock; closing one session
/// must not invalidate unrelated vault sessions that use the same context.
private final class SharedAuthorizationDevice: DeviceOperations {
    private let device: EnclaveDevice
    init(_ device: EnclaveDevice) { self.device = device }
    var identity: DevicePublicKey { device.identity }
    func sign(_ bytes: Data) throws -> Data { try device.sign(bytes) }
    func unwrap(_ envelope: KeyEnvelope, context: Data) throws -> SymmetricKey { try device.unwrap(envelope, context: context) }
    func close() { device.releaseHandles() }
    deinit { close() }
}

#if DEBUG
public enum DebugEnrollmentResetFailure: Error, LocalizedError {
    case pendingWork, noVaults, lastOwner, waiting
    static func verifiesRemoval(history: TrustedMembershipHistory, head: Data, removed: Set<UUID>) throws -> Bool {
        guard !removed.isEmpty else { return false }
        let envelope = try MembershipEnvelope.decode(head)
        guard let pinned = try? history.state(forDigest: envelope.digest()), pinned == envelope else { return false }
        return removed.isSubset(of: Set(envelope.membership.removedDevices ?? []))
    }
    static func removing(_ device: UUID, from current: Membership) throws -> Membership {
        guard current.accounts.count == 1, let member = current.accounts.first,
              member.role == .owner, member.devices.contains(where: { $0.device == device }),
              member.devices.count > 1 else { throw DebugEnrollmentResetFailure.lastOwner }
        return try Membership(accounts: [AccountMember(id: member.id, role: member.role,
            devices: member.devices.filter { $0.device != device })], offlineRecovery: current.offlineRecovery,
            removedDevices: Array(Set((current.removedDevices ?? []) + [device])).sorted { $0.uuidString < $1.uuidString })
    }
    public var errorDescription: String? {
        switch self {
        case .pendingWork: return "Finish syncing local edits, resolve conflicts, and finish recovery before resetting enrollment."
        case .noVaults: return "This device has no enrolled cloud vaults to reset."
        case .lastOwner: return "Every vault must have another owner device before this device can be removed."
        case .waiting: return "Removal is still pending. Keep another owner device unlocked, then run Reset Enrollment again to resume. Local enrollment has not been cleared."
        }
    }
}
#endif
