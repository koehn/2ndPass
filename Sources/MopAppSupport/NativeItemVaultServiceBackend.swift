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
    }
    private struct State: @unchecked Sendable {
        var generation = 0
        var context: Context?
        var authorization: ContextInvalidator?
        var pendingAuthorization: ContextInvalidator?
        var listeners: [UUID: AsyncStream<Void>.Continuation] = [:]
        var changePump: Task<Void, Never>?
        var remoteVaults: [VaultDescriptor]?
        var discoveryAttempted = false
        var discoveryTask: Task<Void, Never>?
        var enrollmentTask: Task<Void, Never>?
        var enrollmentTaskID: UUID?
        var provisionalBootstraps: [UUID: ItemVaultBootstrap] = [:]
        var enrollmentAttempted = false
    }
    private let state = Mutex(State())
    private let directory: URL?
    private let gate = OperationGate()
    public init(state: URL? = nil) { directory = state }
    public func lock() {
        let resources = state.withLock { value in
            value.generation += 1
            value.enrollmentTask?.cancel(); value.enrollmentTask = nil; value.enrollmentTaskID = nil; value.enrollmentAttempted = false
            value.authorization?.invalidate(); value.authorization = nil
            value.pendingAuthorization?.invalidate(); value.pendingAuthorization = nil
            let bootstraps = Array(value.provisionalBootstraps.values)
            value.provisionalBootstraps.removeAll()
            return (value.context, bootstraps)
        }
        resources.1.forEach { $0.lock() }
        resources.0?.runtime.lock()
    }
    deinit {
        lock()
        state.withLock { $0.changePump?.cancel(); $0.discoveryTask?.cancel(); $0.enrollmentTask?.cancel(); $0.listeners.values.forEach { $0.finish() } }
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
                return existing
            } catch MopError.cloudAccount {
                // A retired account is never rebound in place. Drop only live
                // handles and observers; its scoped ciphertext/outbox stays put.
                let retired = state.withLock { value -> (ContextInvalidator?, ContextInvalidator?, Task<Void, Never>?, [ItemVaultBootstrap])? in
                    guard value.context?.account === existing.account else { return nil }
                    let resources = (value.authorization, value.pendingAuthorization, value.changePump, Array(value.provisionalBootstraps.values))
                    value.provisionalBootstraps.removeAll()
                    value.generation += 1
                    value.remoteVaults = nil; value.discoveryAttempted = false
                    value.discoveryTask?.cancel(); value.discoveryTask = nil
                    value.enrollmentTask?.cancel(); value.enrollmentTask = nil; value.enrollmentTaskID = nil; value.enrollmentAttempted = false
                    value.context = nil; value.authorization = nil
                    value.pendingAuthorization = nil; value.changePump = nil
                    return resources
                }
                if let retired {
                    retired.0?.invalidate(); retired.1?.invalidate(); retired.2?.cancel()
                    retired.3.forEach { $0.lock() }
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
        let repository = try EncryptedItemRepository(storeURL: root.appendingPathComponent("Items.sqlite"))
        let runtime = try ItemVaultSyncRuntime(account: account, repository: repository)
        let context = Context(account: account, repository: repository, runtime: runtime)
        let accepted = state.withLock { value in
            guard value.generation == generation else { return false }
            value.context = context; return true
        }
        guard accepted else { runtime.invalidate(); throw MopError.authentication }
        let pump = Task { [weak self] in
            let stream = await repository.changes()
            for await _ in stream {
                guard !Task.isCancelled, let self else { break }
                let listeners = self.state.withLock { Array($0.listeners.values) }
                listeners.forEach { $0.yield(()) }
            }
        }
        state.withLock { $0.changePump = pump }
        try await runtime.setSessionLoader { [weak self] record in
            guard let self else { return nil }
            return try await self.loadWithoutPrompt(record, account: account, repository: repository)
        }
        guard state.withLock({ $0.generation == generation && $0.context?.account === account }) else { throw MopError.authentication }
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
        guard let context = state.withLock({ $0.context }) else { return nil }
        return try? await context.runtime.session(vaultID: vaultID)
    }
    public func invalidateDiscovery() {
        state.withLock { $0.remoteVaults = nil; $0.discoveryAttempted = false; $0.enrollmentAttempted = false }
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
        _ = try await resumeDeletions()
        let local = try await inventory(offline: false)
        let context = try await serialized { try await self.connected() }
        scheduleAutomaticEnrollment(context)
        if let remote = state.withLock({ $0.remoteVaults }) {
            return ItemVaultDiscovery(vaults: mergeDiscovery(local, remote), complete: true)
        }
        if local.isEmpty {
            // An empty local trust store is not evidence of an empty cloud account.
            let remote = try await NativeItemEnrollmentTransport(account: context.account).discover()
            try context.account.withWritePermission {}
            state.withLock { if $0.context?.account === context.account { $0.remoteVaults = remote } }
            return ItemVaultDiscovery(vaults: remote, complete: true)
        }
        let start = state.withLock { value in
            guard !value.discoveryAttempted, value.discoveryTask == nil else { return false }
            value.discoveryAttempted = true; return true
        }
        if start {
            let task = Task { [weak self] in
                let remote = try? await NativeItemEnrollmentTransport(account: context.account).discover()
                guard !Task.isCancelled, let self else { return }
                let listeners = self.state.withLock { current -> [AsyncStream<Void>.Continuation] in
                    guard current.context?.account === context.account else { return [] }
                    current.discoveryTask = nil
                    current.remoteVaults = remote
                    current.enrollmentAttempted = false
                    return Array(current.listeners.values)
                }
                listeners.forEach { $0.yield(()) }
                self.scheduleAutomaticEnrollment(context)
            }
            state.withLock { $0.discoveryTask = task }
        }
        return ItemVaultDiscovery(vaults: local, complete: false)
    }
    /// No prompts or timer: an unlocked existing device answers same-account
    /// enrollment packets after foregrounding, cloud hints or explicit refresh.
    private func scheduleAutomaticEnrollment(_ context: Context) {
        let taskID = UUID()
        let generation = state.withLock { value -> Int? in
            guard value.context?.account === context.account, value.authorization != nil,
                  !value.enrollmentAttempted, value.enrollmentTaskID == nil else { return nil }
            value.enrollmentAttempted = true; value.enrollmentTaskID = taskID
            return value.generation
        }
        guard let generation else { return }
        let task = Task { [weak self] in
            guard let self else { return }
            var changed = false
            defer {
                let completion = self.state.withLock { value -> ([AsyncStream<Void>.Continuation], Bool) in
                    guard value.enrollmentTaskID == taskID, value.generation == generation else { return ([], false) }
                    value.enrollmentTask = nil; value.enrollmentTaskID = nil
                    // A cloud hint arriving during this pass is retained as one
                    // event-driven follow-up, rather than lost or polled for.
                    let retry = !value.enrollmentAttempted && value.authorization != nil
                        && value.context?.account === context.account
                    return (changed ? Array(value.listeners.values) : [], retry)
                }
                completion.0.forEach { $0.yield(()) }
                if completion.1 { self.scheduleAutomaticEnrollment(context) }
            }
            do {
                try self.checkEnrollment(context, generation: generation, requireAuthorization: true)
                let transport = NativeItemEnrollmentTransport(account: context.account)
                let inventory = try await context.runtime.inventory()
                let requests = try await transport.requests()
                Self.logger.notice("Enrollment trace: owner scan; requests=\(requests.count) localVaults=\(inventory.count)")
                for (id, bytes) in requests {
                    try self.checkEnrollment(context, generation: generation, requireAuthorization: true)
                    guard let request = try? DeviceEnrollmentRequest.decode(bytes), request.id == id,
                          request.scope == self.enrollmentScope(context.account, vaultID: request.scope.vault),
                          let record = inventory.first(where: { $0.scope.binding.vaultID == request.scope.vault }) else { continue }
                    do {
                        var session = await self.existing(request.scope.vault)
                        if session?.isUnlocked != true {
                            session = try await self.loadWithoutPrompt(record, account: context.account, repository: context.repository)
                            if let session { try await context.runtime.register(session: session, synchronize: true) }
                        }
                        guard session?.isUnlocked == true else { continue }
                        // Scope and signature checks are required even though the
                        // authenticated private account is the bootstrap trust basis.
                        do {
                            try self.checkEnrollment(context, generation: generation, requireAuthorization: true)
                            let approval = try await context.runtime.approveEnrollment(request)
                            try self.checkEnrollment(context, generation: generation, requireAuthorization: true)
                            try await transport.save(approval.encoded(), id: request.id, approval: true)
                            Self.logger.notice("Enrollment trace: approval saved")
                            changed = true
                        } catch DeviceEnrollmentFailure.expired { continue }
                    } catch {
                        // A stale request must not starve independent requests.
                        // Recheck cancellation/account authorization before continuing.
                        try Task.checkCancellation()
                        try self.checkEnrollment(context, generation: generation, requireAuthorization: true)
                        let native = error as NSError
                        Self.logger.error("Enrollment trace: owner request failed; domain=\(native.domain, privacy: .public) code=\(native.code)")
                    }
                }
                if let remote = self.state.withLock({ $0.remoteVaults }) {
                    for vault in remote {
                        if let record = inventory.first(where: { $0.scope.binding.vaultID.uuidString == vault.id }),
                           try await context.repository.vaultInitialization(record.scope.repositoryScope) != nil { continue }
                        guard let id = UUID(uuidString: vault.id), self.state.withLock({ $0.authorization != nil }) else { continue }
                        try self.checkEnrollment(context, generation: generation, requireAuthorization: true)
                        let result = try await self.enrollment(.automaticEnrollment, vaultID: id, allowPrompt: false)
                        changed = changed || result.enrollmentCompleted
                    }
                }
            } catch {
                let native = error as NSError
                Self.logger.error("Enrollment trace: automatic pass failed; domain=\(native.domain, privacy: .public) code=\(native.code)")
                // A foreground or cloud event retries durable work.
            }
        }
        state.withLock { value in
            guard value.enrollmentTaskID == taskID, value.generation == generation else { task.cancel(); return }
            value.enrollmentTask = task
        }
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
                    result.append(VaultDescriptor(id: id.uuidString, name: name, format: "mop-items-v2", enrolled: false))
                    continue
                }
                if let existing = try? await context.runtime.session(vaultID: id), existing.isUnlocked {
                    name = try await existing.vaultMetadata().value.name
                } else if let session = try await loadWithoutPrompt(record, account: context.account, repository: context.repository) {
                    name = try await session.vaultMetadata().value.name
                    try await context.runtime.register(session: session, synchronize: !offline)
                }
                result.append(VaultDescriptor(id: id.uuidString, name: name, format: "mop-items-v2", enrolled: true))
            }
            return result.sorted { ($0.name ?? "", $0.id) < ($1.name ?? "", $1.id) }
        }
    }
    /// Explicit user selection may authenticate to resolve an encrypted current
    /// name. Discovery and cached reads never call this method.
    public func resolveVault(named name: String, offline: Bool) async throws -> UUID? {
        try await serialized { [self] in
            let context = try await connected(offline: offline)
            if offline { await context.runtime.pauseNetwork() }
            var matches: [UUID] = []
            for record in try await context.runtime.inventory() {
                let id = record.scope.binding.vaultID
                let session: ItemVaultSession
                if let existing = try? await context.runtime.session(vaultID: id), existing.isUnlocked { session = existing }
                else {
                    let device = try await device(context, vaultID: id, create: false)
                    let bootstrap = try ItemVaultBootstrap(repository: context.repository, trustStore: KeychainItemVaultTrustStore(), scope: record.scope, device: device)
                    session = try await bootstrap.open()
                    try await context.runtime.register(session: session, synchronize: !offline)
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
        let generation = state.withLock { $0.generation }
        try checkEnrollment(context, generation: generation, requireAuthorization: !allowPrompt)
        if try await context.repository.deletion((try context.account.setupScope(vaultID: vaultID)).repositoryScope) != nil {
            throw VaultDeletionFailure.deleted
        }
        // Presence alone can block new admission, but cannot authorize erasure.
        if try await NativeVaultDeletionTransport(database: context.account.container.privateCloudDatabase).read(vaultID: vaultID) != nil {
            throw VaultDeletionFailure.deleted
        }
        let scope = enrollmentScope(context.account, vaultID: vaultID)
        let store = ItemEnrollmentRequestStore(directory: context.account.directory, scope: scope)
        let transport = NativeItemEnrollmentTransport(account: context.account)
        // Reconcile an approval issued concurrently with cancellation/restart.
        // Retained transcripts contain no private material; their exact request
        // binding is still checked again by the joining bootstrap.
        var recovered: DeviceEnrollmentRequest?
        switch action {
        case .automaticEnrollment, .checkEnrollment, .requestEnrollment, .restartEnrollment, .confirmEnrollment:
            for previous in try store.history() {
                if try await transport.read(id: previous.id, approval: true) != nil { recovered = previous; break }
            }
        default: break
        }
        if let recovered {
            if try store.load()?.id != recovered.id { try store.clear(); _ = try store.reserve(recovered) }
        }
        try checkEnrollment(context, generation: generation, requireAuthorization: !allowPrompt)
        var result = VaultResult(), view = ItemEnrollmentView()
        func projection(_ request: DeviceEnrollmentRequest) -> ItemEnrollmentRequestView {
            ItemEnrollmentRequestView(id: request.id, deviceID: request.identity.device, expiresAt: request.expiresAt)
        }
        switch action {
        case .automaticEnrollment:
            Self.logger.notice("Enrollment trace: checking automatic connection")
            if try await context.repository.vaultInitialization((try context.account.setupScope(vaultID: vaultID)).repositoryScope) != nil {
                result.enrollmentCompleted = true; return result
            }
            if let request = try store.load(), try await transport.read(id: request.id, approval: true) != nil {
                return try await enrollment(.confirmEnrollment(code: ""), vaultID: vaultID, allowPrompt: allowPrompt)
            }
            if let request = try store.load(), (try? request.verify()) == nil {
                _ = try await enrollment(.restartEnrollment(name: ""), vaultID: vaultID, allowPrompt: allowPrompt)
            } else { _ = try await enrollment(.requestEnrollment(name: ""), vaultID: vaultID, allowPrompt: allowPrompt) }
            result.message = "Connecting to your iCloud vault. Open 2ndPass on an existing device to finish securely sharing its keys."
            return result
        case .requestEnrollment, .restartEnrollment:
            if case .restartEnrollment = action {
                if let previous = try store.load() {
                    // An issued approval must be completed, never replaced with a
                    // new request for an identity already present in membership.
                    if try await transport.read(id: previous.id, approval: true) != nil {
                        view.request = projection(previous); view.approvalAvailable = true
                        result.enrollment = view; result.message = "Secure access is ready. Connecting this device…"; return result
                    }
                    try await transport.removeRequest(previous.id)
                }
                try store.clear()
            }
            let request: DeviceEnrollmentRequest
            if let existing = try store.load() { request = existing }
            else {
                request = try await serialized { [self] in
                    try checkEnrollment(context, generation: generation, requireAuthorization: !allowPrompt)
                    let token = generation
                    let provider = try await device(context, vaultID: vaultID, create: true, allowPrompt: allowPrompt)
                    defer { provider.close() }
                    let candidate = try DeviceEnrollmentRequest.create(scope: scope, device: provider)
                    return try state.withLock { value in
                        guard value.generation == token else { throw MopError.authentication }
                        return try context.account.withWritePermission { try store.reserve(candidate) }
                    }
                }
            }
            try request.verify()
            try await transport.save(request.encoded(), id: request.id, approval: false)
            view.request = projection(request)
            result.message = "Connecting to iCloud. Keep an existing device unlocked to share this vault’s keys automatically."
        case .checkEnrollment:
            if let request = try store.load() {
                view.request = projection(request)
                view.approvalAvailable = try await transport.read(id: request.id, approval: true) != nil
                result.message = view.approvalAvailable ? "Secure access is ready. Connecting this device…" : "Waiting for an existing unlocked device to share this vault’s keys automatically."
            }
        case .cancelEnrollment:
            if let request = try store.load() {
                guard try await transport.read(id: request.id, approval: true) == nil else {
                    view.request = projection(request); view.approvalAvailable = true
                    result.enrollment = view; result.message = "Secure access is ready. Connecting this device…"; return result
                }
                try await transport.removeRequest(request.id)
            }
            try store.clear(); result.message = "Connection paused."
        case .enrollmentInbox:
            try await transport.prepare()
            view.inbox = try await transport.requests().compactMap { id, bytes in
                guard let request = try? DeviceEnrollmentRequest.decode(bytes), request.id == id,
                      request.scope == scope, (try? request.verify()) != nil else { return nil }
                return projection(request)
            }.sorted { $0.expiresAt < $1.expiresAt }
        case .approveEnrollment(let id, _):
            guard let bytes = try await transport.read(id: id, approval: false) else { throw MopError.notFound }
            let request = try DeviceEnrollmentRequest.decode(bytes)
            guard request.id == id, request.scope == scope else { throw DeviceEnrollmentFailure.invalidRequest }
            _ = try await open(vaultID)
            let approval = try await context.runtime.approveEnrollment(request)
            try await transport.save(approval.encoded(), id: id, approval: true)
            result.message = "Device connected. Encrypted changes will upload in the background."
            result.addedDevices = [request.identity.device]
            // The request is retained so a lost response can retry the same durable
            // approval. Inbox filtering hides grants already present in the relay.
        case .rejectEnrollment(let id):
            guard let bytes = try await transport.read(id: id, approval: false) else { throw MopError.notFound }
            let request = try DeviceEnrollmentRequest.decode(bytes)
            guard request.id == id, request.scope == scope else { throw DeviceEnrollmentFailure.invalidRequest }
            _ = try await open(vaultID)
            guard try await transport.read(id: id, approval: true) == nil else { throw MopError.vaultConflict }
            try await transport.removeRequest(id); result.message = "Connection canceled."
        case .devices:
            let session = try await open(vaultID)
            let current = try session.currentDeviceID
            result.devices = try session.enrolledDevices.map {
                VaultDeviceRecord(id: $0.device, name: $0.device == current ? "This device" : "Device " + $0.device.uuidString.prefix(8),
                    isCurrent: $0.device == current)
            }
        case .confirmEnrollment:
            guard let request = try store.load(), let bytes = try await transport.read(id: request.id, approval: true) else { throw MopError.notFound }
            let approval = try DeviceEnrollmentApproval.decode(bytes)
            _ = try approval.acceptFromAuthenticatedPrivateCloudKit(request: request, scope: scope)
            guard let (metadata, systemFields, successors) = try await transport.admissionMetadata(approval: approval) else {
                view.request = projection(request); view.approvalAvailable = true
                result.enrollment = view; result.message = "Waiting for an existing device to upload encrypted vault access. This device will connect automatically."; return result
            }
            let bootstrapID = UUID()
            let bootstrap = try await serialized { [self] in
                try checkEnrollment(context, generation: generation, requireAuthorization: !allowPrompt)
                let provider = try await device(context, vaultID: vaultID, create: false, allowPrompt: allowPrompt)
                let bootstrap = try ItemVaultBootstrap(repository: context.repository, trustStore: KeychainItemVaultTrustStore(),
                    scope: context.account.setupScope(vaultID: vaultID), device: provider)
                let accepted = state.withLock { value in
                    guard value.generation == generation, value.context?.account === context.account else { return false }
                    value.provisionalBootstraps[bootstrapID] = bootstrap; return true
                }
                guard accepted else { bootstrap.lock(); throw MopError.authentication }
                return bootstrap
            }
            defer { _ = state.withLock { $0.provisionalBootstraps.removeValue(forKey: bootstrapID) } }
            let session = try await bootstrap.acceptFromAuthenticatedPrivateCloudKit(approval: approval, request: request,
                metadata: metadata, metadataSystemFields: systemFields, successors: successors)
            do { try checkEnrollment(context, generation: generation, requireAuthorization: true) }
            catch { session.lock(); throw error }
            try await context.runtime.register(session: session, synchronize: true)
            invalidateDiscovery()
            result.enrollmentCompleted = true; result.defaultVault = vaultID.uuidString
            result.message = "Device connected. Vault items will download in the background."
        default: throw ItemVaultServiceFailure.unavailable
        }
        result.enrollment = view
        return result
    }
    public func open(_ vaultID: UUID) async throws -> ItemVaultSession { try await open(vaultID, offline: false) }
    public func open(_ vaultID: UUID, offline: Bool) async throws -> ItemVaultSession {
        // Revealing an already open vault never waits for commissioning, another
        // vault's authentication, or the cloud delivery queue.
        let snapshot = state.withLock { ($0.generation, $0.context) }
        if let context = snapshot.1, (try? context.account.withWritePermission {}) != nil {
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
            let trust = try KeychainItemVaultTrustStore()
            guard try trust.load(scope: scope) != nil else { throw MopError.vaultMissing }
            let device = try await device(context, vaultID: vaultID, create: false)
            let bootstrap = try ItemVaultBootstrap(repository: context.repository, trustStore: trust, scope: scope, device: device)
            let session = try await bootstrap.open()
            try await session.retireLegacyHealthSynchronization()
            try await context.runtime.register(session: session, synchronize: !offline)
            if !offline {
                state.withLock { $0.enrollmentAttempted = false }
                scheduleAutomaticEnrollment(context)
            }
            return session
        }
    }
    public func create(name: String, id: UUID, archiveData: Data?, recoveryKey: SecretBytes?) async throws -> ItemVaultSession {
        try await serialized { [self] in
            let context = try await connected(), scope = try context.account.setupScope(vaultID: id)
            guard try await context.repository.deletion(scope.repositoryScope) == nil,
                  try await NativeVaultDeletionTransport(database: context.account.container.privateCloudDatabase).read(vaultID: id) == nil else { throw VaultDeletionFailure.deleted }
            let device = try await device(context, vaultID: id, create: true)
            let bootstrap = try ItemVaultBootstrap(repository: context.repository, trustStore: KeychainItemVaultTrustStore(), scope: scope, device: device)
            let session: ItemVaultSession
            if let archiveData, let recoveryKey { session = try await bootstrap.restore(archiveData: archiveData, recoveryKey: recoveryKey, name: name) }
            else if archiveData == nil, recoveryKey == nil { session = try await bootstrap.create(name: name) }
            else { throw PortableArchiveFailure.invalid }
            do { try await context.runtime.register(session: session, synchronize: true) }
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
    public func conflictAdapter() async throws -> CloudKitSyncAdapter {
        guard let context = state.withLock({ $0.context }) else { throw MopError.authentication }
        return try await context.runtime.cloudAdapter()
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
        let bootstrap = try ItemVaultBootstrap(repository: repository, trustStore: KeychainItemVaultTrustStore(), scope: record.scope, device: device)
        let session = try await bootstrap.open()
        try await session.retireLegacyHealthSynchronization()
        guard state.withLock({ $0.generation == snapshot.0 }) else { session.lock(); return nil }
        return session
    }
    private func openDevice(_ account: NativeItemCloudAccount, vaultID: UUID, context: LAContext, create: Bool) throws -> any DeviceOperations {
        let keyScope = account.containerIdentifier + "/" + account.environment + "/items/" + account.accountNamespace + "/" + vaultID.uuidString
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
