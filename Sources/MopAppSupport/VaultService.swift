import Foundation
import LocalAuthentication
import Synchronization
import MopCore
import MopAuth
import MopVault
import MopKeychain
import MopCloudKit

public struct VaultMemberRecord: Sendable, Identifiable {
    public let id: String
    public let role: String
}
public enum VaultManagement: Sendable {
    case fingerprint, trust(fingerprint: String)
    case recover(file: URL, fingerprint: String)
}
public enum VaultOperation: Sendable {
    case discover, catalog, passwordQuality(item: String), read(SecretReference), save(ItemEdit)
    case write(SecretReference, SecretBytes, replace: Bool), delete(SecretReference)
    case recentlyDeleted, trashItem(name: String, revision: String), restoreItem(id: UUID, revision: String)
    case members, manage(VaultManagement), sync
    case create(name: String, strict: Bool, recovery: URL)
    case createPrepared
    case rename(String), deleteVault, export(URL)
}
extension VaultOperation {
    var allowsCachedRead: Bool {
        switch self {
        case .discover, .catalog, .read, .passwordQuality, .recentlyDeleted, .export: true
        default: false
        }
    }
}
public struct VaultResult: Sendable {
    public var vaults: [VaultDescriptor] = []
    public var defaultVault: String?
    public var catalog: ItemCatalog?
    public var deletedCatalog: ItemCatalog?
    public var value: SecretBytes?
    public var valueIsConcealed = true
    public var otpExpiresAt: Date?
    public var otpPeriod: Int?
    public var passwordQuality: [String: PasswordQuality] = [:]
    public var members: [VaultMemberRecord] = []
    public var message = ""
    public var usingCache = false
    public var offlineDate: Date?
    public init() {}
    public func requireCatalog() throws -> ItemCatalog {
        guard let catalog else { throw MopError.invalidVault }; return catalog
    }
}
public protocol VaultService: Sendable {
    var authenticatedAt: TimeInterval? { get }
    func lock()
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult
}

public extension VaultService {
    var isAuthenticated: Bool { authenticatedAt != nil }
}

// LAContext explicitly supports invalidation of a pending evaluation. This box
// exposes only that operation across threads, not general mutable context access.
private final class ContextInvalidator: @unchecked Sendable {
    let context: LAContext
    init(_ context: LAContext) { self.context = context }
    func invalidate() { context.invalidate() }
}

// Locking never waits for network I/O or a blocking biometric evaluation. Only
// the LAContext invalidation callback crosses the worker's isolation boundary.
private final class SessionControl: Sendable {
    struct State {
        var generation = 0
        var authenticatedAt: TimeInterval?
        var invalidate: (@Sendable () -> Void)?
        var tasks: [UUID: @Sendable () -> Void] = [:]
    }
    private let state = Mutex(State())
    var generation: Int { state.withLock { $0.generation } }
    var authenticated: Bool { authenticatedAt != nil }
    var authenticatedAt: TimeInterval? { state.withLock { $0.authenticatedAt } }
    func check(_ token: Int) throws {
        guard state.withLock({ $0.generation == token }) else { throw MopError.authentication }
        try Task.checkCancellation()
    }
    func register(_ invalidate: @escaping @Sendable () -> Void, token: Int) throws {
        let accepted = state.withLock { value in
            guard value.generation == token else { return false }
            value.invalidate = invalidate; return true
        }
        if !accepted { invalidate(); throw MopError.authentication }
    }
    func authorized(_ token: Int) throws {
        try state.withLock { value in
            guard value.generation == token else { throw MopError.authentication }
            value.authenticatedAt = ProcessInfo.processInfo.systemUptime
        }
    }
    func registerTask(_ id: UUID, token: Int, cancel: @escaping @Sendable () -> Void) {
        let accepted = state.withLock { value in
            guard value.generation == token else { return false }
            value.tasks[id] = cancel; return true
        }
        if !accepted { cancel() }
    }
    func finishedTask(_ id: UUID) { state.withLock { $0.tasks[id] = nil } }
    func lock() {
        let callbacks = state.withLock { value in
            value.generation += 1; value.authenticatedAt = nil
            let callbacks = Array(value.tasks.values) + [value.invalidate].compactMap { $0 }
            value.invalidate = nil; value.tasks.removeAll(); return callbacks
        }
        callbacks.forEach { $0() }
    }
}

/// A FIFO permit, held across suspension points. Actor reentrancy alone would
/// allow a second mutation to enter while the first waits for CloudKit.
private actor OperationGate {
    private var occupied = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func enter() async {
        if !occupied { occupied = true; return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func leave() {
        if waiters.isEmpty { occupied = false } else { waiters.removeFirst().resume() }
    }
}

/// Native GUI boundary. Worker objects are confined to a single operation permit;
/// they are never accessed by the main actor or concurrently by other operations.
public final class NativeVaultService: VaultService, @unchecked Sendable {
    private let control = SessionControl()
    private let gate = OperationGate()
    private let worker: Worker
    public var authenticatedAt: TimeInterval? { control.authenticatedAt }

    public init(state: URL? = nil, configuration: any VaultPlatformConfiguration = DefaultVaultPlatformConfiguration(),
                documents: any DocumentAccessing = SystemDocumentAccess()) {
        let state = state ?? configuration.stateDirectory
        worker = Worker(state: state.standardizedFileURL, documents: documents, identityKeys: SynchronizedIdentityStore(), accountAuthentication: { strict, register in
            let context = try AccountAuthenticationPolicy.authorize(state: state, strict: strict ?? false, reason: "unlock your Mop vaults", contextCreated: { context in
                let invalidator = ContextInvalidator(context)
                try register { invalidator.invalidate() }
            })
            let invalidator = ContextInvalidator(context)
            return { invalidator.invalidate() }
        }, transport: {
            let config = try configuration.cloudConfiguration()
            return AppleCloudTransport(container: config.container, environment: config.environment)
        })
    }

    // Internal injection keeps test keys/transports and authentication out of the public app API.
    init(state: URL, identityKeys: any IdentityKeyStore, transport: @escaping () throws -> any CloudTransport,
         authenticate: @escaping AccountAuthenticationFactory) {
        worker = Worker(state: state, identityKeys: identityKeys, accountAuthentication: authenticate, transport: transport)
    }
    typealias AccountAuthenticationFactory = (Bool?, (@escaping @Sendable () -> Void) throws -> Void) throws -> (@Sendable () -> Void)

    public func lock() {
        control.lock()
        worker.published.clear()
        let token = control.generation
        Task.detached { [self] in
            await gate.enter()
            if worker.generation < token { worker.reset() }
            await gate.leave()
        }
    }
    public func execute(_ operation: VaultOperation, vault: String?, offline: Bool = false) async throws -> VaultResult {
        let token = control.generation
        let operationTask = Task.detached { [self] in
            do {
                if let result = try worker.published.read(operation, selection: vault, offline: offline, control: control, token: token) { return result }
            } catch {
                if let failure = error as? MopError,
                   [.authentication, .signing, .invalidIdentity, .invalidVault, .vaultUntrusted, .notVaultMember, .cloudAccount].contains(failure),
                   control.generation == token { lock() }
                throw error
            }
            await gate.enter()
            // An old queued request must never clean up a newer session.
            guard control.generation == token else {
                await gate.leave(); throw MopError.authentication
            }
            do {
                try control.check(token)
                if worker.generation != token { worker.reset(); worker.generation = token }
                let result: VaultResult
                let cached = offline || (operation.allowsCachedRead && !NetworkAvailability.shared.isOnline)
                do {
                    result = try await worker.execute(operation, selection: vault, offline: cached, control: control, token: token)
                } catch MopError.cloudUnavailable where !cached && operation.allowsCachedRead {
                    // Only transport unavailability permits a verified-cache fallback.
                    // Never hide revocation, account changes, missing vaults or bad signatures.
                    try control.check(token)
                    worker.closeStores()
                    result = try await worker.execute(operation, selection: vault, offline: true, control: control, token: token)
                }
                try control.check(token)
                try worker.publishSnapshots(control: control, token: token)
                await gate.leave()
                return result
            } catch {
                if let error = error as? MopError,
                   [.authentication, .signing, .invalidIdentity, .invalidVault, .vaultUntrusted, .notVaultMember, .cloudAccount].contains(error) {
                    if control.generation == token { control.lock() }
                }
                // A failed operation cannot leave a partially mutated store reusable.
                worker.closeStores()
                if control.generation != token { worker.reset() }
                await gate.leave()
                throw error
            }
        }
        let taskID = UUID()
        control.registerTask(taskID, token: token) { operationTask.cancel() }
        defer { control.finishedTask(taskID) }
        return try await withTaskCancellationHandler {
            try await operationTask.value
        } onCancel: {
            operationTask.cancel()
        }
    }
    deinit { control.lock() }
}

private final class Worker {
    let state: URL
    let documents: any DocumentAccessing
    let transportFactory: () throws -> any CloudTransport
    var generation = -1
    var repository: CloudRepository?
    let identityKeys: any IdentityKeyStore
    var accountIdentity: AccountIdentity?
    let accountAuthentication: NativeVaultService.AccountAuthenticationFactory
    var accountAuthenticationClose: (@Sendable () -> Void)?
    var stores: [UUID: CloudSecretStore] = [:]
    var snapshotDates: [UUID: Date] = [:]
    let published = PublishedSnapshots()
    init(state: URL, documents: any DocumentAccessing = SystemDocumentAccess(), identityKeys: any IdentityKeyStore, accountAuthentication: @escaping NativeVaultService.AccountAuthenticationFactory, transport: @escaping () throws -> any CloudTransport) {
        self.documents = documents; self.identityKeys = identityKeys; self.accountAuthentication = accountAuthentication
        self.state = state; transportFactory = transport
    }
    func closeStores() { published.clear(); stores.values.forEach { $0.close() }; stores.removeAll(); snapshotDates.removeAll() }
    func reset() { accountAuthenticationClose?(); accountAuthenticationClose = nil; closeStores(); accountIdentity?.close(); accountIdentity = nil; repository = nil }
    deinit { reset() }

    func publishSnapshots(control: SessionControl, token: Int) throws {
        try control.check(token)
        try published.update(stores: stores, dates: snapshotDates, offline: repository?.offline == true,
                             opener: accountIdentity.map { $0 as any VaultKeyOpener }, generation: token)
    }

    func userIdentity(_ repo: CloudRepository, control: SessionControl, token: Int, strict: Bool? = nil) async throws -> AccountIdentity {
        try control.check(token)
        if let accountIdentity, strict != true { return accountIdentity }
        if !control.authenticated || strict == true {
            let close = try accountAuthentication(strict) { try control.register($0, token: token) }
            do { try control.check(token); try control.authorized(token) } catch { close(); throw error }
            accountAuthenticationClose?()
            accountAuthenticationClose = close
        }
        if let accountIdentity { return accountIdentity }
        let identity = try await repo.accountIdentity(keys: identityKeys, create: !repo.offline) { try control.check(token) }
        do { try control.check(token) } catch { identity.close(); throw error }
        accountIdentity = identity
        return identity
    }
    func repo(offline: Bool, control: SessionControl, token: Int) async throws -> CloudRepository {
        let opened = try await CloudRepository.open(transport: transportFactory(), state: state, offline: offline)
        try control.check(token)
        if let previous = repository,
           previous.accountID != opened.accountID {
            throw MopError.cloudAccount
        }
        if repository?.offline != opened.offline { closeStores() }
        repository = opened
        return opened
    }
    func store(_ vault: CloudVault, offline: Bool, control: SessionControl, token: Int) async throws -> (CloudSecretStore, Date?) {
        let bytes: Data
        let date: Date?
        if offline { (bytes, date) = try vault.cached() }
        else { bytes = try await vault.sync(); date = nil }
        try control.check(token)
        _ = try VaultDocument.decode(bytes)
        guard let repository else { throw MopError.cloudAccount }
        let opener = try await userIdentity(repository, control: control, token: token)
        snapshotDates[vault.id] = date ?? Date()
        if let existing = stores[vault.id], existing.snapshot == bytes { return (existing, date) }
        stores.removeValue(forKey: vault.id)?.close()
        let opened = try CloudSecretStore(vault: vault, snapshot: bytes, opener: opener, offline: offline)
        try control.check(token)
        stores[vault.id] = opened
        return (opened, date)
    }
    private func snapshotResult(_ operation: VaultOperation, store: CloudSecretStore) throws -> VaultResult {
        var result = VaultResult()
        switch operation {
        case .read(let reference):
            let path = [reference.section, reference.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
            let type = try store.catalog().items.first { $0.name == reference.item }?
                .fields.first { $0.path == path }?.type
            let stored = try store.read(reference)
            if type == .otp {
                let otp = try TimeBasedOTP(String(decoding: stored, as: UTF8.self)), date = Date()
                result.value = SecretBytes(utf8: try otp.code(at: date))
                result.otpExpiresAt = otp.expires(at: date); result.otpPeriod = otp.period
            } else { result.value = stored }
            result.valueIsConcealed = type?.concealed ?? true
        case .passwordQuality(let name):
            guard let item = try store.catalog().items.first(where: { $0.name == name }) else { throw MopError.notFound }
            for field in item.fields where field.type == .password {
                result.passwordQuality[field.path] = field.passwordQuality
            }
        default: throw MopError.invalidProcess
        }
        return result
    }

    func execute(_ operation: VaultOperation, selection: String?, offline: Bool, control: SessionControl, token: Int) async throws -> VaultResult {
        if case .passwordQuality = operation {
            guard control.authenticated else { throw MopError.authentication }
        }
        // Reveal/copy and strength metadata use the last authenticated snapshot.
        // The operation gate protects sessions from concurrent mutation; generation
        // checks still reject results after lock. Catalog refreshes and all writes
        // continue through the online validation path below.
        switch operation {
        case .read, .passwordQuality:
            try control.check(token)
            if control.authenticated, let selection, let id = UUID(uuidString: selection),
               let store = stores[id] {
                var result = try snapshotResult(operation, store: store)
                result.usingCache = offline || repository?.offline == true
                result.offlineDate = result.usingCache ? snapshotDates[id] : nil
                return result
            }
        default: break
        }
        let repo = try await repo(offline: offline, control: control, token: token)
        var result = VaultResult()
        result.usingCache = offline
        switch operation {
        case .discover:
            let anchor = try await repo.identityAnchor()
            result.vaults = try await repo.descriptors(identity: anchor?.identity)
            if anchor == nil, result.vaults.contains(where: { $0.format == "mop-vault-v5" }) { throw MopError.identityPending }
            result.defaultVault = try? repo.selected(nil).id.uuidString
            return result
        default: break
        }
        let vault: CloudVault
        if let selection {
            guard let id = UUID(uuidString: selection) else { throw MopError.invalidVault }
            vault = try repo.vault(id)
        } else { vault = try repo.selected(nil) }
        try control.check(token)
        switch operation {
        case .sync:
            guard !offline else { throw MopError.offlineWrite }
            _ = try await vault.sync(); return result
        case .create(let name, let strict, let recoveryURL):
            guard !offline else { throw MopError.offlineWrite }
            try VaultName.validate(name)
            try await repo.ensureAvailable(name)
            try control.check(token)
            _ = try OutputFile(url: recoveryURL, force: false, mode: 0o600, protectedFiles: [], protectedDirectories: [state])
            let owner = try await userIdentity(repo, control: control, token: token, strict: strict)
            let device: any VaultKeyOpener = owner
            let recovery = RecoveryKey()
            try control.check(token)
            try recovery.save(to: recoveryURL)
            let bytes = try VaultSession.createAccountSnapshot(id: vault.id, name: name, owner: owner, recovery: recovery)
            let doc = try VaultDocument.decode(bytes)
            guard let slot = doc.header.recipients.first(where: { $0.publicKey == device.publicKey }) else { throw MopError.invalidVault }
            let fingerprint = try VaultTrust.fingerprint(document: doc, key: device.unwrap(slot, vaultID: vault.id))
            try control.check(token)
            let created = try await repo.create(bytes, fingerprint: fingerprint)
            try control.check(token)
            let store = try CloudSecretStore(vault: created, snapshot: bytes, opener: device)
            stores[vault.id] = store
            result.catalog = try store.catalog()
            result.message = "Vault created. Move the recovery credential offline.\nAccess key fingerprint: \(VaultCoding.digest(device.publicKey))\nVault fingerprint: \(fingerprint)"
            return result
        case .createPrepared:
            guard !offline, var intent = try PendingVaultCreation.load(state: state),
                  intent.id == vault.id, intent.exported else { throw MopError.invalidRecovery }
            guard intent.account == nil || intent.account == repo.accountID else { throw MopError.cloudAccount }
            let owner = try await userIdentity(repo, control: control, token: token, strict: intent.strict)
            let device: any VaultKeyOpener = owner
            if intent.snapshot == nil {
                try await repo.ensureAvailable(intent.name)
                let recovery = try RecoveryKey(file: PendingVaultCreation.recoveryURL(state: state))
                let bytes = try VaultSession.createAccountSnapshot(id: vault.id, name: intent.name, owner: owner, recovery: recovery)
                let doc = try VaultDocument.decode(bytes)
                guard let slot = doc.header.recipients.first(where: { $0.publicKey == device.publicKey }) else { throw MopError.invalidVault }
                intent.fingerprint = try VaultTrust.fingerprint(document: doc, key: device.unwrap(slot, vaultID: vault.id))
                intent.snapshot = bytes
                intent.account = repo.accountID
                try control.check(token)
                try intent.save(state: state)
            }
            guard let initial = intent.snapshot, let fingerprint = intent.fingerprint else { throw MopError.invalidVault }
            let bytes: Data
            if intent.submitted {
                // Never resurrect a deleted vault when a submitted creation has no head.
                do { bytes = try await vault.sync() }
                catch MopError.vaultMissing { throw MopError.cloudUncertain }
                guard try await vault.revisions().contains(VaultCoding.digest(initial)) else { throw MopError.vaultConflict }
                // The fingerprint is local authenticated creation evidence, not cloud input.
                try vault.establishTrust(bytes, opener: device, fingerprint: fingerprint, revision: nil)
            } else {
                try control.check(token)
                intent.submitted = true
                try intent.save(state: state)
                _ = try await repo.create(initial, fingerprint: fingerprint)
                bytes = initial
            }
            try control.check(token)
            let store = try CloudSecretStore(vault: vault, snapshot: bytes, opener: device)
            stores[vault.id] = store
            result.catalog = try store.catalog()
            result.message = "Vault created. Keep the exported recovery credential offline.\nAccess key fingerprint: \(VaultCoding.digest(device.publicKey))\nVault fingerprint: \(fingerprint)"
            try PendingVaultCreation.finish(state: state)
            return result
        case .deleteVault:
            guard !offline else { throw MopError.offlineWrite }
            // Deletion does not require decrypting the vault, including unsupported formats.
            if !control.authenticated {
                let context = try AccountAuthenticationPolicy.authorize(state: state, reason: "delete this Mop vault and all its cloud history", contextCreated: { context in
                    let invalidator = ContextInvalidator(context)
                    try control.register({ invalidator.invalidate() }, token: token)
                })
                defer { context.invalidate() }
                try control.check(token)
                try await repo.delete(vault.id)
            } else { try await repo.delete(vault.id) }
            stores.removeValue(forKey: vault.id)?.close()
            return result
        case .manage(let action):
            guard !offline else { throw MopError.offlineWrite }
            switch action {
            case .trust(let fingerprint):
                guard VaultTrust.validFingerprint(fingerprint) else { throw MopError.invalidProcess }
                let bytes = try await vault.sync()
                let device = try await userIdentity(repo, control: control, token: token)
                try vault.establishTrust(bytes, opener: device, fingerprint: fingerprint, revision: nil)
                stores.removeValue(forKey: vault.id)?.close()
                result.message = "Vault key trusted for this account and vault."
                return result
            case .recover(let file, let fingerprint):
                guard VaultTrust.validFingerprint(fingerprint) else { throw MopError.invalidProcess }
                let bytes = try await vault.sync()
                try control.check(token)
                let owner = try await userIdentity(repo, control: control, token: token)
                let recovery = try RecoveryKey(file: file)
                try vault.establishTrust(bytes, opener: recovery, fingerprint: fingerprint, revision: nil)
                let store = try CloudSecretStore(vault: vault, snapshot: bytes, opener: recovery)
                defer { store.close() }
                try control.check(token)
                try await store.adoptOwner(owner, beforePublish: { try control.check(token) })
                stores.removeValue(forKey: vault.id)?.close()
                result.message = "Vault access recovered. Return the recovery credential offline."
                return result
            default: break
            }
        default: break
        }
        switch operation {
        case .catalog, .recentlyDeleted, .read, .export, .passwordQuality: break
        default: guard !offline else { throw MopError.offlineWrite }
        }
        let (store, date) = try await store(vault, offline: offline, control: control, token: token)
        result.offlineDate = date
        try control.check(token)
        switch operation {
        case .catalog, .recentlyDeleted:
            if !offline { try await store.purgeExpiredItems(at: Date()) }
            result.catalog = try store.catalog()
            result.deletedCatalog = try store.recentlyDeleted(at: Date())
        case .trashItem(let name, let revision):
            try await store.trashItem(name: name, revision: revision, at: Date())
            result.catalog = try store.catalog()
            result.deletedCatalog = try store.recentlyDeleted(at: Date())
        case .restoreItem(let id, let revision):
            try await store.restoreItem(id: id, revision: revision, at: Date())
            result.catalog = try store.catalog()
            result.deletedCatalog = try store.recentlyDeleted(at: Date())
        case .passwordQuality, .read:
            let local = try snapshotResult(operation, store: store)
            result.value = local.value
            result.valueIsConcealed = local.valueIsConcealed
            result.passwordQuality = local.passwordQuality
        case .save(let edit): try await store.saveItem(edit); result.catalog = try store.catalog()
        case .write(let reference, let value, let replace):
            try await store.write(reference, value: value, replace: replace); result.catalog = try store.catalog()
        case .delete(let reference): try await store.delete(reference); result.catalog = try store.catalog()
        case .members:
            result.members = store.membership?.members.map { VaultMemberRecord(id: $0.identity.id, role: $0.role.rawValue) } ?? []
        case .rename(let name):
            try await repo.ensureAvailable(name, excluding: vault.id)
            try control.check(token)
            try await store.rename(name); result.catalog = try store.catalog()
        case .export(let url):
            try control.check(token)
            try documents.write(to: url) { target in
                let output = try OutputFile(url: target, force: false, mode: 0o600, protectedFiles: [], protectedDirectories: [state])
                try control.check(token)
                try output.write(store.snapshot)
            }
        case .manage(let action):
            switch action {
            case .fingerprint: result.message = try store.fingerprint()
            default: throw MopError.invalidProcess
            }
            result.catalog = try store.catalog()
        default: throw MopError.invalidProcess
        }
        return result
    }
}

// The gate owns mutable stores. This separate lock owns read-only session copies,
// so network waits and uncommitted writes never block or leak into item reads.
// Clear these copies before closing their shared key opener in Worker.reset().
private final class PublishedSnapshots: @unchecked Sendable {
    private let lock = NSLock()
    private var sessions: [UUID: VaultSession] = [:]
    private var otps: [UUID: [String: TimeBasedOTP]] = [:]
    private var dates: [UUID: Date] = [:]
    private var offline = false
    private var generation = -1
    func clear() {
        lock.lock(); defer { lock.unlock() }
        sessions.values.forEach { $0.close() }; sessions.removeAll(); dates.removeAll(); otps.removeAll()
    }
    func update(stores: [UUID: CloudSecretStore], dates: [UUID: Date], offline: Bool,
                opener: (any VaultKeyOpener)?, generation: Int) throws {
        lock.lock(); defer { lock.unlock() }
        guard let opener else { return }
        for (id, store) in stores where sessions[id]?.snapshot != store.snapshot {
            let next = try VaultSession(snapshot: store.snapshot, trust: store.vault.trust, opener: opener)
            sessions.removeValue(forKey: id)?.close(); otps[id] = nil; sessions[id] = next
        }
        for id in Array(sessions.keys) where stores[id] == nil { sessions.removeValue(forKey: id)?.close(); otps[id] = nil }
        self.dates = dates; self.offline = offline; self.generation = generation
    }
    func read(_ operation: VaultOperation, selection: String?, offline: Bool,
              control: SessionControl, token: Int) throws -> VaultResult? {
        lock.lock(); defer { lock.unlock() }
        try control.check(token)
        guard generation == token, control.authenticated, let selection,
              let id = UUID(uuidString: selection), let session = sessions[id] else { return nil }
        var result = VaultResult()
        switch operation {
        case .read(let reference):
            let path = [reference.section, reference.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
            let type = try session.catalog().items.first { $0.name == reference.item }?
                .fields.first { $0.path == path }?.type
            if type == .otp {
                if otps[id]?[reference.description] == nil {
                    let stored = try session.read(reference)
                    otps[id, default: [:]][reference.description] = try TimeBasedOTP(String(decoding: stored, as: UTF8.self))
                }
                guard let otp = otps[id]?[reference.description] else { throw MopError.invalidOTP }
                let date = Date()
                result.value = SecretBytes(utf8: try otp.code(at: date))
                result.otpExpiresAt = otp.expires(at: date); result.otpPeriod = otp.period
            } else { result.value = try session.read(reference) }
            result.valueIsConcealed = type?.concealed ?? true
        case .passwordQuality(let name):
            guard let item = try session.catalog().items.first(where: { $0.name == name }) else { throw MopError.notFound }
            for field in item.fields where field.type == .password { result.passwordQuality[field.path] = field.passwordQuality }
        default: return nil
        }
        result.usingCache = offline || self.offline
        result.offlineDate = result.usingCache ? dates[id] : nil
        try control.check(token)
        return result
    }
}
