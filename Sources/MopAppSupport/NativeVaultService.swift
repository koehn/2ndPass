import Foundation
import CloudKit
import LocalAuthentication
import OSLog
import Synchronization
import MopCore
import MopAuth
import MopVaultNext

/// Catalogs for distinct vaults may overlap; other cloud operations are exclusive.
/// Local reads use verified session snapshots.
/// Hardware handles and transient keys never survive an operation. Locking clears
/// snapshots, invalidates authentication, and rejects earlier-generation results.
public final class NativeVaultService: VaultService, @unchecked Sendable {
    private let control = SessionControl()
    private let gate = OperationGate()
    private let authorizationGate = OperationGate()
    private let progressState = Mutex<(String, Double?)?>(nil)
    public var operationProgress: String? { progressState.withLock { $0?.0 } }
    public var operationFraction: Double? { progressState.withLock { $0?.1 } }
    private func reportProgress(_ message: String, fraction: Double? = nil) { progressState.withLock { $0 = (message, fraction) } }
    private let state: URL
    private let wallNow: @Sendable () -> Date
    private let usageStore: any ItemUsageStoring
    private let configuration: any VaultPlatformConfiguration
    private let documents: any DocumentAccessing
    private let makeTransport: (String, String) throws -> any VaultTransport
    private let deleteDevice: (String, UUID) throws -> Void
    private let removedRegistry = Mutex<NextRegistry?>(nil)
    private let openDevice: (String, UUID, LAContext, Bool) throws -> any DeviceOperations
    private let authenticate: (@escaping (LAContext) throws -> Void) async throws -> LAContext
    private var authorization: (token: Int, context: LAContext)?
    private var allowsAttachments = true
    private var attachmentSyncOverride: Bool?
    private let publishesAutoFill: Bool
    private var accountObserver: NSObjectProtocol?
    public var sessionGeneration: Int { control.generation }
    public var authenticatedAt: TimeInterval? { control.authenticatedAt }
    public init(state: URL? = nil, allowsAttachments: Bool = true, configuration: any VaultPlatformConfiguration = DefaultVaultPlatformConfiguration(), documents: any DocumentAccessing = SystemDocumentAccess(), usageStore: (any ItemUsageStoring)? = nil, wallNow: @escaping @Sendable () -> Date = Date.init) {
        self.wallNow = wallNow
        self.usageStore = usageStore ?? ItemUsageStore(state: state ?? configuration.stateDirectory)
        self.allowsAttachments = allowsAttachments
        makeTransport = { try CloudRevisionTransport(container: $0, environment: $1) }
        deleteDevice = { try DeviceKeychain.remove(scope: $0, member: $1) }
        openDevice = { try DeviceKeychain.open(scope: $0, member: $1, context: $2, create: $3) }
        authenticate = { try await Authentication.authorizeAsync(reason: "use your 2ndPass device keys", contextCreated: $0) }
        self.state = state ?? configuration.stateDirectory; self.configuration = configuration; self.documents = documents
        publishesAutoFill = state == nil && Bundle.main.object(forInfoDictionaryKey: "MopPublishesAutoFill") as? Bool == true
        if publishesAutoFill { Task { try? await AutoFillPublisher.shared.refresh() } }
        let directory = self.state, control = self.control
        accountObserver = NotificationCenter.default.addObserver(forName: .CKAccountChanged, object: nil, queue: nil) { _ in
            control.lock(); try? NextAccountBinding.invalidate(state: directory)
        }
    }
    // Test-only injection is internal. Public app/CLI construction always uses
    // Apple's hardware provider, account checks and user-presence authentication.
    init(state: URL, configuration: any VaultPlatformConfiguration, transport: any VaultTransport, allowsAttachments: Bool = true, attachmentSyncOverride: Bool? = nil,
         openDevice: @escaping (String, UUID, LAContext, Bool) throws -> any DeviceOperations,
         deleteDevice: @escaping (String, UUID) throws -> Void = { _, _ in },
         authenticate: @escaping (@escaping (LAContext) throws -> Void) async throws -> LAContext, usageStore: (any ItemUsageStoring)? = nil, wallNow: @escaping @Sendable () -> Date = Date.init) {
        self.wallNow = wallNow; self.usageStore = usageStore ?? ItemUsageStore(state: state)
        self.allowsAttachments = allowsAttachments; self.attachmentSyncOverride = attachmentSyncOverride
        self.state = state; self.configuration = configuration; documents = SystemDocumentAccess()
        publishesAutoFill = false; makeTransport = { _, _ in transport }
        self.openDevice = openDevice; self.deleteDevice = deleteDevice; self.authenticate = authenticate
    }
    public func cachedCatalog(vault: String) async throws -> VaultResult? {
        try CloudVaultBoundary.requireCloud(vault)
        do { return try await execute(.catalog, vault: vault, offline: true) }
        catch MopError.vaultMissing { return nil }
    }
    public func endRecoverySession() {
        recoverySession.withLock { session in session?.keys.values.forEach { $0.close() }; session = nil }
        generatedRecovery.withLock { $0 = nil }
    }
    public func lock() { control.lock() }
    deinit { control.lock(); if let accountObserver { NotificationCenter.default.removeObserver(accountObserver) } }
    /// Read the already verified session snapshot independently of the cloud
    /// operation queue. Only the requested field's item key is unwrapped.
    public func readLocal(_ reference: SecretReference, vault: String?) async throws -> VaultResult {
        try CloudVaultBoundary.requireCloud(vault)
        try CloudVaultBoundary.requireCloud(reference.vault)
        let token = control.generation
        let session = try control.localRead(vault: vault, name: reference.vault, token: token)
        let task = Task.detached { [self] in
            try control.check(token)
            let account = try NextAccountBinding.account(state: state, container: session.container, environment: session.environment)
            guard account == session.account else { throw MopError.cloudAccount }
            let registry = try NextRegistry(state: state, container: session.container, environment: session.environment, account: account)
            guard try !registry.removed() else { throw MopError.deviceRemoved }
            let key = try openDevice(session.container + "/" + session.environment + "/device", registry.member, session.context.context, false)
            defer {
                if let enclave = key as? EnclaveDevice { enclave.releaseHandles() }
                else { key.close() }
            }
            let read = try session.reader.read(reference, device: key, allowsAttachments: allowsAttachments)
            var result = VaultResult(); result.usingCache = true; result.offlineDate = session.verifiedAt
            if read.field.type == .otp {
                let otp = try TimeBasedOTP(String(decoding: read.value, as: UTF8.self)), now = wallNow()
                result.value = SecretBytes(utf8: try otp.code(at: now)); result.otpExpiresAt = otp.expires(at: now); result.otpPeriod = otp.period
            } else { result.value = read.value }
            result.valueIsConcealed = read.field.type.concealed
            if let id = read.itemID {
                result.usageIdentity = ItemUsageIdentity(account: registry.member.uuidString, vault: session.reader.vault.id.uuidString, item: id)
            }
            try control.check(token)
            return result
        }
        let id = UUID(); control.registerTask(id, token: token) { task.cancel() }
        defer { control.finishedTask(id) }
        return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
    }
    public func execute(_ operation: VaultOperation, vault: String?, offline: Bool = false) async throws -> VaultResult {
        try CloudVaultBoundary.requireCloud(vault)
        switch operation {
        case .create(let name), .rename(let name): try CloudVaultBoundary.validateName(name)
        case .read(let ref), .delete(let ref), .write(let ref, _, _): try CloudVaultBoundary.requireCloud(ref.vault)
        default: break
        }
        if case .manage(.automaticEnrollment) = operation, !isAuthenticated { throw MopError.authentication }
        let token = control.generation
        let started = wallNow()
        let catalogVault: String?
        if case .catalog = operation { catalogVault = vault.flatMap(UUID.init(uuidString:))?.uuidString }
        else { catalogVault = nil }
        let task = Task.detached { [self] in
            await gate.enter(vault: catalogVault)
            progressState.withLock { $0 = nil }
            do {
                try control.check(token)
                var result = try await run(operation, selection: vault, offline: offline, token: token)
                try control.check(token)
                result.catalog?.usageScope = result.usageScope
                result.deletedCatalog?.usageScope = result.usageScope
                if !offline, let account = result.usageScope, let retained = result.retainedItemIDs, let vault = result.usageVault {
                    let usageStore = self.usageStore
                    Task {
                        do { try await usageStore.prune(account: account, vault: vault, keeping: retained, before: started) }
                        catch { ItemUsageLogging.failure(error) }
                    }
                }
                if publishesAutoFill, let catalog = result.catalog, let vault, UUID(uuidString: vault) != nil {
                    do { try await AutoFillPublisher.shared.publish(catalog: catalog, vaultID: vault) }
                    catch { result.autoFillStatus = await AutoFillPublisher.shared.status() }
                }
                progressState.withLock { $0 = nil }
                await gate.leave(vault: catalogVault); return result
            } catch {
                if Task.isCancelled {
                    recoverySession.withLock { session in session?.keys.values.forEach { $0.close() }; session = nil }
                    generatedRecovery.withLock { $0 = nil }
                }
                progressState.withLock { $0 = nil }
                let needsCleanup = removedRegistry.withLock { $0 != nil }
                if needsCleanup { control.lock() }
                await gate.leave(vault: catalogVault)
                if needsCleanup {
                    // Drain concurrent catalogs before deleting account caches/keys.
                    await gate.enter()
                    do {
                        if let registry = removedRegistry.withLock({ $0 }) {
                            try await clearRemovedAccount(registry)
                            removedRegistry.withLock { $0 = nil }
                        }
                    } catch { await gate.leave(); throw error }
                    await gate.leave()
                }
                throw error
            }
        }
        let id = UUID(); control.registerTask(id, token: token) { task.cancel() }
        defer { control.finishedTask(id) }
        return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
    }
    private func clearRemovedAccount(_ registry: NextRegistry) async throws {
        // An interrupted recovery may already have enrolled this key in iCloud.
        // Keep it until recovery finalization releases the removal barrier.
        if try registry.hasPendingRecovery() { return }
        // The durable marker blocks every process before deletion begins.
        do {
            try deleteDevice(registry.container + "/" + registry.environment + "/device", registry.member)
            try registry.clearRemovedAccount()
            if (try? AutoFillStorage.directory()) != nil { try await AutoFillPublisher.shared.prune(keeping: []) }
            authorization?.context.invalidate(); authorization = nil
        } catch { throw MopError.deviceRemovalPending }
    }
    private func authorizedContext(token: Int) async throws -> LAContext {
        await authorizationGate.enter()
        do {
            try control.check(token)
            let context: LAContext
            if let cached = authorization, cached.token == token { context = cached.context }
            else {
                authorization?.context.invalidate(); authorization = nil
                context = try await authenticate { context in
                    let invalidator = ContextInvalidator(context)
                    try self.control.register({ invalidator.invalidate() }, token: token)
                }
                try control.check(token); try control.authorized(token)
                authorization = (token, context)
            }
            await authorizationGate.leave()
            return context
        } catch { await authorizationGate.leave(); throw error }
    }
    private struct RecoverySession {
        let token: Int
        let scope: RecoveryScope
        var keys: [String: OfflineRecoveryKey] = [:]
        var vaults: [UUID: (VaultAddress, VerifiedVault)] = [:]
    }
    private let recoverySession = Mutex<RecoverySession?>(nil)
    private let generatedRecovery = Mutex<(Int, DevicePublicKey)?>(nil)

    private func runRecovery(_ action: VaultManagement, registry: NextRegistry, transport: any VaultTransport, token: Int) async throws -> VaultResult? {
        switch action {
        case .recoveryTestReset, .recoveryEligibility, .recoveryGenerate, .recoveryStatus, .recoveryRevoke, .recoveryResume, .recoveryActivate,
             .recoveryOpen, .recoveryCatalog, .recoveryRead, .recoveryComplete: break
        default: return nil
        }
        let scope = try RecoveryScope(container: registry.container, environment: registry.environment, account: registry.account)
        var result = VaultResult(); result.recoveryScope = scope
        func register(_ key: OfflineRecoveryKey) throws {
            try control.register({ key.close() }, token: token)
        }
        func closeDevice(_ key: any DeviceOperations) {
            if let enclave = key as? EnclaveDevice { enclave.releaseHandles() } else { key.close() }
        }
        func owner() async throws -> any DeviceOperations {
            let context = try await authorizedContext(token: token)
            try control.check(token)
            return try openDevice(registry.container + "/" + registry.environment + "/device", registry.member, context, true)
        }
        func sessionVault(_ id: UUID) throws -> (VaultAddress, VerifiedVault, OfflineRecoveryKey) {
            try control.check(token)
            return try recoverySession.withLock { session in
                guard let session, session.token == token, session.scope == scope,
                      let (address, vault) = session.vaults[id], let identity = vault.membership.offlineRecovery,
                      let key = session.keys[identity.fingerprint] else { throw MopError.invalidRecovery }
                return (address, vault, key)
            }
        }
        func hasAccess(to vault: VerifiedVault) async throws -> Bool {
            let context = try await authorizedContext(token: token)
            let device: any DeviceOperations
            do { device = try openDevice(registry.container + "/" + registry.environment + "/device", registry.member, context, false) }
            catch MopError.invalidIdentity { return false }
            defer { closeDevice(device) }
            guard vault.membership.role(of: device.identity) != nil else { return false }
            _ = try VaultEngine.catalog(in: vault, device: device)
            return true
        }
        switch action {
        case .recoveryTestReset(let copy):
            reportProgress("Verifying your offline copy before resetting this device…")
            let context = try await authorizedContext(token: token)
            let device = try openDevice(registry.container + "/" + registry.environment + "/device", registry.member, context, false)
            defer { closeDevice(device) }
            let key = try OfflineRecoveryKey(document: copy, scope: scope)
            defer { key.close() }
            try register(key)
            let record = try await transport.recoveryConfiguration(scope: scope)
            guard !record.configuration.incomplete, record.configuration.active == key.identity,
                  try registry.entries().allSatisfy({ $0.address.database == .private }) else { throw MopError.invalidRecovery }
            let addresses = try await transport.discover().filter { $0.database == .private }
            guard !addresses.isEmpty else { throw MopError.vaultMissing }
            let verificationCache = FileManager.default.temporaryDirectory.appendingPathComponent("mop-recovery-reset-" + UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: verificationCache) }
            var heads: [(VaultAddress, String)] = []
            for (index, address) in addresses.enumerated() {
                try control.check(token)
                reportProgress("Testing recovery: vault \(index + 1) of \(addresses.count)…", fraction: Double(index) / Double(addresses.count))
                var vault = try await VerifiedVault.bootstrapRecovery(at: address, transport: transport)
                guard vault.membership.role(of: device.identity) == .owner,
                      vault.membership.offlineRecovery == key.identity else { throw MopError.invalidRecovery }
                vault = try await AttachmentDownloads(state: verificationCache, address: address).load(vault, digests: vault.attachmentDigests, transport: transport, offline: false)
                // Validate a complete recovery, including retained records and blobs,
                // entirely in memory. Never publish this trial revision.
                _ = try VaultEngine.recover(vault, using: key, owner: device.identity)
                heads.append((address, vault.digest))
            }
            guard try await transport.recoveryConfiguration(scope: scope).version == record.version,
                  Set(try await transport.discover().filter { $0.database == .private }.map(\.vault)) == Set(addresses.map(\.vault)) else { throw MopError.vaultConflict }
            for (address, digest) in heads {
                guard try await transport.head(at: address).digest == digest else { throw MopError.vaultConflict }
            }
            try control.check(token)
            // Use the durable removal barrier and existing drained cleanup path.
            // The barrier prevents automatic enrollment even after a restart.
            try registry.setRemoved(true)
            removedRegistry.withLock { $0 = registry }
            throw MopError.deviceRemoved
        case .recoveryEligibility:
            reportProgress("Checking this device’s vault access…")
            let addresses = try await transport.discover().filter { $0.database == .private }
            for address in addresses {
                try control.check(token)
                let vault = try await VerifiedVault.bootstrapRecovery(at: address, transport: transport)
                if try await hasAccess(to: vault), !(try registry.recoveryPending(vault.id)) {
                    result.vaults.append(VaultDescriptor(id: vault.id.uuidString, name: vault.name, format: "mop-vault-v7", enrolled: true))
                } else { result.recoveryNeeded = true }
            }
            result.message = addresses.isEmpty ? "No iCloud vaults were found for this Apple Account." :
                (result.recoveryNeeded ? "Use your offline copy to open vaults this device cannot access." : "This device can already open your vaults. 2ndPass is working correctly, and recovery isn’t needed.")
            return result
        case .recoveryGenerate:
            _ = try await authorizedContext(token: token)
            let key = try OfflineRecoveryKey(scope: scope); defer { key.close() }; try register(key)
            generatedRecovery.withLock { $0 = (token, key.identity) }
            result.recoveryCode = try key.code(); result.recoveryFile = try key.export(); result.recoveryFingerprint = key.identity.fingerprint
            result.message = "Save an offline copy, then re-enter or re-import it to activate recovery."
            return result
        case .recoveryStatus:
            reportProgress("Discovering vaults for coverage checks…")
            var configuration = try await transport.recoveryConfiguration(scope: scope).configuration
            let expected = configuration.operation == nil ? configuration.active : configuration.target
            var statuses: [RecoveryVaultStatus] = []
            let addresses = try await transport.discover().filter { $0.database == .private }
            for (index, address) in addresses.enumerated() {
                reportProgress("Checking coverage: vault \(index + 1) of \(addresses.count)…", fraction: Double(index) / Double(addresses.count))
                try control.check(token)
                do {
                    let vault = try await VerifiedVault.bootstrapRecovery(at: address, transport: transport)
                    result.vaults.append(VaultDescriptor(id: vault.id.uuidString, name: vault.name, format: "mop-vault-v7", enrolled: false))
                    statuses.append(RecoveryVaultStatus(id: address.vault, fingerprint: vault.membership.offlineRecovery?.fingerprint,
                        complete: vault.membership.offlineRecovery == expected,
                        issue: vault.membership.offlineRecovery == expected ? nil : "Coverage differs from the account configuration. Resume to reconcile."))
                } catch {
                    statuses.append(RecoveryVaultStatus(id: address.vault, fingerprint: nil, complete: false, issue: "Coverage could not be verified."))
                }
            }
            configuration.vaults = statuses; result.recoveryVaults = statuses
            result.recoveryConfiguration = configuration
            if configuration.incomplete || statuses.contains(where: { !$0.complete }) {
                result.message = "Recovery coverage is incomplete. Keep both offline copies until replacement finishes."
            } else { result.message = configuration.active == nil ? "No offline recovery key is configured." : (statuses.isEmpty ? "No owned iCloud vaults were found." : "Offline recovery is enabled for \(statuses.count == 1 ? "your iCloud vault" : "all \(statuses.count) of your discovered iCloud vaults").") }
            return result
        case .recoveryOpen(let copy):
            _ = try await authorizedContext(token: token)
            let key = try OfflineRecoveryKey(document: copy, scope: scope); try register(key)
            var retained = false
            defer { if !retained { key.close() } }
            var configuration = try await transport.recoveryConfiguration(scope: scope).configuration
            if configuration.pendingCreation != nil, configuration.active == key.identity {
                try await transport.finishRecoveryCreation(scope: scope, using: key.identity)
                configuration = try await transport.recoveryConfiguration(scope: scope).configuration
            }
            var found: [UUID: (VaultAddress, VerifiedVault)] = [:]
            for address in try await transport.discover() where address.database == .private {
                try control.check(token)
                do {
                    let vault = try await VerifiedVault.bootstrapRecovery(at: address, transport: transport)
                    if try await hasAccess(to: vault), !(try registry.recoveryPending(vault.id)) { continue }
                    guard vault.membership.offlineRecovery == key.identity else {
                        result.recoveryVaults.append(RecoveryVaultStatus(id: address.vault, fingerprint: vault.membership.offlineRecovery?.fingerprint, complete: false, issue: "Use the offline copy matching this vault's fingerprint.")); continue
                    }
                    _ = try VaultEngine.catalog(in: vault, device: key)
                    found[vault.id] = (address, vault)
                    result.vaults.append(VaultDescriptor(id: vault.id.uuidString, name: vault.name, format: "mop-vault-v7", enrolled: false))
                    result.recoveryVaults.append(RecoveryVaultStatus(id: vault.id, fingerprint: key.identity.fingerprint, complete: false))
                } catch {
                    result.recoveryVaults.append(RecoveryVaultStatus(id: address.vault, fingerprint: nil, complete: false, issue: "Vault could not be verified or opened."))
                }
            }
            guard !found.isEmpty else { key.close(); throw MopError.invalidRecovery }
            try control.check(token)
            recoverySession.withLock { session in
                if session?.token != token || session?.scope != scope { session = RecoverySession(token: token, scope: scope) }
                session!.keys[key.identity.fingerprint]?.close()
                session!.keys[key.identity.fingerprint] = key
                session!.vaults.merge(found) { _, new in new }
            }
            retained = true
            result.recoveryConfiguration = configuration; result.recoveryReadOnly = true
            result.message = "Read-only recovery access opened. Existing devices and accounts keep access. Complete recovery for each vault."
            return result
        case .recoveryCatalog(let id):
            let (_, vault, key) = try sessionVault(id)
            result.catalog = try VaultEngine.catalog(in: vault, device: key)
            result.recoveryReadOnly = true
            return result
        case .recoveryRead(let id, let reference):
            let (address, snapshot, key) = try sessionVault(id)
            var vault = snapshot
            if let digest = try vault.attachmentDigest(for: reference, device: key) {
                vault = try await AttachmentDownloads(state: state, address: address).load(vault, digests: [digest], transport: transport, offline: false)
            }
            result.value = try VaultEngine.read(reference, in: vault, device: key)
            let parsed = try SecretReference(vault: vault.name, relativePath: reference)
            let path = [parsed.section, parsed.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
            let catalog = try VaultEngine.catalog(in: vault, device: key)
            if catalog.items.first(where: { $0.name == parsed.item })?.fields.first(where: { $0.path == path })?.type == .attachment {
                result.recoveredAttachment = try Attachment.decode(String(decoding: result.value!, as: UTF8.self))
                result.value = nil
            }
            result.recoveryReadOnly = true; result.valueIsConcealed = true
            return result
        case .recoveryComplete(let id):
            let (address, _, key) = try sessionVault(id)
            var current = try await VerifiedVault.bootstrapRecovery(at: address, transport: transport)
            guard current.membership.offlineRecovery == key.identity else { throw MopError.invalidRecovery }
            let alreadyCommitted = try await hasAccess(to: current)
            guard try !alreadyCommitted || registry.recoveryPending(id) else { throw MopError.invalidRecovery }
            let downloads = AttachmentDownloads(state: state, address: address)
            do { current = try await downloads.load(current, digests: current.attachmentDigests, transport: transport, offline: false) }
            catch {
                result.recoveryReadOnly = true
                result.recoveryVaults = [RecoveryVaultStatus(id: id, fingerprint: key.identity.fingerprint, complete: false, issue: "Attachment data is unavailable. Read-only access remains; existing devices and accounts keep access.")]
                result.message = result.recoveryVaults[0].issue!
                return result
            }
            var device = try await owner()
            if (current.membership.removedDevices ?? []).contains(device.identity.device) {
                closeDevice(device)
                try deleteDevice(registry.container + "/" + registry.environment + "/device", registry.member)
                device = try await owner()
            }
            defer { closeDevice(device) }
            let next = try alreadyCommitted ? current : VaultEngine.recover(current, using: key, owner: device.identity)
            let entry = NextEntry(address: address, checkpoint: current.bytes, digest: current.digest, name: current.name, submitted: true, ready: false)
            let storage = try registry.storage(entry)
            let pin = try storage.load(binding: address.binding).map { try VerifiedVault(checkpoint: $0.snapshot, independentlyVerifiedDigest: $0.verifiedDigest) } ?? current
            let coordinator = try PublicationCoordinator(address: address, checkpoint: pin, transport: transport, storage: storage)
            _ = try await coordinator.refresh(reconcileUnchangedPending: true)
            guard await coordinator.offlineSnapshot().0.digest == current.digest else { throw MopError.vaultConflict }
            try control.check(token)
            try registry.setRecoveryPending(true, vault: id)
            if !alreadyCommitted { try await coordinator.publish(next) }
            try downloads.cache(next)
            let inbox = try await transport.enrollment(at: address)
            try await transport.saveEnrollment(EnrollmentMailbox(), version: inbox.version, at: address)
            try control.check(token)
            try registry.setRemoved(false)
            try registry.put(NextEntry(address: address, checkpoint: next.bytes, digest: next.digest, name: next.name, submitted: true, ready: true))
            try registry.setRecoveryPending(false, vault: id)
            recoverySession.withLock { $0?.vaults[id] = (address, next) }
            result.recoveryVaults = [RecoveryVaultStatus(id: id, fingerprint: key.identity.fingerprint, complete: true)]
            result.message = "Vault recovered onto this device. Existing devices, accounts, and sharing retain access."
            return result
        default: break
        }
        // Lifecycle changes require ordinary owner authority for every affected
        // vault. Recovery first restores that authority on a replacement device.
        reportProgress("Preparing recovery configuration…")
        let device = try await owner(); defer { closeDevice(device) }
        if case .recoveryResume = action { try await transport.finishRecoveryCreation(scope: scope, using: device.identity) }
        var record = try await transport.recoveryConfiguration(scope: scope)
        var configuration = record.configuration
        guard configuration.pendingCreation == nil else { throw MopError.vaultConflict }
        let target: DevicePublicKey?
        switch action {
        case .recoveryActivate(let copy, let fingerprint):
            reportProgress("Verifying your recovery copy…")
            let verified = try OfflineRecoveryKey(document: copy, scope: scope); defer { verified.close() }
            guard verified.identity.fingerprint == fingerprint else { throw MopError.invalidRecovery }
            // CLI can verify an exported copy across process boundaries using its
            // separately displayed public fingerprint. App-generated state adds
            // a same-session equality check when available.
            try generatedRecovery.withLock { pending in
                if let pending, pending.0 == token { guard pending.1 == verified.identity else { throw MopError.invalidRecovery } }
            }
            target = verified.identity
        case .recoveryRevoke: target = nil
        case .recoveryResume:
            if !configuration.incomplete, configuration.active == nil { result.recoveryConfiguration = configuration; return result }
            target = configuration.operation == nil ? configuration.active : configuration.target
        default: throw MopError.invalidProcess
        }
        if configuration.incomplete {
            guard target == configuration.target else { throw MopError.vaultConflict }
        } else {
            let addresses = try await transport.discover().filter { $0.database == .private }
            for (index, address) in addresses.enumerated() {
                reportProgress("Verifying owner access: vault \(index + 1) of \(addresses.count)…", fraction: Double(index) / Double(addresses.count))
                let vault = try await VerifiedVault.bootstrapRecovery(at: address, transport: transport)
                guard vault.membership.role(of: device.identity) == .owner else { throw MopError.cloudPermission }
            }
            configuration.target = target; configuration.operation = UUID()
            configuration.vaults = addresses.map { RecoveryVaultStatus(id: $0.vault, fingerprint: nil, complete: false) }
            try await transport.saveRecoveryConfiguration(configuration, version: record.version)
            record = try await transport.recoveryConfiguration(scope: scope)
        }
        let operation = configuration.operation
        let addresses = try await transport.discover().filter { $0.database == .private }
        for (index, address) in addresses.enumerated() {
            reportProgress("Updating recovery: vault \(index + 1) of \(addresses.count)…", fraction: Double(index) / Double(addresses.count))
            try control.check(token)
            record = try await transport.recoveryConfiguration(scope: scope)
            guard record.configuration.operation == operation, record.configuration.target == target else { throw MopError.vaultConflict }
            configuration = record.configuration
            var status = RecoveryVaultStatus(id: address.vault, fingerprint: nil, complete: false)
            do {
                var vault = try await VerifiedVault.bootstrapRecovery(at: address, transport: transport)
                result.vaults.append(VaultDescriptor(id: vault.id.uuidString, name: vault.name, format: "mop-vault-v7", enrolled: false))
                status.fingerprint = vault.membership.offlineRecovery?.fingerprint
                guard vault.membership.role(of: device.identity) == .owner else { throw MopError.cloudPermission }
                if vault.membership.offlineRecovery != target {
                    let downloads = AttachmentDownloads(state: state, address: address)
                    if vault.membership.offlineRecovery != nil {
                        reportProgress("Loading attachments: vault \(index + 1) of \(addresses.count)…", fraction: Double(index) / Double(addresses.count))
                        vault = try await downloads.load(vault, digests: vault.attachmentDigests, transport: transport, offline: false)
                    }
                    let entry = NextEntry(address: address, checkpoint: vault.bytes, digest: vault.digest, name: vault.name, submitted: true, ready: true)
                    let storage = try registry.storage(entry)
                    let pin = try storage.load(binding: address.binding).map { try VerifiedVault(checkpoint: $0.snapshot, independentlyVerifiedDigest: $0.verifiedDigest) } ?? vault
                    let coordinator = try PublicationCoordinator(address: address, checkpoint: pin, transport: transport, storage: storage)
                    _ = try await coordinator.refresh(reconcileUnchangedPending: true)
                    let refreshed = await coordinator.offlineSnapshot().0
                    guard refreshed.digest == vault.digest else { throw MopError.vaultConflict }
                    reportProgress("Updating encryption: vault \(index + 1) of \(addresses.count)…", fraction: Double(index) / Double(addresses.count))
                    let next = try VaultEngine.setOfflineRecovery(target, in: vault, owner: device)
                    reportProgress("Saving to iCloud: vault \(index + 1) of \(addresses.count)…", fraction: Double(index) / Double(addresses.count))
                    try control.check(token); try await coordinator.publish(next)
                    try downloads.cache(next)
                    status.fingerprint = target?.fingerprint
                }
                status.complete = true
            } catch {
                try control.check(token)
                status.issue = "Not completed: " + ((error as? MopError)?.errorDescription ?? "iCloud or attachment data unavailable. Retry to resume.")
            }
            configuration.vaults.removeAll { $0.id == address.vault }; configuration.vaults.append(status)
            try await transport.saveRecoveryConfiguration(configuration, version: record.version)
        }
        reportProgress("Confirming recovery coverage with iCloud…")
        record = try await transport.recoveryConfiguration(scope: scope); configuration = record.configuration
        guard configuration.operation == operation else { throw MopError.vaultConflict }
        let finalAddresses = try await transport.discover().filter { $0.database == .private }
        let complete = Set(configuration.vaults.filter(\.complete).map(\.id))
        if Set(finalAddresses.map(\.vault)).isSubset(of: complete) {
            configuration.active = target; configuration.target = nil; configuration.operation = nil
            try await transport.saveRecoveryConfiguration(configuration, version: record.version)
            generatedRecovery.withLock { $0 = nil }
        }
        result.recoveryConfiguration = configuration; result.recoveryVaults = configuration.vaults
        result.message = configuration.incomplete ? "Recovery coverage is incomplete. Keep both offline copies and resume after resolving unavailable vaults." : "Recovery settings updated for all your owned iCloud vaults."
        return result
    }

    private func run(_ operation: VaultOperation, selection: String?, offline: Bool, token: Int) async throws -> VaultResult {
        if offline && !operation.allowsCachedRead {
            if case .discover = operation {} else { throw MopError.offlineWrite }
        }
        let config = try configuration.cloudConfiguration()
        let transport = try makeTransport(config.container, config.environment)
        let account: String
        if offline {
            try await transport.validateOfflineAccount()
            account = try NextAccountBinding.account(state: state, container: config.container, environment: config.environment)
        } else {
            account = try await transport.account()
            try control.check(token)
            try NextAccountBinding.remember(state: state, container: config.container, environment: config.environment, account: account)
        }
        try control.check(token)
        let registry = try NextRegistry(state: state, container: config.container, environment: config.environment, account: account)
        var result = VaultResult(); result.usingCache = offline; result.usageScope = registry.member.uuidString
        if case .manage(let action) = operation, !offline,
           let recovery = try await runRecovery(action, registry: registry, transport: transport, token: token) { return recovery }
        if try registry.removed() {
            if case .catalog = operation {
                removedRegistry.withLock { $0 = registry }
                throw MopError.deviceRemoved
            }
            // Also retries an interrupted local cleanup before offering reconnection.
            try await clearRemovedAccount(registry)
            if case .manage(.reconnect) = operation {
                try registry.setRemoved(false)
                result.message = "Ready to reconnect. Open and unlock 2ndPass on another device."
                return result
            }
            if case .discover = operation { result.deviceRemoved = true; return result }
            throw MopError.deviceRemoved
        }
        if case .manage(.reconnect) = operation { return result }
        if case .manage(.resetCloudAccess) = operation {
            guard !offline else { throw MopError.offlineWrite }
            _ = try await authorizedContext(token: token)
            // Explicit local repair must not discard an interrupted recovery's key.
            guard try !registry.hasPendingRecovery() else { throw MopError.vaultConflict }
            try control.check(token)
            // Reuse the durable barrier and drained cleanup used for revocation.
            // No cloud membership or vault data is changed. A fresh device key
            // must be approved through enrollment before access can resume.
            try registry.setRemoved(true)
            removedRegistry.withLock { $0 = registry }
            throw MopError.deviceRemoved
        }
        if case .manage(let action) = operation {
            switch action {
            case .devices, .removeAccountDevice:
                // Account device keys span its personal vaults. Revoke from every
                // locally enrolled private vault, retaining normal CAS semantics.
                let entries = try registry.entries().filter { $0.address.database == .private && $0.ready }
                var devices: [UUID: VaultDeviceRecord] = [:]
                var affected: [NextEntry] = []
                var removingSelf = false
                for entry in entries {
                    let listing = try await run(.members, selection: entry.address.vault.uuidString, offline: false, token: token)
                    for device in listing.devices {
                        var combined = devices[device.id] ?? device
                        combined.vaultNames[entry.address.vault.uuidString] = entry.name
                        devices[device.id] = combined
                    }
                    if case .removeAccountDevice(let id) = action,
                       let target = listing.devices.first(where: { $0.id == id }) {
                        // Preflight before any publication: never strand a vault
                        // without an ordinary owner device.
                        guard listing.devices.count > 1 else { throw MopError.lastOwnerDevice }
                        affected.append(entry); removingSelf = removingSelf || target.isCurrent
                    }
                }
                if case .removeAccountDevice(let id) = action {
                    reportProgress("Checking device access…")
                    var completed: [String] = []
                    for entry in affected {
                        do {
                            _ = try await run(.manage(.removeDevice(id)), selection: entry.address.vault.uuidString, offline: false, token: token)
                            completed.append(entry.name)
                            devices[id]?.vaultNames.removeValue(forKey: entry.address.vault.uuidString)
                        } catch {
                            try control.check(token)
                            guard !completed.isEmpty else { throw error }
                            // Remote commits cannot be rolled back. Keep keys on partial self-removal.
                            result.deviceRemovalIncomplete = true
                            result.devices = devices.values.sorted { $0.name < $1.name }
                            let done = completed.isEmpty ? "No removals were confirmed." : "Removed from: " + completed.joined(separator: ", ") + "."
                            result.message = done + " Removal from " + entry.name + " was not confirmed; remaining vaults were not changed. Refresh Devices before retrying."
                            return result
                        }
                    }
                    devices.removeValue(forKey: id)
                    if removingSelf {
                        try registry.setRemoved(true); removedRegistry.withLock { $0 = registry }
                        throw MopError.deviceRemoved
                    }
                }
                result.devices = devices.values.sorted { $0.name < $1.name }
                result.message = "Device list refreshed."
                if case .removeAccountDevice = action {
                    result.message = "Device removed from your enrolled personal vaults. It will clear local access when it next connects."
                }
                return result
            default: break
            }
        }
        if case .discover = operation {
            var entries = try registry.entries()
            result.vaults = entries.map { VaultDescriptor(id: $0.address.vault.uuidString, name: $0.name, format: "mop-vault-v7", enrolled: $0.ready) }
            if !offline {
                let discovered = try await transport.discover()
                try control.check(token)
                guard discovered.allSatisfy({ $0.account == account && $0.container == config.container && $0.environment == config.environment }) else { throw MopError.cloudAccount }
                // A complete zone listing plus a missing head confirms remote
                // deletion. Never forget vaults on permission or network failures.
                for entry in entries where entry.submitted && !discovered.contains(entry.address) {
                    do { _ = try await transport.head(at: entry.address) }
                    catch MopError.vaultMissing {
                        try control.check(token)
                        try registry.forget(entry)
                        control.removeLocalRead(entry.address.vault.uuidString)
                    }
                }
                entries = try registry.entries()
                result.vaults = entries.map { VaultDescriptor(id: $0.address.vault.uuidString, name: $0.name, format: "mop-vault-v7", enrolled: $0.ready) }
                if publishesAutoFill {
                    try await AutoFillPublisher.shared.prune(keeping: Set(entries.map { $0.address.vault.uuidString }))
                }
                for address in discovered where !entries.contains(where: { $0.address == address }) {
                    // No registry pin and no key access: cloud visibility is not trust.
                    if !result.vaults.contains(where: { $0.id == address.vault.uuidString }) {
                        result.vaults.append(VaultDescriptor(id: address.vault.uuidString, name: "iCloud vault · " + String(address.vault.uuidString.prefix(8)), format: "mop-vault-v7", enrolled: false))
                    }
                }
            }
            let accessible = result.vaults.filter(\.enrolled)
            result.defaultVault = accessible.count == 1 ? accessible[0].id : nil
            return result
        }
        if offline && !operation.allowsCachedRead { throw MopError.offlineWrite }
        let context = try await authorizedContext(token: token)
        func close(_ device: any DeviceOperations) {
            if let enclave = device as? EnclaveDevice { enclave.releaseHandles() }
            else { device.close() }
        }
        let scope = config.container + "/" + config.environment
        func device(member: UUID? = nil, create: Bool = false) throws -> any DeviceOperations {
            try control.check(token)
            guard try !registry.removed() else { throw MopError.deviceRemoved }
            return try openDevice(scope + "/device", member ?? registry.member, context, create)
        }
        func checkedRequest(_ bytes: Data, fingerprint: String) throws -> DeviceRequest {
            let request = try ExchangeFile.decode(DeviceRequest.self, from: bytes); try request.validate()
            guard request.fingerprint == fingerprint,
                  request.container == config.container, request.environment == config.environment else { throw MopError.invalidIdentity }
            return request
        }
        func readDocument(_ url: URL) throws -> Data {
            let access = url.startAccessingSecurityScopedResource(); defer { if access { url.stopAccessingSecurityScopedResource() } }
            return try LocalFile.read(url, limit: 24 * 1024 * 1024)
        }
        if case .manage(.deviceRequest) = operation {
            let key = try device(create: true); defer { close(key) }
            let request = try DeviceRequest(container: config.container, environment: config.environment, account: account, device: key)
            result.document = try ExchangeFile.encode(request)
            result.message = "Request fingerprint: \(request.fingerprint)\nAccount: \(request.device.member)\nDevice: \(request.device.device)\nCompare the request fingerprint through a trusted channel. Private keys remain on this device."
            return result
        }
        if case .manage(let action) = operation {
            let enrollmentName: String?
            switch action {
            case .requestEnrollment(let name), .restartEnrollment(let name): enrollmentName = name
            case .checkEnrollment: enrollmentName = nil
            default: enrollmentName = nil
            }
            switch action {
            case .requestEnrollment, .restartEnrollment, .cancelEnrollment, .checkEnrollment, .confirmEnrollment:
                guard let selection, let id = UUID(uuidString: selection) else { throw MopError.invalidProcess }
                let address = try VaultAddress(container: config.container, environment: config.environment, account: account,
                    database: .private, owner: CKCurrentUserDefaultName, vault: id)
                guard try await transport.discover().contains(address) else { throw MopError.vaultMissing }
                let key = try device(create: enrollmentName != nil); defer { close(key) }
                var local = try registry.enrollment(id)
                let restart: Bool
                if case .restartEnrollment = action { restart = true } else { restart = false }
                if case .cancelEnrollment = action {
                    guard var cancelled = local else { result.message = "No request to cancel."; return result }
                    cancelled.rejected = true; cancelled.confirmedCode = nil
                    try registry.saveEnrollment(cancelled)
                    let inbox = try await transport.enrollment(at: address)
                    var mailbox = inbox.mailbox
                    if let index = mailbox.exchanges.firstIndex(where: { $0.id == cancelled.id }), mailbox.exchanges[index].approved == nil {
                        mailbox.exchanges[index].rejected = true
                        try control.check(token); try await transport.saveEnrollment(mailbox, version: inbox.version, at: address)
                    }
                    result.enrollments = [cancelled]
                    result.message = "Request cancelled. Restart when you are ready. Existing vault access is unchanged."
                    return result
                }
                if !restart, let cancelled = local, cancelled.rejected {
                    // Retry cancellation after a lost response; a local paused state
                    // must not leave the old request actionable indefinitely.
                    let inbox = try await transport.enrollment(at: address)
                    var mailbox = inbox.mailbox
                    if let index = mailbox.exchanges.firstIndex(where: { $0.id == cancelled.id }),
                       mailbox.exchanges[index].approved == nil, !mailbox.exchanges[index].rejected {
                        mailbox.exchanges[index].rejected = true
                        try control.check(token); try await transport.saveEnrollment(mailbox, version: inbox.version, at: address)
                    }
                    result.enrollments = [cancelled]
                    result.message = "Request cancelled or declined. Choose Restart connection to send a new request."
                    return result
                }
                if restart || local == nil || local!.request.expires <= Date() {
                    guard let name = enrollmentName else { throw MopError.invalidIdentity }
                    let previous = local.map { ($0.superseded ?? []) + [$0.id] } ?? []
                    let request = try DeviceRequest(container: config.container, environment: config.environment, account: account, device: key)
                    local = EnrollmentExchange(request: try EnrollmentRequest(vault: id, request: request, name: name, device: key))
                    local!.superseded = Array(previous.suffix(32))
                    try registry.saveEnrollment(local!)
                }
                guard var local, local.request.request.device == key.identity else { throw MopError.invalidIdentity }
                try local.request.validate(at: address)
                var inbox = try await transport.enrollment(at: address)
                var mailbox = inbox.mailbox
                var retired = false
                for index in mailbox.exchanges.indices where (local.superseded ?? []).contains(mailbox.exchanges[index].id) {
                    if mailbox.exchanges[index].approved == nil && !mailbox.exchanges[index].rejected {
                        mailbox.exchanges[index].rejected = true; retired = true
                    }
                }
                if retired {
                    try control.check(token); try await transport.saveEnrollment(mailbox, version: inbox.version, at: address)
                    inbox = try await transport.enrollment(at: address); mailbox = inbox.mailbox
                }
                mailbox.exchanges.removeAll { $0.request.expires <= Date() }
                if let index = mailbox.exchanges.firstIndex(where: { $0.id == local.id }) {
                    var remote = mailbox.exchanges[index]
                    guard try ExchangeFile.encode(remote.request) == ExchangeFile.encode(local.request) else { throw MopError.vaultUntrusted }
                    if remote.rejected {
                        local.rejected = true; local.confirmedCode = nil
                        try registry.saveEnrollment(local)
                        result.enrollments = [local]
                        result.message = "Request declined. Choose Restart connection to try again."
                        return result
                    }
                    if let packet = remote.invitation {
                        let referenced = packet.checkpoint.isEmpty
                            ? try await transport.revision(packet.invitation.checkpoint, at: address) : nil
                        let root = try remote.verifiedInvitation(at: address, referencedCheckpoint: referenced)
                        if case .confirmEnrollment(let code) = action {
                            guard local.verificationCode == code, remote.verificationCode == code,
                                  local.acceptance != nil else { throw MopError.vaultUntrusted }
                            local.confirmedCode = code
                            try registry.saveEnrollment(local)
                        }
                        if remote.approved != nil {
                            guard local.verificationCode != nil, local.verificationCode == remote.verificationCode,
                                  local.acceptance != nil else { throw MopError.vaultUntrusted }
                            let entry = NextEntry(address: address, checkpoint: root.bytes, digest: root.digest, name: root.name, submitted: true, ready: true)
                            let storage = try registry.storage(entry)
                            let coordinator = try PublicationCoordinator(address: address, checkpoint: root, transport: transport, storage: storage)
                            _ = try await coordinator.refresh()
                            let current = await coordinator.offlineSnapshot().0
                            guard current.membership.role(of: key.identity) == .owner,
                                  current.acceptedEnrollment(remote.invitation!.invitation.nonce) else { throw MopError.notVaultMember }
                            try control.check(token); try registry.put(entry)
                            result.enrollmentCompleted = true
                            result.addedDevices = current.membership.devices.filter {
                                $0.member == key.identity.member && $0 != key.identity
                            }.map(\.device)
                            result.message = "This device is approved. Your vault is ready."
                            return result
                        }
                        if local.verificationCode != remote.verificationCode || remote.acceptance == nil {
                            remote.acceptance = try Acceptance(invitation: remote.invitation!.invitation, expectedCheckpoint: root.digest, device: key)
                            let superseded = local.superseded
                            local = remote
                            local.superseded = superseded
                            local.confirmedCode = nil // Same-account bootstrap trusts the private CloudKit mailbox.
                            try registry.saveEnrollment(local)
                            mailbox.exchanges[index] = remote
                            try control.check(token); try await transport.saveEnrollment(mailbox, version: inbox.version, at: address)
                        }
                        result.enrollments = [local]
                        result.message = "Connecting securely to your vault…"
                    } else {
                        // A missing server invitation invalidates the displayed code.
                        local.invitation = nil; local.acceptance = nil; local.confirmedCode = nil; local.approved = nil
                        try registry.saveEnrollment(local)
                        result.enrollments = [local]; result.message = "Waiting for another device. Open and unlock 2ndPass there to connect automatically."
                    }
                } else {
                    local.invitation = nil; local.acceptance = nil; local.confirmedCode = nil; local.approved = nil
                    try registry.saveEnrollment(local)
                    mailbox.exchanges.append(local)
                    try control.check(token); try await transport.saveEnrollment(mailbox, version: inbox.version, at: address)
                    result.enrollments = [local]; result.message = "Waiting for another device. Open and unlock 2ndPass there to connect automatically."
                }
                return result
            default: break
            }
        }
        if case .manage(.importCheckpoint(let document, let fingerprint, let sharedOwner)) = operation {
            let root = try VerifiedVault.restoreBackup(document, independentlyVerifiedDigest: fingerprint)
            let key = try device(); defer { close(key) }
            guard root.membership.role(of: key.identity) != nil else { throw MopError.notVaultMember }
            let address = try VaultAddress(container: config.container, environment: config.environment, account: account,
                database: sharedOwner == nil ? .private : .shared, owner: sharedOwner ?? CKCurrentUserDefaultName, vault: root.id)
            try AttachmentDownloads(state: state, address: address).cache(root)
            let entry = NextEntry(address: address, checkpoint: root.bytes, digest: root.digest, name: root.name, submitted: true, ready: true)
            let storage = try registry.storage(entry)
            let coordinator = try PublicationCoordinator(address: address, checkpoint: root, transport: transport, storage: storage)
            _ = try await coordinator.refresh()
            try control.check(token); try registry.put(entry)
            result.message = "Trusted vault \(root.id). Refreshed and verified its signed descendants."
            return result
        }
        if case .manage(.accept(let bytes, let checkpoint, let shareURL)) = operation {
            let packet = try ExchangeFile.decode(InvitationPacket.self, from: bytes)
            try packet.request.validate()
            guard packet.request.account == account, packet.request.container == config.container,
                  packet.request.environment == config.environment else { throw MopError.invalidIdentity }
            let key = try device(); defer { close(key) }
            guard key.identity == packet.request.device else { throw MopError.invalidIdentity }
            let root = try VerifiedVault(checkpoint: packet.checkpoint, independentlyVerifiedDigest: checkpoint)
            guard root.id == packet.invitation.vault, root.id == packet.address.vault,
                  root.membership.role(of: packet.invitation.issuer) == .owner,
                  root.membership.accounts.first(where: { $0.role == .owner })?.id == AccountScope.member(container: config.container, environment: config.environment, account: packet.address.account),
                  packet.address.container == config.container, packet.address.environment == config.environment else { throw MopError.vaultUntrusted }
            let acceptance = try Acceptance(invitation: packet.invitation, expectedCheckpoint: checkpoint, device: key)
            let address: VaultAddress
            if packet.address.account == account {
                guard packet.address.database == .private else { throw MopError.vaultUntrusted }
                address = try VaultAddress(container: config.container, environment: config.environment, account: account, database: .private, owner: CKCurrentUserDefaultName, vault: root.id)
            } else {
                guard let shareURL else { throw MopError.cloudInvalidRequest }
                address = try await transport.acceptShare(shareURL, vault: root.id, expectedOwner: packet.address.account)
            }
            try control.check(token)
            // Trust comes from the independently compared checkpoint; share URL
            // acceptance alone never establishes a root or grants a device key.
            if let existing = try registry.entries().first(where: { $0.address.vault == root.id }) {
                guard existing.address == address else { throw MopError.vaultUntrusted }
            } else { try registry.put(NextEntry(address: address, checkpoint: root.bytes, digest: root.digest, name: root.name, submitted: true, ready: true)) }
            result.document = try ExchangeFile.encode(AcceptancePacket(invitation: packet, acceptance: acceptance))
            result.message = "Return this acceptance to the owner. Access begins only after owner approval; refresh afterward."
            return result
        }
        if case .create(let name) = operation {
            let recoveryScope = try RecoveryScope(container: config.container, environment: config.environment, account: account)
            let configuration = try await transport.recoveryConfiguration(scope: recoveryScope).configuration
            guard configuration.operation == nil else { throw MopError.vaultConflict }
            let owner = try device(create: true); defer { close(owner) }
            let id = selection.flatMap(UUID.init(uuidString:)) ?? UUID()
            var entry: NextEntry
            if let pending = try registry.entries().first(where: { $0.address.vault == id }) { entry = pending }
            else {
                guard !(try registry.entries().contains { $0.name == name }) else { throw MopError.duplicate }
                let root = try VaultEngine.create(name: name, owner: owner, recovery: configuration.active, id: id)
                let address = try VaultAddress(container: config.container, environment: config.environment, account: account, database: .private, owner: CKCurrentUserDefaultName, vault: id)
                entry = NextEntry(address: address, checkpoint: root.bytes, digest: root.digest, name: name, submitted: false, ready: false)
                try registry.put(entry)
            }
            let root = try VerifiedVault(checkpoint: entry.checkpoint, independentlyVerifiedDigest: entry.digest)
            guard root.membership.role(of: owner.identity) == .owner else { throw MopError.cloudPermission }
            let reservation = try await transport.recoveryConfiguration(scope: recoveryScope)
            guard reservation.configuration.operation == nil, root.membership.offlineRecovery == reservation.configuration.active else { throw MopError.vaultConflict }
            if let pending = reservation.configuration.pendingCreation {
                guard pending == root.bytes else { throw MopError.vaultConflict }
            } else {
                var next = reservation.configuration; next.pendingCreation = root.bytes
                try await transport.saveRecoveryConfiguration(next, version: reservation.version)
            }
            let storage = try registry.storage(entry)
            if !entry.submitted {
                entry.submitted = true; try registry.put(entry)
                try control.check(token)
                try await transport.initialize(root, at: entry.address)
            }
            // After an interrupted submission only reconcile. Never regenerate
            // the root or recreate a missing previously submitted zone.
            let coordinator = try PublicationCoordinator(address: entry.address, checkpoint: root, transport: transport, storage: storage)
            _ = try await coordinator.refresh()
            let current = await coordinator.offlineSnapshot().0
            entry.ready = true; try registry.put(entry)
            try await transport.finishRecoveryCreation(scope: recoveryScope, using: owner.identity)
            result.catalog = try VaultEngine.catalog(in: current, device: owner)
            result.message = "Vault created: \(id)\nCheckpoint: \(current.digest)\nAdd another device or offline recovery in Vault settings."
            return result
        }
        var entry = try registry.select(selection)
        let storage = try registry.storage(entry)
        let root = try VerifiedVault(checkpoint: entry.checkpoint, independentlyVerifiedDigest: entry.digest)
        let coordinator = try PublicationCoordinator(address: entry.address, checkpoint: root, transport: transport, storage: storage)
        if !offline { _ = try await coordinator.refresh(reconcileUnchangedPending: true) }
        var (current, date) = await coordinator.offlineSnapshot()
        if !offline && (!entry.ready || entry.name != current.name) { entry.ready = true; entry.name = current.name; try registry.put(entry) }
        result.offlineDate = offline ? date : nil
        try control.check(token)
        let key = try device(); defer { close(key) }
        guard current.membership.role(of: key.identity) != nil else {
            // Only a verified descendant excluding a previously enrolled key
            // authorizes local deletion. Network/permission errors never do.
            guard root.membership.role(of: key.identity) != nil ||
                    (current.membership.removedDevices ?? []).contains(key.identity.device) else { throw MopError.notVaultMember }
            try registry.setRemoved(true)
            removedRegistry.withLock { $0 = registry }
            throw MopError.deviceRemoved
        }
        let attachments = AttachmentDownloads(state: state, address: entry.address)
        if allowsAttachments {
            var needed: Set<String> = []
            switch operation {
            case .read(let reference):
                if let digest = try current.attachmentDigest(for: reference.relativePath, device: key) { needed.insert(digest) }
            case .export, .upgradeSecurity, .previewImport, .commitImport: needed = current.attachmentDigests
            case .manage(.removeMember), .manage(.removeDevice):
                reportProgress("Preparing encrypted files…")
                needed = current.attachmentDigests
            case .sync:
                if !offline && (attachmentSyncOverride ?? AttachmentDownloadSettings.duringSync) { needed = current.attachmentDigests }
            default: break
            }
            current = try await attachments.load(current, digests: needed, transport: transport, offline: offline)
            try control.check(token)
        }
        if case .sync = operation { result.message = "Verified checkpoint: \(current.digest)"; return result }
        if case .manage(let action) = operation {
            switch action {
            case .enrollmentInbox, .automaticEnrollment, .approveEnrollment, .rejectEnrollment:
                guard current.membership.role(of: key.identity) == .owner, entry.address.database == .private else { throw MopError.cloudPermission }
                let inbox = try await transport.enrollment(at: entry.address)
                var mailbox = inbox.mailbox
                let enrollmentLogger = Logger(subsystem: "com.koehn.mop", category: "Enrollment")
                enrollmentLogger.notice("Owner check: \(mailbox.exchanges.count) requests")
                mailbox.exchanges.removeAll { $0.request.expires <= Date() }
                var changed = mailbox.exchanges.count != inbox.mailbox.exchanges.count
                for index in mailbox.exchanges.indices {
                    var exchange = mailbox.exchanges[index]
                    // Never display malformed requests as actionable approval prompts.
                    do { try exchange.request.validate(at: entry.address) }
                    catch {
                        enrollmentLogger.error("Skipping invalid enrollment request: \(String(describing: error), privacy: .public)")
                        continue
                    }
                    enrollmentLogger.notice("Request state: invited=\(exchange.invitation != nil) accepted=\(exchange.acceptance != nil) approved=\(exchange.approved != nil) rejected=\(exchange.rejected)")
                    if (current.membership.removedDevices ?? []).contains(exchange.request.request.device.device) {
                        exchange.rejected = true; mailbox.exchanges[index] = exchange; changed = true
                        continue
                    }
                    if exchange.rejected || exchange.approved != nil || exchange.invitation.map({ current.acceptedEnrollment($0.invitation.nonce) }) == true { continue }
                    if exchange.invitation?.invitation.checkpoint != current.digest {
                        let invitation = try VaultEngine.invite(member: exchange.request.request.device.member, role: .owner, to: current, owner: key, expires: exchange.request.expires)
                        // The signed invitation pins a revision already in CloudKit.
                        // Repeating its bytes per device can overflow the mailbox.
                        exchange.invitation = InvitationPacket(request: exchange.request.request, invitation: invitation, address: entry.address, checkpoint: Data())
                        exchange.acceptance = nil; exchange.approved = nil
                        mailbox.exchanges[index] = exchange; changed = true
                    }
                }
                if case .rejectEnrollment(let id) = action {
                    guard let index = mailbox.exchanges.firstIndex(where: { $0.id == id }), mailbox.exchanges[index].approved == nil else { throw MopError.invalidIdentity }
                    mailbox.exchanges[index].rejected = true; changed = true
                    result.message = "Device request declined."
                }
                var approval: (UUID, String)?
                if case .approveEnrollment(let id, let code) = action { approval = (id, code) }
                if case .automaticEnrollment = action {
                    // One grant per pass: each publication changes the checkpoint.
                    if let ready = mailbox.exchanges.first(where: {
                        !$0.rejected && $0.approved == nil && $0.acceptance != nil &&
                        (try? $0.request.validate(at: entry.address)) != nil
                    }), let code = ready.verificationCode { approval = (ready.id, code) }
                }
                if let (id, code) = approval {
                    guard let index = mailbox.exchanges.firstIndex(where: { $0.id == id }) else { throw MopError.invalidIdentity }
                    var exchange = mailbox.exchanges[index]
                    guard !exchange.rejected else { throw MopError.invalidIdentity }
                    var referenced: Data?
                    if let packet = exchange.invitation, packet.checkpoint.isEmpty {
                        // An uncertain publication may already have advanced the head.
                        // Verify against the invitation's pinned revision, not that head.
                        referenced = packet.invitation.checkpoint == current.digest ? current.bytes
                            : try await transport.revision(packet.invitation.checkpoint, at: entry.address)
                    }
                    _ = try exchange.verifiedInvitation(at: entry.address, referencedCheckpoint: referenced)
                    guard exchange.verificationCode == code, let acceptance = exchange.acceptance,
                          acceptance.device == exchange.request.request.device,
                          acceptance.invitation.nonce == exchange.invitation?.invitation.nonce else { throw MopError.vaultConflict }
                    if !current.acceptedEnrollment(acceptance.invitation.nonce) {
                        let proposal = try VaultEngine.approve(acceptance, expectedDeviceFingerprint: acceptance.device.fingerprint, in: current, owner: key)
                        try control.check(token); try await coordinator.publish(proposal) { self.reportProgress($0) }
                        current = proposal
                    }
                    exchange.approved = Data(); mailbox.exchanges[index] = exchange; changed = true
                    result.message = "Device approved. It will open the vault automatically."
                }
                if changed { try control.check(token); try await transport.saveEnrollment(mailbox, version: inbox.version, at: entry.address) }
                // Read notifications from signed membership, not the expiring mailbox.
                result.addedDevices = current.membership.devices.filter {
                    $0.member == key.identity.member && $0 != key.identity
                }.map(\.device)
                result.enrollments = mailbox.exchanges.filter {
                    (try? $0.request.validate(at: entry.address)) != nil && $0.approved == nil && !$0.rejected
                }
                return result
            default: break
            }
        }
        if !offline {
            switch operation {
            case .catalog, .recentlyDeleted:
                if let purged = try VaultEngine.purgeExpired(in: current, device: key) {
                    try control.check(token); try await coordinator.publish(purged); current = purged
                }
            default: break
            }
        }
        var proposal: VerifiedVault?
        var reconcile = false
        switch operation {
        case .catalog, .recentlyDeleted: break
        case .readHistory(let entry, let revision):
            result.value = try VaultEngine.readHistory(entry, revision: revision, in: current, device: key)
            return result
        case .restoreHistory(let entry, let revision):
            proposal = try VaultEngine.restoreHistory(entry, revision: revision, in: current, device: key, at: wallNow())
        case .clearHistory(let field, let revision):
            proposal = try VaultEngine.clearHistory(field, revision: revision, in: current, device: key)
        case .reconcileLocalCredentials(let ids, let revision):
            proposal = try VaultEngine.invalidateMissingLocalCredentials(ids, revision: revision, in: current, device: key)
        case .savePasswordChecks(let checks, let revision):
            proposal = try VaultEngine.savePasswordChecks(checks, revision: revision, in: current, device: key)
        case .saveCredentialAccount(let registration, let revision):
            proposal = try VaultEngine.saveCredentialAccount(registration, revision: revision, in: current, device: key, at: wallNow())
        case .upgradeSecurity(let url, let revision):
            guard current.membership.role(of: key.identity) == .owner else { throw MopError.cloudPermission }
            guard current.digest == revision else { throw MopError.vaultConflict }
            try documents.write(to: url) { target in
                try OutputFile(url: target, force: false, mode: 0o600, protectedFiles: [], protectedDirectories: [state]).write(try current.backup())
                let restored = try VerifiedVault.restoreBackup(Data(contentsOf: target), independentlyVerifiedDigest: current.digest)
                guard restored.digest == current.digest else { throw MopError.invalidVault }
                _ = try VaultEngine.catalog(in: restored, device: key)
            }
            proposal = try VaultEngine.upgradeSecurity(revision: revision, in: current, device: key)
        case .passwordQuality(let name):
            guard let item = try VaultEngine.catalog(in: current, device: key).items.first(where: { $0.name == name }) else { throw MopError.notFound }
            for field in item.fields where field.type == .password { result.passwordQuality[field.path] = field.passwordQuality }
            return result
        case .read(let reference):
            guard reference.vault == current.name else { throw MopError.vaultSelectionMismatch }
            let catalog = try VaultEngine.catalog(in: current, device: key)
            let path = [reference.section, reference.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
            guard let field = catalog.items.first(where: { $0.name == reference.item })?.fields.first(where: { $0.path == path }) else { throw MopError.notFound }
            guard allowsAttachments || field.type != .attachment else { throw MopError.notFound }
            if let itemID = catalog.items.first(where: { $0.name == reference.item })?.storageID {
                result.usageIdentity = ItemUsageIdentity(account: registry.member.uuidString, vault: current.id.uuidString, item: itemID)
            }
            let value = try VaultEngine.read(reference.relativePath, in: current, device: key)
            if field.type == .otp {
                let otp = try TimeBasedOTP(String(decoding: value, as: UTF8.self)), now = Date()
                result.value = SecretBytes(utf8: try otp.code(at: now)); result.otpExpiresAt = otp.expires(at: now); result.otpPeriod = otp.period
            } else { result.value = value }
            result.valueIsConcealed = field.type.concealed
            return result
        case .previewImport(let document, let selected):
            let plan = try VaultEngine.previewImport(document, selected: selected, in: current, device: key)
            result.importPreview = plan.preview
            return result
        case .commitImport(let document, let selected, let vaultID, let revision):
            reportProgress("Checking selected items…")
            guard vaultID == current.id, revision == current.digest else { throw MopError.vaultConflict }
            let plan = try VaultEngine.previewImport(document, selected: selected, in: current, device: key)
            if !plan.items.isEmpty {
                proposal = try VaultEngine.importItems(plan.items, revision: revision, in: current, device: key, at: wallNow()) { completed, total in
                    try self.control.check(token)
                    self.reportProgress("Encrypting items: \(completed) of \(total)", fraction: total > 0 ? Double(completed) / Double(total) : nil)
                }
            }
            var report = plan.preview.report; report.imported = plan.items.count; report.committed = true
            result.importReport = report
        case .save(let edit): proposal = try VaultEngine.saveItem(edit, in: current, device: key, at: wallNow())
        case .write(let reference, let value, let replace):
            guard reference.vault == current.name else { throw MopError.vaultSelectionMismatch }
            let exists = try VaultEngine.references(in: current, device: key).contains(reference.relativePath)
            guard exists == replace else { throw exists ? MopError.duplicate : MopError.notFound }
            proposal = try VaultEngine.write(reference.relativePath, value: value, in: current, device: key, at: wallNow())
        case .delete(let reference):
            guard reference.vault == current.name else { throw MopError.vaultSelectionMismatch }
            proposal = try VaultEngine.write(reference.relativePath, value: nil, in: current, device: key, at: wallNow())
        case .trashItem(let name, let revision): proposal = try VaultEngine.trashItem(name: name, revision: revision, in: current, device: key, at: wallNow())
        case .restoreItem(let id, let revision): proposal = try VaultEngine.restoreItem(id: id, revision: revision, in: current, device: key, at: wallNow())
        case .members:
            let names: [UUID: String]
            if entry.address.database == .private {
                let inbox = try await transport.enrollment(at: entry.address)
                names = Dictionary(inbox.mailbox.exchanges.filter {
                    (try? $0.request.request.validate()) != nil
                }.map { ($0.request.request.device.device, $0.request.name) }, uniquingKeysWith: { first, _ in first })
            } else { names = [:] }
            result.devices = current.membership.devices.filter { $0.member == registry.member }.map {
                VaultDeviceRecord(id: $0.device,
                    name: $0 == key.identity ? ProcessInfo.processInfo.hostName : (names[$0.device] ?? "Device " + String($0.device.uuidString.prefix(8))),
                    isCurrent: $0 == key.identity)
            }
            result.members = current.membership.accounts.flatMap { member in member.devices.map { VaultMemberRecord(id: $0.device.uuidString, role: "\(member.role.rawValue) · account \(member.id) · \($0.fingerprint)") } }
            if let recovery = current.membership.offlineRecovery { result.members.append(VaultMemberRecord(id: recovery.device.uuidString, role: "offline recovery · \(recovery.fingerprint)")) }
        case .rename(let name):
            guard !(try registry.entries().contains { $0.name == name && $0.address != entry.address }) else { throw MopError.duplicate }
            proposal = try VaultEngine.rename(name, in: current, device: key)
        case .export(let url):
            try documents.write(to: url) { target in
                try OutputFile(url: target, force: false, mode: 0o600, protectedFiles: [], protectedDirectories: [state]).write(try current.backup())
            }
            result.message = "Encrypted backup exported. Checkpoint: \(current.digest)"
        case .deleteVault:
            guard current.membership.role(of: key.identity) == .owner else { throw MopError.cloudPermission }
            try control.check(token); try await transport.delete(at: entry.address); try registry.forget(entry)
            control.removeLocalRead(current.id.uuidString)
            result.retainedItemIDs = []; result.usageVault = current.id.uuidString
            result.message = "Cloud vault deleted. Existing local ciphertext and backups retained."; return result
        case .manage(let action):
            switch action {
            case .fingerprint: result.message = current.digest
            case .trust(let fingerprint):
                guard fingerprint == current.digest else { throw MopError.vaultUntrusted }; result.message = "Checkpoint matches the verified vault."
            case .invite(let bytes, let fingerprint, let role), .inviteAccount(let bytes, let fingerprint, let role):
                let request = try checkedRequest(bytes, fingerprint: fingerprint)
                if case .inviteAccount = action {
                    guard request.account != account, role != .owner else { throw MopError.invalidIdentity }
                }
                let invitation = try VaultEngine.invite(member: request.device.member, role: role, to: current, owner: key, expires: Date().addingTimeInterval(86400))
                result.document = try ExchangeFile.encode(InvitationPacket(request: request, invitation: invitation, address: entry.address, checkpoint: current.bytes))
                result.message = "Invitation checkpoint: \(current.digest)\nCompare this checkpoint independently on the receiving device."
                if request.account != account {
                    let url = try await transport.share(with: request.account, role: role, at: entry.address)
                    result.message += "\nShare URL: \(url.absoluteString)"
                }
            case .inviteOwnDevice(let bytes, let fingerprint):
                let request = try checkedRequest(bytes, fingerprint: fingerprint)
                guard request.account == account else { throw MopError.invalidIdentity }
                let invitation = try VaultEngine.invite(member: request.device.member, role: .owner, to: current, owner: key, expires: Date().addingTimeInterval(86400))
                result.document = try ExchangeFile.encode(InvitationPacket(request: request, invitation: invitation, address: entry.address, checkpoint: current.bytes))
                result.message = "Invitation checkpoint: \(current.digest)\nCompare this checkpoint on your new device, then import its acceptance here."
            case .approve(let bytes, let fingerprint):
                let packet = try ExchangeFile.decode(AcceptancePacket.self, from: bytes)
                let request = try checkedRequest(ExchangeFile.encode(packet.invitation.request), fingerprint: fingerprint)
                guard request.device == packet.acceptance.device, packet.invitation.invitation.nonce == packet.acceptance.invitation.nonce else { throw MopError.invalidIdentity }
                proposal = try VaultEngine.approve(packet.acceptance, expectedDeviceFingerprint: request.device.fingerprint, in: current, owner: key)
                reconcile = true
            case .removeMember(let id): proposal = try VaultEngine.remove(member: id, from: current, owner: key); reconcile = true
            case .removeDevice(let id):
                proposal = try VaultEngine.remove(device: id, from: current, owner: key) { completed, total in
                    try self.control.check(token)
                    self.reportProgress("Updating encryption: \(completed) of \(total) items")
                }
                reconcile = true
            case .role(let id, let role): proposal = try VaultEngine.setRole(role, member: id, in: current, owner: key); reconcile = true
            case .reconcileShare:
                guard current.membership.role(of: key.identity) == .owner else { throw MopError.cloudPermission }
                try await transport.reconcileShare(current.membership, at: entry.address)
                result.message = "Cloud sharing permissions match the signed roster."
            default: throw MopError.invalidProcess
            }
        default: throw MopError.invalidProcess
        }
        if let proposal {
            if operationProgress != nil { reportProgress("Saving the updated vault to iCloud…") }
            try attachments.cache(proposal)
            try control.check(token); try await coordinator.publish(proposal) { self.reportProgress($0) }
            try control.check(token)
            entry.name = proposal.name; entry.ready = true; try registry.put(entry)
            if reconcile {
                if operationProgress != nil { reportProgress("Confirming cloud access…") }
                try await transport.reconcileShare(proposal.membership, at: entry.address)
            }
            result.message = "Published checkpoint: \(proposal.digest)"
        }
        let verified = proposal ?? current
        if verified.membership.role(of: key.identity) == nil { return result }
        let catalogs = try VaultEngine.catalogs(in: verified, device: key)
        try control.saveLocalRead(LocalReadSession(reader: catalogs.reader, verifiedAt: await coordinator.offlineSnapshot().1, account: account,
            container: config.container, environment: config.environment, context: ContextInvalidator(context)), token: token)
        result.catalog = catalogs.active
        result.deletedCatalog = catalogs.deleted
        result.retainedItemIDs = catalogs.retainedIDs
        result.usageVault = verified.id.uuidString
        return result
    }
}
