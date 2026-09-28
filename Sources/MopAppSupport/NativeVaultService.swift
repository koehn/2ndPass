import Foundation
import CloudKit
import LocalAuthentication
import OSLog
import Synchronization
import MopCore
import MopAuth
import MopVaultNext

/// One authenticated operation at a time. Hardware handles and transient keys
/// never survive an operation; only the authenticated LAContext spans the session; locking invalidates pending authentication and
/// rejects results from an earlier generation.
public final class NativeVaultService: VaultService, @unchecked Sendable {
    private let control = SessionControl()
    private let gate = OperationGate()
    private let progressState = Mutex<(String, Double?)?>(nil)
    public var operationProgress: String? { progressState.withLock { $0?.0 } }
    public var operationFraction: Double? { progressState.withLock { $0?.1 } }
    private func reportProgress(_ message: String, fraction: Double? = nil) { progressState.withLock { $0 = (message, fraction) } }
    private let state: URL
    private let configuration: any VaultPlatformConfiguration
    private let documents: any DocumentAccessing
    private let makeTransport: (String, String) throws -> any VaultTransport
    private let deleteDevice: (String, UUID) throws -> Void
    private var removedRegistry: NextRegistry?
    private let openDevice: (String, UUID, LAContext, Bool) throws -> any DeviceOperations
    private let authenticate: (@escaping (LAContext) throws -> Void) async throws -> LAContext
    private var authorization: (token: Int, context: LAContext)?
    private var allowsAttachments = true
    private var attachmentSyncOverride: Bool?
    private let publishesAutoFill: Bool
    private var accountObserver: NSObjectProtocol?
    public var authenticatedAt: TimeInterval? { control.authenticatedAt }
    public init(state: URL? = nil, allowsAttachments: Bool = true, configuration: any VaultPlatformConfiguration = DefaultVaultPlatformConfiguration(), documents: any DocumentAccessing = SystemDocumentAccess()) {
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
         authenticate: @escaping (@escaping (LAContext) throws -> Void) async throws -> LAContext) {
        self.allowsAttachments = allowsAttachments; self.attachmentSyncOverride = attachmentSyncOverride
        self.state = state; self.configuration = configuration; documents = SystemDocumentAccess()
        publishesAutoFill = false; makeTransport = { _, _ in transport }
        self.openDevice = openDevice; self.deleteDevice = deleteDevice; self.authenticate = authenticate
    }
    public func lock() { control.lock() }
    deinit { control.lock(); if let accountObserver { NotificationCenter.default.removeObserver(accountObserver) } }
    public func execute(_ operation: VaultOperation, vault: String?, offline: Bool = false) async throws -> VaultResult {
        if case .manage(.automaticEnrollment) = operation, !isAuthenticated { throw MopError.authentication }
        let token = control.generation
        let task = Task.detached { [self] in
            await gate.enter()
            progressState.withLock { $0 = nil }
            do {
                try control.check(token)
                var result = try await run(operation, selection: vault, offline: offline, token: token)
                try control.check(token)
                if publishesAutoFill, let catalog = result.catalog, let vault, UUID(uuidString: vault) != nil {
                    do { try await AutoFillPublisher.shared.publish(catalog: catalog, vaultID: vault) }
                    catch { result.autoFillStatus = await AutoFillPublisher.shared.status() }
                }
                progressState.withLock { $0 = nil }
                await gate.leave(); return result
            } catch {
                progressState.withLock { $0 = nil }
                if let registry = removedRegistry {
                    do { control.lock(); try await clearRemovedAccount(registry); removedRegistry = nil }
                    catch { await gate.leave(); throw error }
                }
                await gate.leave(); throw error
            }
        }
        let id = UUID(); control.registerTask(id, token: token) { task.cancel() }
        defer { control.finishedTask(id) }
        return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
    }
    private func clearRemovedAccount(_ registry: NextRegistry) async throws {
        // The durable marker blocks every process before deletion begins.
        do {
            try deleteDevice(registry.container + "/" + registry.environment + "/device", registry.member)
            try registry.clearRemovedAccount()
            if (try? AutoFillStorage.directory()) != nil { try await AutoFillPublisher.shared.prune(keeping: []) }
            authorization?.context.invalidate(); authorization = nil
        } catch { throw MopError.deviceRemovalPending }
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
        var result = VaultResult(); result.usingCache = offline
        if try registry.removed() {
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
                        try registry.setRemoved(true); removedRegistry = registry
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
            let entries = try registry.entries()
            result.vaults = entries.map { VaultDescriptor(id: $0.address.vault.uuidString, name: $0.name, format: "mop-vault-v7", enrolled: $0.ready) }
            if !offline {
                let discovered = try await transport.discover()
                try control.check(token)
                guard discovered.allSatisfy({ $0.account == account && $0.container == config.container && $0.environment == config.environment }) else { throw MopError.cloudAccount }
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
        func close(_ device: any DeviceOperations) {
            if let enclave = device as? EnclaveDevice { enclave.releaseHandles() }
            else { device.close() }
        }
        let scope = config.container + "/" + config.environment
        func device(recovery: Bool = false, member: UUID? = nil, create: Bool = false) throws -> any DeviceOperations {
            try control.check(token)
            guard try !registry.removed() else { throw MopError.deviceRemoved }
            return try openDevice(scope + (recovery ? "/recovery" : "/device"), member ?? registry.member, context, create)
        }
        func checkedRequest(_ bytes: Data, fingerprint: String, recovery: Bool) throws -> DeviceRequest {
            let request = try ExchangeFile.decode(DeviceRequest.self, from: bytes); try request.validate()
            guard request.fingerprint == fingerprint, request.recovery == recovery,
                  request.container == config.container, request.environment == config.environment else { throw MopError.invalidIdentity }
            return request
        }
        func readDocument(_ url: URL) throws -> Data {
            let access = url.startAccessingSecurityScopedResource(); defer { if access { url.stopAccessingSecurityScopedResource() } }
            return try LocalFile.read(url, limit: 24 * 1024 * 1024)
        }
        if case .manage(.deviceRequest(let recovery)) = operation {
            let key = try device(recovery: recovery, create: true); defer { close(key) }
            let request = try DeviceRequest(container: config.container, environment: config.environment, account: account, recovery: recovery, device: key)
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
                    let request = try DeviceRequest(container: config.container, environment: config.environment, account: account, recovery: false, device: key)
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
                  packet.request.environment == config.environment, !packet.request.recovery else { throw MopError.invalidIdentity }
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
        if case .create(let name, let recoveryFile, let fingerprint) = operation {
            let recovery: DeviceRequest?
            if let recoveryFile, let fingerprint {
                recovery = try checkedRequest(readDocument(recoveryFile), fingerprint: fingerprint, recovery: true)
            } else {
                guard recoveryFile == nil, fingerprint == nil else { throw MopError.invalidRecovery }
                recovery = nil
            }
            let owner = try device(create: true); defer { close(owner) }
            guard recovery?.device.device != owner.identity.device else { throw MopError.invalidRecovery }
            let id = selection.flatMap(UUID.init(uuidString:)) ?? UUID()
            var entry: NextEntry
            if let pending = try registry.entries().first(where: { $0.address.vault == id }) { entry = pending }
            else {
                guard !(try registry.entries().contains { $0.name == name }) else { throw MopError.duplicate }
                let root = try VaultEngine.create(name: name, owner: owner, recovery: recovery?.device, id: id)
                let address = try VaultAddress(container: config.container, environment: config.environment, account: account, database: .private, owner: CKCurrentUserDefaultName, vault: id)
                entry = NextEntry(address: address, checkpoint: root.bytes, digest: root.digest, name: name, submitted: false, ready: false)
                try registry.put(entry)
            }
            let root = try VerifiedVault(checkpoint: entry.checkpoint, independentlyVerifiedDigest: entry.digest)
            guard root.membership.role(of: owner.identity) == .owner else { throw MopError.cloudPermission }
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
            result.catalog = try VaultEngine.catalog(in: current, device: owner)
            result.message = "Vault created: \(id)\nCheckpoint: \(current.digest)\nAdd another device or optional hardware recovery in Vault settings."
            return result
        }
        if case .manage(.recoverHardware(let backup, let checkpoint, let ownerBytes, let recoveryBytes, let copy)) = operation {
            let source = try VerifiedVault.restoreBackup(backup, independentlyVerifiedDigest: checkpoint)
            let ownerRequest = try ExchangeFile.decode(DeviceRequest.self, from: ownerBytes); try ownerRequest.validate()
            let nextRecovery = try ExchangeFile.decode(DeviceRequest.self, from: recoveryBytes); try nextRecovery.validate()
            guard !ownerRequest.recovery, nextRecovery.recovery,
                  [ownerRequest, nextRecovery].allSatisfy({ $0.container == config.container && $0.environment == config.environment }) else { throw MopError.invalidRecovery }
            guard let recoveryIdentity = source.membership.recovery else { throw MopError.invalidRecovery }
            let recovery = try device(recovery: true, member: recoveryIdentity.member); defer { close(recovery) }
            guard recovery.identity == source.membership.recovery else { throw MopError.invalidRecovery }
            if copy {
                let owner = try device(create: true); defer { close(owner) }
                guard owner.identity == ownerRequest.device else { throw MopError.invalidIdentity }
                let root = try VaultEngine.recoverCopy(source, using: recovery, name: source.name, owner: owner, replacementRecovery: nextRecovery.device)
                let address = try VaultAddress(container: config.container, environment: config.environment, account: account, database: .private, owner: CKCurrentUserDefaultName, vault: root.id)
                var entry = NextEntry(address: address, checkpoint: root.bytes, digest: root.digest, name: root.name, submitted: true, ready: false)
                try registry.put(entry); try control.check(token)
                try await transport.initialize(root, at: address)
                entry.ready = true; try registry.put(entry)
                try AttachmentDownloads(state: state, address: address).cache(root)
                result.document = try root.backup()
                result.message = "Recovered into new vault \(root.id). Source retained. Checkpoint: \(root.digest)"
            } else {
                guard source.membership.accounts.first(where: { $0.role == .owner })?.id == registry.member else { throw MopError.cloudAccount }
                let address = try VaultAddress(container: config.container, environment: config.environment, account: account, database: .private, owner: CKCurrentUserDefaultName, vault: source.id)
                let entry = NextEntry(address: address, checkpoint: source.bytes, digest: source.digest, name: source.name, submitted: true, ready: true)
                if !(try registry.entries().contains { $0.address.vault == source.id }) { try registry.put(entry) }
                let storage = try registry.storage(entry)
                let coordinator = try PublicationCoordinator(address: address, checkpoint: source, transport: transport, storage: storage)
                _ = try await coordinator.refresh()
                var current = await coordinator.offlineSnapshot().0
                let downloads = AttachmentDownloads(state: state, address: address)
                try downloads.cache(source)
                current = try await downloads.load(current, digests: current.attachmentDigests, transport: transport, offline: false)
                let next = try VaultEngine.recover(current, using: recovery, owner: ownerRequest.device, replacementRecovery: nextRecovery.device)
                try control.check(token); try await coordinator.publish(next)
                try await transport.reconcileShare(next.membership, at: address)
                try downloads.cache(next)
                result.document = try next.backup()
                result.message = "Recovered owner device; old devices and members removed. Checkpoint: \(next.digest)"
            }
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
            removedRegistry = registry
            throw MopError.deviceRemoved
        }
        let attachments = AttachmentDownloads(state: state, address: entry.address)
        if allowsAttachments {
            var needed: Set<String> = []
            switch operation {
            case .read(let reference):
                if let digest = try current.attachmentDigest(for: reference.relativePath, device: key) { needed.insert(digest) }
            case .export, .previewImport, .commitImport: needed = current.attachmentDigests
            case .manage(.removeMember), .manage(.removeDevice):
                reportProgress("Preparing encrypted files…")
                needed = current.attachmentDigests
            case .manage(.replaceRecovery):
                if current.membership.recovery != nil {
                    reportProgress("Preparing encrypted files…")
                    needed = current.attachmentDigests
                }
            case .sync, .catalog:
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
                proposal = try VaultEngine.importItems(plan.items, revision: revision, in: current, device: key) { completed, total in
                    try self.control.check(token)
                    self.reportProgress("Encrypting items: \(completed) of \(total)", fraction: total > 0 ? Double(completed) / Double(total) : nil)
                }
            }
            var report = plan.preview.report; report.imported = plan.items.count; report.committed = true
            result.importReport = report
        case .save(let edit): proposal = try VaultEngine.saveItem(edit, in: current, device: key)
        case .write(let reference, let value, let replace):
            guard reference.vault == current.name else { throw MopError.vaultSelectionMismatch }
            let exists = try VaultEngine.references(in: current, device: key).contains(reference.relativePath)
            guard exists == replace else { throw exists ? MopError.duplicate : MopError.notFound }
            proposal = try VaultEngine.write(reference.relativePath, value: value, in: current, device: key)
        case .delete(let reference):
            guard reference.vault == current.name else { throw MopError.vaultSelectionMismatch }
            proposal = try VaultEngine.write(reference.relativePath, value: nil, in: current, device: key)
        case .trashItem(let name, let revision): proposal = try VaultEngine.trashItem(name: name, revision: revision, in: current, device: key)
        case .restoreItem(let id, let revision): proposal = try VaultEngine.restoreItem(id: id, revision: revision, in: current, device: key)
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
            if let recovery = current.membership.recovery { result.members.append(VaultMemberRecord(id: recovery.device.uuidString, role: "hardware recovery · \(recovery.fingerprint)")) }
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
            result.message = "Cloud vault deleted. Existing local ciphertext and backups retained."; return result
        case .manage(let action):
            switch action {
            case .fingerprint: result.message = current.digest
            case .trust(let fingerprint):
                guard fingerprint == current.digest else { throw MopError.vaultUntrusted }; result.message = "Checkpoint matches the verified vault."
            case .invite(let bytes, let fingerprint, let role), .inviteAccount(let bytes, let fingerprint, let role):
                let request = try checkedRequest(bytes, fingerprint: fingerprint, recovery: false)
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
                let request = try checkedRequest(bytes, fingerprint: fingerprint, recovery: false)
                guard request.account == account else { throw MopError.invalidIdentity }
                let invitation = try VaultEngine.invite(member: request.device.member, role: .owner, to: current, owner: key, expires: Date().addingTimeInterval(86400))
                result.document = try ExchangeFile.encode(InvitationPacket(request: request, invitation: invitation, address: entry.address, checkpoint: current.bytes))
                result.message = "Invitation checkpoint: \(current.digest)\nCompare this checkpoint on your new device, then import its acceptance here."
            case .approve(let bytes, let fingerprint):
                let packet = try ExchangeFile.decode(AcceptancePacket.self, from: bytes)
                let request = try checkedRequest(ExchangeFile.encode(packet.invitation.request), fingerprint: fingerprint, recovery: false)
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
            case .replaceRecovery(let bytes, let fingerprint):
                let request = try checkedRequest(bytes, fingerprint: fingerprint, recovery: true)
                proposal = try VaultEngine.replaceRecovery(with: request.device, in: current, owner: key)
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
        result.catalog = try VaultEngine.catalog(in: verified, device: key)
        result.deletedCatalog = try VaultEngine.catalog(in: verified, device: key, deleted: true)
        return result
    }
}
