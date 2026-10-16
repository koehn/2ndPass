import Foundation
import Synchronization
import MopCore
import MopSync
import MopVaultNext

/// Recovery uses the same pinned histories, content inbox, grants and rotation
/// operations as normal access. Only the recovery key is session-local.
final class ContentRecoveryCoordinator: @unchecked Sendable {
    private let account: NativeItemCloudAccount
    private let repository: EncryptedItemRepository
    private let runtime: ItemVaultSyncRuntime
    private let trust: KeychainItemVaultTrustStore
    let store: ItemRecoveryStateStore
    private let key = Mutex<OfflineRecoveryKey?>(nil)
    var operationProgress: String? { nil }
    var operationFraction: Double? { nil }
    init(account: NativeItemCloudAccount, repository: EncryptedItemRepository, runtime: ItemVaultSyncRuntime) throws {
        self.account = account; self.repository = repository; self.runtime = runtime
        trust = try KeychainItemVaultTrustStore()
        store = ItemRecoveryStateStore(directory: account.directory.appendingPathComponent("ContentPreview3"), account: account.accountNamespace)
    }
    func lock() { key.withLock { $0?.close(); $0 = nil }; Task { await runtime.clearRecoveryRecipient() } }
    deinit { lock() }
    private func recovery() throws -> OfflineRecoveryKey {
        guard let value = key.withLock({ $0 }) else { throw ItemRecoveryFailure.codeRequired }; return value
    }
    private let configurationKey = "content-recovery-configuration3"
    private struct Rotation: Codable { let target: DevicePublicKey? }
    func configuration() async throws -> RecoveryConfiguration {
        var result: RecoveryConfiguration
        if let bytes = try await repository.engineState(account: account.accountNamespace, database: configurationKey) {
            result = try JSONDecoder().decode(RecoveryConfiguration.self, from: bytes)
            try result.validate()
            guard result.scope == account.recoveryScope else { throw MopError.cloudAccount }
        } else { result = RecoveryConfiguration(scope: account.recoveryScope) }
        let operations = try await repository.operations(account: account.accountNamespace, database: "private")
        let records = try await runtime.inventory()
        var recipients: [DevicePublicKey?] = []
        result.vaults = try records.map { record in
            let history = try ItemVaultMembershipAuthority.history(record: record, trustStore: trust, allowingDeviceRemoval: true)
            recipients.append(history.current.membership.offlineRecovery)
            let pending = operations.contains { $0.vaultID == history.vault && $0.state != .completed && [.recovery, .membership, .rotateContent, .publishItem, .grant, .prepareGrant].contains($0.kind) }
            return RecoveryVaultStatus(id: history.vault, fingerprint: history.current.membership.offlineRecovery?.fingerprint,
                complete: !pending && (!result.incomplete || history.current.membership.offlineRecovery == result.target))
        }
        if result.incomplete, result.vaults.allSatisfy(\.complete) {
            result.active = result.target; result.target = nil; result.operation = nil
            try await saveConfiguration(result)
        } else if !result.incomplete, let first = recipients.first, recipients.allSatisfy({ $0 == first }) { result.active = first }
        return result
    }
    private func saveConfiguration(_ value: RecoveryConfiguration) async throws {
        try value.validate()
        try await repository.saveEngineState(setupEncode(value), account: account.accountNamespace, database: configurationKey, permit: account)
    }
    func handle(_ operation: SyncOperation, permit: any RepositoryWritePermit) async -> SyncOperationOutcome {
        do {
            guard let vault = operation.vaultID, operation.kind == .recovery else { return .attention(.invalidAuthority) }
            let target = try JSONDecoder().decode(Rotation.self, from: operation.payload).target
            let session = try await runtime.authorizedSession(vault).contentSession
            if session.history.current.membership.offlineRecovery == target { return .completed }
            let current = session.history.current.membership
            let membership = try Membership(accounts: current.accounts, offlineRecovery: target, removedDevices: current.removedDevices)
            let signed = try await session.prepareMembership(membership, owner: permit)
            _ = try await repository.enqueue(signed)
            return .retry(.dependency)
        } catch MopError.authentication { return .authorization }
        catch { return ItemVaultSyncRuntime.workFailureOutcome(error) }
    }
    func grant(_ operation: SyncOperation, session: GrantBackedContentSession, permit: any RepositoryWritePermit) async -> SyncOperationOutcome? {
        guard let recovery = key.withLock({ $0 }), session.history.current.membership.offlineRecovery == recovery.identity else { return nil }
        if operation.kind == .rotateContent { return await session.handle(operation, owner: permit, recovery: recovery) }
        do {
            try await session.prepareRecoveryGrant(operation, recovery: recovery, owner: permit)
            return .completed
        } catch CloudSyncAdapterError.membershipUnavailable { return .retry(.dependency) }
        catch MopError.authentication { return .authorization }
        catch { return nil }
    }
    typealias DeviceLoader = @Sendable (UUID, Bool) async throws -> any DeviceOperations
    typealias Check = @Sendable () throws -> Void
    func execute(_ action: VaultManagement, device: DeviceLoader, check: Check) async throws -> VaultResult {
        try check()
        var result = VaultResult(); result.recoveryScope = account.recoveryScope
        switch action {
        case .recoveryGenerate:
            let value = try OfflineRecoveryKey(scope: account.recoveryScope); defer { value.close() }
            result.recoveryCode = try value.code(); result.recoveryFile = try value.export(); result.recoveryFingerprint = value.identity.fingerprint
        case .recoveryStatus:
            result.recoveryConfiguration = try await configuration()
        case .recoveryActivate(let document, let fingerprint):
            let value = try OfflineRecoveryKey(document: document, scope: account.recoveryScope); defer { value.close() }
            guard fingerprint.isEmpty || value.identity.fingerprint == fingerprint else { throw MopError.invalidRecovery }
            result.recoveryConfiguration = try await rotate(to: value.identity, device: device, check: check)
        case .recoveryRevoke:
            result.recoveryConfiguration = try await rotate(to: nil, device: device, check: check)
        case .recoveryResume:
            let value = try await configuration()
            result.recoveryConfiguration = try await rotate(to: value.incomplete ? value.target : value.active, device: device, check: check)
        case .recoveryOpen(let document):
            let value = try OfflineRecoveryKey(document: document, scope: account.recoveryScope)
            key.withLock { $0?.close(); $0 = value }
            let hints = try await repository.contentDiscovery(account: account.accountNamespace)
            let reader = NativeContentHistoryReader(account: account)
            var vaults: [UUID] = []
            for hint in hints {
                try check()
                let history = try await reader.history(hint.vaultID)
                guard history.current.membership.offlineRecovery == value.identity else { continue }
                let scope = try account.setupScope(vaultID: hint.vaultID), genesis = history.orderedStates[0]
                let record = try account.withWritePermission {
                    try trust.reserve(ItemVaultSetupRecord(scope: scope, sourceDigest: setupHash(Data(("recovery3:" + value.identity.fingerprint).utf8)),
                        name: "vault", genesis: genesis.encoded(), pinnedDigest: genesis.digest()))
                }
                guard record.pinnedDigest == (try genesis.digest()) else { throw MopError.vaultUntrusted }
                let local = try ItemVaultMembershipAuthority.history(record: record, trustStore: trust, allowingDeviceRemoval: true)
                guard try history.state(forDigest: local.current.digest()) == local.current else { throw MopError.vaultUntrusted }
                try account.withWritePermission { try trust.reserveMembership(scope: scope, successors: history.orderedStates.dropFirst().map { try $0.encoded() }) }
                if try await repository.vaultInitialization(scope.repositoryScope) == nil {
                    _ = try await repository.initializeEnrolledContentVault(scope: scope.repositoryScope,
                        policy: GrantBackedContentStorage.recipientPolicy(history: history), membershipState: record.genesis,
                        currentControl: history.current.encoded(), setupID: record.setupID, authorization: account)
                }
                vaults.append(hint.vaultID)
                result.vaults.append(VaultDescriptor(id: hint.vaultID.uuidString, name: nil, format: "mop-content-v3", enrolled: false))
            }
            guard !vaults.isEmpty else { lock(); throw MopError.invalidRecovery }
            if try store.load()?.blocksRegularAccess != true { try store.save(ItemRecoveryState(account: account.accountNamespace, vaults: vaults)) }
            try await runtime.useRecoveryRecipient(value.identity.fingerprint)
            result.recoveryReadOnly = true
            result.message = "Recovery access is open. Encrypted content and grants download automatically."
        case .recoveryCatalog(let vault), .recoveryRead(let vault, _):
            let recovery = try recovery(), history = try history(vault)
            guard history.current.membership.offlineRecovery == recovery.identity else { throw MopError.invalidRecovery }
            let versions = try await repository.itemsForPortableExport(account: account.accountNamespace, vaultID: vault)
            var items: [VaultItem] = []
            for version in versions where version.scope.itemID != ItemVaultSession.metadataRecordID && !version.isTombstone {
                let (content, grant) = try await GrantBackedContentStorage(repository: repository)
                    .readablePair(scope: version.scope, history: history, recipient: recovery.identity.fingerprint)
                let catalog = try ContentItemArchive.catalog(content.open(component: ContentItemArchive.catalogComponent, grant: grant, history: history, device: recovery),
                    item: version.scope.itemID, componentNames: Set(content.components.keys))
                try check()
                try await repository.rememberReadableContent(scope: version.scope,
                    reference: ReadableContentReference(version: content.header.version, keyGeneration: content.header.keyGeneration,
                        grant: grant.identifier, recipient: recovery.identity.fingerprint), expectedHead: version.versionID, permit: account)
                items.append(catalog.item)
                if case .recoveryRead(_, let path) = action, let id = catalog.references[path] {
                    let value = try content.open(component: id, grant: grant, history: history, device: recovery)
                    if catalog.item.fields.contains(where: { $0.type == .attachment && SecretReference.encode(catalog.item.name) + "/" + $0.path == path }) {
                        result.recoveredAttachment = try value.withFoundationData { try Attachment.decode(String(decoding: $0, as: UTF8.self)) }
                    } else { result.value = value }
                }
            }
            result.catalog = ItemCatalog(vault: vault.uuidString, revision: try history.current.digest(), items: items)
        case .recoveryComplete(let vault):
            try await complete([vault], device: device, check: check)
            result.message = "Recovery enrollment is saved. Access finishes automatically while this device is unlocked."
        case .recoveryCompleteAll(let vaults):
            try await complete(vaults, device: device, check: check)
            result.message = "Recovery enrollment is saved. Access finishes automatically while this device is unlocked."
        case .recoveryEligibility:
            result.recoveryNeeded = true
        default: throw ItemVaultServiceFailure.unavailable
        }
        if let progress = try await progress() {
            result.recoveryInProgress = progress.blocksRegularAccess && progress.phase != .preview
            result.recoveryVaults = progress.vaults.map { RecoveryVaultStatus(id: $0, fingerprint: nil, complete: progress.completed.contains($0)) }
        }
        try check(); return result
    }
    private func history(_ vault: UUID) throws -> TrustedMembershipHistory {
        guard let pin = try trust.load(scope: account.setupScope(vaultID: vault)) else { throw MopError.vaultMissing }
        return try ItemVaultMembershipAuthority.history(record: pin, trustStore: trust, allowingDeviceRemoval: true)
    }
    private func grant(_ content: ContentEnvelope, scope: ItemScope, recovery: OfflineRecoveryKey, history: TrustedMembershipHistory) async throws -> ContentKeyGrant {
        guard history.current.membership.offlineRecovery == recovery.identity else { throw MopError.invalidRecovery }
        let grants = try await repository.contentGrants(scope: scope, keyGeneration: content.header.keyGeneration)
        guard let value = grants.first(where: { $0.recipient == recovery.identity.fingerprint }) else { throw ItemRecoveryFailure.pending }
        return try ContentKeyGrant.decode(value.bytes, content: content, history: history)
    }
    private func rotate(to target: DevicePublicKey?, device: DeviceLoader, check: Check) async throws -> RecoveryConfiguration {
        var value = try await configuration()
        if value.incomplete { guard value.target == target else { throw ItemRecoveryFailure.configurationBusy } }
        else { value.operation = UUID(); value.target = target }
        var work: [SyncOperation] = []
        for record in try await runtime.inventory() {
            // Explicit user action may authorize once. The durable handler never prompts.
            let provider = try await device(record.scope.binding.vaultID, false); provider.close()
            try check()
            let bytes = try setupEncode(Rotation(target: target))
            let pending = try await repository.operations(account: account.accountNamespace, database: "private")
            if !pending.contains(where: { $0.kind == .recovery && $0.vaultID == record.scope.binding.vaultID && $0.payload == bytes && $0.state != .completed }) {
                work.append(SyncOperation(account: account.accountNamespace, vaultID: record.scope.binding.vaultID, kind: .recovery, payload: bytes))
            }
        }
        try await repository.saveContentWorkflowState(setupEncode(value), account: account.accountNamespace, name: configurationKey, operations: work, permit: account)
        try await runtime.wake(reason: .unlocked)
        return try await configuration()
    }
    private func complete(_ vaults: [UUID], device: DeviceLoader, check: Check) async throws {
        guard !vaults.isEmpty, Set(vaults).count == vaults.count, var progress = try store.load() else { throw ItemRecoveryFailure.codeRequired }
        if progress.phase == .preview || progress.phase == .complete { progress.vaults = vaults; progress.completed = []; progress.phase = .enrolling }
        else { guard Set(vaults).isSubset(of: Set(progress.vaults)) else { throw ItemRecoveryFailure.recoveryInProgress } }
        for vault in vaults {
            let joining = try await device(vault, true); defer { joining.close() }
            let history = try history(vault)
            if history.current.membership.devices.contains(joining.identity), progress.approvals[vault.uuidString] == nil {
                let request = try DeviceEnrollmentRequest.create(scope: EnrollmentScope(container: account.containerIdentifier, environment: account.environment,
                    account: account.accountNamespace, vault: vault, member: account.memberID), device: joining)
                let reconnect = try DeviceEnrollmentApproval.reconnect(request: request, history: history, owner: joining)
                progress.approvals[vault.uuidString] = try reconnect.encoded()
                try check(); try store.save(progress)
                continue
            }
            let approval: DeviceEnrollmentApproval
            if let bytes = progress.approvals[vault.uuidString] { approval = try DeviceEnrollmentApproval.decode(bytes) }
            else {
                let request = try DeviceEnrollmentRequest.create(scope: EnrollmentScope(container: account.containerIdentifier, environment: account.environment,
                    account: account.accountNamespace, vault: vault, member: account.memberID), device: joining)
                approval = try DeviceEnrollmentApproval.create(request: request, history: history, owner: recovery())
                progress.approvals[vault.uuidString] = try approval.encoded()
                try check(); try store.save(progress)
            }
            guard approval.request.identity == joining.identity else { throw MopError.invalidRecovery }
            if !approval.isReconnect {
                _ = try await repository.enqueue(SyncOperation(id: approval.request.id, account: account.accountNamespace, vaultID: vault, kind: .membership, payload: try approval.encoded()))
            }
        }
        try store.save(progress); try await runtime.wake(reason: .unlocked)
    }
    func progress() async throws -> ItemRecoveryState? {
        guard var progress = try store.load() else { return nil }
        guard progress.phase != .preview && progress.phase != .complete else { return progress }
        let operations = try await repository.activeOperations(account: account.accountNamespace, database: "private")
        for vault in progress.vaults where !progress.completed.contains(vault) {
            guard let bytes = progress.approvals[vault.uuidString] else { continue }
            let approval = try DeviceEnrollmentApproval.decode(bytes), current = try history(vault)
            guard try await repository.recipientGrantReadiness(scope: account.setupScope(vaultID: vault).repositoryScope,
                recipient: approval.request.identity.fingerprint) else { continue }
            guard current.current.membership.devices.contains(approval.request.identity),
                  !operations.contains(where: { $0.vaultID == vault && $0.state != .completed && [.membership, .rotateContent, .publishItem, .prepareGrant, .grant, .applyIncoming, .fetchContentVersion, .fetchMembership, .resolveConflict].contains($0.kind) }),
                  try await repository.item(account.setupScope(vaultID: vault).binding.item(ItemVaultSession.metadataRecordID)) != nil else { continue }
            progress.completed.append(vault)
        }
        if Set(progress.completed) == Set(progress.vaults) { progress.phase = .complete }
        if try store.load() != progress { try store.save(progress) }; return progress
    }
}
