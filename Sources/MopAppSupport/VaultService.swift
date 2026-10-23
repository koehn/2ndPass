import Foundation
import OSLog
import LocalAuthentication
import Synchronization
import MopCore
import MopAuth
import MopKeychain
import MopVaultNext
import MopSync

public struct VaultDeviceRecord: Sendable, Identifiable {
    public let id: UUID
    public let name: String
    public let isCurrent: Bool
    public var vaultNames: [String: String]
    public init(id: UUID, name: String, isCurrent: Bool, vaultNames: [String: String] = [:]) {
        self.id = id; self.name = name; self.isCurrent = isCurrent; self.vaultNames = vaultNames
    }
}
public enum VaultManagement: Sendable {
    case automaticEnrollment
    case devices, removeDevice(UUID)
    case recoveryEligibility, recoveryGenerate, recoveryStatus, recoveryRevoke, recoveryResume
    case recoveryActivate(copy: SecretBytes, fingerprint: String)
    case recoveryOpen(copy: SecretBytes)
    case recoveryCatalog(UUID), recoveryRead(UUID, String), recoveryComplete(UUID), recoveryCompleteAll([UUID])
}
public enum VaultOperation: Sendable {
    case discover, catalog, passwordQuality(item: String), read(SecretReference), save(ItemEdit)
    case write(SecretReference, SecretBytes, replace: Bool), delete(SecretReference)
    case readHistory(entry: String, revision: String), restoreHistory(entry: String, revision: String), clearHistory(field: UUID, revision: String)
    case savePasswordChecks([CachedPasswordCheck], revision: String)
    case recentlyDeleted, trashItem(name: String, revision: String), restoreItem(id: UUID, revision: String)
    case manage(VaultManagement), sync
    case create(name: String)
    case rename(String), deleteVault
    /// Portable logical backup, independent of enrolled keys and cloud state.
    case exportPortable(URL)
    case restorePortable(document: Data, key: SecretBytes, name: String)
}
extension VaultOperation {
    var allowsCachedRead: Bool {
        switch self {
        case .discover, .catalog, .read, .passwordQuality, .recentlyDeleted, .readHistory, .exportPortable: true
        default: false
        }
    }
}
public enum VaultSaveStatus: String, Sendable { case local, cloudConfirmed, pending }

/// Counts include the metadata record. Before approval the total is unknown.
public struct VaultEnrollmentProgress: Sendable, Equatable {
    public let ready: Int
    public let total: Int
    public init(ready: Int, total: Int) { self.total = max(0, total); self.ready = min(max(0, ready), max(0, total)) }
    public var fraction: Double? { total > 0 ? Double(ready) / Double(total) : nil }
}

public struct VaultResult: Sendable {
    public var pendingVaultDeletions: [String: VaultDeletionPhase] = [:]
    public var deletionStatus: VaultDeletionPhase?
    public var saveStatus: VaultSaveStatus?
    /// Exact durable mutations, retained even when cloud confirmation is pending.
    public var mutationIDs: [UUID] = []
    public var recoveryConfiguration: RecoveryConfiguration?
    public var recoveryScope: RecoveryScope?
    public var recoveryFingerprint: String?
    public var recoveryCode: SecretBytes?
    public var recoveryFile: SecretBytes?
    public var recoveryVaults: [RecoveryVaultStatus] = []
    public var recoveryInProgress = false
    public var recoveryNeeded = false
    public var recoveryReadOnly = false
    public var recoveredAttachment: Attachment?
    public var usageScope: String?
    public var usageVault: String?
    public var usageIdentity: ItemUsageIdentity?
    public var retainedItemIDs: Set<String>?
    public var vaults: [VaultDescriptor] = []
    public var discoveryComplete = true
    public var enrollmentProgress: [String: VaultEnrollmentProgress] = [:]
    public var enrollment: ItemEnrollmentView?
    public var defaultVault: String?
    public var autoFillStatus: AutoFillPublicationStatus?
    public var catalog: ItemCatalog?
    /// Both nil means the local display projection is complete. Counts exclude vault metadata.
    public var catalogDownloading = false
    public var catalogWaitingCount: Int?
    public var catalogLoadedCount: Int?
    public var catalogTotalCount: Int?
    public var deletedCatalog: ItemCatalog?
    public var value: SecretBytes?
    public var valueIsConcealed = true
    public var otpExpiresAt: Date?
    public var otpPeriod: Int?
    public var passwordQuality: [String: PasswordQuality] = [:]
    public var devices: [VaultDeviceRecord] = []
    public var deviceRemovalIncomplete = false
    public var deviceRemoved = false
    public var addedDevices: [UUID] = []
    public var enrollmentCompleted = false
    public var document: Data?
    public var message = ""
    public var usingCache = false
    public var offlineDate: Date?
    public init() {}
    public func requireCatalog() throws -> ItemCatalog {
        guard let catalog else { throw MopError.invalidVault }; return catalog
    }
}
public enum VaultServiceCapability: CaseIterable, Hashable, Sendable {
    case enrollment, deviceRemoval, recovery, vaultDeletion, portableBackup, passwordCheckCache
}

public enum VaultChange: Sendable {
    case store
    case display(vault: String)
}

public protocol VaultService: Sendable {
    #if DEBUG
    func debugResetEnrollment() async throws
    #endif
    func refreshAutoFillSuggestions(offline: Bool) async throws -> AutoFillPublicationStatus
    func resolveAutoFill(recordIdentifier: String, kind: AutoFillKind) async throws -> (AutoFillEntry, VaultResult)
    var capabilities: Set<VaultServiceCapability> { get }
    func changes() async -> AsyncStream<Void>
    func events() async -> AsyncStream<VaultChange>
    func checkConflicts(vault: String) async throws -> ItemVaultConflictCheck
    func conflicts(vault: String) async throws -> [ItemVaultConflictPreview]
    func resolve(_ preview: ItemVaultConflictPreview, choice: ItemConflictChoice) async throws
    func revealConflict(_ preview: ItemVaultConflictPreview, side: ItemVaultConflictSide, path: String) async throws -> SecretBytes
    func invalidateDiscovery()
    /// Foreground/push wake, independent of local catalog reads and authentication.
    func requestSynchronization() async throws
    func requestSynchronization(refreshPrerequisites: Bool) async throws
    func synchronizationHealth() async throws -> SyncHealthSnapshot?
    func discardSynchronizationWork(on day: Date) async throws -> Int
    func synchronizationDiagnostics() async throws -> [SyncOperationDiagnostic]
    var sessionGeneration: Int { get }
    var authenticatedAt: TimeInterval? { get }
    /// Authorization retained while a new device waits for vault admission.
    var enrollmentAuthorizedAt: TimeInterval? { get }
    var operationProgress: String? { get }
    var operationFraction: Double? { get }
    func endRecoverySession()
    func reauthenticate() async throws
    var requiresLocalAuthentication: Bool { get }
    func lock()
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult
    func readLocal(_ reference: SecretReference, vault: String?) async throws -> VaultResult
    func readLocal(_ reference: SecretReference, vault: String?, itemID: String?) async throws -> VaultResult
    func userActivity()
    func setMaintenanceActive(_ active: Bool)
    func pendingVaultDeletionCount() async throws -> Int?
    func displayCatalog(vault: String) async throws -> VaultResult
    /// A verified, explicitly stale catalog for initial display, if available.
    func cachedCatalog(vault: String) async throws -> VaultResult?
}

public extension VaultService {
    func reauthenticate() async throws { throw ItemVaultServiceFailure.unavailable }
    var requiresLocalAuthentication: Bool { false }
    #if DEBUG
    func debugResetEnrollment() async throws { throw ItemVaultServiceFailure.unavailable }
    #endif
    func refreshAutoFillSuggestions(offline: Bool) async throws -> AutoFillPublicationStatus { throw ItemVaultServiceFailure.unavailable }
    func resolveAutoFill(recordIdentifier: String, kind: AutoFillKind) async throws -> (AutoFillEntry, VaultResult) {
        throw ItemVaultServiceFailure.unavailable
    }
    func userActivity() {}
    func setMaintenanceActive(_ active: Bool) {}
    func pendingVaultDeletionCount() async throws -> Int? { nil }
    func conflicts(vault: String) async throws -> [ItemVaultConflictPreview] { [] }
    func checkConflicts(vault: String) async throws -> ItemVaultConflictCheck {
        try await ItemVaultConflictCheck(choices: conflicts(vault: vault), pending: 0)
    }
    func resolve(_ preview: ItemVaultConflictPreview, choice: ItemConflictChoice) async throws { throw ItemVaultServiceFailure.unavailable }
    func revealConflict(_ preview: ItemVaultConflictPreview, side: ItemVaultConflictSide, path: String) async throws -> SecretBytes { throw ItemVaultServiceFailure.unavailable }

    func displayCatalog(vault: String) async throws -> VaultResult { try await execute(.catalog, vault: vault, offline: false) }
    func readLocal(_ reference: SecretReference, vault: String?, itemID: String?) async throws -> VaultResult {
        try await readLocal(reference, vault: vault)
    }
    func invalidateDiscovery() {}
    func requestSynchronization() async throws {}
    func requestSynchronization(refreshPrerequisites: Bool) async throws { try await requestSynchronization() }
    func synchronizationHealth() async throws -> SyncHealthSnapshot? { nil }
    func discardSynchronizationWork(on day: Date) async throws -> Int { throw ItemVaultServiceFailure.unavailable }
    func synchronizationDiagnostics() async throws -> [SyncOperationDiagnostic] { [] }
    var capabilities: Set<VaultServiceCapability> { Set(VaultServiceCapability.allCases) }
    func events() async -> AsyncStream<VaultChange> {
        let pair = AsyncStream<VaultChange>.makeStream()
        let source = await changes()
        let pump = Task {
            for await _ in source {
                guard !Task.isCancelled else { break }
                pair.continuation.yield(.store)
            }
            pair.continuation.finish()
        }
        pair.continuation.onTermination = { _ in pump.cancel() }
        return pair.stream
    }
    func changes() async -> AsyncStream<Void> { AsyncStream { $0.finish() } }
    var sessionGeneration: Int { 0 }
    func endRecoverySession() {}
    func cachedCatalog(vault: String) async throws -> VaultResult? { nil }
    var operationProgress: String? { nil }
    var operationFraction: Double? { nil }
    var enrollmentAuthorizedAt: TimeInterval? { nil }
    var isAuthenticated: Bool { authenticatedAt != nil }
    func readLocal(_ reference: SecretReference, vault: String?) async throws -> VaultResult {
        guard isAuthenticated else { throw MopError.authentication }
        return try await execute(.read(reference), vault: vault, offline: true)
    }
}

// LAContext explicitly supports invalidation of a pending evaluation. This box
// exposes only that operation across threads, not general mutable context access.
final class ContextInvalidator: @unchecked Sendable {
    let context: LAContext
    init(_ context: LAContext) { self.context = context }
    func invalidate() { context.invalidate() }
}

/// FIFO permits held across suspension points. Distinct catalog vaults may
/// overlap; aliases, same-vault operations and account-wide mutations cannot.
actor OperationGate {
    private var exclusive = false
    private var vaults: Set<String> = []
    private var waiters: [(UUID, String?, CheckedContinuation<Void, Error>)] = []
    private func available(_ vault: String?) -> Bool {
        guard !exclusive else { return false }
        return vault.map { !vaults.contains($0) } ?? vaults.isEmpty
    }
    private func occupy(_ vault: String?) {
        if let vault { vaults.insert(vault) } else { exclusive = true }
    }
    func enter(vault: String? = nil) async throws {
        try Task.checkCancellation()
        if waiters.isEmpty && available(vault) { occupy(vault); return }
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { waiters.append((id, vault, $0)) }
        } onCancel: { Task { await self.cancel(id) } }
        if Task.isCancelled { leave(vault: vault); throw CancellationError() }
    }
    private func cancel(_ id: UUID) {
        guard let index = waiters.firstIndex(where: { $0.0 == id }) else { return }
        waiters.remove(at: index).2.resume(throwing: CancellationError())
        drain()
    }
    func leave(vault: String? = nil) {
        if let vault { vaults.remove(vault) } else { exclusive = false }
        drain()
    }
    private func drain() {
        while let first = waiters.first, available(first.1) {
            waiters.removeFirst(); occupy(first.1); first.2.resume()
        }
    }
}

public extension VaultManagement {
    var isItemRecovery: Bool {
        switch self {
        case .recoveryEligibility, .recoveryGenerate, .recoveryStatus, .recoveryRevoke, .recoveryResume,
             .recoveryActivate, .recoveryOpen, .recoveryCatalog, .recoveryRead, .recoveryComplete, .recoveryCompleteAll: true
        default: false
        }
    }
}

/// Only verified content differences belong in choices. Pending records need
/// automatic reconciliation or another successful comparison, never a choice.
public struct ItemVaultConflictCheck: Sendable {
    public var choices: [ItemVaultConflictPreview]
    public var pending: Int
    public init(choices: [ItemVaultConflictPreview], pending: Int) {
        self.choices = choices; self.pending = pending
    }
}
