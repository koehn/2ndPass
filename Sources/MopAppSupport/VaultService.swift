import Foundation
import OSLog
import LocalAuthentication
import Synchronization
import MopCore
import MopAuth
import MopKeychain
import MopVaultNext

public struct VaultMemberRecord: Sendable, Identifiable {
    public let id: String
    public let role: String
}
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
    case requestEnrollment(name: String), restartEnrollment(name: String), cancelEnrollment, checkEnrollment, enrollmentInbox, automaticEnrollment, confirmEnrollment(code: String)
    case approveEnrollment(id: UUID, code: String), rejectEnrollment(id: UUID)
    case fingerprint, trust(fingerprint: String)
    case deviceRequest
    case inviteOwnDevice(request: Data, fingerprint: String)
    case inviteAccount(request: Data, fingerprint: String, role: MemberRole)
    case invite(request: Data, fingerprint: String, role: MemberRole)
    case accept(packet: Data, checkpoint: String, shareURL: URL?)
    case approve(packet: Data, fingerprint: String)
    case devices, removeAccountDevice(UUID), reconnect, resetCloudAccess
    case removeMember(UUID), removeDevice(UUID), role(UUID, MemberRole)
    case recoveryEligibility, recoveryGenerate, recoveryStatus, recoveryRevoke, recoveryResume
    case recoveryTestReset(copy: SecretBytes)
    case recoveryActivate(copy: SecretBytes, fingerprint: String)
    case recoveryOpen(copy: SecretBytes)
    case recoveryCatalog(UUID), recoveryRead(UUID, String), recoveryComplete(UUID)
    case reconcileShare
    case importCheckpoint(document: Data, fingerprint: String, sharedOwner: String?)
}
public enum VaultOperation: Sendable {
    case previewImport(ImportDocument, selected: Set<Int>?)
    case commitImport(ImportDocument, selected: Set<Int>, vault: UUID, revision: String)
    case discover, catalog, passwordQuality(item: String), read(SecretReference), save(ItemEdit)
    case write(SecretReference, SecretBytes, replace: Bool), delete(SecretReference)
    case readHistory(entry: String, revision: String), restoreHistory(entry: String, revision: String), clearHistory(field: UUID, revision: String)
    case reconcileLocalCredentials(Set<UUID>, revision: String)
    case saveCredentialAccount(CredentialAccount, revision: String)
    case savePasswordChecks([CachedPasswordCheck], revision: String)
    case upgradeSecurity(backup: URL, revision: String)
    case recentlyDeleted, trashItem(name: String, revision: String), restoreItem(id: UUID, revision: String)
    case members, manage(VaultManagement), sync
    case create(name: String)
    case rename(String), deleteVault, export(URL)
    /// Portable logical backup, independent of enrolled keys and cloud state.
    case exportPortable(URL)
    case restorePortable(document: Data, key: SecretBytes, name: String)
}
extension VaultOperation {
    var allowsCachedRead: Bool {
        switch self {
        case .discover, .catalog, .read, .passwordQuality, .recentlyDeleted, .readHistory, .export, .exportPortable: true
        default: false
        }
    }
}
public enum VaultSaveStatus: String, Sendable { case local, cloudConfirmed, pending }

public struct VaultResult: Sendable {
    public var saveStatus: VaultSaveStatus?
    /// Exact durable mutations, retained even when cloud confirmation is pending.
    public var mutationIDs: [UUID] = []
    public var recoveryConfiguration: RecoveryConfiguration?
    public var recoveryScope: RecoveryScope?
    public var recoveryFingerprint: String?
    public var recoveryCode: SecretBytes?
    public var recoveryFile: SecretBytes?
    public var recoveryVaults: [RecoveryVaultStatus] = []
    public var recoveryNeeded = false
    public var recoveryReadOnly = false
    public var recoveredAttachment: Attachment?
    public var usageScope: String?
    public var usageVault: String?
    public var usageIdentity: ItemUsageIdentity?
    public var retainedItemIDs: Set<String>?
    public var importPreview: ImportPreview?
    public var importReport: ImportReport?
    public var vaults: [VaultDescriptor] = []
    public var discoveryComplete = true
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
    public var members: [VaultMemberRecord] = []
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
    case enrollment, deviceRemoval, sharing, recovery, securityUpgrade, importDocuments, credentialAccounts, vaultDeletion, portableBackup, passwordCheckCache
}

public enum VaultChange: Sendable {
    case store
    case display(vault: String)
}

public protocol VaultService: Sendable {
    func refreshAutoFillSuggestions(offline: Bool) async throws -> AutoFillPublicationStatus
    func resolveAutoFill(recordIdentifier: String, kind: AutoFillKind) async throws -> (AutoFillEntry, VaultResult)
    var capabilities: Set<VaultServiceCapability> { get }
    func changes() async -> AsyncStream<Void>
    func events() async -> AsyncStream<VaultChange>
    func conflicts(vault: String) async throws -> [ItemVaultConflictPreview]
    func resolve(_ preview: ItemVaultConflictPreview, choice: ItemConflictChoice) async throws
    func revealConflict(_ preview: ItemVaultConflictPreview, side: ItemVaultConflictSide, path: String) async throws -> SecretBytes
    func invalidateDiscovery()
    /// Foreground/push wake, independent of local catalog reads and authentication.
    func requestSynchronization() async throws
    var sessionGeneration: Int { get }
    var authenticatedAt: TimeInterval? { get }
    var operationProgress: String? { get }
    var operationFraction: Double? { get }
    func endRecoverySession()
    func lock()
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult
    func readLocal(_ reference: SecretReference, vault: String?) async throws -> VaultResult
    func readLocal(_ reference: SecretReference, vault: String?, itemID: String?) async throws -> VaultResult
    func userActivity()
    func setMaintenanceActive(_ active: Bool)
    func displayCatalog(vault: String) async throws -> VaultResult
    /// A verified, explicitly stale catalog for initial display, if available.
    func cachedCatalog(vault: String) async throws -> VaultResult?
}

public extension VaultService {
    func refreshAutoFillSuggestions(offline: Bool) async throws -> AutoFillPublicationStatus { throw ItemVaultServiceFailure.unavailable }
    func resolveAutoFill(recordIdentifier: String, kind: AutoFillKind) async throws -> (AutoFillEntry, VaultResult) {
        throw ItemVaultServiceFailure.unavailable
    }
    func userActivity() {}
    func setMaintenanceActive(_ active: Bool) {}
    func conflicts(vault: String) async throws -> [ItemVaultConflictPreview] { [] }
    func resolve(_ preview: ItemVaultConflictPreview, choice: ItemConflictChoice) async throws { throw ItemVaultServiceFailure.unavailable }
    func revealConflict(_ preview: ItemVaultConflictPreview, side: ItemVaultConflictSide, path: String) async throws -> SecretBytes { throw ItemVaultServiceFailure.unavailable }

    func displayCatalog(vault: String) async throws -> VaultResult { try await execute(.catalog, vault: vault, offline: false) }
    func readLocal(_ reference: SecretReference, vault: String?, itemID: String?) async throws -> VaultResult {
        try await readLocal(reference, vault: vault)
    }
    func invalidateDiscovery() {}
    func requestSynchronization() async throws {}
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
