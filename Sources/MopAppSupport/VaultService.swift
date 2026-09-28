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
    case deviceRequest(recovery: Bool)
    case inviteOwnDevice(request: Data, fingerprint: String)
    case inviteAccount(request: Data, fingerprint: String, role: MemberRole)
    case invite(request: Data, fingerprint: String, role: MemberRole)
    case accept(packet: Data, checkpoint: String, shareURL: URL?)
    case approve(packet: Data, fingerprint: String)
    case devices, removeAccountDevice(UUID), reconnect
    case removeMember(UUID), removeDevice(UUID), role(UUID, MemberRole)
    case replaceRecovery(request: Data, fingerprint: String)
    case recoverHardware(backup: Data, checkpoint: String, owner: Data, recovery: Data, copy: Bool)
    case reconcileShare
    case importCheckpoint(document: Data, fingerprint: String, sharedOwner: String?)
}
public enum VaultOperation: Sendable {
    case previewImport(ImportDocument, selected: Set<Int>?)
    case commitImport(ImportDocument, selected: Set<Int>, vault: UUID, revision: String)
    case discover, catalog, passwordQuality(item: String), read(SecretReference), save(ItemEdit)
    case write(SecretReference, SecretBytes, replace: Bool), delete(SecretReference)
    case recentlyDeleted, trashItem(name: String, revision: String), restoreItem(id: UUID, revision: String)
    case members, manage(VaultManagement), sync
    case create(name: String, recovery: URL? = nil, fingerprint: String? = nil)
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
    public var importPreview: ImportPreview?
    public var importReport: ImportReport?
    public var vaults: [VaultDescriptor] = []
    public var defaultVault: String?
    public var autoFillStatus: AutoFillPublicationStatus?
    public var catalog: ItemCatalog?
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
    public var enrollments: [EnrollmentExchange] = []
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
public protocol VaultService: Sendable {
    var authenticatedAt: TimeInterval? { get }
    var operationProgress: String? { get }
    var operationFraction: Double? { get }
    func lock()
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult
}

public extension VaultService {
    var operationProgress: String? { nil }
    var operationFraction: Double? { nil }
    var isAuthenticated: Bool { authenticatedAt != nil }
}

// LAContext explicitly supports invalidation of a pending evaluation. This box
// exposes only that operation across threads, not general mutable context access.
final class ContextInvalidator: @unchecked Sendable {
    let context: LAContext
    init(_ context: LAContext) { self.context = context }
    func invalidate() { context.invalidate() }
}

// Locking never waits for network I/O or a blocking biometric evaluation. Only
// the LAContext invalidation callback crosses the worker's isolation boundary.
final class SessionControl: Sendable {
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
actor OperationGate {
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
