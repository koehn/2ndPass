@preconcurrency import CloudKit
import Foundation
import Synchronization
import MopCore
import MopKeychain
import MopSync
import MopVaultNext

/// A live native account binding, separate from the legacy vault registry.
/// An account-change notification permanently retires this instance. Callers
/// must stop its adapter and authenticate again rather than rebind queued work.
public final class NativeItemCloudAccount: RepositoryWritePermit, @unchecked Sendable {
    public let containerIdentifier: String
    public let environment: String
    public let accountNamespace: String
    public let memberID: UUID
    public let directory: URL
    public let container: CKContainer
    private let userRecordName: String
    private let lifetime: ItemCloudAccountLifetime

    private init(container: CKContainer, identifier: String, environment: String,
                 userRecordName: String, directory: URL, lifetime: ItemCloudAccountLifetime) throws {
        self.container = container; containerIdentifier = identifier; self.environment = environment
        self.userRecordName = userRecordName; self.directory = directory; self.lifetime = lifetime
        accountNamespace = try Self.namespace(container: identifier, environment: environment, userRecordName: userRecordName)
        // Retain the existing native account-member identity without consulting
        // the v7 registry or moving any existing key material.
        memberID = AccountScope.member(container: identifier, environment: environment, account: userRecordName)
    }

    /// Explicit offline mode makes no CloudKit requests. Transient native network
    /// failures may also reopen the last verified device-local namespace. Every
    /// actual cloud operation still verifies the live account before publication.
    public static func connect(offline: Bool = false) async throws -> NativeItemCloudAccount {
        let configuration = try SigningIdentity.cloudConfiguration()
        let directory = try AppStorageLocation.sharedItemSyncDirectory(container: configuration.container,
                                                                       environment: configuration.environment)
        let cache = ItemCloudAccountCache(container: configuration.container, environment: configuration.environment)
        let lifetime = ItemCloudAccountLifetime(onInvalidation: { cache.clear() })
        let container = CKContainer(identifier: configuration.container)
        if offline {
            guard let record = try cache.load(), lifetime.isValid else { throw MopError.cloudAccount }
            return try NativeItemCloudAccount(container: container, identifier: configuration.container,
                environment: configuration.environment, userRecordName: record.userRecordName, directory: directory, lifetime: lifetime)
        }
        do {
            switch try await container.accountStatus() {
            case .available: break
            case .noAccount, .restricted: lifetime.invalidate(); throw MopError.cloudAccount
            case .couldNotDetermine, .temporarilyUnavailable: throw MopError.cloudUnavailable
            @unknown default: throw MopError.cloudUnavailable
            }
            let name = try await container.userRecordID().recordName
            try Task.checkCancellation()
            guard lifetime.isValid else { throw MopError.cloudAccount }
            let value = try NativeItemCloudAccount(container: container, identifier: configuration.container,
                environment: configuration.environment, userRecordName: name, directory: directory, lifetime: lifetime)
            guard try await value.validate() else { throw MopError.cloudAccount }
            try lifetime.withValidity { try cache.save(userRecordName: name) }
            return value
        } catch {
            let native = error as? CKError
            let temporary = (error as? MopError) == .cloudUnavailable
                || native?.code == .networkFailure || native?.code == .networkUnavailable
                || native?.code == .serviceUnavailable || native?.code == .requestRateLimited
            guard temporary, lifetime.isValid, let record = try cache.load() else { throw error }
            return try NativeItemCloudAccount(container: container, identifier: configuration.container,
                environment: configuration.environment, userRecordName: record.userRecordName, directory: directory, lifetime: lifetime)
        }
    }

    /// Called by app/extension account-change observers even when no account
    /// runtime is alive. Reads signed configuration only; never authenticates.
    public static func invalidateOfflineBinding() {
        guard let configuration = try? SigningIdentity.cloudConfiguration() else { return }
        ItemCloudAccountCache(container: configuration.container, environment: configuration.environment).clear()
    }

    public func setupScope(vaultID: UUID) throws -> ItemVaultSetupScope {
        guard lifetime.isValid else { throw MopError.cloudAccount }
        return ItemVaultSetupScope(container: containerIdentifier, environment: environment,
            binding: ItemVaultBinding(account: accountNamespace, database: "private",
                                      zoneOwner: CKCurrentUserDefaultName, vaultID: vaultID))
    }

    public func leaseURL(database: String) throws -> URL {
        guard lifetime.isValid else { throw MopError.cloudAccount }
        return try AppStorageLocation.itemSyncLease(directory: directory, account: accountNamespace, database: database)
    }

    public var validator: CloudAccountValidator { { [self] in try await validate() } }
    public func invalidate() { lifetime.invalidate() }
    public func withWritePermission<T>(_ body: () throws -> T) throws -> T {
        try lifetime.withValidity(body)
    }

    public func validate() async throws -> Bool {
        guard lifetime.isValid else { return false }
        switch try await container.accountStatus() {
        case .available: break
        case .noAccount, .restricted:
            lifetime.invalidate(); return false
        case .couldNotDetermine, .temporarilyUnavailable:
            throw MopError.cloudUnavailable
        @unknown default:
            throw MopError.cloudUnavailable
        }
        let current = try await container.userRecordID().recordName
        try Task.checkCancellation()
        guard current == userRecordName else { lifetime.invalidate(); return false }
        return lifetime.isValid
    }

    static func namespace(container: String, environment: String, userRecordName: String) throws -> String {
        guard !container.isEmpty, ["Development", "Production"].contains(environment),
              !userRecordName.isEmpty, userRecordName != CKCurrentUserDefaultName else { throw MopError.cloudAccount }
        return try setupHash(setupEncode(["2ndpass-item-account-1", container, environment, userRecordName]))
    }
}

final class ItemCloudAccountLifetime: @unchecked Sendable {
    private let valid = Mutex(true)
    private let center: NotificationCenter
    private var observer: NSObjectProtocol?
    private let onInvalidation: @Sendable () -> Void
    init(center: NotificationCenter = .default, onInvalidation: @escaping @Sendable () -> Void = {}) {
        self.center = center
        self.onInvalidation = onInvalidation
        observer = center.addObserver(forName: .CKAccountChanged, object: nil, queue: nil) { [weak self] _ in
            self?.invalidate()
        }
    }
    var isValid: Bool { valid.withLock { $0 } }
    func withValidity<T>(_ body: () throws -> T) throws -> T {
        try valid.withLock { value in
            guard value else { throw MopError.cloudAccount }
            return try body()
        }
    }
    func invalidate() {
        let first = valid.withLock { value in let old = value; value = false; return old }
        if first { onInvalidation() }
    }
    deinit { if let observer { center.removeObserver(observer) } }
}
