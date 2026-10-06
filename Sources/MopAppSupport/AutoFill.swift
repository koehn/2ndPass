import MopLocalIdentity
@preconcurrency import AuthenticationServices
import Foundation
import CryptoKit
import MopCore
import MopKeychain
import MopSync

public enum AutoFillKind: String, Codable, Sendable, CaseIterable {
    case password, oneTimeCode, passkey
    var prefix: String { self == .password ? "mop-autofill-v7" : self == .passkey ? "mop-passkey-v7" : "mop-autofill-otp-v7" }
}

/// Only websites, usernames, credential kinds and opaque locators leave the encrypted catalog.
public struct AutoFillEntry: Equatable, Sendable {
    public let website: String
    public let username: String
    public let recordIdentifier: String
    public let reference: SecretReference
    public let kind: AutoFillKind

    public static func entries(catalog: ItemCatalog, vaultID: String) -> [Self] {
        guard let id = UUID(uuidString: vaultID) else { return [] }
        return catalog.items.filter { $0.type == .login && $0.deletion == nil && !$0.isArchived }.flatMap { item -> [Self] in
            [AutoFillKind.password, .oneTimeCode].flatMap { kind -> [Self] in
                guard exclusionReason(for: item, kind: kind) == nil,
                      let username = usernameField(in: item)?.value,
                      let field = kind == .password ? passwordField(in: item) : otpField(in: item),
                      let reference = try? SecretReference(vault: catalog.vault, relativePath: SecretReference.encode(item.name) + "/" + field.path) else { return [] }
                return Set(item.fields.filter { $0.type == .website }.compactMap { website($0.value ?? "") }).sorted().map { website in
                    let parts = [item.name, field.path, username, website]
                    let digest = SHA256.hash(data: Data(parts.map { "\($0.utf8.count):\($0)" }.joined().utf8)).map { String(format: "%02x", $0) }.joined()
                    return Self(website: website, username: username, recordIdentifier: "\(kind.prefix):\(id.uuidString):\(digest)", reference: reference, kind: kind)
                }
            }
        }
    }
    // The Login template's named, typed fields are the primary credentials.
    // Extra contact emails or secondary secrets must not hide a valid login.
    private static func usernameField(in item: VaultItem) -> ItemField? {
        if let path = item.autoFill?.username { return item.fields.first { $0.path == path && [FieldType.username, .email, .text].contains($0.type) && !($0.value ?? "").isEmpty } }
        let usernames = item.fields.filter { $0.type == .username && !($0.value ?? "").isEmpty }
        if let primary = usernames.first(where: { $0.path == "username" }) { return primary }
        if Set(usernames.compactMap(\.value)).count == 1 { return usernames.first }
        guard usernames.isEmpty else { return nil }
        let emails = item.fields.filter { $0.type == .email && !($0.value ?? "").isEmpty }
        if let primary = emails.first(where: { $0.path == "email" }) { return primary }
        return Set(emails.compactMap(\.value)).count == 1 ? emails.first : nil
    }
    private static func passwordField(in item: VaultItem) -> ItemField? {
        if let path = item.autoFill?.password { return item.fields.first { $0.path == path && [FieldType.password, .concealed].contains($0.type) } }
        let passwords = item.fields.filter { $0.type == .password }
        if let primary = passwords.first(where: { $0.path == "password" }) { return primary }
        return passwords.count == 1 ? passwords.first : nil
    }
    private static func otpField(in item: VaultItem) -> ItemField? {
        if let path = item.autoFill?.oneTimeCode { return item.fields.first { $0.path == path && [FieldType.otp].contains($0.type) } }
        let fields = item.fields.filter { $0.type == .otp }
        if let primary = fields.first(where: { $0.path == "otp" }) { return primary }
        return fields.count == 1 ? fields.first : nil
    }
    /// Nil means the field layout is eligible, not that system publication succeeded.
    public static func exclusionReason(for item: VaultItem, kind: AutoFillKind = .password) -> String? {
        if item.isArchived { return "Archived items are excluded." }
        guard item.type == .login else { return "Set the item type to Login." }
        guard item.deletion == nil else { return "Restore this deleted login first." }
        if let mapping = item.autoFill {
            let relevant = AutoFillMapping(username: mapping.username, password: kind == .password ? mapping.password : nil,
                                           oneTimeCode: kind == .oneTimeCode ? mapping.oneTimeCode : nil)
            if let error = relevant.validationError(in: item.fields) { return error }
        }
        guard usernameField(in: item) != nil else {
            return "Choose a nonempty username in Edit Item → Use for AutoFill, or add a Username field."
        }
        if kind == .password && passwordField(in: item) == nil {
            return "Choose a password in Edit Item → Use for AutoFill, or add a Password field."
        }
        if kind == .oneTimeCode && otpField(in: item) == nil {
            return "Choose a verification code in Edit Item → Use for AutoFill, or add an OTP field."
        }
        guard item.fields.contains(where: { $0.type == .website && website($0.value ?? "") != nil }) else {
            return "Add a Website field in Edit Item and enter a valid HTTP(S) URL or domain."
        }
        return nil
    }
    public static func website(_ value: String) -> String? {
        let value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty,
              let url = URLComponents(string: value.contains("://") ? value : "https://" + value),
              ["https", "http"].contains(url.scheme?.lowercased() ?? ""),
              url.user == nil, url.password == nil,
              let host = url.host?.lowercased(), !host.isEmpty, !host.contains(where: { $0.isWhitespace }),
              host.contains(".") || host == "localhost" else { return nil }
        return host.hasSuffix(".") ? String(host.dropLast()) : host
    }
    public static func vaultID(_ identifier: String) -> String? {
        let parts = identifier.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 3, AutoFillKind.allCases.contains(where: { $0.prefix == parts[0] }), let id = UUID(uuidString: String(parts[1])),
              parts[2].count == 64 && parts[2].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { return nil }
        return id.uuidString
    }
    public var identity: any ASCredentialIdentity { AutoFillIdentity(entry: self).identity }
}

/// This projection deliberately cannot encode a secret, item title or reference.
public struct AutoFillIdentity: Codable, Equatable, Identifiable, Sendable {
    public var id: String { recordIdentifier }
    public let website: String
    public let username: String
    public let recordIdentifier: String
    public let kind: AutoFillKind
    public var credentialID: Data? = nil
    public var userHandle: Data? = nil
    public func matchesPasskey(relyingParty: String, allowed: [Data]) -> Bool {
        guard kind == .passkey, website == relyingParty,
              AutoFillEntry.vaultID(recordIdentifier) != nil,
              let credentialID, credentialID.count == 32,
              let userHandle, (1...64).contains(userHandle.count) else { return false }
        return allowed.isEmpty || allowed.contains(credentialID)
    }
    public init(entry: AutoFillEntry) {
        website = entry.website; username = entry.username; recordIdentifier = entry.recordIdentifier; kind = entry.kind
    }
    public init?(passkey item: VaultItem, vaultID: String) {
        guard UUID(uuidString: vaultID) != nil, item.deletion == nil, !item.isArchived,
              let c = item.credential, c.purposes == [.passkey], (try? c.validate()) != nil,
              let rp = c.relyingParty, let user = c.userName, let credentialID = c.credentialID, let handle = c.userHandle else { return nil }
        website = rp; username = user; kind = .passkey; self.credentialID = credentialID; userHandle = handle
        recordIdentifier = "mop-passkey-v7:" + vaultID + ":" + SHA256.hash(data: credentialID).map { String(format: "%02x", $0) }.joined()
    }
    public init?(identity: AnyObject) {
        // Some macOS store results are internal objects that do not implement
        // the advertised protocol. Never send selectors before checking the type.
        guard identity is ASPasswordCredentialIdentity || identity is ASOneTimeCodeCredentialIdentity || identity is ASPasskeyCredentialIdentity,
              let identity = identity as? any ASCredentialIdentity else { return nil }
        guard let identifier = identity.recordIdentifier else { return nil }
        recordIdentifier = identifier
        if let password = identity as? ASPasswordCredentialIdentity {
            website = password.serviceIdentifier.identifier; username = password.user; kind = .password
        } else if let code = identity as? ASOneTimeCodeCredentialIdentity {
            website = code.serviceIdentifier.identifier; username = code.label; kind = .oneTimeCode
        } else if let passkey = identity as? ASPasskeyCredentialIdentity {
            website = passkey.relyingPartyIdentifier; username = passkey.userName; kind = .passkey
            credentialID = passkey.credentialID; userHandle = passkey.userHandle
        } else { return nil }
    }
    private enum CodingKeys: String, CodingKey { case website, username, recordIdentifier, kind, credentialID, userHandle }
    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        website = try values.decode(String.self, forKey: .website)
        username = try values.decode(String.self, forKey: .username)
        recordIdentifier = try values.decode(String.self, forKey: .recordIdentifier)
        kind = try values.decodeIfPresent(AutoFillKind.self, forKey: .kind) ?? .password
        credentialID = try values.decodeIfPresent(Data.self, forKey: .credentialID)
        userHandle = try values.decodeIfPresent(Data.self, forKey: .userHandle)
        if kind == .passkey { guard credentialID?.count == 32, let userHandle, (1...64).contains(userHandle.count) else { throw CredentialFailure.invalid } }
    }
    public var identity: any ASCredentialIdentity {
        let service = ASCredentialServiceIdentifier(identifier: website, type: .domain)
        switch kind {
        case .passkey: return ASPasskeyCredentialIdentity(relyingPartyIdentifier: website, userName: username, credentialID: credentialID ?? Data(), userHandle: userHandle ?? Data(), recordIdentifier: recordIdentifier)
        case .password: return ASPasswordCredentialIdentity(serviceIdentifier: service, user: username, recordIdentifier: recordIdentifier)
        case .oneTimeCode: return ASOneTimeCodeCredentialIdentity(serviceIdentifier: service, label: username, recordIdentifier: recordIdentifier)
        }
    }
}

/// Shared, device-local metadata for the picker. Apple remains the suggestion
/// destination, but its enumeration API is not the database for our own UI.
public struct AutoFillIndex: Sendable {
    private let directory: URL
    public init(directory: URL) { self.directory = directory }
    private var file: URL { directory.appendingPathComponent("identities.json") }
    private func read(rebuildingInvalidCache: Bool = false) throws -> [AutoFillIdentity] {
        guard FileManager.default.fileExists(atPath: file.path) else { return [] }
        // Filesystem security failures must never be treated as an empty cache.
        let data = try LocalFile.read(file, privateFile: true)
        let entries: [AutoFillIdentity]
        do { entries = try JSONDecoder().decode([AutoFillIdentity].self, from: data) }
        catch {
            if rebuildingInvalidCache { return [] }
            throw MopError.invalidVault
        }
        guard entries.allSatisfy({ AutoFillEntry.vaultID($0.recordIdentifier) != nil && $0.recordIdentifier.hasPrefix($0.kind.prefix + ":") && AutoFillEntry.website($0.website) == $0.website }),
              Set(entries.map(\.recordIdentifier)).count == entries.count else {
            if rebuildingInvalidCache { return [] }
            throw MopError.invalidVault
        }
        return entries
    }
    public func load() throws -> [AutoFillIdentity] {
        let cache = try LocalDirectory(directory: directory)
        return try cache.locked { try read() }
    }
    @discardableResult
    func update(_ transform: ([AutoFillIdentity]) -> [AutoFillIdentity]) throws -> [AutoFillIdentity] {
        let cache = try LocalDirectory(directory: directory)
        return try cache.locked {
            // This is derived metadata, not vault data. Rebuild an unusable
            // index from authenticated catalogs instead of preserving a refresh loop.
            let entries = transform(try read(rebuildingInvalidCache: true)).sorted { $0.recordIdentifier < $1.recordIdentifier }
            let data = try JSONEncoder().encode(entries)
            guard data.count <= 16 * 1024 * 1024 else { throw MopError.invalidVault }
            try LocalFile.write(data, to: file, replace: FileManager.default.fileExists(atPath: file.path))
            return entries
        }
    }
}

public enum AutoFillStorage {
    /// Account changes invalidate offline access as well as visible suggestions.
    public static func invalidate() async {
        NativeItemCloudAccount.invalidateOfflineBinding()
        try? await AutoFillPublisher.shared.prune(keeping: [])
    }

    public static func directory() throws -> URL {
        guard let group = SigningIdentity.appGroupIdentifier,
              !group.contains("$"), let root = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) else { throw MopError.signing }
        return root.appendingPathComponent("AutoFillV7", isDirectory: true)
    }
}

public struct AutoFillPublicationStatus: Codable, Equatable, Sendable {
    public enum Phase: String, Codable, Sendable { case disabled, updating, current, failed, notUpdated }
    public var phase: Phase = .notUpdated
    public var lastSuccess: Date?
    public var message: String?
    // Opaque vault IDs only; failed catalog indexing must not be hidden by another vault’s success.
    public var catalogsNeedingRefresh: Set<String>?
    public init() {}
}

public protocol AutoFillPublishing: Sendable {
    func status() async -> AutoFillPublicationStatus
    func publish(catalog: ItemCatalog, vaultID: String) async throws
    func publish(catalog: ItemCatalog, vaultID: String, complete: Bool, removing itemIDs: Set<String>) async throws
    /// Validate source freshness while holding publication ownership, including across processes.
    func publish(catalog: ItemCatalog, vaultID: String, complete: Bool, removing itemIDs: Set<String>, deferred: Bool,
                 validating: @Sendable () async throws -> Bool) async throws -> Bool
    func refresh() async throws
    func prune(keeping vaultIDs: Set<String>) async throws
}
public extension AutoFillPublishing {
    func prune(keeping vaultIDs: Set<String>) async throws {}
    func publish(catalog: ItemCatalog, vaultID: String, complete: Bool, removing itemIDs: Set<String>, deferred: Bool,
                 validating: @Sendable () async throws -> Bool) async throws -> Bool {
        guard !deferred else { throw ItemVaultServiceFailure.unavailable }
        guard try await validating() else { return false }
        try await publish(catalog: catalog, vaultID: vaultID, complete: complete, removing: itemIDs)
        return true
    }
}

/// All app-side publication is serialized, including full-store replacements.
public actor AutoFillPublisher: AutoFillPublishing {
    public static let shared = AutoFillPublisher()
    private let gate = OperationGate()
    private let indexDirectory: URL?
    private let publishIdentities: @Sendable ([AutoFillIdentity]) async throws -> Void
    private let enabled: @Sendable () async -> Bool
    private let supportsIncremental: @Sendable () async -> Bool
    private let saveIdentities: @Sendable ([AutoFillIdentity]) async throws -> Void
    private let removeIdentities: @Sendable ([AutoFillIdentity]) async throws -> Void
    private let localIdentities: @Sendable () throws -> [AutoFillIdentity]
    private var health: AutoFillPublicationStatus?
    init(directory: URL? = nil, publish: (@Sendable ([AutoFillIdentity]) async throws -> Void)? = nil,
         enabled: (@Sendable () async -> Bool)? = nil,
         incremental: (@Sendable () async -> Bool)? = nil,
         save: (@Sendable ([AutoFillIdentity]) async throws -> Void)? = nil,
         remove: (@Sendable ([AutoFillIdentity]) async throws -> Void)? = nil,
         local: (@Sendable () throws -> [AutoFillIdentity])? = nil) {
        indexDirectory = directory
        if let enabled { self.enabled = enabled }
        else if publish != nil { self.enabled = { true } }
        else { self.enabled = { await ASCredentialIdentityStore.shared.state().isEnabled } }
        if let incremental { supportsIncremental = incremental }
        else if publish != nil { supportsIncremental = { false } }
        else { supportsIncremental = { await ASCredentialIdentityStore.shared.state().supportsIncrementalUpdates } }
        publishIdentities = publish ?? { try await ASCredentialIdentityStore.shared.replaceCredentialIdentities($0.map(\.identity)) }
        saveIdentities = save ?? { try await ASCredentialIdentityStore.shared.saveCredentialIdentities($0.map(\.identity)) }
        removeIdentities = remove ?? { try await ASCredentialIdentityStore.shared.removeCredentialIdentities($0.map(\.identity)) }
        if let local { localIdentities = local }
        else if publish != nil { localIdentities = { [] } }
        else { localIdentities = {
            try LocalIdentityStore.open().list().compactMap(\.passkeySuggestion).compactMap { AutoFillIdentity(identity: $0) }
        } }
    }
    nonisolated static func combinedIdentities(_ entries: [AutoFillIdentity], local: () throws -> [ASPasskeyCredentialIdentity]) -> [any ASCredentialIdentity] {
        // Cloud suggestions do not depend on access to this device's hardware keys.
        entries.map(\.identity) + ((try? local()) ?? [])
    }
    private func directory() throws -> URL { try indexDirectory ?? AutoFillStorage.directory() }
    private func rememberedStatus() -> AutoFillPublicationStatus {
        if let health { return health }
        if let directory = try? directory(),
           let data = try? LocalFile.read(directory.appendingPathComponent("publication.json"), privateFile: true),
           let saved = try? JSONDecoder().decode(AutoFillPublicationStatus.self, from: data) {
            health = saved
        } else { health = AutoFillPublicationStatus() }
        return health!
    }
    private func record(_ state: AutoFillPublicationStatus) {
        guard state != health else { return }
        health = state
        // Health is advisory. A diagnostics write cannot invalidate a successful publication.
        if let directory = try? directory(), let data = try? JSONEncoder().encode(state) {
            let file = directory.appendingPathComponent("publication.json")
            try? LocalFile.write(data, to: file, replace: FileManager.default.fileExists(atPath: file.path))
        }
    }
    public func status() async -> AutoFillPublicationStatus {
        let isEnabled = await enabled()
        var value = rememberedStatus()
        if !isEnabled { value.phase = .disabled }
        else if value.phase == .disabled { value.phase = value.catalogsNeedingRefresh?.isEmpty == false ? .failed : .notUpdated }
        if health?.phase != value.phase { record(value) }
        return value
    }
    private func loadProjection(_ directory: URL) throws -> AutoFillPublicationState {
        let file = directory.appendingPathComponent("projection.json")
        guard FileManager.default.fileExists(atPath: file.path) else { return AutoFillPublicationState() }
        // Read/permission failures are not cache corruption and must fail closed.
        let data = try LocalFile.read(file, privateFile: true)
        guard let state = try? JSONDecoder().decode(AutoFillPublicationState.self, from: data),
              state.schema == AutoFillPublicationState.currentSchema else { return AutoFillPublicationState() }
        return state
    }
    private func saveProjection(_ state: AutoFillPublicationState, directory: URL) throws {
        let file = directory.appendingPathComponent("projection.json")
        let data = try JSONEncoder().encode(state)
        guard data.count <= 32 * 1024 * 1024 else { throw MopError.invalidVault }
        try LocalFile.write(data, to: file, replace: FileManager.default.fileExists(atPath: file.path))
    }
    private func lease(_ directory: URL) async throws -> SynchronizationLease {
        while true {
            try Task.checkCancellation()
            do { return try SynchronizationLease(url: directory.appendingPathComponent("publication.lock")) }
            catch CloudSyncAdapterError.engineAlreadyOwned { try await Task.sleep(for: .milliseconds(50)) }
        }
    }
    @discardableResult
    private func update(scope: String? = nil, retainingScopes: Set<String>? = nil, force: Bool = false, deferSystemUpdate: Bool = false,
                        validating: @Sendable () async throws -> Bool = { true },
                        _ transform: (inout AutoFillPublicationState, [AutoFillIdentity]) -> [AutoFillIdentity]) async throws -> Bool {
        try await gate.enter()
        var status = rememberedStatus(); status.phase = .updating; status.message = nil; health = status
        var indexed = false
        do {
            let directory = try directory()
            let ownership = try await lease(directory)
            defer { withExtendedLifetime(ownership) {} }
            // Another app-group process may have published since our last operation.
            health = nil; status = rememberedStatus()
            guard try await validating() else { await gate.leave(); return false }
            let wasDisabled = status.phase == .disabled
            status.phase = .updating; status.message = nil
            var projection = try loadProjection(directory)
            var persistedProjection = projection
            let index = AutoFillIndex(directory: directory)
            let indexedRows: [AutoFillIdentity]
            var repairIndex = false
            do { indexedRows = try index.load() }
            catch MopError.invalidVault { projection.requiresReconciliation = true; indexedRows = []; repairIndex = true }
            let recovered = projection.items.values.flatMap { $0.values.flatMap(\.identities) }
            let previousDesired = projection.desiredCloud ?? AutoFillPublicationState.unique(indexedRows + recovered)
            let entries = transform(&projection, previousDesired)
            projection.desiredCloud = entries
            // A failed local inventory read is not proof that local passkeys were deleted.
            if let local = try? localIdentities() { projection.local = AutoFillPublicationState.unique(local) }
            let desired = AutoFillPublicationState.unique(entries + projection.local)
            if let scope { status.catalogsNeedingRefresh?.remove(scope) }
            if let retainingScopes { status.catalogsNeedingRefresh = status.catalogsNeedingRefresh?.intersection(retainingScopes) }
            let incremental = deferSystemUpdate ? false : await supportsIncremental()
            let full = force || wasDisabled || (!incremental && projection.published != desired) || projection.requiresReconciliation || projection.published == nil
            let previous = projection.published ?? []
            let old = Dictionary(previous.map { ($0.id, $0) }, uniquingKeysWith: { _, last in last })
            let new = Dictionary(desired.map { ($0.id, $0) }, uniquingKeysWith: { _, last in last })
            let removed = previous.filter { new[$0.id] == nil || new[$0.id] != $0 }
            let saved = desired.filter { old[$0.id] != $0 }
            // Desired metadata is durable before any system call. Confirmed state stays separate.
            if projection != persistedProjection {
                try saveProjection(projection, directory: directory)
                persistedProjection = projection
            }
            // The picker index is derived from the durable desired checkpoint. A
            // crash between these writes is repaired without resurrecting old rows.
            if repairIndex || indexedRows != entries { try index.update { _ in entries } }
            indexed = true
            if deferSystemUpdate {
                // An active fill must not change the host's suggestion store.
                // App activation reconciles this durable desired checkpoint.
                projection.requiresReconciliation = true
                if projection != persistedProjection {
                    try saveProjection(projection, directory: directory)
                    persistedProjection = projection
                }
                status.phase = .notUpdated
                status.message = "Saved suggestions will be published when 2ndPass next becomes active."
                record(status)
                await gate.leave()
                return true
            }
            if await enabled() {
                if full || !removed.isEmpty || !saved.isEmpty {
                    projection.requiresReconciliation = true
                    if projection != persistedProjection {
                        try saveProjection(projection, directory: directory)
                        persistedProjection = projection
                    }
                    if full { try await publishIdentities(desired) }
                    else {
                        if !removed.isEmpty { try await removeIdentities(removed) }
                        if !saved.isEmpty { try await saveIdentities(saved) }
                    }
                    projection.published = desired; projection.requiresReconciliation = false
                    if projection != persistedProjection {
                        try saveProjection(projection, directory: directory)
                        persistedProjection = projection
                    }
                    status.lastSuccess = Date()
                }
                status.phase = .current
                if status.catalogsNeedingRefresh?.isEmpty == false {
                    status.phase = .failed
                    status.message = "Some vault suggestions still need an update. Choose Refresh Suggestions to retry."
                }
            } else {
                projection.requiresReconciliation = true
                if projection != persistedProjection {
                    try saveProjection(projection, directory: directory)
                    persistedProjection = projection
                }
                status.phase = .disabled
            }
            record(status)
            await gate.leave()
            return true
        } catch {
            if !indexed, let scope {
                if status.catalogsNeedingRefresh == nil { status.catalogsNeedingRefresh = [] }
                status.catalogsNeedingRefresh?.insert(scope)
            }
            status.phase = .failed
            status.message = "Suggestions could not be updated. Your saved vault changes are safe. Try Refresh Suggestions."
            record(status)
            await gate.leave(); throw error
        }
    }
    public func publish(catalog: ItemCatalog, vaultID: String) async throws {
        try await publish(catalog: catalog, vaultID: vaultID, complete: true, removing: [])
    }
    /// Keep the picker and routing metadata current without touching the system
    /// identity store while Safari is waiting for a selected credential.
    public func stage(catalog: ItemCatalog, vaultID: String) async throws {
        try await update(scope: vaultID, deferSystemUpdate: true) { state, old in
            state.project(catalog, vaultID: vaultID, complete: true, removing: [], previous: old)
        }
    }
    public func publish(catalog: ItemCatalog, vaultID: String, complete: Bool, removing itemIDs: Set<String> = []) async throws {
        try await update(scope: vaultID) { state, old in
            state.project(catalog, vaultID: vaultID, complete: complete, removing: itemIDs, previous: old)
        }
    }
    public func publish(catalog: ItemCatalog, vaultID: String, complete: Bool, removing itemIDs: Set<String>, deferred: Bool,
                        validating: @Sendable () async throws -> Bool) async throws -> Bool {
        try await update(scope: vaultID, deferSystemUpdate: deferred, validating: validating) { state, old in
            state.project(catalog, vaultID: vaultID, complete: complete, removing: itemIDs, previous: old)
        }
    }
    /// Explicit repair handles system-store resets even when no source items changed.
    public func refresh() async throws { try await update(force: true) { _, old in old } }
    /// Repair system-store drift using public suggestion metadata, without opening a vault.
    public func reconcile() async throws {
        // macOS can return private objects without ASCredentialIdentity getters
        // from enumeration. Reassert our metadata instead of trusting either
        // those objects or a checkpoint that survives a system-store reset.
        try await update(force: true) { _, old in old }
    }
    public func refreshLocalPasskeys() async throws { try await update { _, old in old } }
    public func prune(keeping vaultIDs: Set<String>) async throws {
        try await update(retainingScopes: vaultIDs) { state, old in
            state.items = state.items.filter { vaultIDs.contains($0.key) }
            return old.filter { AutoFillEntry.vaultID($0.id).map { vaultIDs.contains($0) } ?? false }
        }
    }
    func remove(vaultID: String) async throws {
        try await update(scope: vaultID) { state, old in
            state.items[vaultID] = nil
            return old.filter { AutoFillEntry.vaultID($0.id) != vaultID }
        }
    }
}

public enum AutoFillAccess {
    /// Every suggestion must enter the presented extension and authenticate.
    /// Selection alone is not proof of authentication, regardless of credential kind.
    @MainActor public static func completeSystemRequest(recordIdentifier: String, kind: AutoFillKind = .password,
                                                       context: ASCredentialProviderExtensionContext) async throws {
        // Never construct a service, open a snapshot, or return a value here.
        throw NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userInteractionRequired.rawValue)
    }

    /// Use a normally authenticated service, scoped to this fill request.
    public static func oneTimeCode(recordIdentifier: String, service: any VaultService) async throws -> ASOneTimeCodeCredential {
        service.lock()
        defer { service.lock() }
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await resolvedOneTimeCode(recordIdentifier: recordIdentifier, service: service)
        } onCancel: { service.lock() }
    }

    private static func resolvedOneTimeCode(recordIdentifier: String, service: any VaultService) async throws -> ASOneTimeCodeCredential {
        let (_, secret) = try await resolve(recordIdentifier: recordIdentifier, kind: .oneTimeCode, service: service)
        guard let bytes = secret.value, let expiry = secret.otpExpiresAt, expiry > Date(),
              let period = secret.otpPeriod, period > 0 else { throw MopError.invalidOTP }
        return ASOneTimeCodeCredential(code: String(decoding: bytes, as: UTF8.self))
    }

    /// Use a normally authenticated service, scoped to this fill request.
    public static func credential(recordIdentifier: String, service: any VaultService) async throws -> ASPasswordCredential {
        service.lock()
        defer { service.lock() }
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await resolvedCredential(recordIdentifier: recordIdentifier, service: service)
        } onCancel: {
            service.lock()
        }
    }

    /// Re-resolve the locator from the authenticated catalog. Never trust the
    /// username or reference supplied by the system's potentially stale index.
    private static func resolvedCredential(recordIdentifier: String, service: any VaultService) async throws -> ASPasswordCredential {
        let (entry, secret) = try await resolve(recordIdentifier: recordIdentifier, kind: .password, service: service)
        guard let bytes = secret.value else { throw MopError.notFound }
        return ASPasswordCredential(user: entry.username, password: String(decoding: bytes, as: UTF8.self))
    }

    static func resolve(recordIdentifier: String, kind: AutoFillKind, service: any VaultService) async throws -> (AutoFillEntry, VaultResult) {
        try Task.checkCancellation()
        guard recordIdentifier.hasPrefix(kind.prefix + ":"), AutoFillEntry.vaultID(recordIdentifier) != nil else { throw MopError.notFound }
        let (entry, secret) = try await service.resolveAutoFill(recordIdentifier: recordIdentifier, kind: kind)
        try Task.checkCancellation()
        return (entry, secret)
    }
}
