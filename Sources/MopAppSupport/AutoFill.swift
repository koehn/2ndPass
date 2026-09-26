@preconcurrency import AuthenticationServices
import Foundation
import CryptoKit
import MopCore

public enum AutoFillKind: String, Codable, Sendable, CaseIterable {
    case password, oneTimeCode
    var prefix: String { self == .password ? "mop-autofill-v6" : "mop-autofill-otp-v6" }
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
        return catalog.items.filter { $0.type == .login && $0.deletion == nil }.flatMap { item -> [Self] in
            AutoFillKind.allCases.flatMap { kind -> [Self] in
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
        let usernames = item.fields.filter { $0.type == .username && !($0.value ?? "").isEmpty }
        if let primary = usernames.first(where: { $0.path == "username" }) { return primary }
        if Set(usernames.compactMap(\.value)).count == 1 { return usernames.first }
        guard usernames.isEmpty else { return nil }
        let emails = item.fields.filter { $0.type == .email && !($0.value ?? "").isEmpty }
        if let primary = emails.first(where: { $0.path == "email" }) { return primary }
        return Set(emails.compactMap(\.value)).count == 1 ? emails.first : nil
    }
    private static func passwordField(in item: VaultItem) -> ItemField? {
        let passwords = item.fields.filter { $0.type == .password }
        if let primary = passwords.first(where: { $0.path == "password" }) { return primary }
        return passwords.count == 1 ? passwords.first : nil
    }
    private static func otpField(in item: VaultItem) -> ItemField? {
        let fields = item.fields.filter { $0.type == .otp }
        if let primary = fields.first(where: { $0.path == "otp" }) { return primary }
        return fields.count == 1 ? fields.first : nil
    }
    /// Nil means the field layout is eligible, not that system publication succeeded.
    public static func exclusionReason(for item: VaultItem, kind: AutoFillKind = .password) -> String? {
        guard item.type == .login else { return "Set the item type to Login." }
        guard item.deletion == nil else { return "Restore this deleted login first." }
        guard usernameField(in: item) != nil else {
            return "Set a nonempty field’s type to Username (or Email). If there are multiple usernames, name the primary Username field ‘username’."
        }
        if kind == .password && passwordField(in: item) == nil {
            return "Set the password field’s type to Password. If there are multiple passwords, name the primary Password field ‘password’."
        }
        if kind == .oneTimeCode && otpField(in: item) == nil {
            return "Set a field’s type to OTP. If there are multiple OTP fields, name the primary field ‘otp’."
        }
        guard item.fields.contains(where: { $0.type == .website && website($0.value ?? "") != nil }) else {
            return "Set a field’s type to Website and enter a valid HTTP(S) URL or domain."
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
public struct AutoFillIdentity: Codable, Equatable, Sendable {
    public let website: String
    public let username: String
    public let recordIdentifier: String
    public let kind: AutoFillKind
    public init(entry: AutoFillEntry) {
        website = entry.website; username = entry.username; recordIdentifier = entry.recordIdentifier; kind = entry.kind
    }
    public init?(identity: any ASCredentialIdentity) {
        guard let identifier = identity.recordIdentifier else { return nil }
        recordIdentifier = identifier
        if let password = identity as? ASPasswordCredentialIdentity {
            website = password.serviceIdentifier.identifier; username = password.user; kind = .password
        } else if let code = identity as? ASOneTimeCodeCredentialIdentity {
            website = code.serviceIdentifier.identifier; username = code.label; kind = .oneTimeCode
        } else { return nil }
    }
    private enum CodingKeys: String, CodingKey { case website, username, recordIdentifier, kind }
    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        website = try values.decode(String.self, forKey: .website)
        username = try values.decode(String.self, forKey: .username)
        recordIdentifier = try values.decode(String.self, forKey: .recordIdentifier)
        kind = try values.decodeIfPresent(AutoFillKind.self, forKey: .kind) ?? .password
    }
    public var identity: any ASCredentialIdentity {
        let service = ASCredentialServiceIdentifier(identifier: website, type: .domain)
        switch kind {
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
        try? NextAccountBinding.invalidate(state: AppStorageLocation.defaultState)
        try? await AutoFillPublisher.shared.prune(keeping: [])
    }

    public static func directory() throws -> URL {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "MopAppGroup") as? String,
              !group.contains("$"), let root = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) else { throw MopError.signing }
        return root.appendingPathComponent("AutoFill", isDirectory: true)
    }
}

/// All app-side publication is serialized, including full-store replacements.
actor AutoFillPublisher {
    static let shared = AutoFillPublisher()
    private let gate = OperationGate()
    private let indexDirectory: URL?
    private let publishIdentities: @Sendable ([AutoFillIdentity]) async throws -> Void
    init(directory: URL? = nil, publish: (@Sendable ([AutoFillIdentity]) async throws -> Void)? = nil) {
        indexDirectory = directory
        publishIdentities = publish ?? { entries in
            let store = ASCredentialIdentityStore.shared
            if await store.state().isEnabled {
                try await store.replaceCredentialIdentities(entries.map(\.identity))
            }
        }
    }
    private func update(_ transform: ([AutoFillIdentity]) -> [AutoFillIdentity]) async throws {
        await gate.enter()
        do {
            let entries = try AutoFillIndex(directory: indexDirectory ?? AutoFillStorage.directory()).update(transform)
            try await publishIdentities(entries)
            await gate.leave()
        } catch { await gate.leave(); throw error }
    }
    func publish(catalog: ItemCatalog, vaultID: String) async throws {
        try await update { old in
            old.filter { AutoFillEntry.vaultID($0.recordIdentifier) != vaultID }
                + AutoFillEntry.entries(catalog: catalog, vaultID: vaultID).map(AutoFillIdentity.init)
        }
    }
    func prune(keeping vaultIDs: Set<String>) async throws {
        try await update { old in
            old.filter { identity in
                guard let id = AutoFillEntry.vaultID(identity.recordIdentifier) else { return false }
                return vaultIDs.contains(id)
            }
        }
    }
    func remove(vaultID: String) async throws {
        try await update { $0.filter { AutoFillEntry.vaultID($0.recordIdentifier) != vaultID } }
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

    private static func resolve(recordIdentifier: String, kind: AutoFillKind, service: any VaultService) async throws -> (AutoFillEntry, VaultResult) {
        try Task.checkCancellation()
        guard recordIdentifier.hasPrefix(kind.prefix + ":"), let id = AutoFillEntry.vaultID(recordIdentifier) else { throw MopError.notFound }
        let result = try await service.execute(.catalog, vault: id, offline: true)
        let catalog = try result.requireCatalog()
        guard let entry = AutoFillEntry.entries(catalog: catalog, vaultID: id).first(where: { $0.recordIdentifier == recordIdentifier && $0.kind == kind }) else { throw MopError.notFound }
        let secret = try await service.execute(.read(entry.reference), vault: id, offline: true)
        try Task.checkCancellation()
        return (entry, secret)
    }
}
