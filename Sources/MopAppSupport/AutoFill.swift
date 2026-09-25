@preconcurrency import AuthenticationServices
import Foundation
import CryptoKit
import OSLog
import MopCore
import MopVault
import MopCloudKit
import MopKeychain

/// Only websites, usernames and opaque locators leave the encrypted catalog.
public struct AutoFillEntry: Equatable, Sendable {
    public let website: String
    public let username: String
    public let recordIdentifier: String
    public let reference: SecretReference

    public static func entries(catalog: ItemCatalog, vaultID: String) -> [Self] {
        guard let id = UUID(uuidString: vaultID) else { return [] }
        return catalog.items.filter { $0.type == .login && $0.deletion == nil }.flatMap { item -> [Self] in
            guard exclusionReason(for: item) == nil,
                  let username = usernameField(in: item)?.value,
                  let password = passwordField(in: item),
                  let reference = try? SecretReference(vault: catalog.vault, relativePath: SecretReference.encode(item.name) + "/" + password.path) else { return [] }
            return Set(item.fields.filter { $0.type == .website }.compactMap { website($0.value ?? "") }).sorted().map { website in
                let parts = [item.name, password.path, username, website]
                let digest = SHA256.hash(data: Data(parts.map { "\($0.utf8.count):\($0)" }.joined().utf8)).map { String(format: "%02x", $0) }.joined()
                return Self(website: website, username: username, recordIdentifier: "mop-autofill-v1:\(id.uuidString):\(digest)", reference: reference)
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
    /// Nil means the field layout is eligible, not that system publication succeeded.
    public static func exclusionReason(for item: VaultItem) -> String? {
        guard item.type == .login else { return "Set the item type to Login." }
        guard item.deletion == nil else { return "Restore this deleted login first." }
        guard usernameField(in: item) != nil else {
            return "Set a nonempty field’s type to Username (or Email). If there are multiple usernames, name the primary Username field ‘username’."
        }
        guard passwordField(in: item) != nil else {
            return "Set the password field’s type to Password. If there are multiple passwords, name the primary Password field ‘password’."
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
        guard parts.count == 3, parts[0] == "mop-autofill-v1", let id = UUID(uuidString: String(parts[1])),
              VaultTrust.validFingerprint(String(parts[2])) else { return nil }
        return id.uuidString
    }
    public var identity: ASPasswordCredentialIdentity {
        ASPasswordCredentialIdentity(serviceIdentifier: ASCredentialServiceIdentifier(identifier: website, type: .domain), user: username, recordIdentifier: recordIdentifier)
    }
}

/// This projection deliberately cannot encode a secret, item title or reference.
public struct AutoFillIdentity: Codable, Equatable, Sendable {
    public let website: String
    public let username: String
    public let recordIdentifier: String
    public init(entry: AutoFillEntry) {
        website = entry.website; username = entry.username; recordIdentifier = entry.recordIdentifier
    }
    public var identity: ASPasswordCredentialIdentity {
        ASPasswordCredentialIdentity(serviceIdentifier: ASCredentialServiceIdentifier(identifier: website, type: .domain), user: username, recordIdentifier: recordIdentifier)
    }
}

/// Shared, device-local metadata for the picker. Apple remains the suggestion
/// destination, but its enumeration API is not the database for our own UI.
public struct AutoFillIndex: Sendable {
    private let directory: URL
    public init(directory: URL) { self.directory = directory }
    private var file: URL { directory.appendingPathComponent("identities.json") }
    private func read() throws -> [AutoFillIdentity] {
        guard FileManager.default.fileExists(atPath: file.path) else { return [] }
        let entries = try JSONDecoder().decode([AutoFillIdentity].self, from: SafeFile.read(file, privateFile: true))
        guard entries.allSatisfy({ AutoFillEntry.vaultID($0.recordIdentifier) != nil && AutoFillEntry.website($0.website) == $0.website }),
              Set(entries.map(\.recordIdentifier)).count == entries.count else { throw MopError.invalidVault }
        return entries
    }
    public func load() throws -> [AutoFillIdentity] {
        let cache = try CloudCache(directory: directory)
        return try cache.locked { try read() }
    }
    @discardableResult
    func update(_ transform: ([AutoFillIdentity]) -> [AutoFillIdentity]) throws -> [AutoFillIdentity] {
        let cache = try CloudCache(directory: directory)
        return try cache.locked {
            let entries = transform(try read()).sorted { $0.recordIdentifier < $1.recordIdentifier }
            let data = try JSONEncoder().encode(entries)
            guard data.count <= VaultCoding.maximumFileSize else { throw MopError.invalidVault }
            try SafeFile.write(data, to: file, replace: FileManager.default.fileExists(atPath: file.path))
            return entries
        }
    }
}

public enum AutoFillStorage {
    /// Account changes invalidate offline access as well as visible suggestions.
    public static func invalidate() async {
        if let directory = try? directory() {
            let cloud = directory.appendingPathComponent("cloud")
            for name in (try? FileManager.default.contentsOfDirectory(atPath: cloud.path)) ?? [] {
                guard VaultTrust.validFingerprint(name) else { continue }
                let binding = cloud.appendingPathComponent(name).appendingPathComponent("binding.json")
                try? FileManager.default.removeItem(at: binding)
            }
        }
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
    /// Only for provideCredentialWithoutUserInteraction. AutoFill owns user
    /// authentication on this path; the returned password goes directly to the
    /// system, never to a caller or a reusable unlocked app session. The picker
    /// must continue using a normally authenticated NativeVaultService.
    @MainActor public static func completeSystemRequest(recordIdentifier: String,
                                                       context: ASCredentialProviderExtensionContext) async throws {
        let extensionInfo = Bundle.main.object(forInfoDictionaryKey: "NSExtension") as? [String: Any]
        guard extensionInfo?["NSExtensionPointIdentifier"] as? String == "com.apple.authentication-services-credential-provider-ui"
        else { throw MopError.authentication }
        let configuration = DefaultVaultPlatformConfiguration()
        let service = NativeVaultService(state: try AutoFillStorage.directory(),
            identityKeys: SynchronizedIdentityStore(allowUserInteraction: false), transport: {
                let config = try configuration.cloudConfiguration()
                return AppleCloudTransport(container: config.container, environment: config.environment)
            }, authenticate: { _ in
                // AuthenticationServices authenticates the user for the non-UI
                // request. Do not run a second LocalAuthentication challenge.
                return {}
            })
        let credential = try await systemCredential(recordIdentifier: recordIdentifier, service: service)
        try Task.checkCancellation()
        context.completeRequest(withSelectedCredential: credential, completionHandler: nil)
    }

    static func systemCredential(recordIdentifier: String, service: any VaultService) async throws -> ASPasswordCredential {
        defer { service.lock() }
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await credential(recordIdentifier: recordIdentifier, service: service)
        } onCancel: {
            service.lock()
        }
    }

    /// Re-resolve the locator from the authenticated catalog. Never trust the
    /// username or reference supplied by the system's potentially stale index.
    public static func credential(recordIdentifier: String, service: any VaultService) async throws -> ASPasswordCredential {
        guard let id = AutoFillEntry.vaultID(recordIdentifier) else { throw MopError.notFound }
        let result = try await service.execute(.catalog, vault: id, offline: true)
        let catalog = try result.requireCatalog()
        guard let entry = AutoFillEntry.entries(catalog: catalog, vaultID: id).first(where: { $0.recordIdentifier == recordIdentifier }) else { throw MopError.notFound }
        let secret = try await service.execute(.read(entry.reference), vault: id, offline: true)
        try Task.checkCancellation()
        guard let bytes = secret.value else { throw MopError.notFound }
        return ASPasswordCredential(user: entry.username, password: String(decoding: bytes, as: UTF8.self))
    }
}
