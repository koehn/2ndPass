#if os(iOS)
import Foundation
import Security
import LocalAuthentication
import MopCore

/// iOS validates the signed application's entitlements when accessing Keychain
/// and CloudKit. Do not use macOS SecCode APIs or parse provisioning profiles.
public enum SigningIdentity {
    public static var appGroupIdentifier: String? {
        Bundle.main.object(forInfoDictionaryKey: "MopAppGroup") as? String
    }

    public static func accessGroup() throws -> String {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "MopKeychainAccessGroup") as? String,
              let identifier = Bundle.main.bundleIdentifier,
              group.hasSuffix("." + (identifier.hasSuffix(".AutoFill") ? String(identifier.dropLast(".AutoFill".count)) : identifier)), !group.contains("$"), !group.contains("*") else {
            throw MopError.signing
        }
        let context = LAContext()
        context.interactionNotAllowed = true
        defer { context.invalidate() }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessGroup as String: group,
            kSecAttrService as String: "mop.identity-check",
            kSecAttrAccount as String: UUID().uuidString,
            kSecUseAuthenticationContext as String: context
        ]
        guard SecItemCopyMatching(query as CFDictionary, nil) == errSecItemNotFound else { throw MopError.signing }
        return group
    }

    public static func cloudConfiguration() throws -> (container: String, environment: String) {
        _ = try accessGroup()
        guard let container = Bundle.main.object(forInfoDictionaryKey: "MopCloudContainer") as? String,
              container == "iCloud.com.koehn.mop",
              let environment = Bundle.main.object(forInfoDictionaryKey: "MopCloudEnvironment") as? String,
              ["Development", "Production"].contains(environment) else { throw MopError.signing }
        return (container, environment)
    }
}
#endif
