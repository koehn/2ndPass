import Foundation
import Security
import LocalAuthentication
import MopCore

public enum SigningIdentity {
    public static func accessGroup() throws -> String {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              let applicationID = entitlements["com.apple.application-identifier"] as? String,
              let groups = entitlements["keychain-access-groups"] as? [String],
              groups == [applicationID], !applicationID.contains("*"),
              entitlements["com.apple.security.get-task-allow"] as? Bool != true,
              entitlements["get-task-allow"] as? Bool != true,
              entitlements["com.apple.security.cs.disable-library-validation"] as? Bool != true,
              entitlements["com.apple.security.cs.allow-dyld-environment-variables"] as? Bool != true,
              let flags = info[kSecCodeInfoFlags as String] as? UInt32,
              flags & 0x10000 != 0, // CS_RUNTIME: require hardened runtime.
              let executable = info[kSecCodeInfoMainExecutable as String] as? URL,
              let bundle = applicationBundle(for: executable),
              let bundleID = bundle.bundleIdentifier,
              applicationID.hasSuffix("." + bundleID),
              FileManager.default.fileExists(atPath: bundle.bundleURL.appendingPathComponent("Contents/embedded.provisionprofile").path)
        else { throw MopError.signing }
        // Let securityd verify the provisioned entitlement too. This query cannot
        // prompt and asks only for a nonexistent diagnostic item, never key data.
        let context = LAContext()
        context.interactionNotAllowed = true
        defer { context.invalidate() }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessGroup as String: applicationID,
            kSecAttrService as String: "mop.identity-check",
            kSecAttrAccount as String: UUID().uuidString,
            kSecUseAuthenticationContext as String: context]
        guard SecItemCopyMatching(query as CFDictionary, nil) == errSecItemNotFound else { throw MopError.signing }
        return applicationID
    }

    // Bundle.main may describe the CLI symlink's directory. Use the executable
    // identified by Security.framework for the validated running code instead.
    private static func applicationBundle(for executable: URL) -> Bundle? {
        let resolved = executable.resolvingSymlinksInPath()
        let macOS = resolved.deletingLastPathComponent()
        let contents = macOS.deletingLastPathComponent()
        let root = contents.deletingLastPathComponent()
        guard macOS.lastPathComponent == "MacOS", contents.lastPathComponent == "Contents",
              root.pathExtension == "app", let bundle = Bundle(url: root),
              bundle.executableURL?.resolvingSymlinksInPath() == resolved else { return nil }
        return bundle
    }
}
