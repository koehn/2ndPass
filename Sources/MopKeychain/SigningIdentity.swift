import Foundation
import Security
import MopCore

public enum SigningIdentity {
    public static func accessGroup() throws -> String {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              let applicationID = entitlements["com.apple.application-identifier"] as? String,
              let groups = entitlements["keychain-access-groups"] as? [String],
              groups == [applicationID],
              let bundleID = Bundle.main.bundleIdentifier,
              applicationID.hasSuffix("." + bundleID),
              FileManager.default.fileExists(atPath: Bundle.main.bundleURL.appendingPathComponent("Contents/embedded.provisionprofile").path)
        else { throw MopError.signing }
        return applicationID
    }
}
