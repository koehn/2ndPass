import Foundation
import LocalAuthentication
import Security
import MopCore
import MopKeychain

/// Separate namespace keeps a failed/interrupted migration from overwriting the
/// only enrolled identity. Legacy keys remain available for historical grants.
public enum WrappedDeviceKeychain {
    private static func query(scope: String, member: UUID) throws -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecUseDataProtectionKeychain as String: true,
         kSecAttrSynchronizable as String: false,
         kSecAttrAccessGroup as String: try SigningIdentity.accessGroup(),
         kSecAttrService as String: "mop.wrapped-device.v1." + Codec.digest(Data(scope.utf8)),
         kSecAttrAccount as String: member.uuidString]
    }
    private static func read(scope: String, member: UUID, context: LAContext) throws -> WrappedDevice.Representation? {
        var request = try query(scope: scope, member: member)
        request[kSecUseAuthenticationContext as String] = context
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &value)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw MopError.keychain(status) }
        guard let bytes = value as? Data, bytes.count <= 64 * 1024 else { throw MopError.invalidIdentity }
        let result = try JSONDecoder().decode(WrappedDevice.Representation.self, from: bytes)
        guard result.version == 1, result.scope == scope, result.identity.member == member else { throw MopError.invalidIdentity }
        try result.identity.validate()
        return result
    }
    public static func publicIdentity(scope: String, member: UUID) throws -> DevicePublicKey? {
        let context = LAContext(); context.interactionNotAllowed = true
        defer { context.invalidate() }
        return try read(scope: scope, member: member, context: context)?.identity
    }
    public static func open(scope: String, member: UUID, context: LAContext, create: Bool = false) throws -> WrappedDevice {
        if let existing = try read(scope: scope, member: member, context: context) {
            return try WrappedDevice.open(existing, scope: scope, member: member, context: context)
        }
        guard create else { throw MopError.invalidIdentity }
        let (candidate, representation) = try WrappedDevice.create(member: member, scope: scope, context: context)
        var insert = try query(scope: scope, member: member)
        insert[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        insert[kSecValueData as String] = try Codec.encode(representation)
        let status = SecItemAdd(insert as CFDictionary, nil)
        if status == errSecSuccess { return candidate }
        candidate.close()
        if status == errSecDuplicateItem, let existing = try read(scope: scope, member: member, context: context) {
            return try WrappedDevice.open(existing, scope: scope, member: member, context: context)
        }
        throw MopError.keychain(status)
    }
    public static func remove(scope: String, member: UUID) throws {
        let status = SecItemDelete(try query(scope: scope, member: member) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw MopError.keychain(status) }
    }
}
