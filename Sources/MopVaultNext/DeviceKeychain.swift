import Foundation
import LocalAuthentication
import Security
import MopCore
import MopKeychain

/// Disjoint from v5 synchronized identities. Never reads, updates, or deletes them.
public enum DeviceKeychain {
    public static func remove(scope: String, member: UUID) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
            kSecAttrAccessGroup as String: try SigningIdentity.accessGroup(),
            kSecAttrService as String: "mop.device-identity.v7." + Codec.digest(Data(scope.utf8)),
            kSecAttrAccount as String: member.uuidString
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw MopError.keychain(status) }
    }
    public static func open(scope: String, member: UUID, context: LAContext, create: Bool = false) throws -> EnclaveDevice {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
            kSecAttrAccessGroup as String: try SigningIdentity.accessGroup(),
            kSecAttrService as String: "mop.device-identity.v7." + Codec.digest(Data(scope.utf8)),
            kSecAttrAccount as String: member.uuidString
        ]
        func read() throws -> EnclaveDevice? {
            var request = query
            request[kSecUseAuthenticationContext as String] = context
            request[kSecReturnData as String] = true
            request[kSecMatchLimit as String] = kSecMatchLimitOne
            var value: CFTypeRef?
            let status = SecItemCopyMatching(request as CFDictionary, &value)
            if status == errSecItemNotFound { return nil }
            guard status == errSecSuccess else { throw MopError.keychain(status) }
            guard let bytes = value as? Data, bytes.count <= 64 * 1024 else { throw MopError.invalidIdentity }
            let representation = try JSONDecoder().decode(EnclaveDevice.Representation.self, from: bytes)
            guard representation.identity.member == member else { throw MopError.invalidIdentity }
            return try EnclaveDevice(representation: representation, context: context)
        }
        if let existing = try read() { return existing }
        guard create else { throw MopError.invalidIdentity }
        let candidate = try EnclaveDevice(member: member, context: context)
        var insert = query
        insert[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        insert[kSecValueData as String] = try Codec.encode(candidate.representation())
        let status = SecItemAdd(insert as CFDictionary, nil)
        if status == errSecSuccess { return candidate }
        // The winning provider must retain the caller's live context. Releasing a
        // losing candidate must not invalidate it through the candidate's deinit.
        candidate.detachContextAndClose()
        if status == errSecDuplicateItem {
            guard let winner = try read() else { throw MopError.invalidIdentity }
            return winner
        }
        throw MopError.keychain(status)
    }
}
