import Foundation
import Security
import MopCore

/// Immutable identity items. Never update or delete an identity during retries:
/// both operations propagate to every device through iCloud Keychain.
public protocol IdentityKeyStore {
    func read(scope: String, id: UUID) throws -> Data?
    func insert(_ material: Data, scope: String, id: UUID) throws
}
public struct SynchronizedIdentityStore: IdentityKeyStore {
    public init() {}
    static func query(scope: String, id: UUID, group: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecUseDataProtectionKeychain as String: true,
         kSecAttrSynchronizable as String: true,
         kSecAttrAccessGroup as String: group,
         kSecAttrService as String: "mop.user-identity.v1." + scope,
         kSecAttrAccount as String: id.uuidString]
    }
    public func read(scope: String, id: UUID) throws -> Data? {
        var query = Self.query(scope: scope, id: id, group: try SigningIdentity.accessGroup())
        query[kSecReturnData as String] = true; query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        try KeychainStore.check(status)
        guard let data = result as? Data, data.count == 64 else { throw MopError.invalidIdentity }
        return data
    }
    public func insert(_ material: Data, scope: String, id: UUID) throws {
        guard material.count == 64 else { throw MopError.invalidIdentity }
        var query = Self.query(scope: scope, id: id, group: try SigningIdentity.accessGroup())
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
        query[kSecValueData as String] = material
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            guard try read(scope: scope, id: id) == material else { throw MopError.invalidIdentity }
            return
        }
        try KeychainStore.check(status)
    }
}
