import Foundation
import Security
import MopCore
import MopKeychain

/// A device-local hint for opening the last verified local account namespace.
/// It never authorizes CloudKit access, enrollment, or rebinding an outbox.
struct ItemCloudAccountCache: Sendable {
    struct Record: Codable {
        let container: String
        let environment: String
        let userRecordName: String
    }
    let container: String
    let environment: String
    private func query() throws -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecUseDataProtectionKeychain as String: true,
         kSecAttrSynchronizable as String: false,
         kSecAttrAccessGroup as String: try SigningIdentity.accessGroup(),
         kSecAttrService as String: "mop.item-last-account.v1",
         kSecAttrAccount as String: try setupHash(setupEncode([container, environment]))]
    }
    func load() throws -> Record? {
        var query = try query()
        query[kSecReturnData as String] = true; query[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainItemVaultTrustFailure.status(status) }
        guard let data = value as? Data, data.count <= 16_384 else { throw MopError.cloudAccount }
        let record = try JSONDecoder().decode(Record.self, from: data)
        guard record.container == container, record.environment == environment,
              !record.userRecordName.isEmpty else { throw MopError.cloudAccount }
        return record
    }
    func save(userRecordName: String) throws {
        let data = try setupEncode(Record(container: container, environment: environment, userRecordName: userRecordName))
        let base = try query()
        let status = SecItemUpdate(base as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw KeychainItemVaultTrustFailure.status(status) }
        var add = base
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let added = SecItemAdd(add as CFDictionary, nil)
        guard added == errSecSuccess else { throw KeychainItemVaultTrustFailure.status(added) }
    }
    func clear() { if let query = try? query() { SecItemDelete(query as CFDictionary) } }
}
