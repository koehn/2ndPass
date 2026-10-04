import Foundation
import Security
import MopCore
import MopKeychain
import MopVaultNext

/// ThisDeviceOnly, nonsynchronizing local trust. Cloud data cannot install or
/// replace an enrollment pin. A duplicate add always rereads the existing winner.
public struct KeychainItemVaultTrustStore: ItemVaultInventoryStore, ItemVaultMembershipTrustStore {
    private let accessGroup: String
    public init() throws { accessGroup = try SigningIdentity.accessGroup() }

    public func load(scope: ItemVaultSetupScope) throws -> ItemVaultSetupRecord? {
        var query = try baseQuery(scope)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainItemVaultTrustFailure.status(status) }
        guard let data = result as? Data, data.count <= 65_536 else { throw ItemVaultBootstrapFailure.invalidTrust }
        let record = try JSONDecoder().decode(ItemVaultSetupRecord.self, from: data)
        guard record.scope == scope else { throw ItemVaultBootstrapFailure.invalidTrust }
        return record
    }

    public func reserve(_ candidate: ItemVaultSetupRecord) throws -> ItemVaultSetupRecord {
        let data = try setupEncode(candidate)
        guard data.count <= 65_536 else { throw ItemVaultBootstrapFailure.invalidTrust }
        var query = try baseQuery(candidate.scope)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecSuccess { return candidate }
        guard status == errSecDuplicateItem else { throw KeychainItemVaultTrustFailure.status(status) }
        guard let stored = try load(scope: candidate.scope) else { throw ItemVaultBootstrapFailure.missingSetup }
        return stored
    }

    public func records(container: String, environment: String, account: String) throws -> [ItemVaultSetupRecord] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrService as String: "mop.item-vault-setup.v1",
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw KeychainItemVaultTrustFailure.status(status) }
        guard let values = result as? [Data] else { throw ItemVaultBootstrapFailure.invalidTrust }
        return try values.map { bytes in
            guard bytes.count <= 65_536 else { throw ItemVaultBootstrapFailure.invalidTrust }
            return try JSONDecoder().decode(ItemVaultSetupRecord.self, from: bytes)
        }.filter { $0.scope.container == container && $0.scope.environment == environment && $0.scope.binding.account == account }
    }

    private struct MembershipCheckpoint: Codable {
        let scope: ItemVaultSetupScope
        let generation: UInt64
        let bytes: Data
    }
    public func membershipHistory(scope: ItemVaultSetupScope) throws -> [Data] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrService as String: "mop.item-vault-membership.v1",
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw KeychainItemVaultTrustFailure.status(status) }
        guard let values = result as? [Data] else { throw ItemVaultBootstrapFailure.invalidTrust }
        let slots = try values.map { bytes -> MembershipCheckpoint in
            guard bytes.count <= 262_144 else { throw ItemVaultBootstrapFailure.invalidTrust }
            return try JSONDecoder().decode(MembershipCheckpoint.self, from: bytes)
        }.filter { $0.scope == scope }.sorted { $0.generation < $1.generation }
        guard slots.count <= 127, slots.enumerated().allSatisfy({ $0.element.generation == UInt64($0.offset + 2) }),
              let record = try load(scope: scope) else { throw ItemVaultBootstrapFailure.invalidTrust }
        let bytes = slots.map(\.bytes)
        _ = try ItemVaultMembershipAuthority.history(record: record, successors: bytes)
        return bytes
    }
    public func reserveMembership(scope: ItemVaultSetupScope, successors: [Data]) throws {
        guard let record = try load(scope: scope) else { throw ItemVaultBootstrapFailure.missingSetup }
        _ = try ItemVaultMembershipAuthority.history(record: record, successors: successors)
        let existing = try membershipHistory(scope: scope)
        guard existing.count <= successors.count,
              Array(successors.prefix(existing.count)) == existing else { throw ItemVaultBootstrapFailure.invalidTrust }
        for index in existing.count..<successors.count {
            let slot = MembershipCheckpoint(scope: scope, generation: UInt64(index + 2), bytes: successors[index])
            let data = try setupEncode(slot)
            guard data.count <= 262_144 else { throw ItemVaultBootstrapFailure.invalidTrust }
            var query = try baseQuery(scope)
            query[kSecAttrService as String] = "mop.item-vault-membership.v1"
            query[kSecAttrAccount as String] = try setupHash(setupEncode(scope)) + ":" + String(slot.generation)
            query[kSecValueData as String] = data
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let status = SecItemAdd(query as CFDictionary, nil)
            guard status == errSecSuccess || status == errSecDuplicateItem else { throw KeychainItemVaultTrustFailure.status(status) }
            if status == errSecDuplicateItem {
                let winner = try membershipHistory(scope: scope)
                guard winner.count > index, winner[index] == successors[index] else { throw ItemVaultBootstrapFailure.invalidTrust }
            }
        }
    }

    private func baseQuery(_ scope: ItemVaultSetupScope) throws -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecUseDataProtectionKeychain as String: true,
         kSecAttrSynchronizable as String: false,
         kSecAttrAccessGroup as String: accessGroup,
         kSecAttrService as String: "mop.item-vault-setup.v1",
         kSecAttrAccount as String: try setupHash(setupEncode(scope))]
    }
}

public enum KeychainItemVaultTrustFailure: Error, Equatable, Sendable {
    case status(OSStatus)
}
