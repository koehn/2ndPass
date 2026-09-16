import Foundation
import LocalAuthentication
import Security
import MopCore
import MopAuth

public final class KeychainStore: SecretStore {
    public static let servicePrefix = "mop.v1/"
    private let accessGroup: String
    private let context: LAContext
    private var closed = false

    /// Intended for an already authenticated context; OS access controls are still
    /// enforced if a caller supplies an unauthenticated context (integration tests).
    public init(accessGroup: String, context: LAContext) {
        self.accessGroup = accessGroup
        self.context = context
    }

    public static func open() throws -> KeychainStore {
        let group = try SigningIdentity.accessGroup()
        return KeychainStore(accessGroup: group, context: try Authentication.authorize())
    }

    public static func service(for reference: SecretReference) -> String {
        servicePrefix + [reference.vault, reference.item].map(SecretReference.encode).joined(separator: "/")
    }

    private func query(_ reference: SecretReference? = nil) throws -> [String: Any] {
        guard !closed else { throw MopError.authentication }
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseAuthenticationContext as String: context,
        ]
        if let reference {
            // The historical backend has no section column. Fail before an OS
            // operation rather than alias a sectioned field to a sectionless one.
            guard reference.section == nil else { throw MopError.invalidReference }
            query[kSecAttrService as String] = Self.service(for: reference)
            query[kSecAttrAccount as String] = reference.field
        }
        return query
    }

    public func read(_ reference: SecretReference) throws -> String {
        var query = try query(reference)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true
        var result: CFTypeRef?
        try Self.check(SecItemCopyMatching(query as CFDictionary, &result))
        guard let data = result as? Data, let value = String(data: data, encoding: .utf8) else {
            throw MopError.invalidUTF8
        }
        return value
    }

    public func write(_ reference: SecretReference, value: String, replace: Bool) throws {
        var query = try query(reference)
        if replace {
            // Reading first requires the existing item's OS access control, too.
            _ = try read(reference)
            try Self.check(SecItemUpdate(query as CFDictionary, [kSecValueData as String: Data(value.utf8)] as CFDictionary))
        } else {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, &error
            ) else {
                _ = error?.takeRetainedValue()
                throw MopError.keychain(errSecParam)
            }
            query[kSecAttrAccessControl as String] = access
            query[kSecValueData as String] = Data(value.utf8)
            try Self.check(SecItemAdd(query as CFDictionary, nil))
        }
    }

    public func list(vault: String?) throws -> [SecretReference] {
        var query = try query()
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        query[kSecReturnAttributes as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        try Self.check(status)
        guard let rows = result as? [[String: Any]] else { throw MopError.keychain(errSecDecode) }
        return rows.compactMap { row in
            guard let service = row[kSecAttrService as String] as? String,
                  service.hasPrefix(Self.servicePrefix),
                  let field = row[kSecAttrAccount as String] as? String,
                  let reference = try? SecretReference("mop://" + service.dropFirst(Self.servicePrefix.count) + "/" + SecretReference.encode(field)),
                  vault == nil || reference.vault == vault else { return nil }
            return reference
        }.sorted()
    }

    public func delete(_ reference: SecretReference) throws {
        // The OS does not necessarily authenticate deletion; require a protected
        // read first as well as the command's explicit LocalAuthentication check.
        _ = try read(reference)
        try Self.check(SecItemDelete(try query(reference) as CFDictionary))
    }

    public func close() {
        closed = true
        context.invalidate()
    }

    deinit { context.invalidate() }

    public static func check(_ status: OSStatus) throws {
        switch status {
        case errSecSuccess: return
        case errSecItemNotFound: throw MopError.notFound
        case errSecDuplicateItem: throw MopError.duplicate
        case errSecAuthFailed, errSecUserCanceled, errSecInteractionNotAllowed: throw MopError.authentication
        case errSecMissingEntitlement: throw MopError.signing
        default: throw MopError.keychain(status)
        }
    }
}
