import CryptoKit
import Foundation
import LocalAuthentication
import Security
import MopCore
import MopKeychain

/// Stores device-local, Secure Enclave-backed asymmetric identities.
///
/// Isolation: items live in the non-synchronizable, `WhenUnlockedThisDeviceOnly`
/// Data Protection Keychain under the app's private access group. They are never
/// written to CloudKit, iCloud, backups, or any synchronizable store. Only the
/// non-sensitive public key and metadata are persisted; the private key exists
/// solely as an opaque Secure Enclave handle that cannot be exported.
public final class LocalIdentityStore {
    public static var isAvailable: Bool { SecureEnclave.isAvailable }
    public static let service = "mop.local-identity.v1"

    private let accessGroup: String

    /// A persisted record: the non-sensitive identity plus the opaque Secure
    /// Enclave key handle. The handle is not the private key and cannot be used
    /// outside the Secure Enclave.
    struct Record: Codable {
        let version: Int
        let identity: LocalIdentity
        let opaqueKey: Data
    }

    /// Explicit access group (for tests and callers that already resolved one).
    public init(accessGroup: String) {
        self.accessGroup = accessGroup
    }

    /// Resolve the private app access group from the signed bundle.
    public static func open() throws -> LocalIdentityStore {
        LocalIdentityStore(accessGroup: try SigningIdentity.accessGroup())
    }

    // MARK: - Catalog

    public func list() throws -> [LocalIdentity] {
        var query = baseQuery()
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        query[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        try Self.check(status)
        guard let rows = result as? [Data] else { throw MopError.keychain(errSecDecode) }
        return try rows.map { try self.decode($0).identity }
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    public func read(id: UUID) throws -> LocalIdentity { try fetch(id).identity }

    public func publicKey(id: UUID) throws -> Data { try read(id: id).publicKey }

    // MARK: - Create

    /// Generate a new hardware identity for `protocolType` and persist it.
    /// Authorization must grant creation for exactly the requested purpose.
    public func create(name: String, protocolType: LocalIdentityProtocol, authorization: LocalAuthorization, metadata: LocalProtocolMetadata? = nil) throws -> LocalIdentity {
        guard SecureEnclave.isAvailable else { throw MopError.enclaveUnavailable }
        let algorithm: LocalIdentityAlgorithm = protocolType.isSigning ? .p256Signing : .p256KeyAgreement
        let validatedName = try LocalIdentity.validateName(name)
        // Reject duplicate names before generating a key we would have to abandon.
        let existing = try list()
        guard !existing.contains(where: { $0.name == validatedName }) else { throw MopError.duplicate }

        try authorization.begin(id: nil, purpose: protocolType, operation: .create)
        let accessControl = try makeAccessControl()
        let id = UUID()
        var publicKey: Data
        var opaque: Data
        switch algorithm {
        case .p256Signing:
            let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl, authenticationContext: authorization.context)
            publicKey = key.publicKey.x963Representation
            opaque = key.dataRepresentation
        case .p256KeyAgreement:
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl, authenticationContext: authorization.context)
            publicKey = key.publicKey.x963Representation
            opaque = key.dataRepresentation
        }

        let identity = try LocalIdentity(id: id, name: validatedName, algorithm: algorithm,
                                         protocolType: protocolType, publicKey: publicKey, metadata: metadata)
        let record = Record(version: 2, identity: identity, opaqueKey: opaque)
        var insert = baseQuery()
        insert[kSecAttrAccount as String] = identity.id.uuidString
        insert[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        insert[kSecValueData as String] = try Self.encode(record)
        try authorization.check()
        let status = SecItemAdd(insert as CFDictionary, nil)
        if status == errSecSuccess { try authorization.check(); return identity }
        if status == errSecDuplicateItem { throw MopError.duplicate }
        throw MopError.keychain(status)
    }

    // MARK: - Use

    /// Produce a DER-encoded ECDSA signature over `data` in the Secure Enclave.
    func sign(id: UUID, data: Data, authorization: LocalAuthorization, operation: LocalKeyOperation = .sign) throws -> Data {
        guard SecureEnclave.isAvailable else { throw MopError.enclaveUnavailable }
        let record = try fetch(id)
        guard record.identity.algorithm == .p256Signing else { throw MopError.localIdentityCapability }
        try authorization.begin(id: id, purpose: record.identity.protocolType, operation: operation)
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: record.opaqueKey, authenticationContext: authorization.context)
        let signature = try key.signature(for: data).derRepresentation
        try authorization.check()
        guard try fetch(id).opaqueKey == record.opaqueKey else { throw MopError.notFound }
        return signature
    }

    /// Perform Secure Enclave ECDH with `peerPublicKey` (x963) and return the
    /// shared secret. The private key never leaves the enclave.
    func deriveSharedSecret(id: UUID, peerPublicKey: Data, authorization: LocalAuthorization) throws -> SymmetricKey {
        guard SecureEnclave.isAvailable else { throw MopError.enclaveUnavailable }
        let record = try fetch(id)
        guard record.identity.algorithm == .p256KeyAgreement else { throw MopError.localIdentityCapability }
        guard let peer = try? P256.KeyAgreement.PublicKey(x963Representation: peerPublicKey) else {
            throw MopError.invalidLocalIdentity
        }
        try authorization.begin(id: id, purpose: record.identity.protocolType, operation: .keyAgreement)
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: record.opaqueKey, authenticationContext: authorization.context)
        let shared = try key.sharedSecretFromKeyAgreement(with: peer)
        var bytes = Data()
        shared.withUnsafeBytes { bytes.append(contentsOf: $0) }
        defer { SecretBytes.wipe(&bytes) }
        try authorization.check()
        _ = try fetch(id)
        return SymmetricKey(data: bytes)
    }

    // MARK: - Delete

    /// Delete an identity. The caller must authorize this destructive operation first;
    /// fetching the public catalog record does not authenticate the user.
    public func delete(id: UUID, authorization: LocalAuthorization) throws {
        let record = try fetch(id)
        try authorization.begin(id: id, purpose: record.identity.protocolType, operation: .delete)
        try authorization.check()
        var query = baseQuery()
        query[kSecAttrAccount as String] = id.uuidString
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecItemNotFound { return }
        try Self.check(status)
    }

    // MARK: - Plumbing

    func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrService as String: Self.service
        ]
    }

    private func makeAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &error
        ) else {
            _ = error?.takeRetainedValue()
            throw MopError.keychain(errSecParam)
        }
        return accessControl
    }

    func fetch(_ id: UUID) throws -> Record {
        var query = baseQuery()
        query[kSecAttrAccount as String] = id.uuidString
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { throw MopError.notFound }
        try Self.check(status)
        guard let bytes = result as? Data else { throw MopError.invalidLocalIdentity }
        return try decode(bytes)
    }

    private func decode(_ bytes: Data) throws -> Record {
        do {
            guard let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any], object["version"] as? Int == 2 else { throw MopError.unsupportedLocalIdentity }
            let record = try JSONDecoder().decode(Record.self, from: bytes)
            try record.identity.validate()
            return record
        } catch let error as MopError { throw error }
        catch { throw MopError.invalidLocalIdentity }
    }

    static func encode(_ record: Record) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(record)
    }

    static func check(_ status: OSStatus) throws {
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

