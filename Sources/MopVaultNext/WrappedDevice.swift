import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Synchronization
import MopCore

/// Device-only enclave protection at rest; software keys exist only in an unlocked
/// owner. Closing synchronously revokes all operations. CryptoKit may retain copies
/// internally: releasing keys is not a claim of complete physical zeroization.
public final class WrappedDevice: DeviceOperations, @unchecked Sendable {
    public struct Representation: Codable, Sendable {
        public let version: Int
        public let identity: DevicePublicKey
        public let scope: String
        let wrappingKey: Data
        let encapsulatedKey: Data
        let ciphertext: Data
    }
    private struct Keys {
        let encryption: P256.KeyAgreement.PrivateKey
        let signing: P256.Signing.PrivateKey
    }
    private let keys: Mutex<Keys?>
    public let identity: DevicePublicKey

    private init(identity: DevicePublicKey, keys: Keys) {
        self.identity = identity; self.keys = Mutex(keys)
    }
    private static func info(scope: String, identity: DevicePublicKey) throws -> Data {
        struct Binding: Encodable {
            let domain = "2ndpass-wrapped-device-1"
            let scope: String
            let identity: DevicePublicKey
        }
        return try Codec.encode(Binding(scope: scope, identity: identity))
    }
    public static func create(member: UUID, scope: String, context: LAContext) throws -> (WrappedDevice, Representation) {
        guard SecureEnclave.isAvailable else { throw MopError.enclaveUnavailable }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence], &error) else { throw MopError.authentication }
        let wrapping = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access, authenticationContext: context)
        return try seal(member: member, scope: scope, wrappingPublicKey: wrapping.publicKey, representation: wrapping.dataRepresentation)
    }
    // Internal generic boundaries allow deterministic crypto tests; production
    // creation/unlock always requires Secure Enclave, without software fallback.
    static func seal(member: UUID, scope: String, wrappingPublicKey: P256.KeyAgreement.PublicKey,
                     representation: Data) throws -> (WrappedDevice, Representation) {
        guard !scope.isEmpty else { throw MopError.invalidIdentity }
        let keys = Keys(encryption: P256.KeyAgreement.PrivateKey(), signing: P256.Signing.PrivateKey())
        let identity = try DevicePublicKey(member: member, encryption: keys.encryption.publicKey.x963Representation,
                                          signing: keys.signing.publicKey.x963Representation)
        var bytes = keys.encryption.rawRepresentation + keys.signing.rawRepresentation
        defer { SecretBytes.wipe(&bytes) }
        var sender = try HPKE.Sender(recipientKey: wrappingPublicKey, ciphersuite: .P256_SHA256_AES_GCM_256,
                                     info: info(scope: scope, identity: identity))
        let ciphertext = try sender.seal(bytes)
        return (WrappedDevice(identity: identity, keys: keys), Representation(version: 1, identity: identity, scope: scope,
            wrappingKey: representation, encapsulatedKey: sender.encapsulatedKey, ciphertext: ciphertext))
    }
    public static func open(_ representation: Representation, scope: String, member: UUID, context: LAContext) throws -> WrappedDevice {
        guard SecureEnclave.isAvailable else { throw MopError.enclaveUnavailable }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: representation.wrappingKey, authenticationContext: context)
        return try open(representation, scope: scope, member: member, using: key)
    }
    static func open<K: HPKEDiffieHellmanPrivateKey>(_ representation: Representation, scope: String,
                                                  member: UUID, using key: K) throws -> WrappedDevice {
        guard representation.version == 1, representation.scope == scope, representation.identity.member == member,
              representation.encapsulatedKey.count == 65, representation.ciphertext.count == 80 else { throw MopError.invalidIdentity }
        try representation.identity.validate()
        var recipient = try HPKE.Recipient(privateKey: key, ciphersuite: .P256_SHA256_AES_GCM_256,
            info: info(scope: scope, identity: representation.identity), encapsulatedKey: representation.encapsulatedKey)
        var bytes = try recipient.open(representation.ciphertext)
        defer { SecretBytes.wipe(&bytes) }
        guard bytes.count == 64 else { throw MopError.invalidIdentity }
        let keys = try Keys(encryption: P256.KeyAgreement.PrivateKey(rawRepresentation: bytes.prefix(32)),
                            signing: P256.Signing.PrivateKey(rawRepresentation: bytes.suffix(32)))
        guard keys.encryption.publicKey.x963Representation == representation.identity.encryption,
              keys.signing.publicKey.x963Representation == representation.identity.signing else { throw MopError.invalidIdentity }
        return WrappedDevice(identity: representation.identity, keys: keys)
    }
    public func checkAuthorization() throws {
        try keys.withLock { guard $0 != nil else { throw MopError.authentication } }
    }
    public func sign(_ bytes: Data) throws -> Data {
        try keys.withLock { value in
            guard let value else { throw MopError.authentication }
            return try value.signing.signature(for: bytes).rawRepresentation
        }
    }
    public func unwrap(_ envelope: KeyEnvelope, context: Data) throws -> SymmetricKey {
        try keys.withLock { value in
            guard let value else { throw MopError.authentication }
            return try envelope.open(using: value.encryption, context: context)
        }
    }
    public func close() { keys.withLock { $0 = nil } }
    deinit { close() }
}
