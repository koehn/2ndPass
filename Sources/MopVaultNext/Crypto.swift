import CryptoKit
import Foundation
import MopCore

enum Codec {
    static let maximumSize = 16 * 1024 * 1024
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
    static func hash(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}

public struct KeyEnvelope: Codable, Equatable, Sendable {
    public let encapsulatedKey: Data
    public let ciphertext: Data

    static func seal(_ key: SymmetricKey, to publicKey: Data, context: Data) throws -> Self {
        var sender = try HPKE.Sender(recipientKey: P256.KeyAgreement.PublicKey(x963Representation: publicKey),
                                     ciphersuite: .P256_SHA256_AES_GCM_256, info: context)
        let ciphertext = try key.withUnsafeBytes { try sender.seal($0) }
        return Self(encapsulatedKey: sender.encapsulatedKey, ciphertext: ciphertext)
    }
    // Apple's HPKE protocol supports Enclave device keys and the scoped offline recovery key.
    func open<K: HPKEDiffieHellmanPrivateKey>(using key: K, context: Data) throws -> SymmetricKey {
        guard encapsulatedKey.count == 65, ciphertext.count == 48 else { throw MopError.invalidVault }
        var recipient = try HPKE.Recipient(privateKey: key, ciphersuite: .P256_SHA256_AES_GCM_256,
                                           info: context, encapsulatedKey: encapsulatedKey)
        var bytes = try recipient.open(ciphertext)
        defer { SecretBytes.wipe(&bytes) }
        guard bytes.count == 32 else { throw MopError.invalidVault }
        return SymmetricKey(data: bytes)
    }
}

struct EnvelopeContext: Encodable {
    let domain = "mop-v7-hpke-key"
    let vault: UUID
    let epoch: UInt64
    let recipient: String
    let object: String
}
struct ObjectContext: Encodable {
    let domain = "mop-v7-aes-object"
    let vault: UUID
    let object: String
}
