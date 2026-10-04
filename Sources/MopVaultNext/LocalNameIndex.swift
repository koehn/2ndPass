import CryptoKit
import Foundation
import MopCore

/// Disposable, device-authenticated local lookup acceleration. Never synchronized
/// and never authoritative without an exact comparison to the local item versions.
public struct LocalNameIndex: Codable, Sendable {
    public struct Entry: Codable, Sendable {
        public let version: UUID
        public let name: String
        public let deleted: Bool
        public init(version: UUID, name: String, deleted: Bool) {
            self.version = version; self.name = name; self.deleted = deleted
        }
    }
    public let entries: [UUID: Entry]
    public init(entries: [UUID: Entry]) { self.entries = entries }

    private struct Envelope: Codable {
        let context: Data
        let recipient: String
        let ciphertext: Data
        let wrappedKey: KeyEnvelope
        let signature: Data
    }
    private struct Statement: Encodable {
        let domain = "2ndpass-local-name-index-1"
        let context: Data
        let recipient: String
        let ciphertext: Data
        let wrappedKey: KeyEnvelope
    }
    private struct AssociatedData: Encodable {
        let domain = "2ndpass-local-name-index-content-1"
        let context: Data
        let recipient: String
    }
    public func sealed(context: Data, device: any DeviceOperations) throws -> Data {
        let recipient = device.identity.fingerprint
        let associated = try Codec.encode(AssociatedData(context: context, recipient: recipient))
        let key = SymmetricKey(size: .bits256)
        var plaintext = try Codec.encode(self)
        defer { SecretBytes.wipe(&plaintext) }
        guard plaintext.count <= Codec.maximumSize else { throw MopError.invalidVault }
        let ciphertext = try AES.GCM.seal(plaintext, using: key, authenticating: associated).combined!
        let wrapped = try KeyEnvelope.seal(key, to: device.identity.encryption, context: associated)
        let statement = Statement(context: context, recipient: recipient, ciphertext: ciphertext, wrappedKey: wrapped)
        return try Codec.encode(Envelope(context: context, recipient: recipient, ciphertext: ciphertext,
            wrappedKey: wrapped, signature: device.sign(Codec.encode(statement))))
    }
    public static func open(_ bytes: Data, context: Data, device: any DeviceOperations) throws -> Self {
        guard bytes.count <= Codec.maximumSize * 2 else { throw MopError.invalidVault }
        let value = try JSONDecoder().decode(Envelope.self, from: bytes)
        let statement = Statement(context: value.context, recipient: value.recipient,
            ciphertext: value.ciphertext, wrappedKey: value.wrappedKey)
        guard value.context == context, value.recipient == device.identity.fingerprint,
              device.identity.verifies(value.signature, message: try Codec.encode(statement)) else { throw MopError.vaultUntrusted }
        let associated = try Codec.encode(AssociatedData(context: context, recipient: value.recipient))
        let key = try device.unwrap(value.wrappedKey, context: associated)
        var plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: value.ciphertext), using: key, authenticating: associated)
        defer { SecretBytes.wipe(&plaintext) }
        return try JSONDecoder().decode(Self.self, from: plaintext)
    }
}
