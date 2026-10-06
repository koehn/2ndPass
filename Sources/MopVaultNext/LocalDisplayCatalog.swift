import CryptoKit
import Foundation
import MopCore

/// Device-local display acceleration, never cloud authority or item key material.
/// The key is held only by an authorized session; rows are independently AEAD sealed.
public struct LocalDisplayCatalogKey: Sendable {
    public let id: UUID
    private let key: SymmetricKey
    private let context: Data
    private struct Header: Codable {
        let domain: String
        let id: UUID
        let context: Data
        let recipient: String
        let wrappedKey: KeyEnvelope
    }
    private struct Envelope: Codable { let header: Header; let signature: Data }
    private struct RowContext: Encodable {
        let domain = "2ndpass-local-display-row-1"
        let keyID: UUID
        let context: Data
        let item: UUID
        let version: UUID
    }
    public static func create(context: Data, device: any DeviceOperations) throws -> (key: Self, envelope: Data) {
        let id = UUID(), key = SymmetricKey(size: .bits256)
        let header = Header(domain: "2ndpass-local-display-key-1", id: id, context: context,
            recipient: device.identity.fingerprint, wrappedKey: try KeyEnvelope.seal(key, to: device.identity.encryption, context: context))
        let envelope = try Codec.encode(Envelope(header: header, signature: device.sign(Codec.encode(header))))
        return (Self(id: id, key: key, context: context), envelope)
    }
    public static func open(_ bytes: Data, context: Data, device: any DeviceOperations) throws -> Self {
        guard bytes.count <= 64 * 1024 else { throw MopError.invalidVault }
        let envelope = try JSONDecoder().decode(Envelope.self, from: bytes), header = envelope.header
        guard header.domain == "2ndpass-local-display-key-1", header.context == context,
              header.recipient == device.identity.fingerprint,
              device.identity.verifies(envelope.signature, message: try Codec.encode(header)) else { throw MopError.vaultUntrusted }
        return Self(id: header.id, key: try device.unwrap(header.wrappedKey, context: context), context: context)
    }
    public func seal(_ bytes: Data, item: UUID, version: UUID) throws -> Data {
        guard bytes.count <= Codec.maximumSize else { throw MopError.invalidVault }
        let aad = try Codec.encode(RowContext(keyID: id, context: context, item: item, version: version))
        return try AES.GCM.seal(bytes, using: key, authenticating: aad).combined!
    }
    public func open(_ bytes: Data, item: UUID, version: UUID) throws -> Data {
        guard bytes.count <= Codec.maximumSize + 28 else { throw MopError.invalidVault }
        let aad = try Codec.encode(RowContext(keyID: id, context: context, item: item, version: version))
        return try AES.GCM.open(AES.GCM.SealedBox(combined: bytes), using: key, authenticating: aad)
    }
}
