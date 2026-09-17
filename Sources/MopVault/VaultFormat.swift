import CryptoKit
import Foundation
import MopCore

public enum VaultCoding {
    public static let maximumFileSize = 16 * 1024 * 1024

    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }

    public static func digest(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
}

public struct DeviceRequest: Codable, Equatable, Sendable {
    public let format: String
    public let name: String
    public let publicKey: Data
    public var fingerprint: String { VaultCoding.digest(publicKey) }

    public init(name: String, publicKey: Data) throws {
        self.format = "mop-device-request-v1"
        self.name = name
        self.publicKey = publicKey
        try validate()
    }

    public func validate() throws {
        guard format == "mop-device-request-v1", !name.isEmpty, name.utf8.count <= 128,
              !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              publicKey.count == 65, (try? P256.KeyAgreement.PublicKey(x963Representation: publicKey)) != nil else {
            throw MopError.invalidDevice
        }
    }
}

public struct VaultRecipient: Codable, Equatable, Sendable {
    public let kind: String
    public let name: String
    public let publicKey: Data
    public let encapsulatedKey: Data
    public let wrappedKey: Data
    public var purpose: String = "index"
    public var fingerprint: String { VaultCoding.digest(publicKey) }
}

public struct VaultHeader: Codable, Equatable, Sendable {
    public var format: String
    public let vaultID: UUID
    public var generation: UInt64
    public var parent: String?
    public var recipients: [VaultRecipient]
}

public struct VaultDocument: Codable, Sendable {
    public var header: VaultHeader
    public var sealed: Data
    public var records: [String: VaultRecord] = [:]

    public static func decode(_ bytes: Data) throws -> VaultDocument {
        do {
            guard bytes.count <= VaultCoding.maximumFileSize else { throw MopError.invalidVault }
            let document = try JSONDecoder().decode(Self.self, from: bytes)
            guard document.header.format == "mop-vault-v3", document.header.generation > 0,
                  document.header.recipients.count <= 64,
                  document.header.recipients.filter({ $0.kind == "recovery" }).count == 1,
                  document.header.recipients.contains(where: { $0.kind == "device" }),
                  Set(document.header.recipients.map(\.fingerprint)).count == document.header.recipients.count,
                  document.sealed.count >= 28 else { throw MopError.invalidVault }
            for slot in document.header.recipients {
                guard ["device", "recovery"].contains(slot.kind), slot.encapsulatedKey.count == 65,
                      slot.wrappedKey.count == 48, slot.purpose == "index" else { throw MopError.invalidVault }
                _ = try DeviceRequest(name: slot.name, publicKey: slot.publicKey)
            }
            for (id, record) in document.records {
                guard UUID(uuidString: id)?.uuidString == id, record.sealed.count >= 28,
                      record.recipients.count == document.header.recipients.count else { throw MopError.invalidVault }
                for (slot, authorized) in zip(record.recipients, document.header.recipients) {
                    guard slot.kind == authorized.kind, slot.name == authorized.name,
                          slot.publicKey == authorized.publicKey, slot.purpose == "record:" + id,
                          slot.encapsulatedKey.count == 65, slot.wrappedKey.count == 48 else { throw MopError.invalidVault }
                }
            }
            if let parent = document.header.parent {
                guard parent.count == 64, parent.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else { throw MopError.invalidVault }
            }
            return document
        } catch { throw MopError.invalidVault }
    }

    public static func wrap(key: SymmetricKey, request: DeviceRequest, kind: String, vaultID: UUID, purpose: String = "index") throws -> VaultRecipient {
        try request.validate()
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: request.publicKey)
        var sender = try HPKE.Sender(recipientKey: publicKey, ciphersuite: .P256_SHA256_AES_GCM_256,
                                     info: info(vaultID: vaultID, fingerprint: request.fingerprint, kind: kind, purpose: purpose))
        let wrapped = try key.withUnsafeBytes { try sender.seal(Data($0)) }
        return VaultRecipient(kind: kind, name: request.name, publicKey: request.publicKey,
                              encapsulatedKey: sender.encapsulatedKey, wrappedKey: wrapped, purpose: purpose)
    }

    public static func info(vaultID: UUID, fingerprint: String, kind: String, purpose: String = "index") -> Data {
        Data("mop-hpke-p256-sha256-aes256gcm-v3:\(vaultID.uuidString):\(kind):\(fingerprint):\(purpose)".utf8)
    }

    public static func unwrap<K: HPKEDiffieHellmanPrivateKey>(_ slot: VaultRecipient, vaultID: UUID, privateKey: K) throws -> SymmetricKey {
        var recipient = try HPKE.Recipient(privateKey: privateKey, ciphersuite: .P256_SHA256_AES_GCM_256,
                                           info: info(vaultID: vaultID, fingerprint: slot.fingerprint, kind: slot.kind, purpose: slot.purpose),
                                           encapsulatedKey: slot.encapsulatedKey)
        let bytes = try recipient.open(slot.wrappedKey)
        guard bytes.count == 32 else { throw MopError.invalidVault }
        return SymmetricKey(data: bytes)
    }

    // Authenticate the entire record table, including wrapped keys, without opening values.
    private struct AssociatedData: Encodable {
        let header: VaultHeader
        let recordsDigest: String
    }

    private static func associatedData(header: VaultHeader, records: [String: VaultRecord]) throws -> Data {
        try VaultCoding.encode(AssociatedData(header: header, recordsDigest: VaultCoding.digest(VaultCoding.encode(records))))
    }

    public static func seal(header: VaultHeader, index: [String: String], records: [String: VaultRecord], key: SymmetricKey) throws -> VaultDocument {
        let box = try AES.GCM.seal(VaultCoding.encode(index), using: key,
                                  authenticating: associatedData(header: header, records: records))
        guard let combined = box.combined else { throw MopError.invalidVault }
        let document = VaultDocument(header: header, sealed: combined, records: records)
        // Apply identical size/structure limits to writes and reads.
        return try decode(VaultCoding.encode(document))
    }

    public func decryptIndex(key: SymmetricKey) throws -> [String: String] {
        do {
            let plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: key,
                                             authenticating: Self.associatedData(header: header, records: records))
            let index = try JSONDecoder().decode([String: String].self, from: plaintext)
            guard Set(index.values).count == index.count, Set(index.values) == Set(records.keys) else { throw MopError.invalidVault }
            for reference in index.keys {
                guard try SecretReference(reference).description == reference else { throw MopError.invalidVault }
            }
            return index
        } catch { throw MopError.invalidVault }
    }
}

public struct VaultRecord: Codable, Equatable, Sendable {
    public var recipients: [VaultRecipient]
    public var sealed: Data

    private static func context(vaultID: UUID, id: String) -> Data {
        Data("mop-record-v3:\(vaultID.uuidString):\(id)".utf8)
    }

    public static func create(value: String, id: String, header: VaultHeader) throws -> VaultRecord {
        let key = SymmetricKey(size: .bits256)
        let recipients = try header.recipients.map {
            try VaultDocument.wrap(key: key, request: DeviceRequest(name: $0.name, publicKey: $0.publicKey),
                                   kind: $0.kind, vaultID: header.vaultID, purpose: "record:" + id)
        }
        let box = try AES.GCM.seal(Data(value.utf8), using: key, authenticating: context(vaultID: header.vaultID, id: id))
        guard let combined = box.combined else { throw MopError.invalidVault }
        return VaultRecord(recipients: recipients, sealed: combined)
    }

    public func key(id: String, vaultID: UUID, opener: any VaultKeyOpener) throws -> SymmetricKey {
        guard let slot = recipients.first(where: { $0.publicKey == opener.publicKey }),
              slot.purpose == "record:" + id else { throw MopError.invalidVault }
        return try opener.unwrap(slot, vaultID: vaultID)
    }

    public func read(id: String, vaultID: UUID, opener: any VaultKeyOpener) throws -> String {
        let key = try key(id: id, vaultID: vaultID, opener: opener)
        do {
            let bytes = try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: key,
                                         authenticating: Self.context(vaultID: vaultID, id: id))
            guard let value = String(data: bytes, encoding: .utf8) else { throw MopError.invalidVault }
            return value
        } catch { throw MopError.invalidVault }
    }

    public func enrolling(_ request: DeviceRequest, id: String, vaultID: UUID, opener: any VaultKeyOpener) throws -> VaultRecord {
        var record = self
        let key = try key(id: id, vaultID: vaultID, opener: opener)
        record.recipients.append(try VaultDocument.wrap(key: key, request: request, kind: "device", vaultID: vaultID, purpose: "record:" + id))
        record.recipients.sort { $0.fingerprint < $1.fingerprint }
        return record
    }
}
