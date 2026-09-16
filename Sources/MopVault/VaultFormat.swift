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

    public static func decode(_ bytes: Data) throws -> VaultDocument {
        do {
            guard bytes.count <= VaultCoding.maximumFileSize else { throw MopError.invalidVault }
            let document = try JSONDecoder().decode(Self.self, from: bytes)
            guard ["mop-vault-v1", "mop-vault-v2"].contains(document.header.format), document.header.generation > 0,
                  document.header.recipients.count <= 64,
                  document.header.recipients.filter({ $0.kind == "recovery" }).count == 1,
                  document.header.recipients.contains(where: { $0.kind == "device" }),
                  Set(document.header.recipients.map(\.fingerprint)).count == document.header.recipients.count,
                  document.sealed.count >= 28 else { throw MopError.invalidVault }
            for slot in document.header.recipients {
                guard ["device", "recovery"].contains(slot.kind), slot.encapsulatedKey.count == 65,
                      slot.wrappedKey.count == 48 else { throw MopError.invalidVault }
                _ = try DeviceRequest(name: slot.name, publicKey: slot.publicKey)
            }
            if let parent = document.header.parent {
                guard parent.count == 64, parent.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else { throw MopError.invalidVault }
            }
            return document
        } catch { throw MopError.invalidVault }
    }

    public static func wrap(key: SymmetricKey, request: DeviceRequest, kind: String, vaultID: UUID) throws -> VaultRecipient {
        try request.validate()
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: request.publicKey)
        var sender = try HPKE.Sender(recipientKey: publicKey, ciphersuite: .P256_SHA256_AES_GCM_256,
                                     info: info(vaultID: vaultID, fingerprint: request.fingerprint, kind: kind))
        let wrapped = try key.withUnsafeBytes { try sender.seal(Data($0)) }
        return VaultRecipient(kind: kind, name: request.name, publicKey: request.publicKey,
                              encapsulatedKey: sender.encapsulatedKey, wrappedKey: wrapped)
    }

    public static func info(vaultID: UUID, fingerprint: String, kind: String) -> Data {
        Data("mop-hpke-p256-sha256-aes256gcm-v1:\(vaultID.uuidString):\(kind):\(fingerprint)".utf8)
    }

    public static func unwrap<K: HPKEDiffieHellmanPrivateKey>(_ slot: VaultRecipient, vaultID: UUID, privateKey: K) throws -> SymmetricKey {
        var recipient = try HPKE.Recipient(privateKey: privateKey, ciphersuite: .P256_SHA256_AES_GCM_256,
                                           info: info(vaultID: vaultID, fingerprint: slot.fingerprint, kind: slot.kind),
                                           encapsulatedKey: slot.encapsulatedKey)
        let bytes = try recipient.open(slot.wrappedKey)
        guard bytes.count == 32 else { throw MopError.invalidVault }
        return SymmetricKey(data: bytes)
    }

    public static func seal(header: VaultHeader, secrets: [String: String], key: SymmetricKey) throws -> VaultDocument {
        let plaintext = try VaultCoding.encode(secrets)
        guard plaintext.count < VaultCoding.maximumFileSize / 2 else { throw MopError.invalidVault }
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: VaultCoding.encode(header))
        guard let combined = box.combined else { throw MopError.invalidVault }
        return VaultDocument(header: header, sealed: combined)
    }

    public func decrypt(key: SymmetricKey) throws -> [String: String] {
        do {
            let plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: key,
                                             authenticating: VaultCoding.encode(header))
            let secrets = try JSONDecoder().decode([String: String].self, from: plaintext)
            for reference in secrets.keys {
                let parsed = try SecretReference(reference)
                guard parsed.description == reference, header.format != "mop-vault-v1" || parsed.section == nil else { throw MopError.invalidVault }
            }
            return secrets
        } catch { throw MopError.invalidVault }
    }
}
