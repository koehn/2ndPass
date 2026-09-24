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

public struct RecipientKey: Codable, Equatable, Sendable {
    public let format: String
    public let name: String
    public let publicKey: Data
    public var fingerprint: String { VaultCoding.digest(publicKey) }

    public init(name: String, publicKey: Data) throws {
        self.format = "mop-recipient-key-v1"
        self.name = name
        self.publicKey = publicKey
        try validate()
    }

    public func validate() throws {
        guard format == "mop-recipient-key-v1", !name.isEmpty, name.utf8.count <= 128,
              !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              publicKey.count == 65, (try? P256.KeyAgreement.PublicKey(x963Representation: publicKey)) != nil else {
            throw MopError.invalidIdentity
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
    public var name: String
    public var generation: UInt64
    public var parent: String?
    public var recipients: [VaultRecipient]
    public var membership: VaultMembership? = nil
}

struct VaultIndex: Codable {
    var references: [String: String]
    var items: [VaultItem]
}

public struct VaultDocument: Codable, Sendable {
    public var header: VaultHeader
    public var sealed: Data
    public var records: [String: VaultRecord] = [:]
    public var signature: Data? = nil
    public var signer: Data? = nil

    public static func decode(_ bytes: Data) throws -> VaultDocument {
        do {
            guard bytes.count <= VaultCoding.maximumFileSize else { throw MopError.invalidVault }
            struct Version: Decodable { struct Header: Decodable { let format: String }; let header: Header }
            if let version = try? JSONDecoder().decode(Version.self, from: bytes), ["mop-vault-v1", "mop-vault-v2", "mop-vault-v3", "mop-vault-v4"].contains(version.header.format) { throw MopError.legacyVault }
            let document = try JSONDecoder().decode(Self.self, from: bytes)
            try VaultName.validate(document.header.name)
            guard document.header.format == "mop-vault-v5", document.header.generation > 0,
                  document.header.recipients.count == 2,
                  document.header.recipients.filter({ $0.kind == "recovery" }).count == 1,
                  document.header.recipients.contains(where: { $0.kind == "member" }),
                  Set(document.header.recipients.map(\.fingerprint)).count == document.header.recipients.count,
                  document.sealed.count >= 28 else { throw MopError.invalidVault }
            guard let membership = document.header.membership else { throw MopError.invalidVault }
            try membership.validate(vaultID: document.header.vaultID)
            guard document.header.recipients.contains(where: { $0.publicKey == membership.owner.encryptionKey && $0.kind == "member" }) else { throw MopError.invalidVault }
            try document.verifySignature()
            for slot in document.header.recipients {
                guard ["member", "recovery"].contains(slot.kind), slot.encapsulatedKey.count == 65,
                      slot.wrappedKey.count == 48, slot.purpose == "index" else { throw MopError.invalidVault }
                _ = try RecipientKey(name: slot.name, publicKey: slot.publicKey)
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
        } catch MopError.legacyVault { throw MopError.legacyVault }
          catch { throw MopError.invalidVault }
    }

    public static func wrap(key: SymmetricKey, request: RecipientKey, kind: String, vaultID: UUID, purpose: String = "index") throws -> VaultRecipient {
        try request.validate()
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: request.publicKey)
        var sender = try HPKE.Sender(recipientKey: publicKey, ciphersuite: .P256_SHA256_AES_GCM_256,
                                     info: info(vaultID: vaultID, fingerprint: request.fingerprint, kind: kind, purpose: purpose))
        let wrapped = try key.withUnsafeBytes { try sender.seal($0) }
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
        var bytes = try recipient.open(slot.wrappedKey)
        defer { KeyMaterial.wipe(&bytes) }
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

    public static func seal(header: VaultHeader, index: [String: String], records: [String: VaultRecord], key: SymmetricKey, items: [VaultItem] = [], signer: (any VaultSigningOpener)? = nil) throws -> VaultDocument {
        let plaintext = try items.isEmpty ? VaultCoding.encode(index) : VaultCoding.encode(VaultIndex(references: index, items: items))
        let box = try AES.GCM.seal(plaintext, using: key,
                                  authenticating: associatedData(header: header, records: records))
        guard let combined = box.combined else { throw MopError.invalidVault }
        var document = VaultDocument(header: header, sealed: combined, records: records)
        if header.format == "mop-vault-v5" {
            guard let signer else { throw MopError.cloudPermission }
            document.signer = signer.signingPublicKey
            document.signature = try signer.sign(document.signingData())
        }
        // Apply identical size/structure limits to writes and reads.
        return try decode(VaultCoding.encode(document))
    }

    private struct SignedRevision: Encodable {
        let domain: String; let header: VaultHeader; let sealed: Data; let recordsDigest: String
    }
    private func signingData() throws -> Data {
        try VaultCoding.encode(SignedRevision(domain: "mop-vault-revision-v1", header: header, sealed: sealed,
                                             recordsDigest: VaultCoding.digest(VaultCoding.encode(records))))
    }
    private func verifySignature() throws {
        guard let signer, let signature, signature.count == 64,
              signer == header.membership?.owner.signingKey || header.recipients.contains(where: { $0.kind == "recovery" && $0.publicKey == signer }),
              let key = try? P256.Signing.PublicKey(x963Representation: signer),
              let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
              key.isValidSignature(sig, for: try signingData()) else { throw MopError.invalidVault }
    }

    public func decryptIndex(key: SymmetricKey) throws -> [String: String] {
        try decryptCatalog(key: key).references
    }

    func decryptCatalog(key: SymmetricKey) throws -> VaultIndex {
        do {
            let plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: key,
                                             authenticating: Self.associatedData(header: header, records: records))
            let catalog: VaultIndex
            if let legacy = try? JSONDecoder().decode([String: String].self, from: plaintext) {
                catalog = VaultIndex(references: legacy, items: [])
            } else { catalog = try JSONDecoder().decode(VaultIndex.self, from: plaintext) }
            let index = catalog.references
            guard Set(index.values).count == index.count, Set(index.values) == Set(records.keys) else { throw MopError.invalidVault }
            for reference in index.keys {
                guard try SecretReference(vault: header.name, relativePath: reference).relativePath == reference else { throw MopError.invalidVault }
            }
            guard Set(catalog.items.map(\.name)).count == catalog.items.count else { throw MopError.invalidVault }
            for item in catalog.items {
                if let deletion = item.deletion {
                    guard item.name == "mop-deleted-" + deletion.id.uuidString,
                          !deletion.originalName.isEmpty, deletion.deletedAt.timeIntervalSince1970.isFinite else { throw MopError.invalidVault }
                }
                guard !item.fields.isEmpty, Set(item.fields.map(\.path)).count == item.fields.count else { throw MopError.invalidVault }
                for field in item.fields {
                    let ref = try SecretReference(vault: header.name, relativePath: SecretReference.encode(item.name) + "/" + field.path)
                    guard ref.item == item.name, index[ref.relativePath] != nil,
                          field.type.concealed ? field.value == nil : field.value != nil else { throw MopError.invalidVault }
                }
            }
            return catalog
        } catch { throw MopError.invalidVault }
    }
}

public struct VaultRecord: Codable, Equatable, Sendable {
    public var recipients: [VaultRecipient]
    public var sealed: Data

    private static func context(vaultID: UUID, id: String) -> Data {
        Data("mop-record-v3:\(vaultID.uuidString):\(id)".utf8)
    }

    public static func create(value: SecretBytes, id: String, header: VaultHeader) throws -> VaultRecord {
        _ = try value.validatedUTF8()
        let key = SymmetricKey(size: .bits256)
        let recipients = try header.recipients.map {
            try VaultDocument.wrap(key: key, request: RecipientKey(name: $0.name, publicKey: $0.publicKey),
                                   kind: $0.kind, vaultID: header.vaultID, purpose: "record:" + id)
        }
        let box = try value.withUnsafeBytes { try AES.GCM.seal($0, using: key, authenticating: context(vaultID: header.vaultID, id: id)) }
        guard let combined = box.combined else { throw MopError.invalidVault }
        return VaultRecord(recipients: recipients, sealed: combined)
    }

    public func key(id: String, vaultID: UUID, opener: any VaultKeyOpener) throws -> SymmetricKey {
        guard let slot = recipients.first(where: { $0.publicKey == opener.publicKey }),
              slot.purpose == "record:" + id else { throw MopError.invalidVault }
        return try opener.unwrap(slot, vaultID: vaultID)
    }

    public func read(id: String, vaultID: UUID, opener: any VaultKeyOpener) throws -> SecretBytes {
        let key = try key(id: id, vaultID: vaultID, opener: opener)
        do {
            var bytes = try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: key,
                                         authenticating: Self.context(vaultID: vaultID, id: id))
            defer { SecretBytes.wipe(&bytes) }
            return try SecretBytes(copying: bytes).validatedUTF8()
        } catch { throw MopError.invalidVault }
    }


}
