import CryptoKit
import Foundation
import MopCore

struct SealedObject: Codable, Equatable, Sendable {
    let ciphertext: Data
    var attachmentDigest: String? = nil
    var attachmentSize: Int? = nil
    var loadedCiphertext: Data? = nil
    enum CodingKeys: String, CodingKey { case ciphertext, envelopes, attachmentDigest, attachmentSize }
    let envelopes: [String: KeyEnvelope]
    func key(vault: UUID, epoch: UInt64, object: String, device: any DeviceOperations) throws -> SymmetricKey {
        let fingerprint = device.identity.fingerprint
        guard let envelope = envelopes[fingerprint] else { throw MopError.notVaultMember }
        return try device.unwrap(envelope, context: Codec.encode(EnvelopeContext(vault: vault, epoch: epoch, recipient: fingerprint, object: object)))
    }
    static func envelopes(key: SymmetricKey, vault: UUID, epoch: UInt64, object: String, membership: Membership) throws -> [String: KeyEnvelope] {
        try Dictionary(uniqueKeysWithValues: membership.recipients.map { recipient in
            (recipient.fingerprint, try KeyEnvelope.seal(key, to: recipient.encryption,
                context: Codec.encode(EnvelopeContext(vault: vault, epoch: epoch, recipient: recipient.fingerprint, object: object))))
        })
    }
    static func seal(_ plaintext: Data, vault: UUID, epoch: UInt64, object: String, membership: Membership,
                     authenticating aad: Data) throws -> Self {
        let key = SymmetricKey(size: .bits256)
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: aad)
        guard let ciphertext = box.combined else { throw MopError.invalidVault }
        return try Self(ciphertext: ciphertext, envelopes: envelopes(key: key, vault: vault, epoch: epoch, object: object, membership: membership))
    }
    func open(vault: UUID, epoch: UInt64, object: String, device: any DeviceOperations, authenticating aad: Data) throws -> Data {
        let key = try key(vault: vault, epoch: epoch, object: object, device: device)
        let bytes: Data
        if let digest = attachmentDigest {
            guard let loaded = loadedCiphertext else { throw AttachmentFailure.unavailable }
            guard loaded.count == attachmentSize, Codec.digest(loaded) == digest else { throw MopError.invalidVault }
            bytes = loaded
        } else { bytes = ciphertext }
        return try AES.GCM.open(AES.GCM.SealedBox(combined: bytes), using: key, authenticating: aad)
    }
}

public enum RevisionOperation: String, Codable, Sendable { case create, content, membership, recovery }

struct CatalogPayload: Codable {
    var references: [String: String]
    var items: [VaultItem]
}

struct Revision: Codable, Sendable {
    struct Header: Codable, Equatable, Sendable {
        var requiredFeatures: [String]? = nil
        let format: String
        let vault: UUID
        let name: String
        let generation: UInt64
        let parent: String?
        let epoch: UInt64
        let membership: Membership
        let operation: RevisionOperation
        // Nonces are consumed by the membership revision, not by a cloud request.
        let acceptedInvitations: [UUID]
    }
    let header: Header
    let catalog: SealedObject
    var records: [String: SealedObject]
    let author: String
    let signature: Data

    private struct Signed: Encodable {
        let domain = "mop-v6-signed-revision"
        let header: Header; let catalog: SealedObject; let records: [String: SealedObject]; let author: String
    }
    private struct CatalogAAD: Encodable {
        let domain = "mop-v6-catalog"
        let header: Header; let recordsDigest: String
    }
    static func aad(header: Header, records: [String: SealedObject]) throws -> Data {
        try Codec.encode(CatalogAAD(header: header, recordsDigest: Codec.digest(Codec.encode(records))))
    }
    func message() throws -> Data { try Codec.encode(Signed(header: header, catalog: catalog, records: records, author: author)) }
    func encoded() throws -> Data {
        let bytes = try Codec.encode(self)
        guard bytes.count <= Codec.maximumSize else { throw MopError.invalidVault }
        return bytes
    }
    static func seal(header: Header, references: [String: String], records: [String: SealedObject], items: [VaultItem] = [], signer: any DeviceOperations) throws -> Self {
        var header = header
        var records = records
        for item in items {
            for field in item.fields where field.type == .attachment {
                guard let id = references[SecretReference.encode(item.name) + "/" + field.path], let record = records[id] else { throw MopError.invalidVault }
                if record.attachmentDigest == nil {
                    records[id] = SealedObject(ciphertext: Data(), attachmentDigest: Codec.digest(record.ciphertext),
                        attachmentSize: record.ciphertext.count, loadedCiphertext: record.ciphertext, envelopes: record.envelopes)
                }
            }
        }
        var features = Set(header.requiredFeatures ?? [])
        if records.count > 4096 || items.contains(where: \.requiresExtendedModel) { features.insert("item-model-1") }
        if items.contains(where: { $0.type == .document || $0.fields.contains(where: { $0.type == .attachment }) }) { features.insert("attachments-1") }
        if items.contains(where: { $0.fields.contains(where: { $0.type.isCompound }) }) { features.insert("compound-fields-1") }
        if records.values.contains(where: { $0.attachmentDigest != nil }) { features.insert("attachment-blobs-1") }
        header.requiredFeatures = features.isEmpty ? nil : features.sorted()
        var plaintext = try Codec.encode(CatalogPayload(references: references, items: items))
        defer { SecretBytes.wipe(&plaintext) }
        let catalog = try SealedObject.seal(plaintext, vault: header.vault, epoch: header.epoch, object: "catalog",
                                          membership: header.membership, authenticating: aad(header: header, records: records))
        let author = signer.identity.fingerprint
        let signature = try signer.sign(Codec.encode(Signed(header: header, catalog: catalog, records: records, author: author)))
        let revision = Self(header: header, catalog: catalog, records: records, author: author, signature: signature)
        try revision.validateStructure()
        _ = try revision.encoded()
        return revision
    }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard bytes.count <= Codec.maximumSize else { throw MopError.invalidVault }
            let value = try JSONDecoder().decode(Self.self, from: bytes)
            try value.validateStructure()
            // Reject alternate JSON encodings, duplicate keys, unknown properties,
            // and noncanonical signed representations at the format boundary.
            guard try value.encoded() == bytes else { throw MopError.invalidVault }
            return value
        } catch { throw MopError.invalidVault }
    }
    func validateStructure() throws {
        if let features = header.requiredFeatures {
            guard !features.isEmpty, features == Set(features).sorted(),
                  Set(features).isSubset(of: ["item-model-1", "attachments-1", "compound-fields-1", "attachment-blobs-1"]),
                  (!(features.contains("attachments-1") || features.contains("compound-fields-1")) || features.contains("item-model-1")) else { throw MopError.invalidVault }
        }
        guard header.format == "mop-vault-v6", header.generation > 0, header.epoch > 0,
              (header.generation == 1) == (header.parent == nil),
              (header.generation == 1) == (header.operation == .create),
              header.epoch <= header.generation,
              header.parent.map(Codec.hash) ?? true,
              signature.count == 64, Codec.hash(author),
              header.acceptedInvitations.count <= 4096,
              Set(header.acceptedInvitations).count == header.acceptedInvitations.count,
              header.acceptedInvitations == header.acceptedInvitations.sorted(by: { $0.uuidString < $1.uuidString }) else { throw MopError.invalidVault }
        try VaultName.validate(header.name)
        try header.membership.validate()
        let recipients = Set(header.membership.recipients.map(\.fingerprint))
        for object in [catalog] + Array(records.values) {
            if let digest = object.attachmentDigest {
                guard header.requiredFeatures?.contains("attachment-blobs-1") == true, Codec.hash(digest),
                      object.ciphertext.isEmpty, let size = object.attachmentSize, size >= 28,
                      size <= Codec.maximumSize else { throw MopError.invalidVault }
            } else {
                guard object.ciphertext.count >= 28, object.attachmentSize == nil else { throw MopError.invalidVault }
            }
            guard Set(object.envelopes.keys) == recipients,
                  object.envelopes.values.allSatisfy({ $0.encapsulatedKey.count == 65 && $0.ciphertext.count == 48 }) else { throw MopError.invalidVault }
        }
        guard catalog.attachmentDigest == nil else { throw MopError.invalidVault }
        guard records.keys.allSatisfy({ UUID(uuidString: $0)?.uuidString == $0 }) else { throw MopError.invalidVault }
    }
    func verifyGenesis() throws {
        guard header.generation == 1, header.epoch == 1, header.parent == nil, header.operation == .create,
              header.acceptedInvitations.isEmpty,
              let signer = header.membership.key(author), header.membership.role(of: signer) == .owner,
              signer.verifies(signature, message: try message()) else { throw MopError.vaultUntrusted }
    }
    func verify(after parent: Revision) throws {
        guard header.vault == parent.header.vault,
              parent.header.generation < UInt64.max, header.generation == parent.header.generation + 1,
              header.parent == Codec.digest(try parent.encoded()),
              let signer = parent.header.membership.key(author),
              signer.verifies(signature, message: try message()) else { throw MopError.vaultUntrusted }
        guard Set(header.requiredFeatures ?? []).isSuperset(of: parent.header.requiredFeatures ?? []) else { throw MopError.invalidVault }
        let role = parent.header.membership.role(of: signer)
        switch header.operation {
        case .create: throw MopError.vaultUntrusted
        case .content:
            guard role == .owner || role == .editor,
                  header.membership == parent.header.membership, header.epoch == parent.header.epoch,
                  header.acceptedInvitations == parent.header.acceptedInvitations else { throw MopError.cloudPermission }
        case .membership, .recovery:
            if header.operation == .membership {
                guard role == .owner, header.membership.owner == parent.header.membership.owner else { throw MopError.cloudPermission }
            } else {
                guard signer == parent.header.membership.recovery,
                      header.membership.owner == parent.header.membership.owner else { throw MopError.cloudPermission }
            }
            guard Set(header.membership.removedDevices ?? []).isSuperset(of: parent.header.membership.removedDevices ?? []) else { throw MopError.invalidVault }
            guard parent.header.epoch < UInt64.max, header.epoch == parent.header.epoch + 1,
                  Set(header.acceptedInvitations).isSuperset(of: parent.header.acceptedInvitations) else { throw MopError.invalidVault }
            let removed = Set(parent.header.membership.recipients.map(\.fingerprint)).subtracting(header.membership.recipients.map(\.fingerprint))
            if !removed.isEmpty || header.operation == .recovery {
                // Fresh object IDs prevent accidentally publishing old ciphertext
                // in a removal. Fresh keys remain the honest writer's obligation.
                guard Set(records.keys).isDisjoint(with: parent.records.keys) else { throw MopError.invalidVault }
            }
        }
    }
    func references(device: any DeviceOperations) throws -> [String: String] { try payload(device: device).references }
    func payload(device: any DeviceOperations) throws -> CatalogPayload {
        var bytes = try catalog.open(vault: header.vault, epoch: header.epoch, object: "catalog", device: device,
                                     authenticating: Self.aad(header: header, records: records))
        defer { SecretBytes.wipe(&bytes) }
        let payload = try JSONDecoder().decode(CatalogPayload.self, from: bytes)
        let references = payload.references
        guard Set(references.values).count == references.count, Set(references.values) == Set(records.keys),
              references.keys.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 4096 }) else { throw MopError.invalidVault }
        guard Set(payload.items.map(\.name)).count == payload.items.count,
              payload.items.allSatisfy({ $0.fields.allSatisfy { !$0.type.concealed || $0.value == nil } }) else { throw MopError.invalidVault }
        for item in payload.items {
            guard Set(item.fields.map(\.path)).count == item.fields.count else { throw MopError.invalidVault }
            for field in item.fields {
                let path = SecretReference.encode(item.name) + "/" + field.path
                _ = try SecretReference(vault: header.name, relativePath: path)
                guard references[path] != nil else { throw MopError.invalidVault }
            }
        }
        return payload
    }
}

/// Constructed only from a independently trusted checkpoint or validated parent.
/// Callers persist a verified checkpoint atomically, separate from downloaded data.
public struct VerifiedVault: Sendable {
    public func acceptedEnrollment(_ nonce: UUID) -> Bool { revision.header.acceptedInvitations.contains(nonce) }
    var revision: Revision
    public let bytes: Data
    public var digest: String { Codec.digest(bytes) }
    public var id: UUID { revision.header.vault }
    public var name: String { revision.header.name }
    public var generation: UInt64 { revision.header.generation }
    public var membership: Membership { revision.header.membership }
    public var parent: String? { revision.header.parent }

    public init(checkpoint bytes: Data, independentlyVerifiedDigest: String) throws {
        guard Codec.hash(independentlyVerifiedDigest), Codec.digest(bytes) == independentlyVerifiedDigest else { throw MopError.vaultUntrusted }
        let revision = try Revision.decode(bytes)
        if revision.header.generation == 1 { try revision.verifyGenesis() }
        // A non-genesis checkpoint is trusted as an entire revision through its
        // independently authenticated digest. A self-declared signer is insufficient.
        self.revision = revision; self.bytes = bytes
    }
    public func applying(_ bytes: Data) throws -> Self {
        let next = try Revision.decode(bytes)
        try next.verify(after: revision)
        return Self(revision: next, bytes: bytes)
    }
    func applying(_ next: Revision) throws -> Self {
        let bytes = try next.encoded()
        _ = try applying(bytes)
        return Self(revision: next, bytes: bytes)
    }
    init(revision: Revision, bytes: Data) { self.revision = revision; self.bytes = bytes }
}
