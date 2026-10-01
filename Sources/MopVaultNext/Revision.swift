import CryptoKit
import Foundation
import MopCore

struct SealedObject: Codable, Equatable, Sendable {
    let ciphertext: Data
    var attachmentDigest: String? = nil
    var attachmentSize: Int? = nil
    var loadedCiphertext: Data? = nil
    var itemID: String? = nil
    enum CodingKeys: String, CodingKey { case ciphertext, envelopes, attachmentDigest, attachmentSize, itemID }
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
        return try open(using: key, authenticating: aad)
    }
    func open(using key: SymmetricKey, authenticating aad: Data) throws -> Data {
        let bytes: Data
        if let digest = attachmentDigest {
            guard let loaded = loadedCiphertext else { throw AttachmentFailure.unavailable }
            guard loaded.count == attachmentSize, Codec.digest(loaded) == digest else { throw MopError.invalidVault }
            bytes = loaded
        } else { bytes = ciphertext }
        return try AES.GCM.open(AES.GCM.SealedBox(combined: bytes), using: key, authenticating: aad)
    }
}

struct ItemKey: Codable, Equatable, Sendable {
    let generation: UInt64
    var envelopes: [String: KeyEnvelope]
    func unwrap(vault: UUID, item: String, device: any DeviceOperations) throws -> SymmetricKey {
        guard let envelope = envelopes[device.identity.fingerprint] else { throw MopError.notVaultMember }
        return try device.unwrap(envelope, context: Self.context(vault: vault, item: item, generation: generation, recipient: device.identity.fingerprint))
    }
    static func context(vault: UUID, item: String, generation: UInt64, recipient: String) throws -> Data {
        try Codec.encode(ItemEnvelopeContext(vault: vault, item: item, generation: generation, recipient: recipient))
    }
    static func wrap(_ key: SymmetricKey, vault: UUID, item: String, generation: UInt64, recipients: [DevicePublicKey]) throws -> Self {
        Self(generation: generation, envelopes: try Dictionary(uniqueKeysWithValues: recipients.map {
            ($0.fingerprint, try KeyEnvelope.seal(key, to: $0.encryption,
                context: context(vault: vault, item: item, generation: generation, recipient: $0.fingerprint)))
        }))
    }
}
struct ItemEnvelopeContext: Encodable {
    let domain = "mop-v7-item-key"
    let vault: UUID; let item: String; let generation: UInt64; let recipient: String
}
struct FieldContext: Encodable {
    let domain = "mop-v7-field"
    let vault: UUID; let item: String; let generation: UInt64; let field: String
}
extension SealedObject {
    static func field(_ bytes: Data, key: SymmetricKey, vault: UUID, item: String, generation: UInt64, id: String) throws -> Self {
        let aad = try Codec.encode(FieldContext(vault: vault, item: item, generation: generation, field: id))
        return Self(ciphertext: try AES.GCM.seal(bytes, using: key, authenticating: aad).combined!, itemID: item, envelopes: [:])
    }
}

public enum RevisionOperation: String, Codable, Sendable { case create, content, membership, recovery }

struct CatalogPayload: Codable {
    var references: [String: String]
    var items: [VaultItem]
    var itemIDs: [String: String]
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
    var itemKeys: [String: ItemKey] = [:]
    let author: String
    let signature: Data

    private struct Signed: Encodable {
        let domain = "mop-v7-signed-revision"
        let header: Header; let catalog: SealedObject; let records: [String: SealedObject]; let itemKeys: [String: ItemKey]; let author: String
    }
    private struct CatalogAAD: Encodable {
        let domain = "mop-v7-catalog"
        let header: Header; let recordsDigest: String; let itemKeys: [String: ItemKey]
    }
    static func aad(header: Header, records: [String: SealedObject], itemKeys: [String: ItemKey]) throws -> Data {
        try Codec.encode(CatalogAAD(header: header, recordsDigest: Codec.digest(Codec.encode(records)), itemKeys: itemKeys))
    }
    func message() throws -> Data { try Codec.encode(Signed(header: header, catalog: catalog, records: records, itemKeys: itemKeys, author: author)) }
    func encoded() throws -> Data {
        let bytes = try Codec.encode(self)
        guard bytes.count <= Codec.maximumSize else { throw MopError.invalidVault }
        return bytes
    }
    static func seal(header: Header, references: [String: String], records: [String: SealedObject], itemKeys: [String: ItemKey] = [:], items: [VaultItem] = [], signer: any DeviceOperations) throws -> Self {
        var header = header
        var records = records
        let used = Set(records.values.compactMap(\.itemID))
        let itemKeys = itemKeys.filter { used.contains($0.key) }
        for item in items {
            for field in item.fields where field.type == .attachment {
                guard let id = references[SecretReference.encode(item.name) + "/" + field.path], let record = records[id] else { throw MopError.invalidVault }
                if record.attachmentDigest == nil {
                    records[id] = SealedObject(ciphertext: Data(), attachmentDigest: Codec.digest(record.ciphertext),
                        attachmentSize: record.ciphertext.count, loadedCiphertext: record.ciphertext, itemID: record.itemID, envelopes: record.envelopes)
                }
            }
        }
        var features = Set(header.requiredFeatures ?? [])
        if header.membership.offlineRecovery != nil { features.insert("offline-recovery-1") }
        if records.count > 4096 || items.contains(where: \.requiresExtendedModel) { features.insert("item-model-1") }
        if items.contains(where: { $0.type == .document || $0.fields.contains(where: { $0.type == .attachment }) }) { features.insert("attachments-1") }
        if items.contains(where: { $0.fields.contains(where: { $0.type.isCompound }) }) { features.insert("compound-fields-1") }
        if records.values.contains(where: { $0.attachmentDigest != nil }) { features.insert("attachment-blobs-1") }
        header.requiredFeatures = features.isEmpty ? nil : features.sorted()
        var itemIDs: [String: String] = [:]
        for (path, id) in references {
            guard let item = records[id]?.itemID else { throw MopError.invalidVault }
            let name = try SecretReference(vault: header.name, relativePath: path).item
            guard itemIDs[name] == nil || itemIDs[name] == item else { throw MopError.invalidVault }
            itemIDs[name] = item
        }
        var plaintext = try Codec.encode(CatalogPayload(references: references, items: items, itemIDs: itemIDs))
        defer { SecretBytes.wipe(&plaintext) }
        let catalog = try SealedObject.seal(plaintext, vault: header.vault, epoch: header.epoch, object: "catalog",
                                          membership: header.membership, authenticating: aad(header: header, records: records, itemKeys: itemKeys))
        let author = signer.identity.fingerprint
        let signature = try signer.sign(Codec.encode(Signed(header: header, catalog: catalog, records: records, itemKeys: itemKeys, author: author)))
        let revision = Self(header: header, catalog: catalog, records: records, itemKeys: itemKeys, author: author, signature: signature)
        try revision.validateStructure()
        _ = try revision.encoded()
        return revision
    }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard bytes.count <= Codec.maximumSize else { throw MopError.invalidVault }
            struct FormatProbe: Decodable { struct Header: Decodable { let format: String }; let header: Header }
            if let probe = try? JSONDecoder().decode(FormatProbe.self, from: bytes), probe.header.format != "mop-vault-v7" { throw MopError.legacyVault }
            let value = try JSONDecoder().decode(Self.self, from: bytes)
            try value.validateStructure()
            // Reject alternate JSON encodings, duplicate keys, unknown properties,
            // and noncanonical signed representations at the format boundary.
            guard try value.encoded() == bytes else { throw MopError.invalidVault }
            return value
        } catch MopError.legacyVault { throw MopError.legacyVault } catch { throw MopError.invalidVault }
    }
    func validateStructure() throws {
        if let features = header.requiredFeatures {
            guard !features.isEmpty, features == Set(features).sorted(),
                  Set(features).isSubset(of: ["item-model-1", "attachments-1", "compound-fields-1", "attachment-blobs-1", "offline-recovery-1"]),
                  (!(features.contains("attachments-1") || features.contains("compound-fields-1")) || features.contains("item-model-1")) else { throw MopError.invalidVault }
        }
        guard header.membership.offlineRecovery == nil || header.requiredFeatures?.contains("offline-recovery-1") == true else { throw MopError.invalidVault }
        guard header.format == "mop-vault-v7", header.generation > 0, header.epoch > 0,
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
            guard (object.itemID == nil ? Set(object.envelopes.keys) == recipients : object.envelopes.isEmpty),
                  object.envelopes.values.allSatisfy({ $0.encapsulatedKey.count == 65 && $0.ciphertext.count == 48 }) else { throw MopError.invalidVault }
        }
        guard Set(records.values.compactMap(\.itemID)) == Set(itemKeys.keys),
              records.values.allSatisfy({ $0.itemID != nil }),
              itemKeys.allSatisfy({ id, key in UUID(uuidString: id)?.uuidString == id && key.generation > 0 &&
                  Set(key.envelopes.keys) == recipients && key.envelopes.values.allSatisfy { $0.encapsulatedKey.count == 65 && $0.ciphertext.count == 48 } }) else { throw MopError.invalidVault }
        guard catalog.itemID == nil, catalog.attachmentDigest == nil else { throw MopError.invalidVault }
        guard records.keys.allSatisfy({ UUID(uuidString: $0)?.uuidString == $0 }) else { throw MopError.invalidVault }
    }
    func verifyGenesis() throws {
        guard header.generation == 1, header.epoch == 1, header.parent == nil, header.operation == .create,
              header.acceptedInvitations.isEmpty, itemKeys.values.allSatisfy({ $0.generation == 1 }),
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
            for (id, key) in itemKeys {
                if let old = parent.itemKeys[id] { guard key == old else { throw MopError.invalidVault } }
                else { guard key.generation == 1 else { throw MopError.invalidVault } }
            }
            for (id, record) in records where parent.records[id] != nil {
                guard try Codec.encode(record) == Codec.encode(parent.records[id]!) else { throw MopError.invalidVault }
            }
        case .membership, .recovery:
            if header.operation == .membership {
                guard role == .owner, header.membership.owner == parent.header.membership.owner else { throw MopError.cloudPermission }
            } else {
                guard signer == parent.header.membership.offlineRecovery,
                      header.membership.offlineRecovery == parent.header.membership.offlineRecovery,
                      header.membership.owner == parent.header.membership.owner,
                      header.membership.removedDevices == parent.header.membership.removedDevices,
                      header.membership.accounts.count == parent.header.membership.accounts.count,
                      header.membership.devices.count <= parent.header.membership.devices.count + 1 else { throw MopError.cloudPermission }
                for old in parent.header.membership.accounts {
                    guard let updated = header.membership.accounts.first(where: { $0.id == old.id }),
                          updated.role == old.role,
                          old.devices.allSatisfy({ updated.devices.contains($0) }),
                          old.id == parent.header.membership.owner || updated == old else { throw MopError.cloudPermission }
                }
            }
            guard Set(header.membership.removedDevices ?? []).isSuperset(of: parent.header.membership.removedDevices ?? []) else { throw MopError.invalidVault }
            guard parent.header.epoch < UInt64.max, header.epoch == parent.header.epoch + 1,
                  Set(header.acceptedInvitations).isSuperset(of: parent.header.acceptedInvitations) else { throw MopError.invalidVault }
            let removed = Set(parent.header.membership.recipients.map(\.fingerprint)).subtracting(header.membership.recipients.map(\.fingerprint))
            guard Set(itemKeys.keys) == Set(parent.itemKeys.keys) else { throw MopError.invalidVault }
            if !removed.isEmpty || header.operation == .recovery {
                for (id, key) in itemKeys {
                    guard let old = parent.itemKeys[id], old.generation < UInt64.max, key.generation == old.generation + 1 else { throw MopError.invalidVault }
                }
                // Fresh object IDs prevent accidentally publishing old ciphertext
                // in a removal. Fresh keys remain the honest writer's obligation.
                guard Set(records.keys).isDisjoint(with: parent.records.keys), records.count == parent.records.count else { throw MopError.invalidVault }
            } else {
                guard try Codec.encode(records) == Codec.encode(parent.records) else { throw MopError.invalidVault }
                for (id, key) in itemKeys {
                    guard let old = parent.itemKeys[id], key.generation == old.generation,
                          old.envelopes.allSatisfy({ key.envelopes[$0.key] == $0.value }) else { throw MopError.invalidVault }
                }
            }
        }
    }
    func references(device: any DeviceOperations) throws -> [String: String] { try payload(device: device).references }
    func payload(device: any DeviceOperations) throws -> CatalogPayload {
        var bytes = try catalog.open(vault: header.vault, epoch: header.epoch, object: "catalog", device: device,
                                     authenticating: Self.aad(header: header, records: records, itemKeys: itemKeys))
        defer { SecretBytes.wipe(&bytes) }
        let payload = try JSONDecoder().decode(CatalogPayload.self, from: bytes)
        let references = payload.references
        var itemNames: [String: String] = [:], itemIDs: [String: String] = [:]
        for (path, recordID) in references {
            let name = try SecretReference(vault: header.name, relativePath: path).item
            guard let id = records[recordID]?.itemID,
                  itemNames[id] == nil || itemNames[id] == name,
                  itemIDs[name] == nil || itemIDs[name] == id else { throw MopError.invalidVault }
            itemNames[id] = name; itemIDs[name] = id
        }
        guard itemIDs == payload.itemIDs else { throw MopError.invalidVault }
        guard Set(references.values).count == references.count, Set(references.values) == Set(records.keys),
              references.keys.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 4096 }) else { throw MopError.invalidVault }
        guard Set(payload.items.map(\.name)).count == payload.items.count,
              payload.items.allSatisfy({ $0.fields.allSatisfy { !$0.type.concealed || $0.value == nil } }) else { throw MopError.invalidVault }
        for item in payload.items {
            guard !item.fields.isEmpty, Set(item.fields.map(\.path)).count == item.fields.count else { throw MopError.invalidVault }
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
