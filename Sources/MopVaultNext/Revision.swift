import CryptoKit
import Foundation
import MopCore

struct SealedObject: Codable, Equatable, Sendable {
    let ciphertext: Data
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
        return try AES.GCM.open(AES.GCM.SealedBox(combined: ciphertext), using: key, authenticating: aad)
    }
}

public enum RevisionOperation: String, Codable, Sendable { case create, content, membership, recovery }

struct CatalogPayload: Codable {
    var references: [String: String]
    var items: [VaultItem]
}

struct Revision: Codable, Sendable {
    struct Header: Codable, Equatable, Sendable {
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
    let records: [String: SealedObject]
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
        guard header.format == "mop-vault-v6", header.generation > 0, header.epoch > 0,
              (header.generation == 1) == (header.parent == nil),
              (header.generation == 1) == (header.operation == .create),
              header.epoch <= header.generation,
              header.parent.map(Codec.hash) ?? true,
              records.count <= 4096, signature.count == 64, Codec.hash(author),
              header.acceptedInvitations.count <= 4096,
              Set(header.acceptedInvitations).count == header.acceptedInvitations.count,
              header.acceptedInvitations == header.acceptedInvitations.sorted(by: { $0.uuidString < $1.uuidString }) else { throw MopError.invalidVault }
        try VaultName.validate(header.name)
        try header.membership.validate()
        let recipients = Set(header.membership.recipients.map(\.fingerprint))
        for object in [catalog] + Array(records.values) {
            guard object.ciphertext.count >= 28, Set(object.envelopes.keys) == recipients,
                  object.envelopes.values.allSatisfy({ $0.encapsulatedKey.count == 65 && $0.ciphertext.count == 48 }) else { throw MopError.invalidVault }
        }
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
    let revision: Revision
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
    init(revision: Revision, bytes: Data) { self.revision = revision; self.bytes = bytes }
}
