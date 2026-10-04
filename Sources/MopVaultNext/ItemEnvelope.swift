import CryptoKit
import Foundation
import MopCore
import MopCredentials

/// Independently authenticated item ciphertext. Membership must come from a
/// separately authenticated security record, never from this item's author.
/// The required membershipStateDigest identifies that signed, ordered state;
/// callers must resolve the digest to the supplied membership through a pinned
/// MembershipEnvelope history, rather than hash an untrusted roster themselves.
public struct ItemEnvelope: Codable, Equatable, Sendable {
    public struct Header: Codable, Equatable, Sendable {
        public let format: String
        public let vault: UUID
        public let item: UUID
        public let version: UUID
        public let generation: UInt64
        public let keyGeneration: UUID
        public let base: UUID?
        public let membership: String
        public let author: String
    }
    public let header: Header
    public let encryptedCatalog: Data
    public let encryptedRecords: [String: Data]
    public let envelopes: [String: KeyEnvelope]
    public let signature: Data

    private struct Statement: Encodable {
        let domain = "2ndpass-item-envelope-signature-2"
        let header: Header
        let encryptedCatalog: Data
        let encryptedRecords: [String: Data]
        let envelopes: [String: KeyEnvelope]
    }
    private struct Context: Encodable {
        let domain = "2ndpass-item-envelope-catalog-2"
        let header: Header
        let component: String
    }
    private struct RecipientContext: Encodable {
        let domain = "2ndpass-item-envelope-key-2"
        let vault: UUID
        let item: UUID
        let keyGeneration: UUID
        let membership: String
        let recipient: String
        init(header: Header, recipient: String) {
            vault = header.vault; item = header.item; keyGeneration = header.keyGeneration
            membership = header.membership; self.recipient = recipient
        }
    }
    private struct RecordContext: Encodable {
        let domain = "2ndpass-item-envelope-record-2"
        let vault: UUID
        let item: UUID
        let keyGeneration: UUID
        let record: String
        init(header: Header, record: String) {
            vault = header.vault; item = header.item; keyGeneration = header.keyGeneration; self.record = record
        }
    }
    private var statement: Statement {
        Statement(header: header, encryptedCatalog: encryptedCatalog,
                  encryptedRecords: encryptedRecords, envelopes: envelopes)
    }

    public static func seal(_ archive: PortableVaultArchive, vault: UUID, generation: UInt64, version: UUID = UUID(),
                            base: UUID? = nil, membership: Membership, membershipStateDigest: String,
                            signer: any DeviceOperations) throws -> Self {
        try archive.validate()
        try membership.validate()
        guard Codec.hash(membershipStateDigest), archive.items.count == 1, let item = archive.items.first,
              let id = archive.itemIDs[item.name].flatMap(UUID.init(uuidString:)),
              archive.security?.accounts.isEmpty ?? true,
              archive.security?.passwordChecks?.isEmpty ?? true,
              let role = membership.role(of: signer.identity), role == .owner || role == .editor,
              base != version, generation > 0, generation <= UInt64(Int64.max), (generation == 1) == (base == nil) else { throw MopError.cloudPermission }
        let header = Header(format: "2ndpass-item-envelope-2", vault: vault, item: id,
                            version: version, generation: generation, keyGeneration: UUID(), base: base, membership: membershipStateDigest,
                            author: signer.identity.fingerprint)
        var projection = item
        let projectedValuePaths = item.fields.filter { $0.value != nil }.map(\.path)
        for index in projection.fields.indices { projection.fields[index].value = nil }
        let catalog = ItemEnvelopeCatalog(item: projection, references: archive.references,
            histories: archive.security?.histories ?? [], projectedValuePaths: projectedValuePaths)
        try catalog.validate(itemID: id, recordIDs: Set(archive.records.keys))
        let key = SymmetricKey(size: .bits256)
        var catalogBytes = try Codec.encode(catalog)
        defer { SecretBytes.wipe(&catalogBytes) }
        let encryptedCatalog = try encrypt(catalogBytes, key: key, header: header, component: "catalog")
        var records: [String: Data] = [:]
        for (record, value) in archive.records {
            records[record] = try value.bytes.withFoundationData {
                try encryptRecord($0, key: key, header: header, record: record)
            }
        }
        let envelopes = try Dictionary(uniqueKeysWithValues: membership.recipients.map { recipient in
            (recipient.fingerprint, try KeyEnvelope.seal(key, to: recipient.encryption,
                context: Codec.encode(RecipientContext(header: header, recipient: recipient.fingerprint))))
        })
        let statement = Statement(header: header, encryptedCatalog: encryptedCatalog, encryptedRecords: records, envelopes: envelopes)
        return Self(header: header, encryptedCatalog: encryptedCatalog, encryptedRecords: records, envelopes: envelopes,
                    signature: try signer.sign(Codec.encode(statement)))
    }

    /// Call with the independently selected destination record's IDs before
    /// accepting a fetched envelope. Signatures alone do not establish freshness.
    public func verify(vault: UUID, item: UUID, membership: Membership, membershipStateDigest: String) throws {
        try membership.validate()
        guard header.format == "2ndpass-item-envelope-2", header.vault == vault, header.item == item,
              header.version != header.base, header.generation > 0, header.generation <= UInt64(Int64.max), (header.generation == 1) == (header.base == nil), Codec.hash(membershipStateDigest), header.membership == membershipStateDigest,
              let author = membership.key(header.author),
              let role = membership.role(of: author), role == .owner || role == .editor,
              signature.count == 64, encryptedCatalog.count >= 28,
              encryptedCatalog.count <= PortableArchive.maximumSize,
              encryptedRecords.count <= 262_144,
              encryptedRecords.allSatisfy({ UUID(uuidString: $0.key)?.uuidString == $0.key && (28...(16 * 1024 * 1024 + 28)).contains($0.value.count) }),
              Set(envelopes.keys) == Set(membership.recipients.map(\.fingerprint)),
              envelopes.values.allSatisfy({ $0.encapsulatedKey.count == 65 && $0.ciphertext.count == 48 }),
              author.verifies(signature, message: try Codec.encode(statement)) else { throw MopError.vaultUntrusted }
    }

    public func encoded() throws -> Data {
        let data = try Codec.encode(self)
        guard data.count <= PortableArchive.maximumSize else { throw PortableArchiveFailure.tooLarge }
        return data
    }

    public static func decode(_ data: Data, vault: UUID, item: UUID, membership: Membership, membershipStateDigest: String) throws -> Self {
        guard data.count <= PortableArchive.maximumSize else { throw PortableArchiveFailure.tooLarge }
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard try Codec.encode(value) == data else { throw MopError.invalidVault }
        try value.verify(vault: vault, item: item, membership: membership, membershipStateDigest: membershipStateDigest)
        return value
    }

    /// Only the catalog is decrypted. Replacements use fresh record UUIDs; the
    /// caller remaps their field references and explicitly retains old history or
    /// removes obsolete records. Unchanged ciphertext and key envelopes are reused.
    public func edit(catalog: ItemEnvelopeCatalog, changedRecords: [String: SecretBytes] = [:],
                     removedRecords: Set<String> = [], membership: Membership, membershipStateDigest: String,
                     signer: any DeviceOperations) throws -> Self {
        guard header.generation < UInt64(Int64.max) else { throw MopError.invalidVault }
        return try editing(catalog: catalog, changedRecords: changedRecords, removedRecords: removedRecords,
            generation: header.generation + 1, base: header.version,
            membership: membership, membershipStateDigest: membershipStateDigest, signer: signer)
    }

    /// Produces a user-reviewed resolution using this local content as the base
    /// projection. The remote branch establishes publication's predecessor. The
    /// repository still performs a CAS over both reviewed conflict versions.
    public func resolvingConflict(with remote: Self, catalog: ItemEnvelopeCatalog,
                                  changedRecords: [String: SecretBytes] = [:], removedRecords: Set<String> = [],
                                  membership: Membership, membershipStateDigest: String,
                                  signer: any DeviceOperations) throws -> Self {
        try remote.verify(vault: header.vault, item: header.item, membership: membership, membershipStateDigest: membershipStateDigest)
        let generation = max(header.generation, remote.header.generation)
        guard generation < UInt64(Int64.max) else { throw MopError.invalidVault }
        return try editing(catalog: catalog, changedRecords: changedRecords, removedRecords: removedRecords,
            generation: generation + 1, base: remote.header.version,
            membership: membership, membershipStateDigest: membershipStateDigest, signer: signer)
    }

    /// Membership changes never silently reuse prior field keys. This explicit
    /// operation decrypts all retained records, generates a new key generation,
    /// and encrypts a complete successor for the new authenticated membership.
    public func rekey(name: String, previousMembership: Membership, previousMembershipStateDigest: String,
                      membership: Membership, membershipStateDigest: String,
                      signer: any DeviceOperations) throws -> Self {
        guard header.generation < UInt64(Int64.max) else { throw MopError.invalidVault }
        let archive = try portableArchive(name: name, device: signer, membership: previousMembership,
            membershipStateDigest: previousMembershipStateDigest)
        return try Self.seal(archive, vault: header.vault, generation: header.generation + 1, base: header.version,
            membership: membership, membershipStateDigest: membershipStateDigest, signer: signer)
    }

    /// Explicit additive admission preserves secret ciphertext. This cannot be
    /// used for revocation or any role/account/recovery authority change.
    public func admittingDevice(_ device: DevicePublicKey, previous: MembershipEnvelope,
                               successor: MembershipEnvelope, signer: any DeviceOperations) throws -> Self {
        try successor.verifyDeviceAddition(of: previous, device: device)
        return try rewrapMembership(previous: previous, successor: successor, signer: signer)
    }

    public func adoptingMembership(history: TrustedMembershipHistory, signer: any DeviceOperations) throws -> Self {
        let previous = try history.state(forDigest: header.membership)
        try history.verifyAdditivePath(from: header.membership)
        guard history.current.header.generation > previous.header.generation else { throw MopError.invalidVault }
        return try rewrapMembership(previous: previous, successor: history.current, signer: signer)
    }

    private func rewrapMembership(previous: MembershipEnvelope, successor: MembershipEnvelope,
                                  signer: any DeviceOperations) throws -> Self {
        guard previous.header.vault == header.vault, previous.membership.role(of: signer.identity) == .owner,
              header.generation < UInt64(Int64.max) else { throw MopError.cloudPermission }
        let key = try key(device: signer, membership: previous.membership, membershipStateDigest: previous.digest())
        let catalog = try catalog(using: key)
        let next = try Header(format: header.format, vault: header.vault, item: header.item,
            version: UUID(), generation: header.generation + 1, keyGeneration: header.keyGeneration,
            base: header.version, membership: successor.digest(), author: signer.identity.fingerprint)
        var bytes = try Codec.encode(catalog)
        defer { SecretBytes.wipe(&bytes) }
        let encrypted = try Self.encrypt(bytes, key: key, header: next, component: "catalog")
        let wrappers = try Dictionary(uniqueKeysWithValues: successor.membership.recipients.map { recipient in
            (recipient.fingerprint, try KeyEnvelope.seal(key, to: recipient.encryption,
                context: Codec.encode(RecipientContext(header: next, recipient: recipient.fingerprint))))
        })
        let statement = Statement(header: next, encryptedCatalog: encrypted, encryptedRecords: encryptedRecords, envelopes: wrappers)
        return Self(header: next, encryptedCatalog: encrypted, encryptedRecords: encryptedRecords, envelopes: wrappers,
            signature: try signer.sign(Codec.encode(statement)))
    }

    private func editing(catalog: ItemEnvelopeCatalog, changedRecords: [String: SecretBytes],
                         removedRecords: Set<String>, generation: UInt64, base: UUID,
                         membership: Membership, membershipStateDigest: String,
                         signer: any DeviceOperations) throws -> Self {
        guard header.membership == membershipStateDigest else { throw ItemEnvelopeFailure.rekeyRequired }
        guard let role = membership.role(of: signer.identity), role == .owner || role == .editor else { throw MopError.cloudPermission }
        let key = try key(device: signer, membership: membership, membershipStateDigest: membershipStateDigest)
        _ = try self.catalog(using: key)
        let previousIDs = Set(encryptedRecords.keys)
        guard removedRecords.isSubset(of: previousIDs),
              Set(changedRecords.keys).isDisjoint(with: previousIDs),
              changedRecords.allSatisfy({ UUID(uuidString: $0.key)?.uuidString == $0.key && $0.value.count <= 16 * 1024 * 1024 }) else { throw ItemEnvelopeFailure.invalidRecordMutation }
        let nextIDs = previousIDs.subtracting(removedRecords).union(changedRecords.keys)
        try catalog.validate(itemID: header.item, recordIDs: nextIDs)
        let nextHeader = Header(format: header.format, vault: header.vault, item: header.item,
            version: UUID(), generation: generation, keyGeneration: header.keyGeneration, base: base,
            membership: membershipStateDigest, author: signer.identity.fingerprint)
        var records = encryptedRecords.filter { !removedRecords.contains($0.key) }
        for (id, bytes) in changedRecords {
            records[id] = try bytes.withFoundationData { try Self.encryptRecord($0, key: key, header: nextHeader, record: id) }
        }
        var catalogBytes = try Codec.encode(catalog)
        defer { SecretBytes.wipe(&catalogBytes) }
        let encryptedCatalog = try Self.encrypt(catalogBytes, key: key, header: nextHeader, component: "catalog")
        let statement = Statement(header: nextHeader, encryptedCatalog: encryptedCatalog, encryptedRecords: records, envelopes: envelopes)
        let value = Self(header: nextHeader, encryptedCatalog: encryptedCatalog, encryptedRecords: records,
            envelopes: envelopes, signature: try signer.sign(Codec.encode(statement)))
        _ = try value.encoded()
        return value
    }

    /// Decrypts only the display/catalog projection. Concealed values and
    /// attachments remain encrypted until read or explicit portable export.
    public func catalog(device: any DeviceOperations, membership: Membership, membershipStateDigest: String) throws -> ItemEnvelopeCatalog {
        let key = try key(device: device, membership: membership, membershipStateDigest: membershipStateDigest)
        return try catalog(using: key)
    }

    /// Unwrap once for both the authenticated catalog and its visible values.
    /// The key is scoped to this call; concealed records and history are untouched.
    public func displayCatalog(device: any DeviceOperations, membership: Membership,
                               membershipStateDigest: String) throws -> (catalog: ItemEnvelopeCatalog, item: VaultItem) {
        let key = try key(device: device, membership: membership, membershipStateDigest: membershipStateDigest)
        let catalog = try catalog(using: key)
        var item = catalog.item
        for index in item.fields.indices where !item.fields[index].type.concealed {
            try Task.checkCancellation()
            guard let record = catalog.references[SecretReference.encode(item.name) + "/" + item.fields[index].path],
                  let ciphertext = encryptedRecords[record] else { throw MopError.invalidVault }
            var bytes = try decryptRecord(ciphertext, key: key, record: record)
            defer { SecretBytes.wipe(&bytes) }
            guard let value = String(data: bytes, encoding: .utf8) else { throw MopError.invalidVault }
            item.fields[index].value = value
        }
        return (catalog, item)
    }

    public func read(record: String, device: any DeviceOperations, membership: Membership, membershipStateDigest: String) throws -> SecretBytes {
        let key = try key(device: device, membership: membership, membershipStateDigest: membershipStateDigest)
        guard let ciphertext = encryptedRecords[record] else { throw MopError.notFound }
        var bytes = try decryptRecord(ciphertext, key: key, record: record)
        defer { SecretBytes.wipe(&bytes) }
        return SecretBytes(copying: bytes)
    }

    public func portableArchive(name: String, device: any DeviceOperations, membership: Membership, membershipStateDigest: String) throws -> PortableVaultArchive {
        let key = try key(device: device, membership: membership, membershipStateDigest: membershipStateDigest)
        let catalog = try catalog(using: key)
        var records: [String: PortableArchiveRecord] = [:]
        for (id, ciphertext) in encryptedRecords {
            var bytes = try decryptRecord(ciphertext, key: key, record: id)
            defer { SecretBytes.wipe(&bytes) }
            records[id] = PortableArchiveRecord(itemID: header.item.uuidString, bytes: SecretBytes(copying: bytes))
        }
        var security = VaultSecurityMetadata()
        security.histories = catalog.histories
        var item = catalog.item
        for index in item.fields.indices where catalog.projectedValuePaths.contains(item.fields[index].path) {
            guard let id = catalog.references[SecretReference.encode(item.name) + "/" + item.fields[index].path],
                  let record = records[id] else { throw MopError.invalidVault }
            item.fields[index].value = String(decoding: try record.bytes.validatedUTF8(), as: UTF8.self)
        }
        let result = PortableVaultArchive(name: name, items: [item],
            itemIDs: [catalog.item.name: header.item.uuidString], references: catalog.references,
            records: records, security: security)
        try result.validate()
        return result
    }

    private static func encrypt(_ bytes: Data, key: SymmetricKey, header: Header, component: String) throws -> Data {
        guard let result = try AES.GCM.seal(bytes, using: key,
            authenticating: Codec.encode(Context(header: header, component: component))).combined else { throw MopError.invalidVault }
        return result
    }
    private static func encryptRecord(_ bytes: Data, key: SymmetricKey, header: Header, record: String) throws -> Data {
        guard let result = try AES.GCM.seal(bytes, using: key,
            authenticating: Codec.encode(RecordContext(header: header, record: record))).combined else { throw MopError.invalidVault }
        return result
    }
    private func decryptRecord(_ bytes: Data, key: SymmetricKey, record: String) throws -> Data {
        try AES.GCM.open(AES.GCM.SealedBox(combined: bytes), using: key,
            authenticating: Codec.encode(RecordContext(header: header, record: record)))
    }
    private func decrypt(_ bytes: Data, key: SymmetricKey, component: String) throws -> Data {
        try AES.GCM.open(AES.GCM.SealedBox(combined: bytes), using: key,
            authenticating: Codec.encode(Context(header: header, component: component)))
    }
    private func key(device: any DeviceOperations, membership: Membership, membershipStateDigest: String) throws -> SymmetricKey {
        try verify(vault: header.vault, item: header.item, membership: membership, membershipStateDigest: membershipStateDigest)
        guard membership.role(of: device.identity) != nil || membership.offlineRecovery == device.identity,
              let envelope = envelopes[device.identity.fingerprint] else { throw MopError.notVaultMember }
        return try device.unwrap(envelope,
            context: Codec.encode(RecipientContext(header: header, recipient: device.identity.fingerprint)))
    }
    private func catalog(using key: SymmetricKey) throws -> ItemEnvelopeCatalog {
        var bytes = try decrypt(encryptedCatalog, key: key, component: "catalog")
        defer { SecretBytes.wipe(&bytes) }
        let result = try JSONDecoder().decode(ItemEnvelopeCatalog.self, from: bytes)
        try result.validate(itemID: header.item, recordIDs: Set(encryptedRecords.keys))
        return result
    }
}

public struct ItemEnvelopeCatalog: Codable, Equatable, Sendable {
    public var item: VaultItem
    public var references: [String: String]
    public var histories: [SecretFieldHistory]
    /// Allows exact portable restoration without storing values in this projection.
    public var projectedValuePaths: [String]
    public init(item: VaultItem, references: [String: String], histories: [SecretFieldHistory] = [], projectedValuePaths: [String] = []) {
        self.item = item; self.references = references; self.histories = histories; self.projectedValuePaths = projectedValuePaths
    }
    public func validate(itemID: UUID, recordIDs: Set<String>) throws {
        let fieldIDs = item.fields.compactMap(\.historyID)
        guard !item.fields.isEmpty, recordIDs.count <= 262_144,
              recordIDs.allSatisfy({ UUID(uuidString: $0)?.uuidString == $0 }),
              Set(item.fields.map(\.path)).count == item.fields.count,
              Set(fieldIDs).count == fieldIDs.count,
              item.fields.allSatisfy({ $0.value == nil }),
              Set(projectedValuePaths).count == projectedValuePaths.count,
              Set(projectedValuePaths).isSubset(of: Set(item.fields.filter { !$0.type.concealed }.map(\.path))),
              Set(references.values).count == references.count,
              Set(item.fields.map { SecretReference.encode(item.name) + "/" + $0.path }) == Set(references.keys),
              Set(histories.map(\.id)).count == histories.count,
              Set(histories.map(\.path)).count == histories.count,
              Set(references.values).union(histories.flatMap { $0.entries.map(\.id) }) == recordIDs else { throw MopError.invalidVault }
        try CloudKey.validate(item: item)
        for reference in references.keys {
            guard reference.utf8.count <= 4096 else { throw MopError.invalidVault }
            _ = try SecretReference(vault: "vault", relativePath: reference)
        }
        var used = Set(references.values)
        for history in histories {
            guard history.itemID == itemID.uuidString, history.entries.count <= 20,
                  item.fields.contains(where: { $0.path == history.path && $0.historyID == history.id && [.password, .concealed].contains($0.type) }) else { throw MopError.invalidVault }
            for entry in history.entries {
                guard entry.replacedAt.timeIntervalSince1970.isFinite, used.insert(entry.id).inserted else { throw MopError.invalidVault }
            }
        }
    }

    /// Builds a value-only patch for an existing field. No previous value is
    /// decrypted: password/concealed replacements retain its immutable record as
    /// history, while other replaced records are explicitly removed.
    public func replacingField(_ path: String, value: SecretBytes, itemID: UUID,
                               at date: Date = Date()) throws -> ItemEnvelopePatch {
        // Field payloads use text encodings, including attachment JSON and
        // credential base64. Reject invalid text before a durable edit can make
        // its subsequent portable projection impossible to reconstruct.
        _ = try value.validatedUTF8()
        guard date.timeIntervalSince1970.isFinite,
              let fieldIndex = item.fields.firstIndex(where: { $0.path == path }),
              let previous = references[SecretReference.encode(item.name) + "/" + path] else { throw MopError.notFound }
        var next = self
        let field = item.fields[fieldIndex]
        if field.type == .attachment {
            _ = try Attachment.decode(String(decoding: value.validatedUTF8(), as: UTF8.self))
        } else if field.type.isCompound {
            _ = try CompoundField(String(decoding: value.validatedUTF8(), as: UTF8.self))
        }
        if item.credential != nil, path == KeyCredential.privateField {
            var checked = item
            checked.fields[fieldIndex].value = String(decoding: try value.validatedUTF8(), as: UTF8.self)
            try CloudKey.validate(item: checked)
        }
        let record = UUID().uuidString
        next.references[SecretReference.encode(item.name) + "/" + path] = record
        var removed: Set<String> = []
        if [.password, .concealed].contains(field.type) {
            let fieldID = field.historyID ?? UUID()
            next.item.fields[fieldIndex].historyID = fieldID
            let historyIndex: Int
            if let existing = next.histories.firstIndex(where: { $0.path == path }) { historyIndex = existing }
            else {
                var history = SecretFieldHistory(itemID: itemID.uuidString, path: path)
                history.id = fieldID
                next.histories.append(history)
                historyIndex = next.histories.count - 1
            }
            next.histories[historyIndex].entries.insert(SecretHistoryEntry(id: previous, replacedAt: date), at: 0)
            let dropped = next.histories[historyIndex].entries.dropFirst(20).map(\.id)
            removed.formUnion(dropped)
            next.histories[historyIndex].entries = Array(next.histories[historyIndex].entries.prefix(20))
        } else { removed.insert(previous) }
        next.item.fields[fieldIndex].value = nil
        next.item.fields[fieldIndex].passwordQuality = nil
        if !field.type.concealed, !next.projectedValuePaths.contains(path) { next.projectedValuePaths.append(path) }
        if next.item.metadata == nil { next.item.metadata = ItemMetadata() }
        next.item.metadata?.updatedAt = date
        return ItemEnvelopePatch(catalog: next, changedRecords: [record: value], removedRecords: removed)
    }
}

public struct ItemEnvelopePatch: Sendable {
    public let catalog: ItemEnvelopeCatalog
    public let changedRecords: [String: SecretBytes]
    public let removedRecords: Set<String>
}

public enum ItemEnvelopeFailure: Error, Equatable, Sendable {
    case rekeyRequired
    case invalidRecordMutation
}

/// Ephemeral conversion result. Vault-wide metadata remains sensitive plaintext
/// and must be stored in a separate encrypted vault-security record by the caller.
/// This is deliberately not Codable and not a whole-vault synchronization unit.
public struct PortableItemEnvelopeSet: Sendable {
    public let vault: UUID
    public let name: String
    public let items: [ItemEnvelope]
    public let security: VaultSecurityMetadata?
    public let exclusions: [String]
    public let membershipStateDigest: String

    private init(vault: UUID, name: String, items: [ItemEnvelope], security: VaultSecurityMetadata?, exclusions: [String], membershipStateDigest: String) {
        self.vault = vault; self.name = name; self.items = items; self.security = security; self.exclusions = exclusions
        self.membershipStateDigest = membershipStateDigest
    }

    /// Reconstructs an archive view from independent persisted ciphertext records.
    /// The repository, not this converter, selects versions and detects omissions.
    public init(vault: UUID, metadata: VaultMetadataEnvelope, items: [ItemEnvelope],
                device: any DeviceOperations, membership: Membership, membershipStateDigest: String) throws {
        try metadata.verify(vault: vault, membership: membership, membershipStateDigest: membershipStateDigest)
        let settings = try metadata.open(device: device, membership: membership, membershipStateDigest: membershipStateDigest)
        var security = settings.security
        for item in items {
            try item.verify(vault: vault, item: item.header.item, membership: membership, membershipStateDigest: membershipStateDigest)
            let histories = try item.catalog(device: device, membership: membership, membershipStateDigest: membershipStateDigest).histories
            if !histories.isEmpty {
                if security == nil { security = VaultSecurityMetadata() }
                security?.histories.append(contentsOf: histories)
            }
        }
        self.init(vault: vault, name: settings.name, items: items, security: security, exclusions: settings.exclusions, membershipStateDigest: membershipStateDigest)
    }

    public func metadataEnvelope(membership: Membership, membershipStateDigest: String, signer: any DeviceOperations) throws -> VaultMetadataEnvelope {
        guard self.membershipStateDigest == membershipStateDigest else { throw MopError.vaultUntrusted }
        var settings = security
        settings?.histories = []
        return try VaultMetadataEnvelope.seal(VaultEnvelopeMetadata(name: name, security: settings, exclusions: exclusions),
            vault: vault, generation: 1, membership: membership, membershipStateDigest: membershipStateDigest, signer: signer)
    }

    public static func seal(_ document: PortableVaultArchive, vault: UUID,
                            membership: Membership, membershipStateDigest: String, signer: any DeviceOperations) throws -> Self {
        try document.validate()
        try membership.validate()
        guard Codec.hash(membershipStateDigest), let role = membership.role(of: signer.identity),
              role == .owner || role == .editor else { throw MopError.cloudPermission }
        // Large imports should traverse the archive graph once, rather than
        // rescanning every field and attachment for each item.
        var recordsByItem: [String: [String: PortableArchiveRecord]] = [:]
        for (id, record) in document.records {
            recordsByItem[record.itemID, default: [:]][id] = record
        }
        var referencesByItem: [String: [String: String]] = [:]
        for (path, recordID) in document.references {
            guard let record = document.records[recordID] else { throw PortableArchiveFailure.invalid }
            referencesByItem[record.itemID, default: [:]][path] = recordID
        }
        let historiesByItem = Dictionary(grouping: document.security?.histories ?? [], by: \.itemID)
        var items: [ItemEnvelope] = []
        items.reserveCapacity(document.items.count)
        for item in document.items {
            guard let id = document.itemIDs[item.name] else { throw PortableArchiveFailure.invalid }
            let references = referencesByItem[id] ?? [:]
            let records = recordsByItem[id] ?? [:]
            var metadata = VaultSecurityMetadata()
            metadata.histories = historiesByItem[id] ?? []
            let projection = PortableVaultArchive(name: document.name, items: [item], itemIDs: [item.name: id],
                references: references, records: records, security: metadata)
            items.append(try ItemEnvelope.seal(projection, vault: vault, generation: 1, membership: membership, membershipStateDigest: membershipStateDigest, signer: signer))
        }
        return Self(vault: vault, name: document.name, items: items, security: document.security, exclusions: document.exclusions, membershipStateDigest: membershipStateDigest)
    }

    public func portableArchive(device: any DeviceOperations, membership: Membership, membershipStateDigest: String) throws -> PortableVaultArchive {
        guard self.membershipStateDigest == membershipStateDigest,
              membership.role(of: device.identity) != nil || membership.offlineRecovery == device.identity else { throw MopError.vaultUntrusted }
        var result = PortableVaultArchive(name: name, items: [], itemIDs: [:], references: [:], records: [:], security: security, exclusions: exclusions)
        for envelope in items {
            try envelope.verify(vault: vault, item: envelope.header.item, membership: membership, membershipStateDigest: membershipStateDigest)
            let item = try envelope.portableArchive(name: name, device: device, membership: membership, membershipStateDigest: membershipStateDigest)
            guard Set(result.itemIDs.keys).isDisjoint(with: item.itemIDs.keys),
                  Set(result.itemIDs.values).isDisjoint(with: item.itemIDs.values),
                  Set(result.records.keys).isDisjoint(with: item.records.keys) else { throw PortableArchiveFailure.invalid }
            result.items.append(contentsOf: item.items)
            result.itemIDs.merge(item.itemIDs) { _, new in new }
            result.references.merge(item.references) { _, new in new }
            result.records.merge(item.records) { _, new in new }
        }
        try result.validate()
        return result
    }
}

/// Vault-wide application metadata, separate from item contents and from the
/// authoritative membership record. It contains no item inventory or history.
public struct VaultEnvelopeMetadata: Codable, Equatable, Sendable {
    public var name: String
    public var security: VaultSecurityMetadata?
    public var exclusions: [String]
    public init(name: String, security: VaultSecurityMetadata? = nil, exclusions: [String] = []) {
        self.name = name; self.security = security; self.exclusions = exclusions
    }
    fileprivate func validate() throws {
        try VaultName.validate(name)
        guard security?.histories.isEmpty ?? true,
              Set(security?.accounts.map(\.id) ?? []).count == (security?.accounts.count ?? 0),
              exclusions.count <= 128, exclusions.allSatisfy({ $0.utf8.count <= 4096 }) else { throw MopError.invalidVault }
        for account in security?.accounts ?? [] { try account.validate() }
    }
}

/// Independently encrypted settings record. Do not update this record for every
/// item mutation; histories travel with their items, not with this metadata.
public struct VaultMetadataEnvelope: Codable, Equatable, Sendable {
    public struct Header: Codable, Equatable, Sendable {
        public let format: String
        public let vault: UUID
        public let version: UUID
        public let generation: UInt64
        public let base: UUID?
        public let membership: String
        public let author: String
    }
    public let header: Header
    public let ciphertext: Data
    public let envelopes: [String: KeyEnvelope]
    public let signature: Data
    private struct Statement: Encodable {
        let domain = "2ndpass-vault-metadata-signature-1"
        let header: Header; let ciphertext: Data; let envelopes: [String: KeyEnvelope]
    }
    private struct Context: Encodable {
        let domain = "2ndpass-vault-metadata-content-1"
        let header: Header
    }
    private struct RecipientContext: Encodable {
        let domain = "2ndpass-vault-metadata-key-1"
        let header: Header; let recipient: String
    }
    private var statement: Statement { Statement(header: header, ciphertext: ciphertext, envelopes: envelopes) }

    public static func seal(_ metadata: VaultEnvelopeMetadata, vault: UUID, generation: UInt64, version: UUID = UUID(), base: UUID? = nil,
                            membership: Membership, membershipStateDigest: String, signer: any DeviceOperations) throws -> Self {
        try metadata.validate()
        try membership.validate()
        guard Codec.hash(membershipStateDigest), let role = membership.role(of: signer.identity), role == .owner || role == .editor,
              version != base, generation > 0, generation <= UInt64(Int64.max), (generation == 1) == (base == nil) else { throw MopError.cloudPermission }
        let header = Header(format: "2ndpass-vault-metadata-1", vault: vault, version: version, generation: generation, base: base,
            membership: membershipStateDigest, author: signer.identity.fingerprint)
        let key = SymmetricKey(size: .bits256)
        var plaintext = try Codec.encode(metadata)
        defer { SecretBytes.wipe(&plaintext) }
        guard plaintext.count <= Codec.maximumSize - 28 else { throw PortableArchiveFailure.tooLarge }
        guard let ciphertext = try AES.GCM.seal(plaintext, using: key,
            authenticating: Codec.encode(Context(header: header))).combined else { throw MopError.invalidVault }
        let envelopes = try Dictionary(uniqueKeysWithValues: membership.recipients.map { recipient in
            (recipient.fingerprint, try KeyEnvelope.seal(key, to: recipient.encryption,
                context: Codec.encode(RecipientContext(header: header, recipient: recipient.fingerprint))))
        })
        let statement = Statement(header: header, ciphertext: ciphertext, envelopes: envelopes)
        return Self(header: header, ciphertext: ciphertext, envelopes: envelopes, signature: try signer.sign(Codec.encode(statement)))
    }

    public func verify(vault: UUID, membership: Membership, membershipStateDigest: String) throws {
        try membership.validate()
        guard header.format == "2ndpass-vault-metadata-1", header.vault == vault,
              header.version != header.base, header.generation > 0, header.generation <= UInt64(Int64.max), (header.generation == 1) == (header.base == nil), Codec.hash(membershipStateDigest), header.membership == membershipStateDigest,
              let author = membership.key(header.author), let role = membership.role(of: author),
              role == .owner || role == .editor,
              (28...Codec.maximumSize).contains(ciphertext.count), signature.count == 64,
              Set(envelopes.keys) == Set(membership.recipients.map(\.fingerprint)),
              envelopes.values.allSatisfy({ $0.encapsulatedKey.count == 65 && $0.ciphertext.count == 48 }),
              author.verifies(signature, message: try Codec.encode(statement)) else { throw MopError.vaultUntrusted }
    }

    public func open(device: any DeviceOperations, membership: Membership, membershipStateDigest: String) throws -> VaultEnvelopeMetadata {
        try verify(vault: header.vault, membership: membership, membershipStateDigest: membershipStateDigest)
        guard membership.role(of: device.identity) != nil || membership.offlineRecovery == device.identity,
              let envelope = envelopes[device.identity.fingerprint] else { throw MopError.notVaultMember }
        let key = try device.unwrap(envelope,
            context: Codec.encode(RecipientContext(header: header, recipient: device.identity.fingerprint)))
        var bytes = try AES.GCM.open(AES.GCM.SealedBox(combined: ciphertext), using: key,
            authenticating: Codec.encode(Context(header: header)))
        defer { SecretBytes.wipe(&bytes) }
        let result = try JSONDecoder().decode(VaultEnvelopeMetadata.self, from: bytes)
        try result.validate()
        return result
    }

    public func encoded() throws -> Data {
        let data = try Codec.encode(self)
        guard data.count <= PortableArchive.maximumSize else { throw PortableArchiveFailure.tooLarge }
        return data
    }
    public static func decode(_ data: Data, vault: UUID, membership: Membership, membershipStateDigest: String) throws -> Self {
        guard data.count <= PortableArchive.maximumSize else { throw PortableArchiveFailure.tooLarge }
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard try Codec.encode(value) == data else { throw MopError.invalidVault }
        try value.verify(vault: vault, membership: membership, membershipStateDigest: membershipStateDigest)
        return value
    }
}
