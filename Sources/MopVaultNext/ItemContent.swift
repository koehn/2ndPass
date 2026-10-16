import Foundation
import MopCore
import MopCredentials

public struct ItemEditOrigin: Codable, Equatable, Sendable {
    public let deviceID: UUID
    public let deviceName: String
    public let updatedAt: Date
    public init(deviceID: UUID, deviceName: String, updatedAt: Date) {
        self.deviceID = deviceID; self.deviceName = deviceName; self.updatedAt = updatedAt
    }
}

public struct ItemContentCatalog: Codable, Equatable, Sendable {
    public var editOrigin: ItemEditOrigin?
    public var item: VaultItem
    public var references: [String: String]
    public var histories: [SecretFieldHistory]
    /// Allows exact portable restoration without storing values in this projection.
    public var projectedValuePaths: [String]
    public init(item: VaultItem, references: [String: String], histories: [SecretFieldHistory] = [], projectedValuePaths: [String] = [], editOrigin: ItemEditOrigin? = nil) {
        self.editOrigin = editOrigin
        self.item = item; self.references = references; self.histories = histories; self.projectedValuePaths = projectedValuePaths
    }
    public func validate(itemID: UUID, recordIDs: Set<String>) throws {
        if let editOrigin {
            guard !editOrigin.deviceName.isEmpty, editOrigin.deviceName.utf8.count <= 1024,
                  editOrigin.updatedAt.timeIntervalSince1970.isFinite else { throw MopError.invalidVault }
        }
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
                               at date: Date = Date()) throws -> ItemContentPatch {
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
        return ItemContentPatch(catalog: next, changedRecords: [record: value], removedRecords: removed)
    }
}

public struct ItemContentPatch: Sendable {
    public init(catalog: ItemContentCatalog, changedRecords: [String: SecretBytes], removedRecords: Set<String>) {
        self.catalog = catalog; self.changedRecords = changedRecords; self.removedRecords = removedRecords
    }
    public let catalog: ItemContentCatalog
    public let changedRecords: [String: SecretBytes]
    public let removedRecords: Set<String>
}

public enum ItemContentFailure: Error, Equatable, Sendable {
    case rekeyRequired
    case invalidRecordMutation
}

/// Ephemeral conversion result. Vault-wide metadata remains sensitive plaintext
/// and must be stored in a separate encrypted vault-security record by the caller.
/// This is deliberately not Codable and not a whole-vault synchronization unit.
public struct VaultMetadata: Codable, Equatable, Sendable {
    public var name: String
    public var security: VaultSecurityMetadata?
    public var exclusions: [String]
    public init(name: String, security: VaultSecurityMetadata? = nil, exclusions: [String] = []) {
        self.name = name; self.security = security; self.exclusions = exclusions
    }
    public func validate() throws {
        try VaultName.validate(name)
        guard security?.histories.isEmpty ?? true,
              exclusions.count <= 128, exclusions.allSatisfy({ $0.utf8.count <= 4096 }) else { throw MopError.invalidVault }
        let checks = security?.passwordChecks ?? []
        guard checks.count <= 262_144, Set(checks.map(\.record)).count == checks.count else { throw MopError.invalidVault }
        for check in checks { try check.validate() }
    }
}

/// Independently encrypted settings record. Do not update this record for every
/// item mutation; histories travel with their items, not with this metadata.
