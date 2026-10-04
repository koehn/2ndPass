import CryptoKit
import Foundation

/// Logical vault contents, independent of device keys and CloudKit's storage format.
/// This is sensitive plaintext. Keep it in an authenticated operation's memory only.
public struct PortableVaultArchive: Codable, Equatable, Sendable {
    public let version: Int
    public var name: String
    public var items: [VaultItem]
    public var itemIDs: [String: String]
    public var references: [String: String]
    public var records: [String: PortableArchiveRecord]
    public var security: VaultSecurityMetadata?
    /// Informational exclusions, never instructions to a restore implementation.
    public var exclusions: [String]

    public init(name: String, items: [VaultItem], itemIDs: [String: String], references: [String: String],
                records: [String: PortableArchiveRecord], security: VaultSecurityMetadata? = nil,
                exclusions: [String] = []) {
        version = 1; self.name = name; self.items = items; self.itemIDs = itemIDs
        self.references = references; self.records = records; self.security = security; self.exclusions = exclusions
    }

    public func validate() throws {
        guard version == 1 else { throw PortableArchiveFailure.unsupportedVersion }
        try VaultName.validate(name)
        guard items.count <= 65_536, records.count <= 262_144,
              Set(items.map(\.name)).count == items.count,
              Set(itemIDs.values).count == itemIDs.count,
              Set(items.map(\.name)) == Set(itemIDs.keys),
              itemIDs.values.allSatisfy({ UUID(uuidString: $0)?.uuidString == $0 }),
              Set(references.values).count == references.count,
              exclusions.count <= 128, exclusions.allSatisfy({ $0.utf8.count <= 4096 }) else { throw PortableArchiveFailure.invalid }
        var used = Set<String>()
        let fieldHistoryIDs = items.flatMap { $0.fields.compactMap(\.historyID) }
        guard Set(fieldHistoryIDs).count == fieldHistoryIDs.count else { throw PortableArchiveFailure.invalid }
        for item in items {
            guard !item.fields.isEmpty, Set(item.fields.map(\.path)).count == item.fields.count,
                  item.fields.allSatisfy({ !$0.type.concealed || $0.value == nil }),
                  let itemID = itemIDs[item.name] else { throw PortableArchiveFailure.invalid }
            if let credential = item.credential { try credential.validate() }
            for field in item.fields {
                let reference = SecretReference.encode(item.name) + "/" + field.path
                _ = try SecretReference(vault: name, relativePath: reference)
                guard reference.utf8.count <= 4096,
                      let record = references[reference], records[record]?.itemID == itemID,
                      used.insert(record).inserted else { throw PortableArchiveFailure.invalid }
            }
        }
        guard used == Set(references.values) else { throw PortableArchiveFailure.invalid }
        if let security {
            guard Set(security.histories.map(\.id)).count == security.histories.count,
                  Set(security.histories.map { $0.itemID + ":" + $0.path }).count == security.histories.count,
                  Set(security.accounts.map(\.id)).count == security.accounts.count else { throw PortableArchiveFailure.invalid }
            for history in security.histories {
                guard let item = items.first(where: { itemIDs[$0.name] == history.itemID }),
                      item.fields.contains(where: { $0.path == history.path && $0.historyID == history.id && [.password, .concealed].contains($0.type) }),
                      history.entries.count <= 20 else { throw PortableArchiveFailure.invalid }
                for entry in history.entries {
                    guard entry.replacedAt.timeIntervalSince1970.isFinite,
                          records[entry.id]?.itemID == history.itemID,
                          used.insert(entry.id).inserted else { throw PortableArchiveFailure.invalid }
                }
            }
            for account in security.accounts {
                try account.validate()
                guard account.linkedItemID.map({ itemIDs.values.contains($0) }) ?? true else { throw PortableArchiveFailure.invalid }
            }
        }
        guard used == Set(records.keys), records.allSatisfy({ id, record in
            UUID(uuidString: id)?.uuidString == id && record.bytes.count <= 16 * 1024 * 1024
        }) else { throw PortableArchiveFailure.invalid }
        // Bound before encoding so an oversized in-memory archive cannot first
        // allocate an arbitrarily large base64/JSON representation.
        var remaining = PortableArchive.maximumSize
        for record in records.values {
            guard record.bytes.count <= remaining else { throw PortableArchiveFailure.tooLarge }
            remaining -= record.bytes.count
        }
    }
}

/// A current field, retained history value, or encoded attachment. Relationships
/// live in the archive's references and metadata; no legacy ciphertext is retained.
public struct PortableArchiveRecord: Codable, Equatable, Sendable {
    public let itemID: String
    public let bytes: SecretBytes
    public init(itemID: String, bytes: SecretBytes) { self.itemID = itemID; self.bytes = bytes }
    private enum CodingKeys: String, CodingKey { case itemID, bytes }
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        itemID = try container.decode(String.self, forKey: .itemID)
        var data = try container.decode(Data.self, forKey: .bytes)
        defer { SecretBytes.wipe(&data) }
        bytes = SecretBytes(copying: data)
    }
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(itemID, forKey: .itemID)
        try bytes.withFoundationData { try container.encode($0, forKey: .bytes) }
    }
}

public struct PortableArchiveExport: Sendable {
    public let data: Data
    /// A generated 256-bit key, not a user password. Save separately from data.
    public let recoveryKey: SecretBytes
}

public enum PortableArchiveFailure: Error, LocalizedError, Sendable {
    case invalid, unsupportedVersion, tooLarge, invalidKey
    public var errorDescription: String? {
        switch self {
        case .invalid: "The portable archive is incomplete, damaged, or could not be authenticated with this key."
        case .unsupportedVersion: "This portable archive requires a different version of 2ndPass."
        case .tooLarge: "The portable archive exceeds the supported size limit."
        case .invalidKey: "Enter the complete generated portable archive recovery key."
        }
    }
}

public enum PortableArchive {
    public static let maximumSize = 256 * 1024 * 1024
    private static let header = Data("2NDPASS-PORTABLE-ARCHIVE-1\n".utf8)
    private static let keyPrefix = Array("2ndpass-archive-key-v1:".utf8)

    public static func seal(_ document: PortableVaultArchive) throws -> PortableArchiveExport {
        try document.validate()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var plaintext = try encoder.encode(document)
        defer { SecretBytes.wipe(&plaintext) }
        guard plaintext.count <= maximumSize - header.count - 28 else { throw PortableArchiveFailure.tooLarge }
        let key = SymmetricKey(size: .bits256)
        guard let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: header).combined else { throw PortableArchiveFailure.invalid }
        let alphabet = Array("0123456789abcdef".utf8)
        var printable = keyPrefix
        defer { _ = printable.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        key.withUnsafeBytes { bytes in
            for byte in bytes { printable.append(alphabet[Int(byte >> 4)]); printable.append(alphabet[Int(byte & 15)]) }
        }
        return PortableArchiveExport(data: header + sealed, recoveryKey: SecretBytes(copying: printable))
    }

    public static func open(_ data: Data, recoveryKey: SecretBytes) throws -> PortableVaultArchive {
        guard data.count <= maximumSize else { throw PortableArchiveFailure.tooLarge }
        guard data.starts(with: header), data.count >= header.count + 28 else { throw PortableArchiveFailure.invalid }
        let key = try decodeKey(recoveryKey)
        var plaintext: Data
        do { plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: data.dropFirst(header.count)), using: key, authenticating: header) }
        catch { throw PortableArchiveFailure.invalid }
        defer { SecretBytes.wipe(&plaintext) }
        let document: PortableVaultArchive
        do { document = try JSONDecoder().decode(PortableVaultArchive.self, from: plaintext) }
        catch { throw PortableArchiveFailure.invalid }
        try document.validate()
        return document
    }

    private static func decodeKey(_ value: SecretBytes) throws -> SymmetricKey {
        var end = value.count
        while end > 0 && [UInt8(10), 13, 32, 9].contains(value[end - 1]) { end -= 1 }
        guard end == keyPrefix.count + 64, value.prefix(keyPrefix.count).elementsEqual(keyPrefix) else { throw PortableArchiveFailure.invalidKey }
        func nibble(_ byte: UInt8) throws -> UInt8 {
            switch byte {
            case 48...57: byte - 48
            case 97...102: byte - 87
            case 65...70: byte - 55
            default: throw PortableArchiveFailure.invalidKey
            }
        }
        var bytes = Data(capacity: 32)
        defer { SecretBytes.wipe(&bytes) }
        for offset in stride(from: keyPrefix.count, to: end, by: 2) {
            bytes.append(try (nibble(value[offset]) << 4) | nibble(value[offset + 1]))
        }
        return SymmetricKey(data: bytes)
    }
}
