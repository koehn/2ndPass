@preconcurrency import CloudKit
import CryptoKit
import Foundation
import MopCore

/// Addresses are routing hints only. The application handler authenticates every
/// payload against independently pinned authority before exposing it to readers.
public enum ContentRecordKind: String, Sendable {
    case head = "MopContentHeadV3", version = "MopContentVersionV3", grant = "MopContentGrantV3"
}

public struct ContentRecordAddress: Sendable {
    public let kind: ContentRecordKind
    public let vault: UUID
    public let item: UUID
    public let identity: String?

    public init(recordType: String, zone: String, record: String) throws {
        guard let kind = ContentRecordKind(rawValue: recordType), zone.hasPrefix("MopContent3-"),
              let vault = UUID(uuidString: String(zone.dropFirst("MopContent3-".count))),
              zone == SyncStoreLayout.contentZone(vault: vault) else { throw CloudSyncAdapterError.malformedRecord }
        let parts = record.split(separator: ":", omittingEmptySubsequences: false)
        guard let first = parts.first, let item = UUID(uuidString: String(first)), first == Substring(item.uuidString),
              parts.count == (kind == .head ? 1 : 2) else { throw CloudSyncAdapterError.malformedRecord }
        let identity = parts.count == 2 ? String(parts[1]) : nil
        if kind == .version {
            guard let identity, let version = UUID(uuidString: identity), version.uuidString == identity else { throw CloudSyncAdapterError.malformedRecord }
        }
        if kind == .grant {
            guard let identity, identity.utf8.count == 64,
                  identity.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw CloudSyncAdapterError.malformedRecord }
        }
        self.kind = kind; self.vault = vault; self.item = item; self.identity = identity
    }
}

public enum ContentRecordTransport {
    public static let inlineLimit = 512 * 1024
    public static let assetChunkLimit = 16 * 1024 * 1024

    /// Persist a version record before/with its mutable head. Immutable versions
    /// make skipped ancestry fetchable by identity without whole-zone scans.
    public static func content(_ content: PreparedContentVersion, kind: ContentRecordKind,
                               systemFields: Data? = nil, assetURL: URL? = nil, assetURLs: [URL]? = nil) throws -> CKRecord {
        guard kind != .grant else { throw CloudSyncAdapterError.malformedRecord }
        let version = content.version
        let name = version.scope.itemID.uuidString + (kind == .version ? ":" + version.versionID.uuidString : "")
        return try record(kind: kind, scope: version.scope, name: name, bytes: version.ciphertext, systemFields: systemFields, assetURL: assetURL, assetURLs: assetURLs)
    }

    public static func publication(_ content: PreparedContentVersion, headSystemFields: Data? = nil,
                                   assetURL: URL? = nil) throws -> (version: CKRecord, head: CKRecord) {
        (try self.content(content, kind: .version, assetURL: assetURL),
         try self.content(content, kind: .head, systemFields: headSystemFields, assetURL: assetURL))
    }

    public static func grant(_ grant: PreparedContentGrant, systemFields: Data? = nil) throws -> CKRecord {
        guard grant.bytes.count <= 16_384 else { throw CloudSyncAdapterError.malformedRecord }
        return try record(kind: .grant, scope: grant.scope, name: grant.scope.itemID.uuidString + ":" + grant.identifier,
            bytes: grant.bytes, systemFields: systemFields, assetURL: nil)
    }

    private static func record(kind: ContentRecordKind, scope: ItemScope, name: String, bytes: Data,
                               systemFields: Data?, assetURL: URL?, assetURLs: [URL]? = nil) throws -> CKRecord {
        guard !bytes.isEmpty, bytes.count <= EncryptedItemRepository.maximumCiphertextBytes,
              scope.database == "private", !scope.account.isEmpty else { throw CloudSyncAdapterError.malformedRecord }
        let zone = CKRecordZone.ID(zoneName: SyncStoreLayout.contentZone(vault: scope.vaultID), ownerName: scope.zoneOwner)
        _ = try ContentRecordAddress(recordType: kind.rawValue, zone: zone.zoneName, record: name)
        let id = CKRecord.ID(recordName: name, zoneID: zone)
        let record: CKRecord
        if let systemFields {
            let decoder = try NSKeyedUnarchiver(forReadingFrom: systemFields)
            decoder.requiresSecureCoding = true
            defer { decoder.finishDecoding() }
            guard let restored = CKRecord(coder: decoder), restored.recordID == id,
                  restored.recordType == kind.rawValue else { throw CloudSyncAdapterError.malformedRecord }
            record = restored
        } else { record = CKRecord(recordType: kind.rawValue, recordID: id) }
        if bytes.count <= inlineLimit {
            record["payload"] = bytes as CKRecordValue; record["asset"] = nil; record["assets"] = nil
        } else {
            let urls = assetURLs ?? assetURL.map { [$0] } ?? []
            guard !urls.isEmpty, urls.count <= (EncryptedItemRepository.maximumCiphertextBytes + assetChunkLimit - 1) / assetChunkLimit else { throw CloudSyncAdapterError.assetDirectoryRequired }
            var materialized = Data()
            for url in urls { materialized.append(try LocalFile.read(url, limit: assetChunkLimit)) }
            guard materialized == bytes else { throw CloudSyncAdapterError.invalidBinding }
            record["payload"] = nil
            record["asset"] = urls.count == 1 ? CKAsset(fileURL: urls[0]) : nil
            record["assets"] = urls.count > 1 ? urls.map { CKAsset(fileURL: $0) } as CKRecordValue : nil
        }
        return record
    }

    /// Materializes downloaded assets into app-owned durable inbox bytes. Never
    /// persist a temporary CKAsset URL and then advance the engine checkpoint.
    public static func materialize(_ record: CKRecord, account: String, database: String = "private") throws -> IncomingRecord {
        let address = try ContentRecordAddress(recordType: record.recordType,
            zone: record.recordID.zoneID.zoneName, record: record.recordID.recordName)
        guard !account.isEmpty, database == "private" else { throw CloudSyncAdapterError.invalidBinding }
        let bytes: Data
        if let inline = record["payload"] as? Data, record["asset"] == nil, record["assets"] == nil {
            guard inline.count <= inlineLimit else { throw CloudSyncAdapterError.malformedRecord }
            bytes = inline
        } else if record["payload"] == nil {
            let assets: [CKAsset]
            if let asset = record["asset"] as? CKAsset, record["assets"] == nil { assets = [asset] }
            else if let chunks = record["assets"] as? [CKAsset], record["asset"] == nil { assets = chunks }
            else { throw CloudSyncAdapterError.malformedRecord }
            guard !assets.isEmpty, assets.count <= (EncryptedItemRepository.maximumCiphertextBytes + assetChunkLimit - 1) / assetChunkLimit else { throw CloudSyncAdapterError.malformedRecord }
            var materialized = Data()
            for asset in assets {
                guard let url = asset.fileURL else { throw CloudSyncAdapterError.malformedRecord }
                let chunk = try LocalFile.read(url, limit: assetChunkLimit)
                guard !chunk.isEmpty, materialized.count <= EncryptedItemRepository.maximumCiphertextBytes - chunk.count else { throw CloudSyncAdapterError.malformedRecord }
                materialized.append(chunk)
            }
            bytes = materialized
        } else { throw CloudSyncAdapterError.malformedRecord }
        let maximum = address.kind == .grant ? 16_384 : EncryptedItemRepository.maximumCiphertextBytes
        guard !bytes.isEmpty, bytes.count <= maximum else { throw CloudSyncAdapterError.malformedRecord }
        let encoder = NSKeyedArchiver(requiringSecureCoding: true)
        record.encodeSystemFields(with: encoder); encoder.finishEncoding()
        let fields = encoder.encodedData
        let identity = try JSONEncoder().encode([account, database, record.recordID.zoneID.ownerName,
            record.recordID.zoneID.zoneName, record.recordType, record.recordID.recordName])
        let digest = SHA256.hash(data: identity + fields + bytes).map { String(format: "%02x", $0) }.joined()
        return IncomingRecord(id: digest, account: account, database: database, zoneName: record.recordID.zoneID.zoneName,
            zoneOwner: record.recordID.zoneID.ownerName, recordName: record.recordID.recordName, recordType: record.recordType,
            bytes: bytes, systemFields: fields, vaultID: address.vault)
    }
}
