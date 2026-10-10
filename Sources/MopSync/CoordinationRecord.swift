@preconcurrency import CloudKit
import CryptoKit
import Foundation
import MopCore

/// These are routing identities, not evidence of authority. Only a cryptographic
/// handler may move an incoming record into the accepted coordination index.
public enum CoordinationRecordKind: String, Codable, Sendable, CaseIterable {
    case discovery, enrollmentRequest, enrollmentApproval, enrollmentAcknowledgment, grantRequest, deletion
    public var recordType: String { "MopCoordination" + rawValue.prefix(1).uppercased() + rawValue.dropFirst() + "V3" }
    public var maximumBytes: Int { self == .enrollmentApproval ? 16 * 1024 * 1024 : self == .deletion ? 1024 * 1024 : 256 * 1024 }
}

public struct PreparedCoordinationRecord: Codable, Equatable, Sendable {
    public let account: String
    public let zoneOwner: String
    public let vault: UUID
    public let kind: CoordinationRecordKind
    public let identity: UUID
    public let bytes: Data
    public var recordName: String { kind.rawValue + ":" + vault.uuidString + ":" + identity.uuidString }
    public var recordID: CKRecord.ID { CKRecord.ID(recordName: recordName,
        zoneID: CKRecordZone.ID(zoneName: SyncStoreLayout.contentCoordinationZone, ownerName: zoneOwner)) }
    public var operationID: UUID {
        let hash = Array(SHA256.hash(data: Data((account + ":" + zoneOwner + ":" + recordName).utf8)).prefix(16))
        return UUID(uuid: (hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]))
    }
    public init(account: String, zoneOwner: String = "__defaultOwner__", vault: UUID, kind: CoordinationRecordKind, identity: UUID, bytes: Data) throws {
        guard !account.isEmpty, zoneOwner == "__defaultOwner__", !bytes.isEmpty, bytes.count <= kind.maximumBytes else { throw CloudSyncAdapterError.invalidBinding }
        self.account = account; self.zoneOwner = zoneOwner; self.vault = vault
        self.kind = kind; self.identity = identity; self.bytes = bytes
    }
    public func operation(dependencies: Set<SyncDependency> = []) throws -> SyncOperation {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return SyncOperation(id: operationID, account: account, vaultID: vault, zoneOwner: zoneOwner,
            kind: .publishCoordination, payload: try encoder.encode(self), dependencies: dependencies)
    }
    public func record(assetURL: URL? = nil) throws -> CKRecord {
        _ = try Self(account: account, zoneOwner: zoneOwner, vault: vault, kind: kind, identity: identity, bytes: bytes)
        let record = CKRecord(recordType: kind.recordType, recordID: recordID)
        if bytes.count <= ContentRecordTransport.inlineLimit { record["payload"] = bytes as CKRecordValue }
        else {
            guard let assetURL, try Data(contentsOf: assetURL, options: .mappedIfSafe) == bytes else { throw CloudSyncAdapterError.assetDirectoryRequired }
            record["asset"] = CKAsset(fileURL: assetURL)
        }
        return record
    }
    public func record(assetDirectory: URL) throws -> CKRecord {
        guard bytes.count > ContentRecordTransport.inlineLimit else { return try record() }
        let accountHash = SHA256.hash(data: Data(account.utf8)).map { String(format: "%02x", $0) }.joined()
        let directory = assetDirectory.appendingPathComponent(accountHash).appendingPathComponent(vault.uuidString)
        try LocalFile.privateDirectory(directory)
        let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        let url = directory.appendingPathComponent(operationID.uuidString + "-" + digest + ".ciphertext")
        if !FileManager.default.fileExists(atPath: url.path) {
            do { try LocalFile.write(bytes, to: url) } catch MopError.duplicate {}
        }
        guard try LocalFile.read(url, privateFile: true, limit: kind.maximumBytes) == bytes else { throw CloudSyncAdapterError.invalidBinding }
        return try record(assetURL: url)
    }

    public static func address(recordType: String, zone: String, record: String) throws -> (kind: CoordinationRecordKind, vault: UUID, identity: UUID) {
        let parts = record.split(separator: ":", omittingEmptySubsequences: false)
        guard zone == SyncStoreLayout.contentCoordinationZone, parts.count == 3,
              let kind = CoordinationRecordKind(rawValue: String(parts[0])), kind.recordType == recordType,
              let vault = UUID(uuidString: String(parts[1])), parts[1] == Substring(vault.uuidString),
              let identity = UUID(uuidString: String(parts[2])), parts[2] == Substring(identity.uuidString) else { throw CloudSyncAdapterError.malformedRecord }
        return (kind, vault, identity)
    }
    public static func materialize(_ record: CKRecord, account: String) throws -> IncomingRecord {
        let address = try address(recordType: record.recordType, zone: record.recordID.zoneID.zoneName, record: record.recordID.recordName)
        guard record.recordID.zoneID.ownerName == "__defaultOwner__", !account.isEmpty else { throw CloudSyncAdapterError.invalidBinding }
        let bytes: Data
        if let inline = record["payload"] as? Data, record["asset"] == nil { bytes = inline }
        else if record["payload"] == nil, let url = (record["asset"] as? CKAsset)?.fileURL {
            guard (try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max) <= address.kind.maximumBytes else { throw CloudSyncAdapterError.malformedRecord }
            bytes = try Data(contentsOf: url)
        } else { throw CloudSyncAdapterError.malformedRecord }
        guard !bytes.isEmpty, bytes.count <= address.kind.maximumBytes else { throw CloudSyncAdapterError.malformedRecord }
        let encoder = NSKeyedArchiver(requiringSecureCoding: true)
        record.encodeSystemFields(with: encoder); encoder.finishEncoding()
        let context = try JSONEncoder().encode([account, "private", record.recordID.zoneID.ownerName, record.recordID.zoneID.zoneName, record.recordType, record.recordID.recordName])
        let digest = SHA256.hash(data: context + encoder.encodedData + bytes).map { String(format: "%02x", $0) }.joined()
        return IncomingRecord(id: digest, account: account, database: "private", zoneName: record.recordID.zoneID.zoneName,
            zoneOwner: record.recordID.zoneID.ownerName, recordName: record.recordID.recordName,
            recordType: record.recordType, bytes: bytes, systemFields: encoder.encodedData, vaultID: address.vault)
    }
}
