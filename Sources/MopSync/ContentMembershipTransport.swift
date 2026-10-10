@preconcurrency import CloudKit
import CryptoKit
import Foundation

/// Membership signatures are shared primitives; the V3 zone is a separate
/// protocol address space. Immutable proposals do not by themselves advance trust.
public enum ContentMembershipTransport {
    public static func materialize(_ record: CKRecord, account: String) throws -> IncomingRecord {
        let prefix = "MopContent3-", zone = record.recordID.zoneID
        guard zone.zoneName.hasPrefix(prefix), let vault = UUID(uuidString: String(zone.zoneName.dropFirst(prefix.count))),
              zone.zoneName == SyncStoreLayout.contentZone(vault: vault), zone.ownerName == CKCurrentUserDefaultName,
              record.recordType == NativeVaultProvisioningTransport.recordType,
              let bytes = record["membership"] as? Data, !bytes.isEmpty, bytes.count <= 512 * 1024 else { throw CloudSyncAdapterError.malformedRecord }
        let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        guard record.recordID.recordName == "membership-head" || record.recordID.recordName == "membership-" + digest else { throw CloudSyncAdapterError.malformedRecord }
        let encoder = NSKeyedArchiver(requiringSecureCoding: true)
        record.encodeSystemFields(with: encoder); encoder.finishEncoding()
        let context = try JSONEncoder().encode([account, "private", zone.ownerName, zone.zoneName, record.recordType, record.recordID.recordName])
        let id = SHA256.hash(data: context + encoder.encodedData + bytes).map { String(format: "%02x", $0) }.joined()
        return IncomingRecord(id: id, account: account, database: "private", zoneName: zone.zoneName, zoneOwner: zone.ownerName,
            recordName: record.recordID.recordName, recordType: record.recordType, bytes: bytes,
            systemFields: encoder.encodedData, vaultID: vault)
    }
}
