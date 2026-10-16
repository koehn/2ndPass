@preconcurrency import CloudKit
import Foundation

/// Removing a trusted vault removes both its download routes and pending writes,
/// including zone creation. Otherwise a queued saveZone can resurrect a deletion.
public enum ContentZoneRouting {
    public static func belongs(_ zone: CKRecordZone.ID, to address: VaultCloudAddress) -> Bool {
        guard zone.ownerName == address.ownerName else { return false }
        return zone.zoneName == address.zoneName || (try? RecipientGrantZone(name: zone.zoneName).vault) == address.vaultID
    }
    public static func belongs(_ change: CKSyncEngine.PendingRecordZoneChange, to address: VaultCloudAddress) -> Bool {
        switch change {
        case .saveRecord(let id), .deleteRecord(let id): return belongs(id.zoneID, to: address)
        @unknown default: return false
        }
    }
    public static func belongs(_ change: CKSyncEngine.PendingDatabaseChange, to address: VaultCloudAddress) -> Bool {
        switch change {
        case .saveZone(let zone): return belongs(zone.zoneID, to: address)
        case .deleteZone(let id): return belongs(id, to: address)
        @unknown default: return false
        }
    }
}
