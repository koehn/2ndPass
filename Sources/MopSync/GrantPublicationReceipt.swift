import Foundation

/// A receipt is evidence for one immutable record in one exact destination.
/// Payload equivalence alone cannot acknowledge another account, owner or zone.
public enum GrantPublicationReceipt {
    public static func validate(_ receipt: IncomingRecord, grant: PreparedContentGrant) throws {
        let destination = try RecipientGrantZone(vault: grant.scope.vaultID, recipient: grant.recipient)
        guard receipt.account == grant.scope.account, receipt.database == grant.scope.database,
              receipt.vaultID == grant.scope.vaultID, receipt.zoneOwner == grant.scope.zoneOwner,
              receipt.zoneName == destination.name, receipt.recordType == ContentRecordKind.grant.rawValue,
              receipt.recordName == grant.scope.itemID.uuidString + ":" + grant.identifier,
              receipt.bytes == grant.bytes, !receipt.systemFields.isEmpty, receipt.systemFields.count <= 1_048_576 else { throw ContentStoreError.identityCollision }
    }
}
