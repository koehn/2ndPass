import Foundation

extension EncryptedItemRepository {
    /// Recovery/enrollment completion needs independent successful fetches AND
    /// local pairs for the enrolled recipient. A content checkpoint alone says
    /// nothing about another zone's delivery or its durable inbox application.
    public func recipientGrantReadiness(scope: VaultScope, recipient: String) throws -> Bool {
        let zone = try RecipientGrantZone(vault: scope.vaultID, recipient: recipient)
        guard try engineState(account: scope.account, database: "content-initial-fetch:" + scope.vaultID.uuidString) == Data([1]),
              try engineState(account: scope.account, database: "grant-initial-fetch4:" + zone.name) == Data([1]) else { return false }
        guard try !hasGrantDestinationRepairs(scope: scope, recipient: recipient) else { return false }
        let index = try itemRevisionIndex(account: scope.account, vaultID: scope.vaultID,
            database: scope.database, zoneOwner: scope.zoneOwner)
        guard !index.isEmpty else { return false }
        for (item, version) in index {
            let itemScope = ItemScope(account: scope.account, vaultID: scope.vaultID, itemID: item,
                database: scope.database, zoneOwner: scope.zoneOwner)
            guard let content = try contentVersion(scope: itemScope, version: version),
                  try !contentGrants(scope: itemScope, keyGeneration: content.keyGeneration, recipient: recipient).isEmpty else { return false }
        }
        return true
    }
}
