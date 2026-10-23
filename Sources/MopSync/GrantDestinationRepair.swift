@preconcurrency import CoreData
import Foundation

extension EncryptedItemRepository {
    private func recipientGrants(scope: VaultScope, recipient: String) throws -> [PreparedContentGrant] {
        try contentRows("ContentGrant", field: "vaultKey", equals: contentVaultKey(scope)).compactMap { row in
            guard let data = row.value(forKey: "value") as? Data else { throw ItemRepositoryError.corruptStore }
            let grant = try JSONDecoder().decode(PreparedContentGrant.self, from: data)
            return grant.recipient == recipient ? grant : nil
        }
    }

    func hasGrantDestinationRepairs(scope: VaultScope, recipient: String) throws -> Bool {
        try transaction {
            try recipientGrants(scope: scope, recipient: recipient).contains { grant in
                let key = contentGrantKey(scope: grant.scope, keyGeneration: grant.keyGeneration, suffix: grant.identifier)
                return try fetchOne("StateBlob", key: "grant-repair4:" + key) != nil
            }
        }
    }

    /// Observed remote absence invalidates delivery evidence, not local decryption.
    /// Requeue exact prepared bytes through normal authority-checked publication.
    public func invalidateGrantDestination(scope: VaultScope, recipient: String, identifier: String? = nil,
                                           permit: any RepositoryWritePermit) throws {
        let zone = try RecipientGrantZone(vault: scope.vaultID, recipient: recipient)
        try permit.withWritePermission {
            try transaction {
                for grant in try recipientGrants(scope: scope, recipient: recipient) where identifier == nil || identifier == grant.identifier {
                    try requeueGrantInTransaction(grant)
                }
                try touchVaultBoundary(scope)
                let key = blobKey(scope.account, "grant-initial-fetch4:" + zone.name)
                let row = try fetchOne("StateBlob", key: key) ?? NSEntityDescription.insertNewObject(forEntityName: "StateBlob", into: context)
                row.setValue(key, forKey: "key"); row.setValue(Data([0]), forKey: "value")
            }
        }
    }
    /// Queue one immutable repair without scanning every grant in the vault or
    /// doing per-item network I/O. The normal publisher validates current authority.
    public func repairGrantDelivery(_ grant: PreparedContentGrant, permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission {
            try transaction {
                guard try contentGrants(scope: grant.scope, keyGeneration: grant.keyGeneration,
                    recipient: grant.recipient).contains(grant) else { throw ContentStoreError.invalidRecord }
                try requeueGrantInTransaction(grant)
                try touchVaultBoundary(VaultScope(account: grant.scope.account, vaultID: grant.scope.vaultID,
                    database: grant.scope.database, zoneOwner: grant.scope.zoneOwner))
            }
        }
    }

    private func requeueGrantInTransaction(_ grant: PreparedContentGrant) throws {
        let scope = VaultScope(account: grant.scope.account, vaultID: grant.scope.vaultID,
            database: grant.scope.database, zoneOwner: grant.scope.zoneOwner)
        let key = contentGrantKey(scope: grant.scope, keyGeneration: grant.keyGeneration, suffix: grant.identifier)
        if let receipt = try fetchOne("StateBlob", key: "content-grant-delivery4:" + key) { context.delete(receipt) }
        try writeJournal(true, entity: "StateBlob", key: "grant-repair4:" + key)
        let operation = SyncOperation(id: contentOperationID("publish:" + key), account: scope.account,
            database: scope.database, vaultID: scope.vaultID, zoneOwner: scope.zoneOwner,
            kind: .grant, payload: try contentEncode(grant))
        let operationKey = journalKey(scope.account, scope.database, operation.id.uuidString)
        if let old: SyncOperation = try journalValue("SyncOperation", key: operationKey) {
            guard old.kind == operation.kind, old.payload == operation.payload else { throw SyncJournalError.identityCollision }
            if old.state == .completed {
                try writeJournal(operation, entity: "SyncOperation", key: operationKey, account: scope.account, database: scope.database)
            }
        } else { _ = try enqueueInTransaction(operation) }
    }

}
