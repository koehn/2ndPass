@preconcurrency import CloudKit
import Foundation

public struct NativeVaultDeletionTransport: VaultDeletionTransport {
    public static let recordType = "MopVaultDeletionV1"
    public static let zoneName = "MopVaultDeletions1"
    private let database: CKDatabase
    public init(database: CKDatabase) { self.database = database }
    private func recordID(_ vault: UUID) throws -> CKRecord.ID {
        guard database.databaseScope == .private else { throw VaultDeletionFailure.invalidNotice }
        return CKRecord.ID(recordName: vault.uuidString, zoneID: .init(zoneName: Self.zoneName, ownerName: CKCurrentUserDefaultName))
    }
    public func read(vaultID: UUID) async throws -> Data? {
        let id = try recordID(vaultID)
        do {
            let record = try await database.record(for: id)
            guard record.recordType == Self.recordType, let bytes = record["notice"] as? Data,
                  bytes.count <= 1_048_576 else { throw VaultDeletionFailure.invalidNotice }
            return bytes
        } catch let error as CKError where error.code == .unknownItem || error.code == .zoneNotFound { return nil }
    }
    public func publish(vaultID: UUID, notice: Data) async throws -> Data {
        let id = try recordID(vaultID)
        guard notice.count <= 1_048_576 else { throw VaultDeletionFailure.invalidNotice }
        _ = try await database.save(CKRecordZone(zoneID: id.zoneID))
        let record = CKRecord(recordType: Self.recordType, recordID: id)
        record["notice"] = notice as CKRecordValue
        do {
            let result = try await database.modifyRecords(saving: [record], deleting: [], savePolicy: .ifServerRecordUnchanged, atomically: true)
            _ = try result.saveResults[id]?.get()
        } catch let error as CKError where error.code == .serverRecordChanged {
            guard let existing = try await read(vaultID: vaultID) else { throw VaultDeletionFailure.invalidNotice }
            return existing
        }
        guard let confirmed = try await read(vaultID: vaultID) else { throw VaultDeletionFailure.invalidNotice }
        return confirmed
    }
    public func deleteZone(address: VaultCloudAddress) async throws {
        guard database.databaseScope == .private, address.ownerName == CKCurrentUserDefaultName,
              address.zoneName == "MopItems-" + address.vaultID.uuidString else { throw VaultDeletionFailure.invalidNotice }
        do { _ = try await database.deleteRecordZone(withID: address.zoneID) }
        catch let error as CKError where error.code == .zoneNotFound || error.code == .unknownItem { return }
    }
}
