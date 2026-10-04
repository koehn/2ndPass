@preconcurrency import CloudKit
import Foundation

/// Performs no network work until invoked by the lease-owning coordinator.
public struct NativeVaultProvisioningTransport: VaultProvisioningTransport {
    public static let recordType = "MopMembershipControlV1"
    private let database: CKDatabase
    public init(database: CKDatabase) { self.database = database }
    private func zone(_ binding: VaultProvisioningBinding) throws -> CKRecordZone.ID {
        guard database.databaseScope == .private, binding.scope.database == "private",
              binding.scope.zoneOwner == CKCurrentUserDefaultName,
              binding.address.ownerName == CKCurrentUserDefaultName,
              binding.address.vaultID == binding.scope.vaultID else { throw VaultProvisioningError.invalidBinding }
        return binding.address.zoneID
    }
    public func zoneExists(binding: VaultProvisioningBinding) async throws -> Bool {
        let id = try zone(binding)
        do { _ = try await database.recordZone(for: id); return true }
        catch let error as CKError where error.code == .zoneNotFound || error.code == .unknownItem { return false }
    }
    public func createZone(binding: VaultProvisioningBinding) async throws {
        _ = try await database.save(CKRecordZone(zoneID: zone(binding)))
    }
    public static func recordID(_ kind: VaultControlRecordKind, binding: VaultProvisioningBinding) -> CKRecord.ID {
        let name: String
        switch kind { case .genesis: name = "membership-" + binding.controlDigest; case .head: name = "membership-head" }
        return CKRecord.ID(recordName: name, zoneID: binding.address.zoneID)
    }
    public func readControl(_ kind: VaultControlRecordKind, binding: VaultProvisioningBinding) async throws -> ProvisioningCloudRecord? {
        _ = try zone(binding)
        do { return try Self.decode(try await database.record(for: Self.recordID(kind, binding: binding)), kind: kind, binding: binding) }
        catch let error as CKError where error.code == .unknownItem { return nil }
        catch let error as CKError where error.code == .zoneNotFound { throw VaultProvisioningError.zoneMissing }
    }
    public func createControl(_ kind: VaultControlRecordKind, binding: VaultProvisioningBinding, bytes: Data) async throws -> ProvisioningCloudRecord {
        _ = try zone(binding)
        guard !bytes.isEmpty, bytes.count <= 512 * 1024 else { throw VaultProvisioningError.controlMismatch }
        let record = CKRecord(recordType: Self.recordType, recordID: Self.recordID(kind, binding: binding))
        record["membership"] = bytes as CKRecordValue
        do {
            let result = try await database.modifyRecords(saving: [record], deleting: [], savePolicy: .ifServerRecordUnchanged, atomically: true)
            guard let saved = result.saveResults[record.recordID] else { throw VaultProvisioningError.controlMismatch }
            return try Self.decode(saved.get(), kind: kind, binding: binding)
        } catch let error as CKError where error.code == .zoneNotFound {
            throw VaultProvisioningError.zoneMissing
        } catch let error as CKError where error.code == .serverRecordChanged {
            guard let existing = try await readControl(kind, binding: binding) else { throw VaultProvisioningError.controlMismatch }
            return existing
        }
    }
    public static func decode(_ record: CKRecord, kind: VaultControlRecordKind,
                              binding: VaultProvisioningBinding) throws -> ProvisioningCloudRecord {
        guard record.recordType == recordType, record.recordID == recordID(kind, binding: binding),
              let bytes = record["membership"] as? Data, !bytes.isEmpty, bytes.count <= 512 * 1024 else {
            throw VaultProvisioningError.controlMismatch
        }
        let coder = NSKeyedArchiver(requiringSecureCoding: true)
        record.encodeSystemFields(with: coder); coder.finishEncoding()
        return ProvisioningCloudRecord(bytes: bytes, systemFields: coder.encodedData)
    }
}
