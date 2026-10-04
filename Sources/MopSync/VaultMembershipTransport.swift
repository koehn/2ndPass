@preconcurrency import CloudKit
import Foundation

/// An existing commissioned zone only: membership changes never create a zone.
/// The caller owns the database lease and verifies every signed history edge.
public protocol VaultMembershipTransport: Sendable {
    func readHead(binding: VaultProvisioningBinding) async throws -> ProvisioningCloudRecord
    func readMembership(binding: VaultProvisioningBinding, digest: String) async throws -> Data
    func createMembership(binding: VaultProvisioningBinding, digest: String, bytes: Data) async throws
    func compareAndSwapHead(binding: VaultProvisioningBinding, bytes: Data,
                            expected: ProvisioningCloudRecord) async throws -> ProvisioningCloudRecord
}

public struct NativeVaultMembershipTransport: VaultMembershipTransport {
    private let database: CKDatabase
    private let provisioning: NativeVaultProvisioningTransport
    public init(database: CKDatabase) {
        self.database = database; provisioning = NativeVaultProvisioningTransport(database: database)
    }
    public func readHead(binding: VaultProvisioningBinding) async throws -> ProvisioningCloudRecord {
        guard let value = try await provisioning.readControl(.head, binding: binding) else { throw VaultProvisioningError.controlMismatch }
        return value
    }
    private func named(_ binding: VaultProvisioningBinding, digest: String) throws -> VaultProvisioningBinding {
        guard digest.count == 64, digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw VaultProvisioningError.controlMismatch
        }
        return VaultProvisioningBinding(scope: binding.scope, address: binding.address,
            setupID: binding.setupID, controlDigest: digest)
    }
    public func readMembership(binding: VaultProvisioningBinding, digest: String) async throws -> Data {
        guard let value = try await provisioning.readControl(.genesis, binding: named(binding, digest: digest)) else {
            throw VaultProvisioningError.controlMismatch
        }
        return value.bytes
    }
    public func createMembership(binding: VaultProvisioningBinding, digest: String, bytes: Data) async throws {
        let stored = try await provisioning.createControl(.genesis, binding: named(binding, digest: digest), bytes: bytes)
        guard stored.bytes == bytes else { throw VaultProvisioningError.controlMismatch }
    }
    public func compareAndSwapHead(binding: VaultProvisioningBinding, bytes: Data,
                                   expected: ProvisioningCloudRecord) async throws -> ProvisioningCloudRecord {
        guard database.databaseScope == .private, binding.scope.database == "private",
              binding.scope.zoneOwner == CKCurrentUserDefaultName, binding.address.ownerName == CKCurrentUserDefaultName,
              binding.address.vaultID == binding.scope.vaultID, !bytes.isEmpty, bytes.count <= 512 * 1024 else {
            throw VaultProvisioningError.invalidBinding
        }
        let decoder = try NSKeyedUnarchiver(forReadingFrom: expected.systemFields)
        decoder.requiresSecureCoding = true
        defer { decoder.finishDecoding() }
        guard let record = CKRecord(coder: decoder),
              record.recordType == NativeVaultProvisioningTransport.recordType,
              record.recordID == NativeVaultProvisioningTransport.recordID(.head, binding: binding) else {
            throw VaultProvisioningError.controlMismatch
        }
        record["membership"] = bytes as CKRecordValue
        do {
            let response = try await database.modifyRecords(saving: [record], deleting: [], savePolicy: .ifServerRecordUnchanged, atomically: true)
            guard let result = response.saveResults[record.recordID] else { throw VaultProvisioningError.controlMismatch }
            return try NativeVaultProvisioningTransport.decode(result.get(), kind: .head, binding: binding)
        } catch let error as CKError where error.code == .zoneNotFound { throw VaultProvisioningError.zoneMissing }
        // Lost acknowledgements are recovered by a separate exact readback. A
        // changed head is never overwritten merely because its author is valid.
    }
}
