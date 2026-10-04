import CloudKit
import Foundation
import Testing
@testable import MopSync

@Test func cloudRecordContainsNoLocalAccountIdentityAndBindsDestination() throws {
    let scope = ItemScope(account: "private-local-account-binding", vaultID: UUID(), itemID: UUID())
    let version = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1, 2, 3]))
    let address = VaultCloudAddress(vaultID: scope.vaultID, zoneName: "vault-zone", ownerName: scope.zoneOwner)
    let record = try CloudKitSyncAdapter.makeRecord(version, address: address)
    #expect(record.recordID.recordName == scope.itemID.uuidString)
    #expect(record.recordID.zoneID.zoneName == address.zoneName)
    #expect(record.recordType == CloudKitSyncAdapter.recordType)
    let envelope = try #require(record["envelope"] as? Data)
    #expect(!String(decoding: envelope, as: UTF8.self).contains(scope.account))
    #expect(throws: CloudSyncAdapterError.invalidBinding) {
        try CloudKitSyncAdapter.makeRecord(version, address: VaultCloudAddress(vaultID: UUID(), zoneName: address.zoneName, ownerName: scope.zoneOwner))
    }
    #expect(throws: CloudSyncAdapterError.invalidBinding) {
        try CloudKitSyncAdapter.makeRecord(version, address: VaultCloudAddress(vaultID: scope.vaultID, zoneName: address.zoneName, ownerName: "other-owner"))
    }
    let encoder = NSKeyedArchiver(requiringSecureCoding: true)
    record.encodeSystemFields(with: encoder)
    encoder.finishEncoding()
    let subsequent = try CloudKitSyncAdapter.makeRecord(version, address: address, serverSystemFields: encoder.encodedData)
    #expect(subsequent.recordID == record.recordID)
    let wrongItem = EncryptedItemVersion(scope: ItemScope(account: scope.account, vaultID: scope.vaultID, itemID: UUID()), baseVersionID: nil, ciphertext: Data([4]))
    #expect(throws: CloudSyncAdapterError.invalidBinding) {
        try CloudKitSyncAdapter.makeRecord(wrongItem, address: address, serverSystemFields: encoder.encodedData)
    }
}

@Test func synchronizationLeaseExcludesConcurrentOwnersAndReleases() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-lease-test-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let path = directory.appendingPathComponent("engine.lock")
    var first: SynchronizationLease? = try SynchronizationLease(url: path)
    #expect(first != nil)
    #expect(throws: CloudSyncAdapterError.engineAlreadyOwned) { try SynchronizationLease(url: path) }
    first = nil
    let next = try SynchronizationLease(url: path)
    withExtendedLifetime(next) {}
}

@Test func largeCloudItemUsesEncryptedAssetsAndRoundTripsWithoutSilentTruncation() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-asset-test-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let scope = ItemScope(account: "account", vaultID: UUID(), itemID: UUID())
    let ciphertext = Data(repeating: 42, count: 1024 * 1024)
    let version = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: ciphertext)
    let address = VaultCloudAddress(vaultID: scope.vaultID, zoneName: "vault-zone", ownerName: scope.zoneOwner)
    #expect(throws: (any Error).self) { try CloudKitSyncAdapter.makeRecord(version, address: address) }
    let record = try CloudKitSyncAdapter.makeRecord(version, address: address, assetDirectory: directory)
    let decoded = try CloudKitSyncAdapter.unverifiedVersion(from: record, account: scope.account, database: scope.database, address: address)
    #expect(decoded == version)
    let staged = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
    #expect(!staged.isEmpty)
    for file in staged { try FileManager.default.removeItem(at: file) }
    #expect(throws: (any Error).self) {
        try CloudKitSyncAdapter.unverifiedVersion(from: record, account: scope.account, database: scope.database, address: address)
    }
}

@Test func conflictRecoveryFetchesCompleteAssetRecordAndRejectsWrongIdentity() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-conflict-assets-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let scope = ItemScope(account: "account", vaultID: UUID(), itemID: UUID())
    let version = EncryptedItemVersion(scope: scope, baseVersionID: UUID(),
        ciphertext: Data(repeating: 42, count: 1024 * 1024), generation: 2)
    let address = VaultCloudAddress(vaultID: scope.vaultID, zoneName: "vault-zone", ownerName: scope.zoneOwner)
    let complete = try CloudKitSyncAdapter.makeRecord(version, address: address, assetDirectory: directory)
    // The callback carries only an identity; recovery must fetch the full payload.
    let shell = CKRecord(recordType: CloudKitSyncAdapter.recordType, recordID: complete.recordID)
    let fetched = try await CloudKitSyncAdapter.fetchConflictRecord(shell.recordID) { id in
        #expect(id == complete.recordID)
        return complete
    }
    #expect(try CloudKitSyncAdapter.unverifiedVersion(from: fetched, account: scope.account,
        database: scope.database, address: address) == version)
    await #expect(throws: CloudSyncAdapterError.invalidBinding) {
        try await CloudKitSyncAdapter.fetchConflictRecord(shell.recordID) { _ in
            CKRecord(recordType: CloudKitSyncAdapter.recordType, recordID: CKRecord.ID(recordName: UUID().uuidString))
        }
    }
    await #expect(throws: CancellationError.self) {
        try await CloudKitSyncAdapter.fetchConflictRecord(shell.recordID) { _ in throw CancellationError() }
    }
}
