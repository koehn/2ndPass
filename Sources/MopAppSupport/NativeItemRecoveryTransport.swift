@preconcurrency import CloudKit
import Foundation
import MopCore
import MopSync
import MopVaultNext

/// All inputs originate in the authenticated same-account private database.
/// Cloud discovery is only an address list; callers still verify each history.
struct NativeItemRecoveryTransport: Sendable {
    let account: NativeItemCloudAccount
    var database: CKDatabase { account.container.privateCloudDatabase }
    func check() async throws {
        try Task.checkCancellation()
        guard try await account.validate() else { throw MopError.cloudAccount }
    }
    func address(_ vault: UUID) -> VaultCloudAddress {
        VaultCloudAddress(vaultID: vault, zoneName: "MopItems-" + vault.uuidString, ownerName: CKCurrentUserDefaultName)
    }
    func binding(_ vault: UUID) -> VaultProvisioningBinding {
        VaultProvisioningBinding(scope: VaultScope(account: account.accountNamespace, vaultID: vault),
            address: address(vault), setupID: "recovery", controlDigest: "")
    }
    func history(_ vault: UUID) async throws -> (TrustedMembershipHistory, ProvisioningCloudRecord) {
        try await check()
        let transport = NativeVaultMembershipTransport(database: database), binding = binding(vault)
        let head = try await transport.readHead(binding: binding)
        var states = [try MembershipEnvelope.decode(head.bytes)]
        while let parent = states.last?.header.parent {
            guard states.count < 4096 else { throw MopError.invalidVault }
            let next = try MembershipEnvelope.decode(try await transport.readMembership(binding: binding, digest: parent))
            guard try next.digest() == parent else { throw MopError.vaultUntrusted }
            states.append(next)
        }
        guard let genesis = states.last, genesis.membership.accounts.count == 1,
              genesis.membership.accounts[0].id == account.memberID else { throw MopError.cloudPermission }
        let scope = try account.setupScope(vaultID: vault), store = try KeychainItemVaultTrustStore()
        let pinned = try store.load(scope: scope)
        let rootDigest = try genesis.digest()
        guard pinned == nil || pinned?.pinnedDigest == rootDigest else { throw MopError.vaultUntrusted }
        var history = try TrustedMembershipHistory(genesis: genesis, vault: vault, pinnedDigest: rootDigest)
        for next in states.reversed().dropFirst() {
            if let request = next.recoveryRequest {
                guard request.scope.container == account.containerIdentifier, request.scope.environment == account.environment,
                      request.scope.account == account.accountNamespace else { throw MopError.vaultUntrusted }
            }
            try next.verifyAccountTransition(of: history.current); try history.append(next)
        }
        if let pinned {
            let local = try ItemVaultMembershipAuthority.history(record: pinned, trustStore: store)
            guard try history.state(forDigest: local.current.digest()) == local.current else { throw MopError.vaultUntrusted }
        }
        try await check()
        return (history, head)
    }
    func publish(_ successor: MembershipEnvelope, expected: ProvisioningCloudRecord) async throws {
        try await check()
        let transport = NativeVaultMembershipTransport(database: database), binding = binding(successor.header.vault)
        let bytes = try successor.encoded()
        try await transport.createMembership(binding: binding, digest: successor.digest(), bytes: bytes)
        do { _ = try await transport.compareAndSwapHead(binding: binding, bytes: bytes, expected: expected) }
        catch {
            guard let readback = try? await transport.readHead(binding: binding), readback.bytes == bytes else { throw error }
        }
        try await check()
    }
    func records(_ vault: UUID) async throws -> [(EncryptedItemVersion, Data)] {
        try await check()
        var token: CKServerChangeToken?, records: [CKRecord.ID: (EncryptedItemVersion, Data)] = [:]
        repeat {
            let page = try await database.recordZoneChanges(inZoneWith: CKRecordZone.ID(zoneName: address(vault).zoneName, ownerName: CKCurrentUserDefaultName), since: token, resultsLimit: 100)
            for (id, result) in page.modificationResultsByID {
                let record = try result.get().record
                guard record.recordType == CloudKitSyncAdapter.recordType else { continue }
                records[id] = (try CloudKitSyncAdapter.unverifiedVersion(from: record, account: account.accountNamespace,
                    database: "private", address: address(vault)), Self.systemFields(record))
            }
            for deletion in page.deletions { records.removeValue(forKey: deletion.recordID) }
            token = page.changeToken
            try await check()
            if !page.moreComing { break }
        } while true
        return Array(records.values)
    }
    @discardableResult func save(_ version: EncryptedItemVersion, expected: Data) async throws -> Data {
        try await check()
        let assets = account.directory.appendingPathComponent("RecoveryAssets").appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: assets, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: assets) }
        let record = try CloudKitSyncAdapter.makeRecord(version, address: address(version.scope.vaultID),
            serverSystemFields: expected, assetDirectory: assets)
        let response = try await database.modifyRecords(saving: [record], deleting: [], savePolicy: .ifServerRecordUnchanged, atomically: true)
        guard let saved = response.saveResults[record.recordID] else { throw MopError.cloudUncertain }
        let committed = try saved.get(); try await check()
        return Self.systemFields(committed)
    }
    private var configurationID: CKRecord.ID {
        CKRecord.ID(recordName: "recovery-configuration", zoneID: CKRecordZone.ID(zoneName: NativeItemEnrollmentTransport.zoneName, ownerName: CKCurrentUserDefaultName))
    }
    func configuration() async throws -> (RecoveryConfiguration, CKRecord?) {
        try await check()
        do {
            let record = try await database.record(for: configurationID)
            guard let bytes = record["membership"] as? Data else { throw MopError.invalidRecovery }
            let value = try JSONDecoder().decode(RecoveryConfiguration.self, from: bytes)
            try value.validate()
            guard value.scope == account.recoveryScope else { throw MopError.cloudAccount }
            return (value, record)
        } catch let error as CKError where error.code == .unknownItem || error.code == .zoneNotFound {
            return (RecoveryConfiguration(scope: account.recoveryScope), nil)
        }
    }
    func saveConfiguration(_ value: RecoveryConfiguration, expected: CKRecord?) async throws {
        try value.validate(); try await check()
        try await NativeItemEnrollmentTransport(account: account).prepare()
        let record = expected ?? CKRecord(recordType: NativeVaultProvisioningTransport.recordType, recordID: configurationID)
        record["membership"] = try JSONEncoder().encode(value) as CKRecordValue
        let response = try await database.modifyRecords(saving: [record], deleting: [], savePolicy: .ifServerRecordUnchanged, atomically: true)
        guard let saved = response.saveResults[record.recordID] else { throw MopError.cloudUncertain }
        _ = try saved.get(); try await check()
    }
    static func systemFields(_ record: CKRecord) -> Data {
        let coder = NSKeyedArchiver(requiringSecureCoding: true); record.encodeSystemFields(with: coder); coder.finishEncoding()
        return coder.encodedData
    }
}
