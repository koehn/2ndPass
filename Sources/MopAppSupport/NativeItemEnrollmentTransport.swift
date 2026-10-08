@preconcurrency import CloudKit
import Foundation
import MopCore
import MopSync
import MopVaultNext

/// The authenticated private database is the bootstrap trust channel for devices
/// on the same Apple Account. Discovery alone never installs vault authority.
struct NativeItemEnrollmentTransport: Sendable {
    static let zoneName = "MopEnrollment-v1"
    private let account: NativeItemCloudAccount
    init(account: NativeItemCloudAccount) { self.account = account }
    private var database: CKDatabase { account.container.privateCloudDatabase }
    private var zone: CKRecordZone.ID { CKRecordZone.ID(zoneName: Self.zoneName, ownerName: CKCurrentUserDefaultName) }
    private func checked() async throws {
        guard try await account.validate() else { throw MopError.cloudAccount }
        try Task.checkCancellation()
    }
    func discover() async throws -> [VaultDescriptor] {
        try await checked()
        let zones = try await database.allRecordZones()
        try await checked()
        return zones.compactMap { zone in
            let prefix = "MopItems-"
            guard zone.zoneID.ownerName == CKCurrentUserDefaultName,
                  zone.zoneID.zoneName.hasPrefix(prefix),
                  let id = UUID(uuidString: String(zone.zoneID.zoneName.dropFirst(prefix.count))),
                  zone.zoneID.zoneName == prefix + id.uuidString else { return nil }
            return VaultDescriptor(id: id.uuidString, name: nil, format: "mop-items-v2", enrolled: false)
        }.sorted { $0.id < $1.id }
    }
    func prepare() async throws {
        try await checked()
        _ = try await database.save(CKRecordZone(zoneID: zone))
        let subscription = CKRecordZoneSubscription(zoneID: zone, subscriptionID: "mop-enrollment-v1")
        let info = CKSubscription.NotificationInfo(); info.shouldSendContentAvailable = true
        subscription.notificationInfo = info
        _ = try await database.save(subscription)
        try await checked()
    }
    func save(_ bytes: Data, id: UUID, approval: Bool) async throws {
        guard !bytes.isEmpty, bytes.count <= 512 * 1024 else { throw MopError.invalidVault }
        try await prepare()
        let recordID = identifier(id, approval: approval)
        if let existing = try await read(id: id, approval: approval) {
            guard existing == bytes else { throw MopError.vaultConflict }; return
        }
        let record = CKRecord(recordType: NativeVaultProvisioningTransport.recordType, recordID: recordID)
        record["membership"] = bytes as CKRecordValue
        do {
            let result = try await database.modifyRecords(saving: [record], deleting: [], savePolicy: .ifServerRecordUnchanged, atomically: true)
            guard let saved = result.saveResults[recordID] else { throw MopError.cloudUncertain }
            _ = try saved.get()
        } catch {
            guard let saved = try? await read(id: id, approval: approval), saved == bytes else { throw error }
        }
        try await checked()
    }
    func read(id: UUID, approval: Bool) async throws -> Data? {
        try await checked()
        do {
            let record = try await database.record(for: identifier(id, approval: approval))
            try await checked()
            return try bytes(record)
        } catch let error as CKError where error.code == .unknownItem || error.code == .zoneNotFound { return nil }
    }
    func requests() async throws -> [(UUID, Data)] {
        try await checked()
        var token: CKServerChangeToken?
        var records: [CKRecord.ID: Data] = [:]
        repeat {
            let page: (modificationResultsByID: [CKRecord.ID: Result<CKDatabase.RecordZoneChange.Modification, any Error>], deletions: [CKDatabase.RecordZoneChange.Deletion], changeToken: CKServerChangeToken, moreComing: Bool)
            do { page = try await database.recordZoneChanges(inZoneWith: zone, since: token, resultsLimit: 100) }
            catch let error as CKError where error.code == .zoneNotFound { return [] }
            try await checked()
            for (id, result) in page.modificationResultsByID {
                let record = try result.get().record
                records[id] = try bytes(record)
            }
            for deletion in page.deletions { records.removeValue(forKey: deletion.recordID) }
            guard records.count <= 1024 else { throw MopError.invalidVault }
            token = page.changeToken
            if !page.moreComing { break }
        } while true
        return records.compactMap { id, bytes in
            guard id.recordName.hasPrefix("request-"),
                  let requestID = UUID(uuidString: String(id.recordName.dropFirst("request-".count))),
                  records[identifier(requestID, approval: true)] == nil else { return nil }
            return (requestID, bytes)
        }
    }
    /// Delete only relay records whose decoded scope names this committed vault.
    /// No zone-wide deletion: the relay also serves unrelated vaults.
    func purgeDeletedVault(_ vaultID: UUID) async throws {
        try await checked()
        var token: CKServerChangeToken?
        var targets: Set<CKRecord.ID> = []
        repeat {
            let page: (modificationResultsByID: [CKRecord.ID: Result<CKDatabase.RecordZoneChange.Modification, any Error>], deletions: [CKDatabase.RecordZoneChange.Deletion], changeToken: CKServerChangeToken, moreComing: Bool)
            do { page = try await database.recordZoneChanges(inZoneWith: zone, since: token, resultsLimit: 100) }
            catch let error as CKError where error.code == .zoneNotFound { return }
            try await checked()
            for (id, result) in page.modificationResultsByID {
                let data = try bytes(result.get().record)
                let scope: EnrollmentScope
                if id.recordName.hasPrefix("request-") { scope = try DeviceEnrollmentRequest.decode(data).scope }
                else if id.recordName.hasPrefix("approval-") { scope = try DeviceEnrollmentApproval.decode(data).request.scope }
                else { continue }
                if scope.vault == vaultID, scope.account == account.accountNamespace,
                   scope.container == account.containerIdentifier, scope.environment == account.environment { targets.insert(id) }
            }
            for deletion in page.deletions { targets.remove(deletion.recordID) }
            token = page.changeToken
            if !page.moreComing { break }
        } while true
        for id in targets {
            try await checked()
            do { _ = try await database.deleteRecord(withID: id) }
            catch let error as CKError where error.code == .unknownItem || error.code == .zoneNotFound { }
        }
    }
    func admissionMetadata(approval: MopVaultNext.DeviceEnrollmentApproval) async throws -> (EncryptedItemVersion, Data, [MopVaultNext.MembershipEnvelope])? {
        try await checked()
        let vault = approval.request.scope.vault
        let address = VaultCloudAddress(vaultID: vault, zoneName: "MopItems-" + vault.uuidString, ownerName: CKCurrentUserDefaultName)
        let binding = VaultProvisioningBinding(scope: VaultScope(account: account.accountNamespace, vaultID: vault),
            address: address, setupID: "enrollment-read", controlDigest: try approval.history[0].digest())
        let transport = NativeVaultMembershipTransport(database: database)
        let head = try MopVaultNext.MembershipEnvelope.decode(try await transport.readHead(binding: binding).bytes)
        let accepted = try approval.successor.digest()
        var current = head, reverse: [MopVaultNext.MembershipEnvelope] = []
        while try current.digest() != accepted {
            guard reverse.count < 4096, current.header.generation > approval.successor.header.generation,
                  let parent = current.header.parent else { throw MopError.vaultUntrusted }
            reverse.append(current)
            current = try MopVaultNext.MembershipEnvelope.decode(try await transport.readMembership(binding: binding, digest: parent))
        }
        let record: CKRecord
        do { record = try await database.record(for: CKRecord.ID(recordName: ItemVaultSession.metadataRecordID.uuidString,
                zoneID: CKRecordZone.ID(zoneName: address.zoneName, ownerName: address.ownerName))) }
        catch let error as CKError where error.code == .unknownItem { return nil }
        try await checked()
        let version = try CloudKitSyncAdapter.unverifiedVersion(from: record, account: account.accountNamespace, database: "private", address: address)
        // Head publication precedes the queued metadata rewrite. Do not install
        // a joining pin until that rewrite reaches this same membership state.
        let metadata = try JSONDecoder().decode(VaultMetadataEnvelope.self, from: version.ciphertext)
        guard metadata.header.membership == (try head.digest()) else { return nil }
        let coder = NSKeyedArchiver(requiringSecureCoding: true); record.encodeSystemFields(with: coder); coder.finishEncoding()
        return (version, coder.encodedData, Array(reverse.reversed()))
    }
    func removeRequest(_ id: UUID) async throws {
        try await checked()
        do { _ = try await database.deleteRecord(withID: identifier(id, approval: false)) }
        catch let error as CKError where error.code == .unknownItem || error.code == .zoneNotFound { }
        try await checked()
    }
    private func identifier(_ id: UUID, approval: Bool) -> CKRecord.ID {
        CKRecord.ID(recordName: (approval ? "approval-" : "request-") + id.uuidString, zoneID: zone)
    }
    private func bytes(_ record: CKRecord) throws -> Data {
        guard record.recordID.zoneID == zone, record.recordType == NativeVaultProvisioningTransport.recordType,
              let bytes = record["membership"] as? Data, !bytes.isEmpty, bytes.count <= 512 * 1024 else { throw MopError.invalidVault }
        return bytes
    }
}
