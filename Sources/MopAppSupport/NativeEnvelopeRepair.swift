@preconcurrency import CloudKit
import Foundation
import MopCore
import MopSync
import MopVaultNext

/// Durable signed requests share the same private relay and wake-up subscription
/// as enrollment. Only the requester deletes a request after verifying access.
struct NativeEnvelopeRepair: Sendable {
    let account: NativeItemCloudAccount
    private var database: CKDatabase { account.container.privateCloudDatabase }
    private var zone: CKRecordZone.ID { CKRecordZone.ID(zoneName: NativeItemEnrollmentTransport.zoneName, ownerName: CKCurrentUserDefaultName) }
    private func id(_ request: EnvelopeRepairRequest) throws -> CKRecord.ID {
        try CKRecord.ID(recordName: "repair-" + request.identifier, zoneID: zone)
    }
    func requests() async throws -> [(CKRecord.ID, EnvelopeRepairRequest)] {
        let transport = NativeItemRecoveryTransport(account: account)
        try await transport.check()
        var token: CKServerChangeToken?, values: [CKRecord.ID: EnvelopeRepairRequest] = [:]
        repeat {
            let page: (modificationResultsByID: [CKRecord.ID: Result<CKDatabase.RecordZoneChange.Modification, any Error>], deletions: [CKDatabase.RecordZoneChange.Deletion], changeToken: CKServerChangeToken, moreComing: Bool)
            do { page = try await database.recordZoneChanges(inZoneWith: zone, since: token, resultsLimit: 100) }
            catch let error as CKError where error.code == .zoneNotFound { return [] }
            for (recordID, result) in page.modificationResultsByID where recordID.recordName.hasPrefix("repair-") {
                let record = try result.get().record
                guard let bytes = record["membership"] as? Data,
                      let request = try? EnvelopeRepairRequest.decode(bytes), (try? id(request)) == recordID else { continue }
                values[recordID] = request
            }
            for deletion in page.deletions { values.removeValue(forKey: deletion.recordID) }
            token = page.changeToken
            try await transport.check()
            if !page.moreComing { break }
        } while true
        return Array(values)
    }
    func request(_ request: EnvelopeRepairRequest) async throws {
        let transport = NativeItemRecoveryTransport(account: account)
        try await transport.check()
        try await NativeItemEnrollmentTransport(account: account).prepare()
        let recordID = try id(request)
        do {
            let existing = try await database.record(for: recordID)
            guard let bytes = existing["membership"] as? Data,
                  try EnvelopeRepairRequest.decode(bytes).identifier == request.identifier else { throw MopError.invalidVault }
            return
        } catch let error as CKError where error.code == .unknownItem { }
        let record = CKRecord(recordType: NativeVaultProvisioningTransport.recordType, recordID: recordID)
        record["membership"] = try request.encoded() as CKRecordValue
        let result = try await database.modifyRecords(saving: [record], deleting: [], savePolicy: .ifServerRecordUnchanged, atomically: true)
        guard let saved = result.saveResults[recordID] else { throw MopError.cloudUncertain }
        do { _ = try saved.get() }
        catch let error as CKError where error.code == .serverRecordChanged { /* Same deterministic request; retry verifies it. */ }
    }
    /// Caller owns the synchronization lease with the uploader stopped.
    func reconcile(vault: UUID, device: any DeviceOperations, check: ItemRecoveryCoordinator.Check) async throws {
        let transport = NativeItemRecoveryTransport(account: account)
        let (history, _) = try await transport.history(vault)
        guard history.current.membership.role(of: device.identity) != nil else { throw MopError.cloudPermission }
        let scope = EnrollmentScope(container: account.containerIdentifier, environment: account.environment,
            account: account.accountNamespace, vault: vault, member: account.memberID)
        let records = try await transport.records(vault)
        let pending = try await requests().filter { $0.1.scope.vault == vault }
        for (record, _) in records {
            try check(); try ItemEnvelopeTransition.verify(record, history: history)
            let old = try history.state(forDigest: ItemEnvelopeTransition.membershipDigest(record))
            if old.membership.role(of: device.identity) == nil {
                try await request(EnvelopeRepairRequest.create(scope: scope, record: record.scope.itemID,
                    version: record.versionID, history: history, device: device))
            }
        }
        for (recordID, request) in pending {
            try check()
            guard (try? request.verify(scope: scope, history: history)) != nil,
                  let (record, fields) = records.first(where: { $0.0.scope.itemID == request.record }) else { continue }
            try ItemEnvelopeTransition.verify(record, history: history)
            let old = try history.state(forDigest: ItemEnvelopeTransition.membershipDigest(record))
            if request.requester == device.identity {
                if (try? ItemEnvelopeTransition.verifyReadable(record, history: history, device: device)) != nil {
                    try await transport.check(); try check(); _ = try await database.deleteRecord(withID: recordID)
                }
            } else if old.membership.role(of: request.requester) == nil,
                      old.membership.role(of: device.identity) == .owner {
                let replacement = try ItemEnvelopeTransition.rewrite(record, history: history, decryptor: device, signer: device)
                try check()
                do { try await transport.save(replacement, expected: fields) }
                catch let error as CKError where error.code == .serverRecordChanged { continue }
            }
        }
    }
}
