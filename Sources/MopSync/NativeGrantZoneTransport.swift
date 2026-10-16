import CloudKit
import Foundation

/// Provisions the current recipient-specific grant destination.
public struct NativeGrantZoneTransport: Sendable {
    public let database: CKDatabase
    private let account: String
    private let validator: CloudAccountValidator
    private let permit: any RepositoryWritePermit
    public init(database: CKDatabase, account: String, validator: @escaping CloudAccountValidator,
                permit: any RepositoryWritePermit) {
        self.database = database; self.account = account; self.validator = validator; self.permit = permit
    }
    private func check(_ grant: PreparedContentGrant? = nil) async throws {
        try Task.checkCancellation(); try permit.withWritePermission {}
        guard database.databaseScope == .private, !account.isEmpty,
              grant == nil || (grant?.scope.account == account && grant?.scope.database == "private" && grant?.scope.zoneOwner == CKCurrentUserDefaultName),
              try await validator() else { throw CloudSyncAdapterError.accountChanged }
        try permit.withWritePermission {}
    }
    public func provision(_ name: String) async throws {
        _ = try RecipientGrantZone(name: name)
        try await check()
        _ = try await database.save(CKRecordZone(zoneID: CKRecordZone.ID(zoneName: name, ownerName: CKCurrentUserDefaultName)))
        try await check()
    }
    @discardableResult
    public func publishAndVerify(_ grant: PreparedContentGrant) async throws -> IncomingRecord {
        let record = try ContentRecordTransport.grant(grant)
        try await check(grant)
        do { _ = try await database.save(record) }
        catch let error as CKError where error.code == .serverRecordChanged { /* exact readback below */ }
        catch {
            AccessSyncTrace.event("grant publication failed", detail: "zone=\(record.recordID.zoneID.zoneName) code=\((error as NSError).code)")
            throw error
        }
        return try await verifyPublication(grant)
    }
    @discardableResult
    public func verifyPublication(_ grant: PreparedContentGrant) async throws -> IncomingRecord {
        let record = try ContentRecordTransport.grant(grant)
        try await check(grant)
        let saved = try await database.record(for: record.recordID)
        try await check(grant)
        let incoming = try ContentRecordTransport.materialize(saved, account: grant.scope.account)
        try GrantPublicationReceipt.validate(incoming, grant: grant)
        return incoming
    }
}
