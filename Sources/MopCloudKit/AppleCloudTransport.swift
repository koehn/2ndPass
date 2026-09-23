@preconcurrency import CloudKit
import Foundation
import Synchronization
import MopCore
import MopVault

/// Foreground operations with per-operation request/resource deadlines. No secrets
/// are passed here: payloads are ciphertext or public enrollment metadata.
public final class AppleCloudTransport: CloudTransport, @unchecked Sendable {
    public let container: String
    public let environment: String
    private let cloud: CKContainer
    private var database: CKDatabase { cloud.privateCloudDatabase }

    public init(container: String, environment: String) {
        self.container = container; self.environment = environment
        cloud = CKContainer(identifier: container)
    }

    private func zone(_ id: UUID) -> CKRecordZone.ID { CKRecordZone.ID(zoneName: "mop-" + id.uuidString, ownerName: CKCurrentUserDefaultName) }
    private func configure(_ op: CKOperation) {
        op.configuration.timeoutIntervalForRequest = 30
        op.configuration.timeoutIntervalForResource = 60
        op.configuration.qualityOfService = .userInitiated
    }

    public func account() async throws -> String {
        // CKContainer's convenience calls do not expose operation configuration.
        // Bound the caller even if account discovery stalls inside the framework.
        try await withCheckedThrowingContinuation { continuation in
            let completed = Mutex(false)
            let finish: @Sendable (Result<String, Error>) -> Void = { result in
                let first = completed.withLock { value in
                    if value { return false }; value = true; return true
                }
                if first { continuation.resume(with: result) }
            }
            Task {
                do {
                    let status = try await self.cloud.accountStatus()
                    if status == .noAccount || status == .restricted { throw MopError.cloudAccount }
                    guard status == .available else { throw MopError.cloudUnavailable }
                    finish(.success(try await self.cloud.userRecordID().recordName))
                } catch { finish(.failure(Self.map(error))) }
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 60) { finish(.failure(MopError.cloudUnavailable)) }
        }
    }

    public func validateOfflineAccount() async throws {
        // Account-status lookup is local; do not fetch a cloud user record offline.
        // An indeterminate status does not constitute evidence of sign-out.
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let completed = Mutex(false)
            let finish: @Sendable (Result<Void, Error>) -> Void = { result in
                let first = completed.withLock { value in if value { return false }; value = true; return true }
                if first { continuation.resume(with: result) }
            }
            cloud.accountStatus { status, _ in
                finish(status == .noAccount || status == .restricted ? .failure(MopError.cloudAccount) : .success(()))
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 2) { finish(.success(())) }
        }
    }

    public func zones() async throws -> [UUID] {
        let values: [CKRecordZone] = try await withCheckedThrowingContinuation { continuation in
            let result = Mutex<[CKRecordZone]>([])
            let op = CKFetchRecordZonesOperation.fetchAllRecordZonesOperation()
            configure(op)
            op.perRecordZoneResultBlock = { _, value in if case .success(let zone) = value { result.withLock { $0.append(zone) } } }
            op.fetchRecordZonesResultBlock = { value in
                switch value { case .success: continuation.resume(returning: result.withLock { $0 })
                case .failure(let error): continuation.resume(throwing: Self.map(error)) }
            }
            database.add(op)
        }
        return values.compactMap { $0.zoneID.zoneName.hasPrefix("mop-") ? UUID(uuidString: String($0.zoneID.zoneName.dropFirst(4))) : nil }.sorted { $0.uuidString < $1.uuidString }
    }

    public func createZone(_ vault: UUID) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let op = CKModifyRecordZonesOperation(recordZonesToSave: [CKRecordZone(zoneID: zone(vault))])
            configure(op)
            op.modifyRecordZonesResultBlock = { value in
                switch value { case .success: continuation.resume(); case .failure(let error): continuation.resume(throwing: Self.map(error)) }
            }
            database.add(op)
        }
    }

    private func record(_ id: String, vault: UUID) async throws -> CKRecord? {
        try await withCheckedThrowingContinuation { continuation in
            let result = Mutex<Result<CKRecord, Error>?>(nil)
            let op = CKFetchRecordsOperation(recordIDs: [CKRecord.ID(recordName: id, zoneID: zone(vault))])
            configure(op)
            op.perRecordResultBlock = { _, value in result.withLock { $0 = value } }
            op.fetchRecordsResultBlock = { value in
                if let item = result.withLock({ $0 }) {
                    switch item {
                    case .success(let record): continuation.resume(returning: record)
                    case .failure(let error):
                        if (error as? CKError)?.code == .unknownItem { continuation.resume(returning: nil) }
                        else { continuation.resume(throwing: Self.map(error)) }
                    }
                } else {
                    switch value { case .success: continuation.resume(throwing: MopError.cloudUnavailable)
                    case .failure(let error): continuation.resume(throwing: Self.map(error)) }
                }
            }
            database.add(op)
        }
    }

    private static func object(_ record: CKRecord) throws -> CloudObject {
        guard let asset = record["payload"] as? CKAsset, let url = asset.fileURL else { throw MopError.invalidVault }
        let data = try SafeFile.read(url)
        let coder = NSKeyedArchiver(requiringSecureCoding: true)
        record.encodeSystemFields(with: coder)
        coder.finishEncoding()
        return CloudObject(data: data, version: coder.encodedData)
    }

    public func fetch(_ id: String, vault: UUID) async throws -> CloudObject? {
        guard let record = try await record(id, vault: vault) else { return nil }
        return try Self.object(record)
    }

    public func save(_ id: String, kind: CloudKind, data: Data, vault: UUID, expected: Data?) async throws -> CloudObject {
        let record: CKRecord
        if let expected {
            do {
                let decoder = try NSKeyedUnarchiver(forReadingFrom: expected)
                decoder.requiresSecureCoding = true
                defer { decoder.finishDecoding() }
                guard let decoded = CKRecord(coder: decoder), decoded.recordID == CKRecord.ID(recordName: id, zoneID: zone(vault)), decoded.recordType == kind.rawValue else { throw MopError.invalidVault }
                record = decoded
            } catch { throw MopError.invalidVault }
        } else { record = CKRecord(recordType: kind.rawValue, recordID: CKRecord.ID(recordName: id, zoneID: zone(vault))) }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-cloud-" + UUID().uuidString)
        try SafeFile.privateDirectory(directory)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("payload")
        try SafeFile.write(data, to: file)
        record["payload"] = CKAsset(fileURL: file)
        let saved: CKRecord = try await withCheckedThrowingContinuation { continuation in
            let result = Mutex<Result<CKRecord, Error>?>(nil)
            let op = CKModifyRecordsOperation(recordsToSave: [record])
            configure(op); op.savePolicy = .ifServerRecordUnchanged; op.isAtomic = true
            op.perRecordSaveBlock = { _, value in result.withLock { $0 = value } }
            op.modifyRecordsResultBlock = { value in
                switch value {
                case .success:
                    if let item = result.withLock({ $0 }) { continuation.resume(with: item.mapError(Self.map)) }
                    else { continuation.resume(throwing: MopError.cloudUnavailable) }
                case .failure(let error):
                    if let item = result.withLock({ $0 }), case .failure(let specific) = item { continuation.resume(throwing: Self.map(specific)) }
                    else { continuation.resume(throwing: Self.map(error)) }
                }
            }
            database.add(op)
        }
        let coder = NSKeyedArchiver(requiringSecureCoding: true)
        saved.encodeSystemFields(with: coder); coder.finishEncoding()
        return CloudObject(data: data, version: coder.encodedData)
    }

    public func requests(vault: UUID) async throws -> [String] {
        var cursor: CKQueryOperation.Cursor?
        var ids: [String] = []
        repeat {
            let page: ([String], CKQueryOperation.Cursor?) = try await withCheckedThrowingContinuation { continuation in
                let rows = Mutex<[String]>([])
                let failure = Mutex<MopError?>(nil)
                let op = cursor.map { CKQueryOperation(cursor: $0) } ?? CKQueryOperation(query: CKQuery(recordType: CloudKind.request.rawValue, predicate: NSPredicate(value: true)))
                configure(op); op.zoneID = zone(vault); op.desiredKeys = []; op.resultsLimit = 100
                op.recordMatchedBlock = { id, result in
                    switch result { case .success: rows.withLock { $0.append(id.recordName) }
                    case .failure(let error): failure.withLock { $0 = Self.map(error) } }
                }
                op.queryResultBlock = { result in
                    if let error = failure.withLock({ $0 }) { continuation.resume(throwing: error); return }
                    switch result { case .success(let cursor): continuation.resume(returning: (rows.withLock { $0 }, cursor))
                    case .failure(let error): continuation.resume(throwing: Self.map(error)) }
                }
                database.add(op)
            }
            ids += page.0; cursor = page.1
            guard ids.count <= 10_000 else { throw MopError.invalidVault }
        } while cursor != nil
        return ids.sorted()
    }

    static func map(_ error: Error) -> MopError {
        if let error = error as? MopError { return error }
        guard let error = error as? CKError else { return .cloudUnavailable }
        if error.code == .partialFailure, let errors = error.partialErrorsByItemID {
            let mapped = errors.values.map(Self.map)
            for candidate in [MopError.vaultConflict, .cloudAccount, .cloudQuota, .cloudThrottled, .cloudPermission, .vaultMissing] {
                if mapped.contains(candidate) { return candidate }
            }
        }
        switch error.code {
        case .serverRecordChanged: return .vaultConflict
        case .notAuthenticated: return .cloudAccount
        case .accountTemporarilyUnavailable: return .cloudUnavailable
        case .quotaExceeded: return .cloudQuota
        case .requestRateLimited, .zoneBusy: return .cloudThrottled
        case .permissionFailure, .missingEntitlement, .badContainer, .badDatabase: return .cloudPermission
        case .zoneNotFound, .userDeletedZone: return .vaultMissing
        default: return .cloudUnavailable
        }
    }
}
