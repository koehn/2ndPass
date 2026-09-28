@preconcurrency import CloudKit
import Foundation
import Synchronization
import MopCore
import MopKeychain

/// V6 uses its own zones and record types. Transport permissions are independent
/// of the signed roster: a CKShare alone never authorizes a cryptographic change.
public final class CloudRevisionTransport: VaultTransport, @unchecked Sendable {
    private let cloud: CKContainer
    private let container: String
    private let environment: String
    public init(container: String, environment: String) throws {
        let provisioned = try SigningIdentity.cloudConfiguration()
        guard container == provisioned.container, environment == provisioned.environment else { throw MopError.cloudInvalidRequest }
        self.container = container; self.environment = environment
        cloud = CKContainer(identifier: container)
    }
    private func configure(_ operation: CKOperation) {
        operation.configuration.timeoutIntervalForRequest = 30
        operation.configuration.timeoutIntervalForResource = 60
        operation.configuration.qualityOfService = .userInitiated
    }
    private func database(_ address: VaultAddress) -> CKDatabase {
        address.database == .private ? cloud.privateCloudDatabase : cloud.sharedCloudDatabase
    }
    private func zone(_ address: VaultAddress) -> CKRecordZone.ID {
        CKRecordZone.ID(zoneName: address.zoneName, ownerName: address.owner)
    }
    private func id(_ name: String, _ address: VaultAddress) -> CKRecord.ID {
        CKRecord.ID(recordName: name, zoneID: zone(address))
    }
    public func account() async throws -> String {
        // Bound discovery separately; CKContainer convenience calls lack an
        // operation configuration. A late callback cannot resume twice.
        try await withCheckedThrowingContinuation { continuation in
            let finished = Mutex(false)
            let finish: @Sendable (Result<String, Error>) -> Void = { result in
                if finished.withLock({ if $0 { return false }; $0 = true; return true }) { continuation.resume(with: result) }
            }
            Task {
                do {
                    guard try await self.cloud.accountStatus() == .available else { throw MopError.cloudAccount }
                    finish(.success(try await self.cloud.userRecordID().recordName))
                } catch { finish(.failure(Self.map(error))) }
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 60) { finish(.failure(MopError.cloudUnavailable)) }
        }
    }
    /// Discovery is an enrollment hint, never a trusted checkpoint or key grant.
    public func discover() async throws -> [VaultAddress] {
        let expectedAccount = try await account()
        var addresses: [VaultAddress] = []
        for scope in [VaultAddress.Database.private, .shared] {
            let database = scope == .private ? cloud.privateCloudDatabase : cloud.sharedCloudDatabase
            let zones: [CKRecordZone] = try await withCheckedThrowingContinuation { continuation in
                let operation = CKFetchRecordZonesOperation.fetchAllRecordZonesOperation()
                configure(operation)
                let fetched = Mutex<[CKRecordZone]>([])
                let failure = Mutex<MopError?>(nil)
                operation.perRecordZoneResultBlock = { _, result in
                    switch result {
                    case .success(let zone): fetched.withLock { $0.append(zone) }
                    case .failure(let error): failure.withLock { $0 = Self.map(error) }
                    }
                }
                operation.fetchRecordZonesResultBlock = { result in
                    switch result {
                    case .failure(let error): continuation.resume(throwing: Self.map(error))
                    case .success:
                        if let error = failure.withLock({ $0 }) { continuation.resume(throwing: error) }
                        else { continuation.resume(returning: fetched.withLock { $0 }) }
                    }
                }
                database.add(operation)
            }
            for zone in zones where zone.zoneID.zoneName.hasPrefix("mop-v7-") {
                guard let id = VaultAddress.discoveredVault(in: zone.zoneID.zoneName) else { continue }
                addresses.append(try VaultAddress(container: container, environment: environment,
                    account: expectedAccount, database: scope, owner: zone.zoneID.ownerName, vault: id))
            }
        }
        guard try await account() == expectedAccount else { throw MopError.cloudAccount }
        return addresses.sorted { $0.binding < $1.binding }
    }
    private func check(_ address: VaultAddress) async throws {
        guard address.container == container, address.environment == environment,
              address.database != .shared || address.owner != CKCurrentUserDefaultName else { throw MopError.cloudInvalidRequest }
        guard try await account() == address.account else { throw MopError.cloudAccount }
    }
    private func fetch(_ name: String, _ address: VaultAddress) async throws -> CKRecord {
        try await withCheckedThrowingContinuation { continuation in
            let item = Mutex<Result<CKRecord, Error>?>(nil)
            let operation = CKFetchRecordsOperation(recordIDs: [id(name, address)])
            configure(operation)
            operation.perRecordResultBlock = { _, result in item.withLock { $0 = result } }
            operation.fetchRecordsResultBlock = { result in
                if let value = item.withLock({ $0 }) { continuation.resume(with: value.mapError(Self.map)) }
                else if case .failure(let error) = result { continuation.resume(throwing: Self.map(error)) }
                else { continuation.resume(throwing: MopError.cloudUnavailable) }
            }
            database(address).add(operation)
        }
    }
    private func save(_ record: CKRecord, _ address: VaultAddress) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let item = Mutex<Result<CKRecord, Error>?>(nil)
            let operation = CKModifyRecordsOperation(recordsToSave: [record])
            configure(operation); operation.savePolicy = .ifServerRecordUnchanged; operation.isAtomic = true
            operation.perRecordSaveBlock = { _, result in item.withLock { $0 = result } }
            operation.modifyRecordsResultBlock = { result in
                if case .failure(let error)? = item.withLock({ $0 }) { continuation.resume(throwing: Self.map(error)) }
                else if case .failure(let error) = result { continuation.resume(throwing: Self.map(error)) }
                else if case .success? = item.withLock({ $0 }) { continuation.resume() }
                else { continuation.resume(throwing: MopError.cloudUncertain) }
            }
            database(address).add(operation)
        }
    }
    public func enrollment(at address: VaultAddress) async throws -> EnrollmentInbox {
        try await check(address)
        guard address.database == .private, address.namespace == .user else { throw MopError.cloudPermission }
        let record: CKRecord
        do { record = try await fetch("enrollment", address) }
        catch MopError.vaultMissing { return EnrollmentInbox(mailbox: EnrollmentMailbox(), version: nil) }
        guard record.recordType == "MopV7Enrollment", let asset = record["payload"] as? CKAsset, let url = asset.fileURL else { throw MopError.invalidVault }
        let data = try LocalFile.read(url, limit: 16 * 1024 * 1024)
        let coder = NSKeyedArchiver(requiringSecureCoding: true)
        record.encodeSystemFields(with: coder); coder.finishEncoding()
        try await check(address)
        return try EnrollmentInbox(mailbox: EnrollmentMailbox.decode(data), version: coder.encodedData)
    }
    public func saveEnrollment(_ mailbox: EnrollmentMailbox, version: Data?, at address: VaultAddress) async throws {
        try await check(address)
        guard address.database == .private, address.namespace == .user else { throw MopError.cloudPermission }
        let record: CKRecord
        if let version {
            let decoder = try NSKeyedUnarchiver(forReadingFrom: version); decoder.requiresSecureCoding = true
            defer { decoder.finishDecoding() }
            guard let restored = CKRecord(coder: decoder), restored.recordID == id("enrollment", address), restored.recordType == "MopV7Enrollment" else { throw MopError.invalidVault }
            record = restored
        } else { record = CKRecord(recordType: "MopV7Enrollment", recordID: id("enrollment", address)) }
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("mop-enrollment-" + UUID().uuidString)
        try LocalFile.privateDirectory(folder)
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appendingPathComponent("payload")
        try LocalFile.write(mailbox.encoded(), to: file)
        record["payload"] = CKAsset(fileURL: file)
        try await save(record, address); try await check(address)
    }
    public func head(at address: VaultAddress) async throws -> RevisionHead {
        try await check(address)
        let record = try await fetch("head", address)
        guard record.recordType == "MopV7Head", let digest = record["digest"] as? String, Codec.hash(digest) else { throw MopError.invalidVault }
        let coder = NSKeyedArchiver(requiringSecureCoding: true)
        record.encodeSystemFields(with: coder); coder.finishEncoding()
        try await check(address)
        return RevisionHead(digest: digest, version: coder.encodedData)
    }
    public func revision(_ digest: String, at address: VaultAddress) async throws -> Data {
        guard Codec.hash(digest) else { throw MopError.invalidVault }
        try await check(address)
        let record = try await fetch(digest, address)
        guard record.recordType == "MopV7Revision", let asset = record["payload"] as? CKAsset, let url = asset.fileURL else { throw MopError.invalidVault }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let bytes = try handle.read(upToCount: Codec.maximumSize + 1) ?? Data()
        guard bytes.count <= Codec.maximumSize, Codec.digest(bytes) == digest else { throw MopError.invalidVault }
        try await check(address)
        return bytes
    }
    public func upload(_ bytes: Data, digest: String, at address: VaultAddress) async throws {
        guard bytes.count <= Codec.maximumSize, Codec.digest(bytes) == digest else { throw MopError.invalidVault }
        let revision = try Revision.decode(bytes)
        guard revision.header.vault == address.vault else { throw MopError.invalidVault }
        try await check(address)
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("mop-v7-upload-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let url = folder.appendingPathComponent("ciphertext")
        try bytes.write(to: url, options: [.atomic])
        let record = CKRecord(recordType: "MopV7Revision", recordID: id(digest, address))
        record["payload"] = CKAsset(fileURL: url)
        do { try await save(record, address) }
        catch MopError.vaultConflict {
            // Idempotent immutable upload, not an overwrite. Refetch assets:
            // CloudKit conflict records need not contain downloaded asset files.
            guard try await self.revision(digest, at: address) == bytes else { throw MopError.invalidVault }
        }
        try await check(address)
    }
    public func attachment(_ digest: String, at address: VaultAddress) async throws -> Data {
        guard Codec.hash(digest) else { throw MopError.invalidVault }
        try await check(address)
        let record = try await fetch("attachment-" + digest, address)
        guard record.recordType == "MopV7Attachment", let asset = record["payload"] as? CKAsset, let url = asset.fileURL else { throw MopError.invalidVault }
        let bytes = try LocalFile.read(url, limit: Codec.maximumSize)
        guard Codec.digest(bytes) == digest else { throw MopError.invalidVault }
        try await check(address)
        return bytes
    }
    public func uploadAttachment(_ bytes: Data, digest: String, at address: VaultAddress) async throws {
        guard bytes.count <= Codec.maximumSize, Codec.hash(digest), Codec.digest(bytes) == digest else { throw MopError.invalidVault }
        try await check(address)
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("mop-attachment-" + UUID().uuidString)
        try LocalFile.privateDirectory(folder)
        defer { try? FileManager.default.removeItem(at: folder) }
        let url = folder.appendingPathComponent("ciphertext")
        try LocalFile.write(bytes, to: url)
        let record = CKRecord(recordType: "MopV7Attachment", recordID: id("attachment-" + digest, address))
        record["payload"] = CKAsset(fileURL: url)
        do { try await save(record, address) }
        catch MopError.vaultConflict {
            guard try await attachment(digest, at: address) == bytes else { throw MopError.invalidVault }
        }
        try await check(address)
    }
    public func publish(_ digest: String, expectedVersion: Data, at address: VaultAddress) async throws {
        guard Codec.hash(digest), expectedVersion.count <= 65536 else { throw MopError.invalidVault }
        try await check(address)
        let decoder = try NSKeyedUnarchiver(forReadingFrom: expectedVersion)
        decoder.requiresSecureCoding = true
        defer { decoder.finishDecoding() }
        guard let record = CKRecord(coder: decoder), record.recordID == id("head", address),
              record.recordType == "MopV7Head", record.recordChangeTag != nil else { throw MopError.invalidVault }
        record["digest"] = digest
        // Explicitly mutate a field even for a same-digest reconciliation fence.
        record["operation"] = UUID().uuidString
        try await save(record, address)
        try await check(address)
    }

    /// Explicit first publication only. A failed response is uncertain: the
    /// caller must persist the locally generated genesis before calling this,
    /// retain its ID/digest, and reconcile that same root rather than creating
    /// a second vault. Refresh never calls this method.
    public func initialize(_ genesis: VerifiedVault, at address: VaultAddress) async throws {
        guard address.database == .private, address.owner == CKCurrentUserDefaultName,
              genesis.id == address.vault, genesis.generation == 1 else { throw MopError.cloudInvalidRequest }
        try genesis.revision.verifyGenesis()
        guard genesis.attachmentDigests.isSubset(of: Set(genesis.loadedAttachments.keys)) else { throw AttachmentFailure.unavailable }
        try await check(address)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let operation = CKModifyRecordZonesOperation(recordZonesToSave: [CKRecordZone(zoneID: zone(address))])
            configure(operation)
            operation.modifyRecordZonesResultBlock = { result in continuation.resume(with: result.mapError(Self.map)) }
            database(address).add(operation)
        }
        try await AttachmentUploads.upload(genesis, transport: self, address: address)
        try await upload(genesis.bytes, digest: genesis.digest, at: address)
        try Task.checkCancellation()
        let record = CKRecord(recordType: "MopV7Head", recordID: id("head", address))
        record["digest"] = genesis.digest; record["operation"] = UUID().uuidString
        do { try await save(record, address) }
        catch MopError.vaultConflict {
            guard try await head(at: address).digest == genesis.digest else { throw MopError.vaultConflict }
        }
        try await check(address)
    }
    private static func map(_ error: Error) -> MopError {
        if let error = error as? MopError { return error }
        guard let error = error as? CKError else { return .cloudUnavailable }
        if error.code == .partialFailure, let errors = error.partialErrorsByItemID {
            let mapped = errors.values.map(Self.map)
            for candidate in [MopError.vaultConflict, .cloudAccount, .cloudPermission, .vaultMissing] where mapped.contains(candidate) { return candidate }
        }
        switch error.code {
        case .serverRecordChanged: return .vaultConflict
        case .notAuthenticated: return .cloudAccount
        case .permissionFailure, .missingEntitlement, .badContainer, .badDatabase: return .cloudPermission
        case .unknownItem, .zoneNotFound, .userDeletedZone: return .vaultMissing
        case .quotaExceeded: return .cloudQuota
        case .requestRateLimited, .zoneBusy: return .cloudThrottled
        case .invalidArguments: return .cloudInvalidRequest
        default: return .cloudUnavailable
        }
    }
}

public extension CloudRevisionTransport {
    func validateOfflineAccount() async throws {
        do {
            let status = try await cloud.accountStatus()
            if status == .noAccount || status == .restricted { throw MopError.cloudAccount }
        } catch let error as CKError where [.networkUnavailable, .networkFailure, .serviceUnavailable, .accountTemporarilyUnavailable].contains(error.code) {
            // Explicit offline access uses the last independently verified scope.
        }
        // A cached read cannot prove remote freshness. Only explicit offline
        // reads may use a locally pinned account after an indeterminate status.
    }
    func share(with account: String, role: MemberRole, at address: VaultAddress) async throws -> URL {
        try await check(address)
        guard address.database == .private, account != address.account, role != .owner else { throw MopError.cloudPermission }
        let share: CKShare
        do {
            guard let existing = try await fetch(CKRecordNameZoneWideShare, address) as? CKShare else { throw MopError.invalidVault }
            share = existing
        } catch MopError.vaultMissing { share = CKShare(recordZoneID: zone(address)) }
        share.publicPermission = .none
        let participant: CKShare.Participant = try await withCheckedThrowingContinuation { continuation in
            let result = Mutex<Result<CKShare.Participant, Error>?>(nil)
            let operation = CKFetchShareParticipantsOperation(userIdentityLookupInfos: [CKUserIdentity.LookupInfo(userRecordID: CKRecord.ID(recordName: account))])
            configure(operation)
            operation.perShareParticipantResultBlock = { _, value in result.withLock { $0 = value } }
            operation.fetchShareParticipantsResultBlock = { value in
                if let item = result.withLock({ $0 }) { continuation.resume(with: item.mapError(Self.map)) }
                else if case .failure(let error) = value { continuation.resume(throwing: Self.map(error)) }
                else { continuation.resume(throwing: MopError.cloudUnavailable) }
            }
            cloud.add(operation)
        }
        guard participant.userIdentity.userRecordID?.recordName == account else { throw MopError.invalidIdentity }
        participant.permission = role == .viewer ? .readOnly : .readWrite
        share.addParticipant(participant)
        try await save(share, address)
        guard let saved = try await fetch(CKRecordNameZoneWideShare, address) as? CKShare, let url = saved.url else { throw MopError.cloudUncertain }
        try await check(address)
        return url
    }
    /// Apply transport revocation after the cryptographic roster commits. On
    /// failure the roster still prevents future decryption; retry this operation.
    func reconcileShare(_ membership: Membership, at address: VaultAddress) async throws {
        try await check(address)
        guard address.database == .private else { throw MopError.cloudPermission }
        let share: CKShare
        do {
            guard let found = try await fetch(CKRecordNameZoneWideShare, address) as? CKShare else { throw MopError.invalidVault }
            share = found
        } catch MopError.vaultMissing { return }
        share.publicPermission = .none
        for participant in share.participants where participant.role != .owner {
            guard let account = participant.userIdentity.userRecordID?.recordName, account != CKCurrentUserDefaultName else { throw MopError.invalidIdentity }
            let member = AccountScope.member(container: container, environment: environment, account: account)
            if let role = membership.accounts.first(where: { $0.id == member })?.role {
                participant.permission = role == .viewer ? .readOnly : .readWrite
            } else { share.removeParticipant(participant) }
        }
        try await save(share, address)
        try await check(address)
    }
    func acceptShare(_ url: URL, vault: UUID, expectedOwner: String) async throws -> VaultAddress {
        guard url.scheme == "https", url.host == "www.icloud.com" || url.host == "icloud.com" else { throw MopError.cloudInvalidRequest }
        let account = try await account()
        let metadata: CKShare.Metadata = try await withCheckedThrowingContinuation { continuation in
            let result = Mutex<Result<CKShare.Metadata, Error>?>(nil)
            let operation = CKFetchShareMetadataOperation(shareURLs: [url]); configure(operation)
            operation.perShareMetadataResultBlock = { _, value in result.withLock { $0 = value } }
            operation.fetchShareMetadataResultBlock = { value in
                if let item = result.withLock({ $0 }) { continuation.resume(with: item.mapError(Self.map)) }
                else if case .failure(let error) = value { continuation.resume(throwing: Self.map(error)) }
                else { continuation.resume(throwing: MopError.cloudUnavailable) }
            }
            cloud.add(operation)
        }
        let zone = metadata.share.recordID.zoneID
        guard metadata.containerIdentifier == container, metadata.share.recordID.recordName == CKRecordNameZoneWideShare,
              metadata.ownerIdentity.userRecordID?.recordName == expectedOwner, expectedOwner != CKCurrentUserDefaultName,
              zone.zoneName == "mop-v7-" + vault.uuidString, zone.ownerName != CKCurrentUserDefaultName,
              metadata.share.publicPermission == .none else { throw MopError.vaultUntrusted }
        let address = try VaultAddress(container: container, environment: environment, account: account, database: .shared, owner: zone.ownerName, vault: vault)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let operation = CKAcceptSharesOperation(shareMetadatas: [metadata]); configure(operation)
            operation.acceptSharesResultBlock = { continuation.resume(with: $0.mapError(Self.map)) }
            cloud.add(operation)
        }
        try await check(address)
        return address
    }
    func delete(at address: VaultAddress) async throws {
        try await check(address)
        guard address.database == .private else { throw MopError.cloudPermission }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let operation = CKModifyRecordZonesOperation(recordZonesToSave: nil, recordZoneIDsToDelete: [zone(address)])
            configure(operation)
            operation.modifyRecordZonesResultBlock = { continuation.resume(with: $0.mapError(Self.map)) }
            database(address).add(operation)
        }
        try await check(address)
    }
}
