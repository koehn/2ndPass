@preconcurrency import CloudKit
import CryptoKit
import Foundation
import MopCore

public struct ContentUpload: Sendable {
    public let operationID: UUID
    public let content: PreparedContentVersion
    public let grant: PreparedContentGrant?
    public let kind: ContentRecordKind
    public let systemFields: Data?
    public init(operationID: UUID, content: PreparedContentVersion, grant: PreparedContentGrant?, kind: ContentRecordKind, systemFields: Data?) {
        self.operationID = operationID; self.content = content; self.grant = grant
        self.kind = kind; self.systemFields = systemFields
    }
    public var scope: ItemScope { content.version.scope }
    public var recordID: CKRecord.ID {
        let suffix = grant.map { ":" + $0.identifier } ?? (kind == .version ? ":" + content.version.versionID.uuidString : "")
        return CKRecord.ID(recordName: scope.itemID.uuidString + suffix,
            zoneID: CKRecordZone.ID(zoneName: SyncStoreLayout.contentZone(vault: scope.vaultID), ownerName: scope.zoneOwner))
    }
    public var byteCount: Int { grant?.bytes.count ?? content.version.ciphertext.count }

    /// The immutable outbox bytes determine the asset name. Both publication
    /// phases reuse that file; existing reference-aware cleanup retains it while
    /// the mutation is pending or a batch is in flight.
    public func record(assetDirectory: URL) throws -> CKRecord {
        if let grant { return try ContentRecordTransport.grant(grant) }
        let version = content.version
        var assetURLs: [URL] = []
        if version.ciphertext.count > ContentRecordTransport.inlineLimit {
            let account = SHA256.hash(data: Data(scope.account.utf8)).map { String(format: "%02x", $0) }.joined()
            var directory = assetDirectory.appendingPathComponent(account).appendingPathComponent(scope.vaultID.uuidString)
            try LocalFile.privateDirectory(directory)
            var values = URLResourceValues(); values.isExcludedFromBackup = true
            try directory.setResourceValues(values)
            for start in stride(from: 0, to: version.ciphertext.count, by: ContentRecordTransport.assetChunkLimit) {
                let chunk = version.ciphertext.subdata(in: start..<min(start + ContentRecordTransport.assetChunkLimit, version.ciphertext.count))
                let digest = SHA256.hash(data: chunk).map { String(format: "%02x", $0) }.joined()
                let url = directory.appendingPathComponent(version.versionID.uuidString + "-" + digest + ".ciphertext")
                if !FileManager.default.fileExists(atPath: url.path) {
                    do { try LocalFile.write(chunk, to: url) } catch MopError.duplicate {}
                }
                guard try LocalFile.read(url, privateFile: true, limit: ContentRecordTransport.assetChunkLimit) == chunk else { throw CloudSyncAdapterError.invalidBinding }
                assetURLs.append(url)
            }
        }
        return try ContentRecordTransport.content(content, kind: kind, systemFields: systemFields, assetURLs: assetURLs)
    }
}

/// Public verification only; implementations must refresh pinned authority and
/// reject obsolete key generations. Secret key access is never needed to send.
public typealias ContentPublicationValidator = @Sendable (ContentUpload, PublicationAuthorityChecks) async throws -> Void

/// One account's authority reads for one preparation phase of one upload batch.
/// Never retain across batches or reuse for the final pre-submission phase.
/// Only remote authority reads are shared; every record still needs verification.
public actor PublicationAuthorityChecks {
    private struct Key: Hashable {
        let vault: UUID
        let authority: Data
    }
    private var reads: [Key: Task<Void, Error>] = [:]

    init() {}

    public func check(vault: UUID, authority: Data,
                      read: @escaping @Sendable () async throws -> Void) async throws {
        try Task.checkCancellation()
        let key = Key(vault: vault, authority: authority)
        let task: Task<Void, Error>
        if let existing = reads[key] { task = existing }
        else {
            task = Task { try await read() }
            reads[key] = task
        }
        // Cache failures too: a rejected vault must not issue another read for
        // each item. A different vault or authority has its own independent read.
        try await task.value
        try Task.checkCancellation()
    }
}
