import Foundation
import MopCore

public extension VerifiedVault {
    static let maximumBackupSize = 256 * 1024 * 1024
    /// Authenticated ciphertext digests; no filename, plaintext, or key material.
    var attachmentDigests: Set<String> { Set(revision.records.values.compactMap(\.attachmentDigest)) }
    var loadedAttachments: [String: Data] {
        var result: [String: Data] = [:]
        for record in revision.records.values {
            if let digest = record.attachmentDigest, let data = record.loadedCiphertext { result[digest] = data }
        }
        return result
    }
    func attachmentDigest(for reference: String, device: any DeviceOperations) throws -> String? {
        let payload = try revision.payload(device: device)
        guard let id = payload.references[reference], let record = revision.records[id] else { throw MopError.notFound }
        return record.attachmentDigest
    }
    func loadingAttachment(_ data: Data, digest: String) throws -> Self {
        guard attachmentDigests.contains(digest), Codec.digest(data) == digest else { throw MopError.invalidVault }
        var result = self
        for (id, record) in revision.records where record.attachmentDigest == digest {
            guard record.attachmentSize == data.count else { throw MopError.invalidVault }
            result.revision.records[id]?.loadedCiphertext = data
        }
        return result
    }
    /// Backups include all referenced encrypted blobs; checkpoint identity remains
    /// the digest of the signed revision, not of this transport wrapper.
    func backup() throws -> Data {
        guard attachmentDigests == Set(loadedAttachments.keys) else { throw AttachmentFailure.unavailable }
        if attachmentDigests.isEmpty { return bytes }
        let data = try Codec.encode(AttachmentBackup(format: "mop-attachment-backup-1", revision: bytes, attachments: loadedAttachments))
        guard data.count <= Self.maximumBackupSize else { throw MopError.invalidVault }
        return data
    }
    static func restoreBackup(_ data: Data, independentlyVerifiedDigest: String) throws -> Self {
        guard data.count <= Self.maximumBackupSize else { throw MopError.invalidVault }
        if let backup = try? JSONDecoder().decode(AttachmentBackup.self, from: data), backup.format == "mop-attachment-backup-1" {
            var vault = try Self(checkpoint: backup.revision, independentlyVerifiedDigest: independentlyVerifiedDigest)
            guard Set(backup.attachments.keys) == vault.attachmentDigests else { throw MopError.invalidVault }
            for (digest, bytes) in backup.attachments { vault = try vault.loadingAttachment(bytes, digest: digest) }
            return vault
        }
        return try Self(checkpoint: data, independentlyVerifiedDigest: independentlyVerifiedDigest)
    }
}
private struct AttachmentBackup: Codable {
    let format: String
    let revision: Data
    let attachments: [String: Data]
}

public extension RevisionTransport {
    func attachment(_ digest: String, at address: VaultAddress) async throws -> Data { throw AttachmentFailure.unavailable }
    func uploadAttachment(_ bytes: Data, digest: String, at address: VaultAddress) async throws { throw AttachmentFailure.unavailable }
}
