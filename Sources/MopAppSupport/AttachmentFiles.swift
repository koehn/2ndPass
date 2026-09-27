import Foundation
import MopCore

public enum AttachmentFiles {
    public static func read(_ source: URL) throws -> Attachment {
        let access = source.startAccessingSecurityScopedResource()
        defer { if access { source.stopAccessingSecurityScopedResource() } }
        var result: Result<Attachment, Error>?
        var coordinationError: NSError?
        NSFileCoordinator().coordinate(readingItemAt: source, options: [], error: &coordinationError) { url in
            result = Result {
                let info = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
                guard info.isRegularFile == true else { throw AttachmentFailure.invalid }
                guard (info.fileSize ?? 0) <= Attachment.maximumBytes else { throw AttachmentFailure.tooLarge }
                var bytes = try LocalFile.read(url, limit: Attachment.maximumBytes)
                defer { SecretBytes.wipe(&bytes) }
                return try Attachment(fileName: url.lastPathComponent, data: bytes)
            }
        }
        if coordinationError != nil { throw MopError.inputOutput }
        guard let result else { throw MopError.inputOutput }
        return try result.get()
    }
}
