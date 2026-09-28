import Foundation
import MopCore

/// Only immutable ciphertext uploads overlap. The caller publishes the revision
/// and head after this barrier completes; no key operations run in these tasks.
enum AttachmentUploads {
    static func upload(_ vault: VerifiedVault, excluding existing: Set<String> = [],
                       transport: any RevisionTransport, address: VaultAddress,
                       progress: (@Sendable (Int, Int) -> Void)? = nil) async throws {
        let required = vault.attachmentDigests.subtracting(existing)
        let loaded = vault.loadedAttachments
        guard required.isSubset(of: Set(loaded.keys)) else { throw AttachmentFailure.unavailable }
        for digest in required {
            _ = try vault.loadingAttachment(loaded[digest]!, digest: digest)
        }
        var pending = required.sorted().makeIterator()
        try Task.checkCancellation()
        progress?(0, required.count)
        try await withThrowingTaskGroup(of: Void.self) { group in
            func enqueue(_ digest: String) {
                group.addTask {
                    try Task.checkCancellation()
                    try await transport.uploadAttachment(loaded[digest]!, digest: digest, at: address)
                }
            }
            for _ in 0..<min(4, required.count) { enqueue(pending.next()!) }
            var completed = 0
            do {
                while let _ = try await group.next() {
                    try Task.checkCancellation()
                    completed += 1; progress?(completed, required.count)
                    if let digest = pending.next() { enqueue(digest) }
                }
            } catch {
                group.cancelAll()
                throw error // Structured concurrency drains children before returning.
            }
        }
        try Task.checkCancellation()
    }
}
