import Foundation

/// Separate transport ownership from the bounded, partially committing loop so
/// interruption semantics can be tested without a live CloudKit account.
func performConflictResolutionBatch(
    _ entries: [(conflict: EncryptedItemConflict, replacement: EncryptedItemVersion?)],
    isolation: isolated (any Actor)? = #isolation,
    quiesce: () async throws -> Void,
    resolve: ((conflict: EncryptedItemConflict, replacement: EncryptedItemVersion?)) async throws -> EncryptedItemVersion,
    finish: () async -> Void
) async throws -> [UUID: Result<EncryptedItemVersion, any Error>] {
    guard !entries.isEmpty else { return [:] }
    guard entries.count <= 25, Set(entries.map { $0.conflict.id }).count == entries.count else {
        throw CloudSyncAdapterError.invalidBinding
    }
    var results: [UUID: Result<EncryptedItemVersion, any Error>] = [:]
    do {
        try Task.checkCancellation()
        try await quiesce()
        for entry in entries {
            try Task.checkCancellation()
            do { results[entry.conflict.id] = .success(try await resolve(entry)) }
            catch { results[entry.conflict.id] = .failure(error) }
        }
        try Task.checkCancellation()
    } catch {
        await finish()
        throw error
    }
    await finish()
    return results
}
