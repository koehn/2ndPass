import Foundation

/// Keeps the process lease alive through the transaction, even if the adapter is
/// stopping. Invalidation waits for a transaction that already acquired the gate.
public final class ConflictPublicationPermit: RepositoryWritePermit, @unchecked Sendable {
    // Every access to valid is protected by this synchronous lock. NSLock avoids
    // transferring the generic, potentially non-Sendable transaction result.
    private let gate = NSLock()
    private var valid = true
    private var lease: SynchronizationLease?
    private let authorization: any RepositoryWritePermit

    public init(lease: SynchronizationLease, authorization: any RepositoryWritePermit) {
        self.lease = lease
        self.authorization = authorization
    }

    public func invalidate() {
        gate.lock()
        defer { gate.unlock() }
        valid = false
        lease = nil
    }

    public func withWritePermission<T>(_ body: () throws -> T) throws -> T {
        gate.lock()
        defer { gate.unlock() }
        guard valid, let lease else { throw CloudSyncAdapterError.operationInterrupted }
        return try withExtendedLifetime(lease) { try authorization.withWritePermission(body) }
    }
}
