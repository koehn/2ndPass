import Darwin
import Foundation
import MopCore

public enum CloudSyncAdapterError: Error, Equatable, Sendable {
    case membershipUnavailable
    case invalidBinding
    case malformedRecord
    case untrustedRecord
    case accountChanged
    case engineNotStarted
    case engineAlreadyOwned
    case leaseUnavailable
    case unexpectedRemoteDeletion
    case storageFailure
    case assetDirectoryRequired
    case unreadableRemoteRecord
    case operationInterrupted
}

/// Keep the reason sync stopped separate from subsequent callback diagnostics.
struct CloudSyncSuspension {
    private(set) var failure: CloudSyncAdapterError?

    mutating func record(_ reason: CloudSyncAdapterError) {
        if failure == nil || reason == .accountChanged { failure = reason }
    }

    func check() throws {
        if let failure { throw failure }
    }
}

/// One engine owns a database's serialized state at a time across app-group processes.
/// The descriptor is immutable and its advisory lock lasts exactly as long as this object.
public final class SynchronizationLease: @unchecked Sendable {
    private let descriptor: Int32

    public init(url: URL) throws {
        try LocalFile.privateDirectory(url.deletingLastPathComponent())
        let fd = open(url.path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw CloudSyncAdapterError.leaseUnavailable }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == getuid(), info.st_mode & 0o077 == 0 else {
            close(fd)
            throw CloudSyncAdapterError.leaseUnavailable
        }
        do { try PrivateACL.validate(fd) }
        catch { close(fd); throw error }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            close(fd)
            throw CloudSyncAdapterError.engineAlreadyOwned
        }
        descriptor = fd
    }

    deinit { close(descriptor) }
}
