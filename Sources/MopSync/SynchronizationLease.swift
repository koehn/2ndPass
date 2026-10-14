import Darwin
import CryptoKit
import CoreFoundation
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
    case inboxFull
}

/// Keep the reason sync stopped separate from subsequent callback diagnostics.
struct CloudSyncSuspension {
    private(set) var failure: CloudSyncAdapterError?

    mutating func record(_ reason: CloudSyncAdapterError) {
        if failure == nil || reason == .accountChanged
            || (failure == .inboxFull && reason != .operationInterrupted) { failure = reason }
    }

    func check() throws {
        if let failure { throw failure }
    }

    // Capacity pauses transport/checkpoints, not the consumer that frees space.
    // No other suspension is allowed to retain local processing authority.
    var allowsLocalProcessing: Bool { failure == nil || failure == .inboxFull }

    func checkLocalProcessing() throws {
        if !allowsLocalProcessing { try check() }
    }
}

/// One engine owns a database's serialized state at a time across app-group processes.
/// The descriptor is immutable and its advisory lock lasts exactly as long as this object.
public final class SynchronizationLease: @unchecked Sendable {
    private let descriptor: Int32
    private let notification: String

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
        notification = leaseNotification(url)
    }

    deinit { close(descriptor); CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFNotificationName(rawValue: notification as CFString), nil, nil, true) }
}

/// Cross-process notification is only a wake hint. The advisory lock remains
/// authoritative, and persisted backoff covers crashes or missed notifications.
public final class SynchronizationLeaseObserver: @unchecked Sendable {
    private let released: @Sendable () -> Void
    public init(url: URL, released: @escaping @Sendable () -> Void) throws {
        self.released = released
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), Unmanaged.passUnretained(self).toOpaque(), { _, observer, _, _, _ in
            guard let observer else { return }
            Unmanaged<SynchronizationLeaseObserver>.fromOpaque(observer).takeUnretainedValue().released()
        }, leaseNotification(url) as CFString, nil, .deliverImmediately)
    }
    deinit { CFNotificationCenterRemoveEveryObserver(CFNotificationCenterGetDarwinNotifyCenter(), Unmanaged.passUnretained(self).toOpaque()) }

}

private func leaseNotification(_ url: URL) -> String {
    "com.koehn.mop.sync-owner-release." + SHA256.hash(data: Data(url.standardizedFileURL.path.utf8)).map { String(format: "%02x", $0) }.joined()
}
