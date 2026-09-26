import Darwin
import Foundation

/// Short local filesystem transactions, with no migration or cleanup behavior.
public final class LocalDirectory: @unchecked Sendable {
    public let directory: URL
    public init(directory: URL) throws { self.directory = directory; try LocalFile.privateDirectory(directory) }
    public func locked<T>(_ action: () throws -> T) throws -> T {
        let url = directory.appendingPathComponent("lock")
        let fd = Darwin.open(url.path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw MopError.filePermissions }
        defer { Darwin.close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_uid == getuid(), st.st_mode & S_IFMT == S_IFREG,
              st.st_mode & 0o077 == 0 else { throw MopError.filePermissions }
        try PrivateACL.validate(fd)
        guard flock(fd, LOCK_EX) == 0 else { throw MopError.inputOutput }
        defer { flock(fd, LOCK_UN) }
        return try action()
    }

}
