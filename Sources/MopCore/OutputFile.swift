import Darwin
import Foundation

/// A pinned destination directory, validated before authentication. No output file
/// is created until the caller has resolved its complete result.
public final class OutputFile {
    private final class DirectoryHandle {
        let fd: Int32
        init(_ fd: Int32) { self.fd = fd }
        deinit { Darwin.close(fd) }
    }
    private let handle: DirectoryHandle
    private var directory: Int32 { handle.fd }
    private let name: String
    private let force: Bool
    private let mode: mode_t
    private let protectedFiles: [URL]

    public static func permissions(_ text: String?) throws -> mode_t {
        guard let text else { return 0o600 }
        guard !text.isEmpty, text.count <= 4, text.utf8.allSatisfy({ (48...55).contains($0) }),
              let value = UInt16(text, radix: 8), value <= 0o777 else { throw MopError.invalidOutput }
        return mode_t(value)
    }

    public init(url: URL, force: Bool, mode: mode_t, protectedFiles: [URL], protectedDirectories: [URL]) throws {
        guard mode <= 0o777 else { throw MopError.invalidOutput }
        let target = url.standardizedFileURL
        let parent = target.deletingLastPathComponent().resolvingSymlinksInPath()
        let canonical = parent.appendingPathComponent(target.lastPathComponent).standardizedFileURL.path
        for file in protectedFiles {
            guard canonical != file.standardizedFileURL.path,
                  canonical != file.resolvingSymlinksInPath().path else { throw MopError.filePermissions }
        }
        for folder in protectedDirectories {
            for path in [folder.standardizedFileURL.path, folder.resolvingSymlinksInPath().path] {
                guard canonical != path, !canonical.hasPrefix(path + "/") else { throw MopError.filePermissions }
            }
        }
        let fd = Darwin.open(parent.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { throw MopError.inputOutput }
        handle = DirectoryHandle(fd)
        name = target.lastPathComponent
        self.force = force
        self.mode = mode
        self.protectedFiles = protectedFiles
        try validateDestination()
    }

    private func validateDestination() throws {
        var target = stat()
        if fstatat(directory, name, &target, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw MopError.inputOutput }
            return
        }
        guard target.st_mode & S_IFMT == S_IFREG else { throw MopError.filePermissions }
        for file in protectedFiles {
            var protected = stat()
            if stat(file.path, &protected) == 0 && target.st_dev == protected.st_dev && target.st_ino == protected.st_ino {
                throw MopError.filePermissions
            }
        }
        guard force else { throw MopError.outputExists }
    }

    public func write(_ data: Data) throws {
        try validateDestination()
        let temporary = ".mop-output-" + UUID().uuidString
        let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw MopError.inputOutput }
        defer { Darwin.close(fd); unlinkat(directory, temporary, 0) }
        // Remove inherited ACL entries so permissions match the explicit mode.
        try PrivateACL.clear(fd)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw MopError.inputOutput }
                offset += count
            }
        }
        guard fchmod(fd, mode) == 0, fsync(fd) == 0 else { throw MopError.inputOutput }
        try validateDestination()
        let result = renameatx_np(directory, temporary, directory, name, force ? 0 : UInt32(RENAME_EXCL))
        guard result == 0 else { throw errno == EEXIST ? MopError.outputExists : MopError.inputOutput }
        // The rename is committed; a directory sync failure must not be reported
        // as if the old destination were still intact.
        _ = fsync(directory)
    }
}
