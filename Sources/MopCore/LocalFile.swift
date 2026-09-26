import Darwin
import Foundation

public enum LocalFile {
    private static func withReadDescriptor<T>(_ url: URL, privateFile: Bool, limit: Int, body: (Int32) throws -> T) throws -> T {
        let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw errno == ENOENT ? MopError.vaultMissing : MopError.inputOutput }
        defer { Darwin.close(fd) }
        var status = stat()
        guard fstat(fd, &status) == 0, status.st_mode & S_IFMT == S_IFREG else { throw MopError.filePermissions }
        if privateFile {
            guard status.st_uid == getuid(), status.st_mode & 0o077 == 0 else { throw MopError.filePermissions }
            try PrivateACL.validate(fd)
        }
        guard status.st_size >= 0, status.st_size <= limit else { throw MopError.invalidVault }
        return try body(fd)
    }

    public static func read(_ url: URL, privateFile: Bool = false, limit: Int = 16 * 1024 * 1024) throws -> Data {
        try withReadDescriptor(url, privateFile: privateFile, limit: limit) { fd in
            do {
                let data = try FileHandle(fileDescriptor: fd, closeOnDealloc: false).read(upToCount: limit + 1) ?? Data()
                guard data.count <= limit else { throw MopError.invalidVault }
                return data
            } catch let error as MopError { throw error }
              catch { throw MopError.inputOutput }
        }
    }

    public static func privateDirectory(_ url: URL, ownerOnly: Bool = true) throws {
        do {
            if !FileManager.default.fileExists(atPath: url.path) {
                try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true,
                                                        attributes: [.posixPermissions: 0o700])
            }
            var status = stat()
            guard lstat(url.path, &status) == 0, status.st_mode & S_IFMT == S_IFDIR,
                  status.st_uid == getuid(), (!ownerOnly || status.st_mode & 0o077 == 0) else { throw MopError.filePermissions }
            if ownerOnly {
                let fd = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard fd >= 0 else { throw MopError.filePermissions }
                defer { Darwin.close(fd) }
                try PrivateACL.validate(fd)
            }
            #if os(iOS)
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
            var excluded = url
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try excluded.setResourceValues(values)
            #endif
        } catch let error as MopError { throw error }
          catch { throw MopError.inputOutput }
    }

    /// Ciphertext snapshots and public device metadata for local files.
    /// New files are exclusive. Replacements require external coordination.
    public static func write<Bytes: ContiguousBytes>(_ data: Bytes, to url: URL, replace: Bool = false) throws {
        let temporary = url.deletingLastPathComponent().appendingPathComponent(".mop-write-" + UUID().uuidString)
        let fd = Darwin.open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw MopError.inputOutput }
        defer { Darwin.close(fd); unlink(temporary.path) }
        #if os(iOS)
        // Protect the empty staging inode before any secret bytes are written.
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: temporary.path)
        #endif
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
        guard fsync(fd) == 0 else { throw MopError.inputOutput }
        if replace {
            guard rename(temporary.path, url.path) == 0 else { throw MopError.inputOutput }
        } else {
            guard link(temporary.path, url.path) == 0 else {
                throw errno == EEXIST ? MopError.duplicate : MopError.inputOutput
            }
        }
        let directory = Darwin.open(url.deletingLastPathComponent().path, O_RDONLY)
        if directory >= 0 { _ = fsync(directory); Darwin.close(directory) }
    }
}
