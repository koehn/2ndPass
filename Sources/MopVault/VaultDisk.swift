import Darwin
import Foundation
import MopCore

public enum SafeFile {
    public static func read(_ url: URL, privateFile: Bool = false, limit: Int = VaultCoding.maximumFileSize) throws -> Data {
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
        do {
            let data = try FileHandle(fileDescriptor: fd, closeOnDealloc: false).read(upToCount: limit + 1) ?? Data()
            guard data.count <= limit else { throw MopError.invalidVault }
            return data
        } catch let error as MopError { throw error }
          catch { throw MopError.inputOutput }
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
        } catch let error as MopError { throw error }
          catch { throw MopError.inputOutput }
    }

    /// Ciphertext for vault/history; public device metadata or recovery material for local files.
    /// New files are exclusive. Replacements require external coordination.
    public static func write(_ data: Data, to url: URL, replace: Bool = false) throws {
        let temporary = url.deletingLastPathComponent().appendingPathComponent(".mop-write-" + UUID().uuidString)
        let fd = Darwin.open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw MopError.inputOutput }
        defer { Darwin.close(fd); unlink(temporary.path) }
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

public final class VaultDisk {
    public let url: URL
    public let trust: VaultTrust
    public var historyURL: URL { URL(fileURLWithPath: url.path + ".history", isDirectory: true) }

    public init(url: URL, trustDirectory: URL) {
        self.url = url.standardizedFileURL
        self.trust = VaultTrust(vault: url, directory: trustDirectory)
    }

    private func coordinate<T>(write: Bool, body: (URL) throws -> T) throws -> T {
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordinationError: NSError?
        var result: Result<T, Error>?
        let accessor: (URL) -> Void = { target in result = Result { try body(target) } }
        if write {
            coordinator.coordinate(writingItemAt: url, options: .forReplacing, error: &coordinationError, byAccessor: accessor)
        } else {
            coordinator.coordinate(readingItemAt: url, options: [], error: &coordinationError, byAccessor: accessor)
        }
        guard coordinationError == nil, let result else { throw MopError.inputOutput }
        return try result.get()
    }

    private func conflicts(_ target: URL) -> [NSFileVersion] {
        NSFileVersion.unresolvedConflictVersionsOfItem(at: target) ?? []
    }

    public func read() throws -> Data {
        guard FileManager.default.fileExists(atPath: url.path) else { throw MopError.vaultMissing }
        return try coordinate(write: false) { target in
            guard self.conflicts(target).isEmpty else { throw MopError.vaultConflict }
            return try SafeFile.read(target)
        }
    }

    public func create(_ bytes: Data) throws {
        // Creation is exclusive even if another process initializes the same path.
        try coordinate(write: true) { target in try SafeFile.write(bytes, to: target) }
    }

    private func preserve(_ bytes: Data) throws -> String {
        try SafeFile.privateDirectory(historyURL, ownerOnly: false)
        let digest = VaultCoding.digest(bytes)
        let target = historyURL.appendingPathComponent(digest + ".moprevision")
        do { try SafeFile.write(bytes, to: target) }
        catch MopError.duplicate {
            guard try SafeFile.read(target) == bytes else { throw MopError.vaultConflict }
        }
        return digest
    }

    public func commit(expected: Data, replacement: Data) throws {
        try coordinate(write: true) { target in
            guard self.conflicts(target).isEmpty, try SafeFile.read(target) == expected else { throw MopError.vaultConflict }
            _ = try self.preserve(expected)
            _ = try self.preserve(replacement)
            try SafeFile.write(replacement, to: target, replace: true)
        }
    }

    /// Preserve every known version before exposing its digest for explicit selection.
    public func revisions() throws -> [String] {
        try coordinate(write: true) { target in
            _ = try self.preserve(SafeFile.read(target))
            for version in self.conflicts(target) { _ = try self.preserve(SafeFile.read(version.url)) }
            do {
                return try FileManager.default.contentsOfDirectory(atPath: self.historyURL.path)
                    .filter { $0.hasSuffix(".moprevision") }.map { String($0.dropLast(12)) }.sorted()
            } catch { throw MopError.inputOutput }
        }
    }

    public func revision(_ digest: String) throws -> Data {
        guard digest.count == 64, digest.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else { throw MopError.invalidVault }
        let bytes = try SafeFile.read(historyURL.appendingPathComponent(digest + ".moprevision"))
        guard VaultCoding.digest(bytes) == digest else { throw MopError.invalidVault }
        return bytes
    }

    public func resolve(selected: Data, transform: (Data, Data) throws -> Data) throws {
        try coordinate(write: true) { target in
            let current = try SafeFile.read(target)
            let versions = self.conflicts(target)
            _ = try self.preserve(current)
            for version in versions { _ = try self.preserve(SafeFile.read(version.url)) }
            let replacement = try transform(selected, current)
            _ = try self.preserve(replacement)
            try SafeFile.write(replacement, to: target, replace: true)
            // Mark only the versions observed in this coordinated transaction resolved.
            for version in versions { version.isResolved = true }
        }
    }
}
