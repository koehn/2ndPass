import Darwin
import Foundation
import MopCore
import MopVault

/// Short filesystem transactions only: no lock is held across a network await.
public final class CloudCache: @unchecked Sendable {
    public let directory: URL
    public init(directory: URL) throws {
        self.directory = directory
        try SafeFile.privateDirectory(directory)
    }

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

    func read<T: Decodable>(_ name: String, as type: T.Type) throws -> T? {
        let url = directory.appendingPathComponent(name)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        do { return try JSONDecoder().decode(type, from: SafeFile.read(url, privateFile: true, limit: VaultCoding.maximumFileSize * 2)) }
        catch let error as MopError { throw error }
        catch { throw MopError.invalidVault }
    }

    func write<T: Encodable>(_ value: T, _ name: String) throws {
        let url = directory.appendingPathComponent(name)
        try SafeFile.write(VaultCoding.encode(value), to: url, replace: FileManager.default.fileExists(atPath: url.path))
    }

    func remove(_ name: String) throws {
        let url = directory.appendingPathComponent(name)
        if FileManager.default.fileExists(atPath: url.path) {
            do { try FileManager.default.removeItem(at: url) } catch { throw MopError.inputOutput }
        }
    }

    func blob(_ digest: String) throws -> Data? {
        guard VaultTrust.validFingerprint(digest) else { throw MopError.invalidVault }
        let url = directory.appendingPathComponent(digest + ".blob")
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let bytes = try SafeFile.read(url, privateFile: true)
        guard VaultCoding.digest(bytes) == digest else { throw MopError.invalidVault }
        return bytes
    }

    func putBlob(_ bytes: Data) throws {
        let digest = VaultCoding.digest(bytes)
        if try blob(digest) == nil { try SafeFile.write(bytes, to: directory.appendingPathComponent(digest + ".blob")) }
    }
}

struct CachedSnapshot: Codable, Sendable {
    let revision: String
    let root: String
    let version: Data
    let fetched: Date
    let document: Data
}

struct Watermark: Codable {
    let generation: UInt64
    let revision: String
}

struct CommitJournal: Codable {
    let expected: String?
    let proposed: String
    let root: String
    let rotationFingerprint: String?
}
