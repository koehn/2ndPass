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
        // Older versions retained every downloaded blob, including rejected input.
        // Snapshots contain complete records; journals reconcile against the server.
        try locked {
            for name in try FileManager.default.contentsOfDirectory(atPath: directory.path)
                where name.hasSuffix(".blob") && VaultTrust.validFingerprint(String(name.dropLast(5))) {
                let path = directory.appendingPathComponent(name).path
                var st = stat()
                guard lstat(path, &st) == 0, st.st_mode & S_IFMT == S_IFREG,
                      st.st_uid == getuid(), unlink(path) == 0 else { throw MopError.filePermissions }
            }
        }
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
        let bytes = try VaultCoding.encode(value)
        guard bytes.count <= VaultCoding.maximumFileSize * 2 else { throw MopError.invalidVault }
        try SafeFile.write(bytes, to: url, replace: FileManager.default.fileExists(atPath: url.path))
    }

    func remove(_ name: String) throws {
        let url = directory.appendingPathComponent(name)
        if FileManager.default.fileExists(atPath: url.path) {
            do { try FileManager.default.removeItem(at: url) } catch { throw MopError.inputOutput }
        }
    }

    /// Reuse only records embedded in the two bounded snapshots. Downloads are
    /// assembled in memory and never create a persistent per-record cache.
    /// Caller holds the cache lock; at most two 16 MiB documents are examined.
    func recordBlobs() throws -> [String: Data] {
        var result: [String: Data] = [:]
        for name in ["snapshot.json", "downloaded.json"] {
            guard let snapshot = try read(name, as: CachedSnapshot.self) else { continue }
            guard VaultCoding.digest(snapshot.document) == snapshot.revision else { throw MopError.invalidVault }
            let document = try VaultDocument.decode(snapshot.document)
            for record in document.records.values {
                let bytes = try VaultCoding.encode(record)
                result[VaultCoding.digest(bytes)] = bytes
            }
        }
        return result
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
