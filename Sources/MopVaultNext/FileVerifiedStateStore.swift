import Darwin
import Foundation
import MopCore

/// One vault lease, held for this object's lifetime, shared by app, CLI and
/// extension through a local app-group directory. Never place this in iCloud.
/// The caller must retain one store for the coordinator's entire lifetime.
public final class FileVerifiedStateStore: VerifiedStateStore, @unchecked Sendable {
    private let directory: Int32
    private let lease: Int32
    private let binding: String
    private let mutex = NSLock()

    public init(directory url: URL, address: VaultAddress) throws {
        binding = address.binding
        // Only create the final component. A caller chooses an existing private
        // local parent; silently manufacturing ancestor paths is inappropriate.
        if mkdir(url.path, 0o700) != 0 && errno != EEXIST { throw MopError.inputOutput }
        let directory = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw MopError.filePermissions }
        var acquired: Int32 = -1
        do {
            try Self.validate(directory, type: S_IFDIR, mode: 0o700)
            acquired = openat(directory, binding + ".lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard acquired >= 0 else { throw MopError.filePermissions }
            try Self.validate(acquired, type: S_IFREG, mode: 0o600)
            guard flock(acquired, LOCK_EX | LOCK_NB) == 0 else { throw MopError.vaultConflict }
        } catch {
            if acquired >= 0 { Darwin.close(acquired) }
            Darwin.close(directory)
            throw error
        }
        self.directory = directory; lease = acquired
    }

    /// Erase this account's managed checkpoint files after a durable removal
    /// marker blocks new operations. Busy vaults cause a retry, never forced deletion.
    public static func clearAccountCache(at url: URL) throws {
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        let directory = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw MopError.filePermissions }
        defer { Darwin.close(directory) }
        try validate(directory, type: S_IFDIR, mode: 0o700)
        let names = try FileManager.default.contentsOfDirectory(atPath: url.path).filter {
            let binding = String($0.prefix(64))
            return Codec.hash(binding) && ($0 == binding + ".json" || ($0.hasPrefix(binding + ".") && $0.hasSuffix(".pending")))
        }
        var leases: [Int32] = []
        defer { leases.forEach { Darwin.close($0) } }
        for binding in Set(names.map { String($0.prefix(64)) }).sorted() {
            let lease = openat(directory, binding + ".lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard lease >= 0 else { throw MopError.filePermissions }
            leases.append(lease)
            try validate(lease, type: S_IFREG, mode: 0o600)
            guard flock(lease, LOCK_EX | LOCK_NB) == 0 else { throw MopError.vaultConflict }
        }
        for name in names {
            guard unlinkat(directory, name, 0) == 0 || errno == ENOENT else { throw MopError.inputOutput }
        }
        guard fsync(directory) == 0 else { throw MopError.inputOutput }
    }

    deinit {
        // Never unlink the lock: replacing its inode would permit two holders.
        Darwin.close(lease); Darwin.close(directory)
    }

    private static func validate(_ fd: Int32, type: mode_t, mode: mode_t) throws {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == geteuid(),
              info.st_mode & S_IFMT == type, info.st_mode & 0o7777 == mode,
              type != S_IFREG || info.st_nlink == 1 else { throw MopError.filePermissions }
        try PrivateACL.validate(fd)
    }

    private func check(_ requested: String) throws {
        guard requested == binding else { throw MopError.vaultUntrusted }
    }

    public func load(binding: String) throws -> VerifiedState? {
        mutex.lock(); defer { mutex.unlock() }
        try check(binding)
        let fd = openat(directory, binding + ".json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 {
            guard errno == ENOENT else { throw MopError.filePermissions }
            return nil
        }
        defer { Darwin.close(fd) }
        try Self.validate(fd, type: S_IFREG, mode: 0o600)
        var bytes = Data(), chunk = [UInt8](repeating: 0, count: 16384)
        while true {
            let count = Darwin.read(fd, &chunk, chunk.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw MopError.inputOutput }
            if count == 0 { break }
            guard bytes.count + count <= 24 * 1024 * 1024 else { throw MopError.invalidVault }
            bytes.append(contentsOf: chunk.prefix(count))
        }
        let state: VerifiedState
        do { state = try JSONDecoder().decode(VerifiedState.self, from: bytes) }
        catch { throw MopError.invalidVault }
        try validate(state)
        return state
    }

    private func validate(_ state: VerifiedState) throws {
        guard state.address.binding == binding, Codec.digest(state.snapshot) == state.verifiedDigest else { throw MopError.vaultUntrusted }
        let verified = try VerifiedVault(checkpoint: state.snapshot, independentlyVerifiedDigest: state.verifiedDigest)
        guard verified.id == state.address.vault else { throw MopError.vaultUntrusted }
        if let pending = state.pending {
            guard pending.parent == verified.digest, Codec.hash(pending.candidate), pending.candidate != pending.parent else { throw MopError.invalidVault }
        }
    }

    public func save(_ state: VerifiedState, binding: String) throws {
        mutex.lock(); defer { mutex.unlock() }
        try check(binding); try validate(state)
        let bytes = try Codec.encode(state)
        guard bytes.count <= 24 * 1024 * 1024 else { throw MopError.invalidVault }
        let name = binding + ".json", temporary = binding + "." + UUID().uuidString + ".pending"
        let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw MopError.inputOutput }
        defer { Darwin.close(fd); unlinkat(directory, temporary, 0) }
        try PrivateACL.clear(fd)
        try bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw MopError.inputOutput }
                offset += count
            }
        }
        guard fsync(fd) == 0 else { throw MopError.inputOutput }
        #if os(macOS)
        guard fcntl(fd, F_FULLFSYNC) == 0 else { throw MopError.inputOutput }
        #endif
        guard renameat(directory, temporary, directory, name) == 0 else { throw MopError.inputOutput }
        // A failure after rename is ambiguous. PublicationCoordinator retains
        // uncertainty instead of treating it as evidence of a failed cloud save.
        guard fsync(directory) == 0 else { throw MopError.inputOutput }
    }
}
