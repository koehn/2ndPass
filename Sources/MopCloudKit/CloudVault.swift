import Darwin
import Foundation
import MopCore
import MopVault

/// Network state and ciphertext only. Authentication lives in CloudSecretStore.
public final class CloudVault {
    public let id: UUID
    public let cache: CloudCache
    public let trust: VaultTrust
    public let transport: any CloudTransport
    private let accountID: String
    private let invalidateBinding: () throws -> Void

    public init(id: UUID, cache: CloudCache, transport: any CloudTransport, accountID: String, invalidateBinding: @escaping () throws -> Void = {}) {
        self.id = id; self.cache = cache; self.transport = transport; self.accountID = accountID; self.invalidateBinding = invalidateBinding
        trust = VaultTrust(vault: cache.directory.appendingPathComponent("identity"), directory: cache.directory.appendingPathComponent("trust"))
    }

    private func checkAccount() async throws {
        do {
            guard try await transport.account() == accountID else { throw MopError.cloudAccount }
        } catch {
            if (error as? MopError) == .cloudAccount { try invalidateBinding() }
            throw error
        }
    }

    func head() async throws -> (CloudHead, CloudObject) {
        try await checkAccount()
        guard let object = try await transport.fetch("head", vault: id) else { throw MopError.vaultMissing }
        let head = try decodeCloud(CloudHead.self, object.data)
        guard VaultTrust.validFingerprint(head.revision), VaultTrust.validFingerprint(head.root) else { throw MopError.invalidVault }
        return (head, object)
    }

    private func manifest(_ digest: String) async throws -> CloudManifest {
        guard VaultTrust.validFingerprint(digest), let object = try await transport.fetch("m-" + digest, vault: id) else { throw MopError.invalidVault }
        let value = try decodeCloud(CloudManifest.self, object.data)
        guard value.format == "mop-cloud-manifest-v1", value.header.vaultID == id,
              value.records.count <= VaultCoding.maximumFileSize / 28,
              value.records.values.allSatisfy(VaultTrust.validFingerprint) else { throw MopError.invalidVault }
        return value
    }

    public func revision(_ digest: String) async throws -> Data {
        let manifest = try await manifest(digest)
        var records: [String: VaultRecord] = [:]
        var total = 0
        for (recordID, hash) in manifest.records.sorted(by: { $0.key < $1.key }) {
            let bytes: Data
            if let cached = try cache.locked({ try cache.blob(hash) }) { bytes = cached }
            else {
                guard let object = try await transport.fetch("s-" + hash, vault: id), VaultCoding.digest(object.data) == hash else { throw MopError.invalidVault }
                bytes = object.data
                try cache.locked { try cache.putBlob(bytes) }
            }
            total += bytes.count
            guard total <= VaultCoding.maximumFileSize else { throw MopError.invalidVault }
            records[recordID] = try decodeCloud(VaultRecord.self, bytes)
        }
        let bytes = try VaultCoding.encode(manifest.document(records: records))
        guard VaultCoding.digest(bytes) == digest else { throw MopError.invalidVault }
        return bytes
    }

    /// Enumerate only ancestors of the published head, never staged revisions.
    public func revisions() async throws -> [String] {
        let (head, _) = try await head()
        return try await ancestry(head)
    }

    private func ancestry(_ head: CloudHead) async throws -> [String] {
        var result: [String] = []
        var seen = Set<String>()
        var cursor = head.revision
        while true {
            guard seen.insert(cursor).inserted, seen.count <= 100_000 else { throw MopError.invalidVault }
            result.append(cursor)
            if cursor == head.root { return result }
            let value = try VaultDocument.decode(await revision(cursor))
            guard let parent = value.header.parent, VaultTrust.validFingerprint(parent) else { throw MopError.invalidVault }
            cursor = parent
        }
    }

    public func cached() throws -> (Data, Date) {
        try cache.locked {
            guard let cached = try cache.read("snapshot.json", as: CachedSnapshot.self) else { throw MopError.vaultMissing }
            try checkWatermark(cached.document)
            guard VaultCoding.digest(cached.document) == cached.revision else { throw MopError.invalidVault }
            return (cached.document, cached.fetched)
        }
    }

    private func checkWatermark(_ bytes: Data) throws {
        let doc = try VaultDocument.decode(bytes)
        guard doc.header.vaultID == id else { throw MopError.invalidVault }
        if let mark = try cache.read("verified.json", as: Watermark.self) {
            guard doc.header.generation >= mark.generation,
                  doc.header.generation != mark.generation || VaultCoding.digest(bytes) == mark.revision else { throw MopError.vaultUntrusted }
        }
    }

    private func recordVerified(_ bytes: Data) throws {
        try checkWatermark(bytes)
        let doc = try VaultDocument.decode(bytes)
        try cache.write(Watermark(generation: doc.header.generation, revision: VaultCoding.digest(bytes)), "verified.json")
        if let downloaded = try cache.read("downloaded.json", as: CachedSnapshot.self), downloaded.document == bytes {
            try cache.write(downloaded, "snapshot.json")
        }
    }

    /// Call only after the cryptographic session has authenticated the document.
    public func verified(_ bytes: Data) throws { try cache.locked { try recordVerified(bytes) } }

    func authenticatedSession(snapshot: Data, opener: any VaultKeyOpener, offline: Bool,
                              onClose: @escaping () -> Void) throws -> VaultSession {
        try cache.locked {
            try checkWatermark(snapshot)
            if !offline, let fingerprint = try cache.read("pending-trust.json", as: String.self) {
                guard try cache.read("downloaded.json", as: CachedSnapshot.self)?.document == snapshot else { throw MopError.vaultConflict }
                try VaultSession.trustSnapshot(snapshot, trust: trust, opener: opener, fingerprint: fingerprint)
                try cache.remove("pending-trust.json")
            }
            let session = try VaultSession(snapshot: snapshot, trust: trust, opener: opener, onClose: onClose)
            try recordVerified(snapshot)
            return session
        }
    }

    func finishCommittedSession(_ session: VaultSession, rotation: Bool) throws {
        try cache.locked {
            try checkWatermark(session.snapshot)
            if rotation {
                // Never let a delayed local completion pin an older key over a
                // newer published rotation from another local process.
                guard try cache.read("downloaded.json", as: CachedSnapshot.self)?.document == session.snapshot else { throw MopError.cloudUncertain }
                try session.pinCommittedKey()
                try cache.remove("pending-trust.json")
            }
            try recordVerified(session.snapshot)
        }
    }

    public func establishTrust(_ bytes: Data, opener: any VaultKeyOpener, fingerprint: String?, revision: String?) throws {
        try cache.locked {
            try checkWatermark(bytes)
            guard try cache.read("downloaded.json", as: CachedSnapshot.self)?.document == bytes else { throw MopError.vaultConflict }
            try VaultSession.trustSnapshot(bytes, trust: trust, opener: opener, fingerprint: fingerprint, revision: revision)
            try cache.remove("pending-trust.json")
            try recordVerified(bytes)
        }
    }

    public func sync() async throws -> Data {
        let lease = try WriterLease(directory: cache.directory)
        defer { lease.close() }
        let head: CloudHead
        let object: CloudObject
        do { (head, object) = try await self.head() }
        catch MopError.vaultMissing {
            // An interrupted initialization may never have published a head. A
            // deleted zone/head cannot prove whether a past commit once existed.
            try cache.locked {
                if try cache.read("journal.json", as: CommitJournal.self) != nil {
                    try cache.write("head-missing", "last-outcome.json")
                    try cache.remove("journal.json")
                }
            }
            throw MopError.vaultMissing
        }
        let bytes = try await revision(head.revision)
        let journal = try cache.locked { try cache.read("journal.json", as: CommitJournal.self) }
        if let journal {
            let committed = try await ancestry(head).contains(journal.proposed)
            // A pending rotation needs authenticated trust completion. Never derive trust
            // from a cloud-supplied fingerprint; this value came from our local session.
            if committed, let fingerprint = journal.rotationFingerprint {
                try cache.locked { try cache.write(fingerprint, "pending-trust.json") }
            }
            try cache.locked {
                if let current = try cache.read("journal.json", as: CommitJournal.self), current.proposed == journal.proposed {
                    try cache.remove("journal.json")
                    try cache.write(committed ? "committed" : "not-committed", "last-outcome.json")
                }
            }
        }
        try cache.locked {
            try checkWatermark(bytes)
            try cache.write(CachedSnapshot(revision: head.revision, root: head.root, version: object.version, fetched: Date(), document: bytes), "downloaded.json")
        }
        return bytes
    }

    private func upload(_ id: String, bytes: Data) async throws {
        if let existing = try await transport.fetch(id, vault: self.id) {
            guard existing.data == bytes else { throw MopError.invalidVault }
            return
        }
        do { _ = try await transport.save(id, kind: .blob, data: bytes, vault: self.id, expected: nil) }
        catch MopError.vaultConflict {
            guard let existing = try await transport.fetch(id, vault: self.id), existing.data == bytes else { throw MopError.invalidVault }
        }
    }

    public func commit(expected: Data?, replacement: Data, rotationFingerprint: String? = nil) async throws {
        try await checkAccount()
        let doc = try VaultDocument.decode(replacement)
        guard doc.header.vaultID == id, try VaultCoding.encode(doc) == replacement else { throw MopError.invalidVault }
        if let rotationFingerprint { guard VaultTrust.validFingerprint(rotationFingerprint) else { throw MopError.vaultUntrusted } }
        let digest = VaultCoding.digest(replacement)
        let current: CloudObject?
        let root: String
        if let expected {
            let (head, object) = try await head()
            let generation = try VaultDocument.decode(expected).header.generation
            guard generation < UInt64.max, head.revision == VaultCoding.digest(expected), doc.header.parent == head.revision,
                  doc.header.generation == generation + 1 else { throw MopError.vaultConflict }
            current = object; root = head.root
        } else {
            guard try await transport.fetch("head", vault: id) == nil else { throw MopError.duplicate }
            current = nil; root = digest
        }
        // Reserve the local writer before staging. A separate process may reconcile
        // only when the writer lock is released (including after process death).
        let lease = try WriterLease(directory: cache.directory)
        defer { lease.close() }
        try cache.locked {
            guard try cache.read("journal.json", as: CommitJournal.self) == nil else { throw MopError.cloudUncertain }
            try cache.write(CommitJournal(expected: expected.map(VaultCoding.digest), proposed: digest, root: root, rotationFingerprint: rotationFingerprint), "journal.json")
        }
        var publishing = false
        do {
            let previousRecords = try expected.map { try VaultDocument.decode($0).records } ?? [:]
            let previousHashes = try Set(previousRecords.values.map { VaultCoding.digest(try VaultCoding.encode($0)) })
            for record in doc.records.values {
                let bytes = try VaultCoding.encode(record)
                let hash = VaultCoding.digest(bytes)
                if !previousHashes.contains(hash) { try await upload("s-" + hash, bytes: bytes) }
                try cache.locked { try cache.putBlob(bytes) }
            }
            try await upload("m-" + digest, bytes: VaultCoding.encode(CloudManifest(document: doc)))
            try await checkAccount()
            publishing = true
            let saved = try await transport.save("head", kind: .head, data: VaultCoding.encode(CloudHead(revision: digest, root: root)), vault: id, expected: current?.version)
            try cache.locked {
                try cache.write(CachedSnapshot(revision: digest, root: root, version: saved.version, fetched: Date(), document: replacement), "downloaded.json")
                if let rotationFingerprint { try cache.write(rotationFingerprint, "pending-trust.json") }
                try cache.remove("journal.json")
            }
        } catch {
            if !publishing || [MopError.vaultConflict, .cloudQuota, .cloudThrottled, .cloudPermission, .cloudAccount, .vaultMissing].contains(error as? MopError ?? .cloudUnavailable) {
                try cache.locked { try cache.remove("journal.json") }
                throw error
            }
            throw MopError.cloudUncertain
        }
    }

    public func status() throws -> [String: String] {
        try cache.locked {
            let snapshot = try cache.read("snapshot.json", as: CachedSnapshot.self)
            let downloaded = try cache.read("downloaded.json", as: CachedSnapshot.self)
            let journal = try cache.read("journal.json", as: CommitJournal.self)
            return ["vault": id.uuidString, "verifiedRevision": snapshot?.revision ?? "none",
                    "downloadedRevision": downloaded?.revision ?? "none", "lastSync": downloaded?.fetched.description ?? "never",
                    "pendingCommit": journal?.proposed ?? "none",
                    "lastOutcome": try cache.read("last-outcome.json", as: String.self) ?? "none"]
        }
    }
}

/// Separate nonblocking process lock prevents sync from treating a live upload as abandoned.
final class WriterLease {
    private var fd: Int32
    init(directory: URL) throws {
        fd = Darwin.open(directory.appendingPathComponent("writer.lock").path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw MopError.filePermissions }
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_uid == getuid(), st.st_mode & S_IFMT == S_IFREG, st.st_mode & 0o077 == 0 else { close(); throw MopError.filePermissions }
        do { try PrivateACL.validate(fd) } catch { close(); throw error }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { close(); throw MopError.cloudUncertain }
    }
    func close() { if fd >= 0 { flock(fd, LOCK_UN); Darwin.close(fd); fd = -1 } }
    deinit { close() }
}
