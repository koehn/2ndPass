import Foundation
import MopCore
import MopVault

public final class CloudRepository {
    public let transport: any CloudTransport
    public let scope: CloudCache
    public let accountID: String
    public let offline: Bool
    private let accounts: CloudCache

    private init(transport: any CloudTransport, scope: CloudCache, accounts: CloudCache, account: String, offline: Bool) {
        self.transport = transport; self.scope = scope; self.accounts = accounts; accountID = account; self.offline = offline
    }

    public static func open(transport: any CloudTransport, state: URL, offline: Bool = false) async throws -> CloudRepository {
        try SafeFile.privateDirectory(state)
        let root = state.appendingPathComponent("cloud")
        try SafeFile.privateDirectory(root)
        let config = VaultCoding.digest(Data((transport.container + ":" + transport.environment).utf8))
        let accounts = try CloudCache(directory: root.appendingPathComponent(config))
        let account: String
        if offline {
            do { try await transport.validateOfflineAccount() }
            catch {
                if (error as? MopError) == .cloudAccount { try accounts.locked { try accounts.remove("binding.json") } }
                throw error
            }
            guard let bound = try accounts.locked({ try accounts.read("binding.json", as: String.self) }) else { throw MopError.cloudAccount }
            account = bound
        } else {
            do { account = try await transport.account() }
            catch {
                if (error as? MopError) == .cloudAccount { try accounts.locked { try accounts.remove("binding.json") } }
                throw error
            }
            try accounts.locked { try accounts.write(account, "binding.json") }
        }
        let scope = try CloudCache(directory: accounts.directory.appendingPathComponent(VaultCoding.digest(Data(account.utf8))))
        return CloudRepository(transport: transport, scope: scope, accounts: accounts, account: account, offline: offline)
    }

    public func online() async throws {
        guard !offline else { throw MopError.offlineWrite }
        do {
            guard try await transport.account() == accountID else { throw MopError.cloudAccount }
        } catch {
            if (error as? MopError) == .cloudAccount { try accounts.locked { try accounts.remove("binding.json") } }
            throw error
        }
    }

    public func list() async throws -> [UUID] { try await online(); return try await transport.zones().filter { $0 != Self.identityZone } }

    /// Header discovery does not authenticate names or membership claims.
    public func descriptors(identity: UserIdentity? = nil) async throws -> [VaultDescriptor] {
        let ids: [UUID]
        if offline {
            ids = try FileManager.default.contentsOfDirectory(atPath: scope.directory.path).compactMap(UUID.init(uuidString:))
        } else { ids = try await list() }
        var rows: [VaultDescriptor] = []
        for id in ids {
            let header: VaultHeader
            if offline {
                let vault = try vault(id)
                // Only authenticated snapshots, never downloaded metadata, supply offline names.
                guard FileManager.default.fileExists(atPath: vault.cache.directory.appendingPathComponent("snapshot.json").path) else { continue }
                do { header = try VaultDocument.decode(vault.cached().0).header }
                catch MopError.legacyVault { continue }
            } else {
                guard let object = try await transport.fetch("head", vault: id) else { continue }
                let head = try decodeCloud(CloudHead.self, object.data)
                guard VaultTrust.validFingerprint(head.revision),
                      let object = try await transport.fetch("m-" + head.revision, vault: id) else { throw MopError.invalidVault }
                struct Metadata: Decodable {
                    struct Header: Decodable { let format: String; let vaultID: UUID }
                    let format: String
                    let header: Header
                }
                let metadata = try decodeCloud(Metadata.self, object.data)
                guard metadata.header.vaultID == id else { throw MopError.invalidVault }
                guard metadata.format == "mop-cloud-manifest-v2", metadata.header.format == "mop-vault-v5" else {
                    rows.append(VaultDescriptor(id: id.uuidString, name: nil, format: metadata.header.format == "mop-vault-v5" ? "unsupported-" + metadata.format : metadata.header.format, enrolled: false))
                    continue
                }
                header = try decodeCloud(CloudManifest.self, object.data).header
                try VaultName.validate(header.name)
            }
            rows.append(VaultDescriptor(id: id.uuidString, name: header.name, format: header.format,
                enrolled: (identity != nil && header.membership?.members.contains { $0.identity == identity } == true)))
        }
        return rows.sorted { ($0.name ?? "", $0.id) < ($1.name ?? "", $1.id) }
    }

    public func resolve(_ selector: String, in rows: [VaultDescriptor], nameOnly: Bool = false) throws -> VaultDescriptor {
        let matches: [VaultDescriptor]
        if !nameOnly, let id = UUID(uuidString: selector), rows.contains(where: { $0.id == id.uuidString }) { matches = rows.filter { $0.id == id.uuidString } }
        else { try VaultName.validate(selector); matches = rows.filter { $0.name == selector } }
        guard !matches.isEmpty else { throw MopError.vaultMissing }
        guard matches.count == 1 else { throw MopError.ambiguousVault }
        guard matches[0].supported else { throw MopError.legacyVault }
        return matches[0]
    }

    /// UUID selection also permits legacy, damaged, and already deleted vaults.
    /// Resolve names exactly once before confirmation; never re-resolve after it.
    public func deletionTarget(_ selector: String) async throws -> VaultDescriptor {
        try await online()
        if let id = UUID(uuidString: selector) {
            let metadata = try? await descriptors()
            return metadata?.first { $0.id == id.uuidString }
                ?? VaultDescriptor(id: id.uuidString, name: nil, format: "unknown", enrolled: false)
        }
        return try resolve(selector, in: await descriptors())
    }

    /// Caller must obtain explicit confirmation and fresh local authentication.
    /// Returns only after remote absence and local cleanup are confirmed.
    public func delete(_ id: UUID) async throws {
        try await online()
        let cache = try CloudCache(directory: scope.directory.appendingPathComponent(id.uuidString))
        let lease = try WriterLease(directory: cache.directory)
        defer { lease.close() }
        var deletionError: Error?
        do { try await transport.deleteZone(id) }
        catch { deletionError = error }
        // A lost response may mean the deletion succeeded. Never automatically
        // resend it: query the same account and UUID before touching local data.
        let remaining: [UUID]
        do { remaining = try await list(); try await online() }
        catch MopError.cloudAccount { throw MopError.cloudAccount }
        catch { throw MopError.vaultDeleteUncertain }
        guard !remaining.contains(id) else {
            if let error = deletionError as? MopError,
               [.cloudPermission, .cloudQuota, .cloudThrottled, .cloudAccount].contains(error) { throw error }
            throw MopError.vaultDeleteUncertain
        }
        do {
            try cache.locked {
                // Retain lock inodes and a tombstone so an already-open session
                // cannot repopulate a deleted offline snapshot.
                try cache.write(true, "deleted.json")
                for name in try FileManager.default.contentsOfDirectory(atPath: cache.directory.path)
                    where !["lock", "writer.lock", "deleted.json"].contains(name) {
                    try FileManager.default.removeItem(at: cache.directory.appendingPathComponent(name))
                }
            }
            try scope.locked {
                if try scope.read("default.json", as: String.self) == id.uuidString { try scope.remove("default.json") }
            }
        } catch { throw MopError.vaultDeleteCleanup }
    }

    public func ensureAvailable(_ name: String, excluding: UUID? = nil) async throws {
        try VaultName.validate(name)
        guard try await !descriptors().contains(where: { $0.name == name && $0.id != excluding?.uuidString }) else { throw MopError.duplicate }
    }

    public func named(_ selector: String) async throws -> CloudVault {
        let row = try resolve(selector, in: await descriptors())
        return try vault(UUID(uuidString: row.id)!)
    }

    public func vault(_ id: UUID) throws -> CloudVault {
        guard id != Self.identityZone else { throw MopError.invalidVault }
        return CloudVault(id: id, cache: try CloudCache(directory: scope.directory.appendingPathComponent(id.uuidString)), transport: transport, accountID: accountID, invalidateBinding: {
            try self.accounts.locked {
                if try self.accounts.read("binding.json", as: String.self) == self.accountID {
                    try self.accounts.remove("binding.json")
                }
            }
        })
    }

    public func selected(_ explicit: String?) throws -> CloudVault {
        let value = try explicit ?? scope.locked { try scope.read("default.json", as: String.self) }
        guard let value, let id = UUID(uuidString: value) else { throw MopError.vaultMissing }
        return try vault(id)
    }

    public func use(_ id: UUID, onlyIfUnset: Bool = false) throws {
        try scope.locked {
            if onlyIfUnset, try scope.read("default.json", as: String.self) != nil { return }
            try scope.write(id.uuidString, "default.json")
        }
    }

    public func create(_ bytes: Data, fingerprint: String) async throws -> CloudVault {
        try await online()
        let doc = try VaultDocument.decode(bytes)
        try await ensureAvailable(doc.header.name)
        let vault = try vault(doc.header.vaultID)
        try await transport.createZone(vault.id)
        try await vault.commit(expected: nil, replacement: bytes, rotationFingerprint: fingerprint)
        try use(vault.id, onlyIfUnset: true)
        return vault
    }


    /// Export only authenticated ciphertext and the public account anchor. The
    /// extension has its own cache; app/CLI storage and journals stay untouched.
    public func exportAutoFillSnapshot(_ id: UUID, expected: Data, to state: URL) throws {
        let source = try vault(id)
        let snapshot: CachedSnapshot = try source.cache.locked {
            guard try source.cache.read("deleted.json", as: Bool.self) != true else { throw MopError.vaultMissing }
            guard let value = try source.cache.read("snapshot.json", as: CachedSnapshot.self) else { throw MopError.vaultMissing }
            guard value.document == expected, value.revision == VaultCoding.digest(expected),
                  let verified = try source.cache.read("verified.json", as: Watermark.self),
                  verified.revision == value.revision else { throw MopError.vaultConflict }
            return value
        }
        guard let anchor = try scope.locked({ try scope.read("account-identity.json", as: CloudIdentityAnchor.self) }) else { throw MopError.identityPending }
        try anchor.validate(scope: identityScope)
        let config = VaultCoding.digest(Data((transport.container + ":" + transport.environment).utf8))
        let accounts = try CloudCache(directory: state.appendingPathComponent("cloud").appendingPathComponent(config))
        let targetScope = try CloudCache(directory: accounts.directory.appendingPathComponent(VaultCoding.digest(Data(accountID.utf8))))
        let target = try CloudCache(directory: targetScope.directory.appendingPathComponent(id.uuidString))
        try target.locked {
            let generation = try VaultDocument.decode(snapshot.document).header.generation
            if let old = try target.read("verified.json", as: Watermark.self) {
                guard generation > old.generation || (generation == old.generation && snapshot.revision == old.revision) else { throw MopError.vaultConflict }
            }
            try target.write(snapshot, "snapshot.json")
            try target.write(Watermark(generation: generation, revision: snapshot.revision), "verified.json")
            try target.remove("deleted.json")
        }
        try targetScope.locked { try targetScope.write(anchor, "account-identity.json") }
        try accounts.locked { try accounts.write(accountID, "binding.json") }
    }

    private func autoFillScope(in state: URL) -> URL {
        let config = VaultCoding.digest(Data((transport.container + ":" + transport.environment).utf8))
        return state.appendingPathComponent("cloud").appendingPathComponent(config).appendingPathComponent(VaultCoding.digest(Data(accountID.utf8)))
    }
    public func removeAutoFillSnapshot(_ id: String, in state: URL) throws {
        guard let id = UUID(uuidString: id) else { throw MopError.invalidVault }
        let cache = try CloudCache(directory: autoFillScope(in: state).appendingPathComponent(id.uuidString))
        try cache.locked {
            try cache.write(true, "deleted.json")
            try cache.remove("snapshot.json")
        }
    }
    public func pruneAutoFillSnapshots(keeping ids: Set<String>, in state: URL) throws {
        let directory = autoFillScope(in: state)
        let accounts = try CloudCache(directory: directory.deletingLastPathComponent())
        try accounts.locked { try accounts.write(accountID, "binding.json") }
        guard FileManager.default.fileExists(atPath: directory.path) else { return }
        for name in try FileManager.default.contentsOfDirectory(atPath: directory.path) where UUID(uuidString: name) != nil && !ids.contains(name) {
            try removeAutoFillSnapshot(name, in: state)
        }
    }

}
