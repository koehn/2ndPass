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


}
