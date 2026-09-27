import Foundation
import MopCore
import MopVaultNext

struct NextEntry: Codable {
    let address: VaultAddress
    let checkpoint: Data
    let digest: String
    var name: String
    var submitted: Bool
    var ready: Bool
}

/// Locally pinned roots, never populated merely by discovering cloud records.
struct NextRegistry {
    let cache: LocalDirectory
    let account: String
    let container: String
    let environment: String
    let member: UUID
    init(state: URL, container: String, environment: String, account: String) throws {
        self.account = account; self.container = container; self.environment = environment
        member = AccountScope.member(container: container, environment: environment, account: account)
        cache = try LocalDirectory(directory: state.appendingPathComponent("v6").appendingPathComponent(member.uuidString))
    }
    private func read<T: Decodable>(_ name: String, as type: T.Type) throws -> T? {
        let url = cache.directory.appendingPathComponent(name)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let bytes = try LocalFile.read(url, privateFile: true, limit: 64 * 1024 * 1024)
        do { return try JSONDecoder().decode(type, from: bytes) }
        catch { throw MopError.invalidVault }
    }
    private func write<T: Encodable>(_ value: T, _ name: String) throws {
        let url = cache.directory.appendingPathComponent(name)
        try LocalFile.write(JSONEncoder().encode(value), to: url, replace: FileManager.default.fileExists(atPath: url.path))
    }
    func removed() throws -> Bool {
        try cache.locked { try read("removed.json", as: Bool.self) ?? false }
    }
    func setRemoved(_ value: Bool) throws {
        try cache.locked { try write(value, "removed.json") }
    }
    /// Only app-managed account caches; explicit exported backups are untouched.
    func clearRemovedAccount() throws {
        try cache.locked {
            try FileVerifiedStateStore.clearAccountCache(at: cache.directory.appendingPathComponent("checkpoints"))
            for name in try FileManager.default.contentsOfDirectory(atPath: cache.directory.path)
                where name.hasPrefix("enrollment-") && name.hasSuffix(".json") {
                try FileManager.default.removeItem(at: cache.directory.appendingPathComponent(name))
            }
            let attachments = cache.directory.appendingPathComponent("attachments")
            if FileManager.default.fileExists(atPath: attachments.path) { try FileManager.default.removeItem(at: attachments) }
            try write([NextEntry](), "vaults.json")
        }
    }
    func enrollment(_ vault: UUID) throws -> EnrollmentExchange? {
        try cache.locked { try read("enrollment-" + vault.uuidString + ".json", as: EnrollmentExchange.self) }
    }
    func saveEnrollment(_ exchange: EnrollmentExchange) throws {
        try cache.locked {
            guard try read("removed.json", as: Bool.self) != true else { throw MopError.deviceRemoved }
            try write(exchange, "enrollment-" + exchange.request.vault.uuidString + ".json")
        }
    }
    func entries() throws -> [NextEntry] {
        try cache.locked { try read("vaults.json", as: [NextEntry].self) ?? [] }
    }
    func put(_ entry: NextEntry) throws {
        guard entry.address.account == account, entry.address.container == container, entry.address.environment == environment else { throw MopError.cloudAccount }
        _ = try VerifiedVault(checkpoint: entry.checkpoint, independentlyVerifiedDigest: entry.digest)
        try cache.locked {
            guard try read("removed.json", as: Bool.self) != true else { throw MopError.deviceRemoved }
            var entries = try read("vaults.json", as: [NextEntry].self) ?? []
            if let old = entries.first(where: { $0.address.vault == entry.address.vault }), old.address != entry.address { throw MopError.vaultUntrusted }
            entries.removeAll { $0.address == entry.address }; entries.append(entry)
            try write(entries, "vaults.json")
        }
    }
    func select(_ selection: String?) throws -> NextEntry {
        let entries = try entries()
        let matches = selection.map { value in entries.filter { $0.address.vault.uuidString == value || $0.name == value } } ?? entries
        guard matches.count <= 1 else { throw MopError.ambiguousVault }
        guard let entry = matches.first else { throw MopError.vaultMissing }
        return entry
    }
    func storage(_ entry: NextEntry) throws -> FileVerifiedStateStore {
        try FileVerifiedStateStore(directory: cache.directory.appendingPathComponent("checkpoints"), address: entry.address)
    }
    func forget(_ entry: NextEntry) throws {
        try cache.locked {
            let entries = try read("vaults.json", as: [NextEntry].self) ?? []
            try write(entries.filter { $0.address != entry.address }, "vaults.json")
        }
        // Retain ciphertext/checkpoints. Explicit cloud deletion isn't permission
        // to erase backups or unrelated local data.
    }
}

struct NextAccountBinding: Codable {
    let container: String
    let environment: String
    let account: String
    var valid: Bool
    static func cache(_ state: URL) throws -> LocalDirectory { try LocalDirectory(directory: state.appendingPathComponent("v6-account-bindings")) }
    static func name(_ container: String, _ environment: String) -> String {
        AccountScope.member(container: container, environment: environment, account: "local-binding").uuidString + ".json"
    }
    static func remember(state: URL, container: String, environment: String, account: String) throws {
        let cache = try cache(state), url = cache.directory.appendingPathComponent(name(container, environment))
        try cache.locked {
            try LocalFile.write(JSONEncoder().encode(Self(container: container, environment: environment, account: account, valid: true)),
                               to: url, replace: FileManager.default.fileExists(atPath: url.path))
        }
    }
    static func account(state: URL, container: String, environment: String) throws -> String {
        let cache = try cache(state), url = cache.directory.appendingPathComponent(name(container, environment))
        return try cache.locked {
            let binding = try JSONDecoder().decode(Self.self, from: LocalFile.read(url, privateFile: true, limit: 4096))
            guard binding.valid, binding.container == container, binding.environment == environment else { throw MopError.cloudAccount }
            return binding.account
        }
    }
    static func invalidate(state: URL) throws {
        let cache = try cache(state)
        try cache.locked {
            for name in try FileManager.default.contentsOfDirectory(atPath: cache.directory.path) where name.hasSuffix(".json") {
                let url = cache.directory.appendingPathComponent(name)
                var binding = try JSONDecoder().decode(Self.self, from: LocalFile.read(url, privateFile: true, limit: 4096))
                binding.valid = false
                try LocalFile.write(JSONEncoder().encode(binding), to: url, replace: true)
            }
        }
    }
}
