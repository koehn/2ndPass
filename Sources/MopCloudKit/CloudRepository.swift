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

    public func list() async throws -> [UUID] { try await online(); return try await transport.zones() }

    public func vault(_ id: UUID) throws -> CloudVault {
        CloudVault(id: id, cache: try CloudCache(directory: scope.directory.appendingPathComponent(id.uuidString)), transport: transport, accountID: accountID, invalidateBinding: {
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
        let vault = try vault(doc.header.vaultID)
        try await transport.createZone(vault.id)
        try await vault.commit(expected: nil, replacement: bytes, rotationFingerprint: fingerprint)
        try use(vault.id, onlyIfUnset: true)
        return vault
    }

    public func request(_ request: DeviceRequest, vault: CloudVault) async throws -> String {
        try await online()
        _ = try await vault.head() // Never recreate a removed zone.
        try request.validate()
        let id = "q-" + request.fingerprint
        let bytes = try VaultCoding.encode(request)
        if let existing = try await transport.fetch(id, vault: vault.id) {
            let prior = try decodeCloud(DeviceRequest.self, existing.data)
            try prior.validate()
            guard prior.publicKey == request.publicKey else { throw MopError.invalidDevice }
        } else { _ = try await transport.save(id, kind: .request, data: bytes, vault: vault.id, expected: nil) }
        return id
    }

    public func request(_ id: String, vault: CloudVault) async throws -> DeviceRequest {
        try await online()
        guard id.hasPrefix("q-"), VaultTrust.validFingerprint(String(id.dropFirst(2))),
              let object = try await transport.fetch(id, vault: vault.id), object.data.count <= 4096 else { throw MopError.invalidDevice }
        let request = try decodeCloud(DeviceRequest.self, object.data)
        try request.validate()
        guard "q-" + request.fingerprint == id else { throw MopError.invalidDevice }
        return request
    }
}
