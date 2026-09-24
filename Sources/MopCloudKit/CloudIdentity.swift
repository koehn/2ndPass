import Foundation
import MopCore
import MopKeychain
import MopVault

/// A conditionally-created public anchor chooses one immutable Keychain item,
/// even if two devices initialize simultaneously. Private material never enters
/// CloudKit or local files. A missing winning key means wait, never replacement.
public struct CloudIdentityAnchor: Codable, Equatable, Sendable {
    public let format: String
    public let keyID: UUID
    public let identity: UserIdentity
    public let scope: String
    public let signature: Data
    private struct Statement: Codable {
        let format: String; let keyID: UUID; let identity: UserIdentity; let scope: String
    }
    init(keyID: UUID, identity: AccountIdentity, scope: String) throws {
        format = "mop-account-identity-v1"; self.keyID = keyID; self.identity = identity.identity; self.scope = scope
        signature = try identity.sign(VaultCoding.encode(Statement(format: format, keyID: keyID, identity: identity.identity, scope: scope)))
    }
    func validate(scope: String) throws {
        try identity.validate()
        guard format == "mop-account-identity-v1", self.scope == scope,
              identity.verifies(signature, data: try VaultCoding.encode(Statement(format: format, keyID: keyID, identity: identity, scope: scope))) else { throw MopError.invalidIdentity }
    }
}

public extension CloudRepository {
    static var identityZone: UUID { UUID(uuidString: "7C6F7075-7365-4273-8964-656E74697479")! }
    var identityScope: String {
        VaultCoding.digest(Data([transport.container, transport.environment, accountID].map { "\($0.utf8.count):" + $0 }.joined().utf8))
    }
    func identityAnchor() async throws -> CloudIdentityAnchor? {
        if offline {
            let cached = try scope.locked { try scope.read("account-identity.json", as: CloudIdentityAnchor.self) }
            try cached?.validate(scope: identityScope)
            return cached
        }
        try await online()
        guard try await transport.zones().contains(Self.identityZone) else {
            // Do not recreate a missing previously-observed anchor.
            if try scope.locked({ try scope.read("account-identity.json", as: CloudIdentityAnchor.self) }) != nil { throw MopError.identityPending }
            return nil
        }
        guard let object = try await transport.fetch("account-identity-v1", vault: Self.identityZone) else {
            if try scope.locked({ try scope.read("account-identity.json", as: CloudIdentityAnchor.self) }) != nil { throw MopError.identityPending }
            return nil
        }
        guard object.data.count <= 4096 else { throw MopError.invalidIdentity }
        let anchor = try decodeCloud(CloudIdentityAnchor.self, object.data)
        try anchor.validate(scope: identityScope)
        try await online()
        try scope.locked {
            if let old = try scope.read("account-identity.json", as: CloudIdentityAnchor.self), old != anchor { throw MopError.invalidIdentity }
            try scope.write(anchor, "account-identity.json")
        }
        return anchor
    }
    /// Call only after local user authentication. `check` guards cancellation and
    /// session/account changes around Keychain and conditional cloud operations.
    func accountIdentity(keys: any IdentityKeyStore, create: Bool, check: () throws -> Void = {}) async throws -> AccountIdentity {
        try check()
        var anchor = try await identityAnchor()
        if anchor == nil {
            guard create, !offline else { throw MopError.identityPending }
            // A deleted registry cannot justify a second owner for existing v5 vaults.
            guard !(try await descriptors()).contains(where: { $0.format == "mop-vault-v5" }) else { throw MopError.identityPending }
            let candidate = AccountIdentity(), id = UUID()
            defer { candidate.close() }
            try check()
            try candidate.withMaterial { try keys.insert($0, scope: identityScope, id: id) }
            let proposed = try CloudIdentityAnchor(keyID: id, identity: candidate, scope: identityScope)
            try await online(); try check()
            try await transport.createZone(Self.identityZone)
            try await online(); try check()
            do {
                _ = try await transport.save("account-identity-v1", kind: .blob, data: VaultCoding.encode(proposed), vault: Self.identityZone, expected: nil)
            } catch {
                // Fetch the winner, including after a lost save acknowledgement.
                // Never repeat this mutation automatically or overwrite its key.
                if let winner = try await identityAnchor() { anchor = winner }
                else { throw error }
            }
            if anchor == nil { anchor = try await identityAnchor() }
        }
        try check()
        guard let anchor, var bytes = try keys.read(scope: identityScope, id: anchor.keyID) else { throw MopError.identityPending }
        defer { SecretBytes.wipe(&bytes) }
        let identity = try AccountIdentity(material: bytes)
        guard identity.identity == anchor.identity else { identity.close(); throw MopError.invalidIdentity }
        do { if !offline { try await online() }; try check() } catch { identity.close(); throw error }
        return identity
    }
}
