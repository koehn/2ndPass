import Foundation
import MopCore

/// A terminal owner statement. The genesis digest, not a device-local bootstrap
/// receipt, identifies the setup across independently enrolled devices.
public struct VaultDeletionNotice: Codable, Equatable, Sendable {
    public struct Binding: Codable, Equatable, Sendable {
        public let container: String
        public let environment: String
        public let account: String
        public let vault: UUID
        public let database: String
        public let zone: String
        public let owner: String
        public let genesis: String
        public init(container: String, environment: String, account: String, vault: UUID,
                    database: String, zone: String, owner: String, genesis: String) {
            self.container = container; self.environment = environment; self.account = account
            self.vault = vault; self.database = database; self.zone = zone; self.owner = owner; self.genesis = genesis
        }
    }
    public let format: String
    public let binding: Binding
    public let operation: UUID
    public let membership: String
    public let author: String
    public let chain: [MembershipEnvelope]
    public let signature: Data
    private struct Statement: Encodable {
        let domain = "2ndpass-vault-deletion-1"
        let binding: Binding
        let operation: UUID
        let membership: String
        let author: String
    }
    private var statement: Statement { .init(binding: binding, operation: operation, membership: membership, author: author) }
    public static func create(binding: Binding, history: TrustedMembershipHistory,
                              owner: any DeviceOperations, operation: UUID = UUID()) throws -> Self {
        guard history.current.membership.role(of: owner.identity) == .owner else { throw MopError.cloudPermission }
        let statement = Statement(binding: binding, operation: operation,
            membership: try history.current.digest(), author: owner.identity.fingerprint)
        let result = Self(format: "2ndpass-vault-deletion-1", binding: binding, operation: operation, membership: statement.membership,
            author: statement.author, chain: history.orderedStates,
            signature: try owner.sign(Codec.encode(statement)))
        try result.verify(binding: binding, trusted: history)
        return result
    }
    public func verify(binding expected: Binding, trusted: TrustedMembershipHistory) throws {
        guard format == "2ndpass-vault-deletion-1", binding == expected, binding.vault == trusted.vault,
              !binding.container.isEmpty, ["Development", "Production"].contains(binding.environment),
              !binding.account.isEmpty, binding.database == "private", binding.owner == "__defaultOwner__",
              binding.zone == "MopItems-" + binding.vault.uuidString,
              chain.count > 0, chain.count <= 128, signature.count == 64,
              let genesis = chain.first else { throw MopError.vaultUntrusted }
        var history = try TrustedMembershipHistory(genesis: genesis, vault: binding.vault, pinnedDigest: binding.genesis)
        for next in chain.dropFirst() { try history.append(next) }
        // A terminal notice can race an additive device admission. Accept a
        // common authenticated branch without replacing newer local checkpoints;
        // never accept a fork or a signer removed/demoted by our newer state.
        let sharedCount = min(history.count, trusted.count)
        guard Array(history.orderedStates.prefix(sharedCount)) == Array(trusted.orderedStates.prefix(sharedCount)),
              history.current.membership.accounts.count == 1,
              try history.current.digest() == membership,
              let signer = history.current.membership.key(author),
              history.current.membership.role(of: signer) == .owner,
              (trusted.count <= history.count || trusted.current.membership.role(of: signer) == .owner),
              signer.verifies(signature, message: try Codec.encode(statement)) else { throw MopError.vaultUntrusted }
    }
    public func encoded() throws -> Data {
        let bytes = try Codec.encode(self)
        guard bytes.count <= 1_048_576 else { throw MopError.invalidVault }
        return bytes
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard bytes.count <= 1_048_576 else { throw MopError.invalidVault }
        let result = try JSONDecoder().decode(Self.self, from: bytes)
        guard try result.encoded() == bytes else { throw MopError.invalidVault }
        return result
    }
}
