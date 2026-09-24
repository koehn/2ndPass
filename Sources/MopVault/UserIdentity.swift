import CryptoKit
import Foundation
import MopCore

/// The public portion of a user's synchronized Mop identity. No Apple Account
/// identifier or private key appears in vault membership metadata.
public struct UserIdentity: Codable, Equatable, Sendable {
    public let encryptionKey: Data
    public let signingKey: Data
    public var id: String { VaultCoding.digest(encryptionKey + signingKey) }
    public init(encryptionKey: Data, signingKey: Data) throws {
        self.encryptionKey = encryptionKey; self.signingKey = signingKey
        try validate()
    }
    public func validate() throws {
        guard encryptionKey.count == 65, signingKey.count == 65,
              (try? P256.KeyAgreement.PublicKey(x963Representation: encryptionKey)) != nil,
              (try? P256.Signing.PublicKey(x963Representation: signingKey)) != nil else { throw MopError.invalidIdentity }
    }
    public func verifies(_ signature: Data, data: Data) -> Bool {
        guard let key = try? P256.Signing.PublicKey(x963Representation: signingKey),
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
        return key.isValidSignature(signature, for: data)
    }
}

public protocol VaultSigningOpener: VaultKeyOpener {
    var signingPublicKey: Data { get }
    func sign(_ data: Data) throws -> Data
}

/// Software key material intentionally synchronizes through iCloud Keychain.
/// It is accessed only after application authentication; it is not an Enclave key.
public final class AccountIdentity: VaultSigningOpener {
    private var encryption: P256.KeyAgreement.PrivateKey?
    private var signing: P256.Signing.PrivateKey?
    public let identity: UserIdentity
    public var publicKey: Data { identity.encryptionKey }
    public var signingPublicKey: Data { identity.signingKey }
    public var request: RecipientKey { try! RecipientKey(name: "Mop account", publicKey: publicKey) }
    public init() {
        let encryption = P256.KeyAgreement.PrivateKey(), signing = P256.Signing.PrivateKey()
        self.encryption = encryption; self.signing = signing
        identity = try! UserIdentity(encryptionKey: encryption.publicKey.x963Representation, signingKey: signing.publicKey.x963Representation)
    }
    public init(material: Data) throws {
        guard material.count == 64 else { throw MopError.invalidIdentity }
        let encryption = try P256.KeyAgreement.PrivateKey(rawRepresentation: material.prefix(32))
        let signing = try P256.Signing.PrivateKey(rawRepresentation: material.suffix(32))
        self.encryption = encryption; self.signing = signing
        identity = try UserIdentity(encryptionKey: encryption.publicKey.x963Representation, signingKey: signing.publicKey.x963Representation)
    }
    public func withMaterial<T>(_ body: (Data) throws -> T) throws -> T {
        guard let encryption, let signing else { throw MopError.authentication }
        var bytes = encryption.rawRepresentation + signing.rawRepresentation
        defer { KeyMaterial.wipe(&bytes) }
        return try body(bytes)
    }
    public func unwrap(_ recipient: VaultRecipient, vaultID: UUID) throws -> SymmetricKey {
        guard let encryption else { throw MopError.authentication }
        guard recipient.publicKey == publicKey else { throw MopError.notVaultMember }
        return try VaultDocument.unwrap(recipient, vaultID: vaultID, privateKey: encryption)
    }
    public func sign(_ data: Data) throws -> Data {
        guard let signing else { throw MopError.authentication }
        return try signing.signature(for: data).rawRepresentation
    }
    public func close() { encryption = nil; signing = nil }
    deinit { close() }
}

public enum VaultMemberRole: String, Codable, Sendable { case owner, editor, viewer }
public struct VaultMember: Codable, Equatable, Sendable {
    public let identity: UserIdentity
    public let role: VaultMemberRole
    public init(identity: UserIdentity, role: VaultMemberRole) { self.identity = identity; self.role = role }
}

/// Version one deliberately grants access to one owner. Additional members and
/// role changes require the future cross-account invitation/authority protocol.
public struct VaultMembership: Codable, Equatable, Sendable {
    public let format: String
    public let vaultID: UUID
    public let members: [VaultMember]
    public let vaultFingerprint: String
    public let signature: Data
    private struct Statement: Codable {
        let format: String; let vaultID: UUID; let members: [VaultMember]; let vaultFingerprint: String
    }
    private var statement: Statement { Statement(format: format, vaultID: vaultID, members: members, vaultFingerprint: vaultFingerprint) }
    public var owner: UserIdentity { members[0].identity }
    public init(vaultID: UUID, fingerprint: String, owner: AccountIdentity) throws {
        format = "mop-membership-v1"; self.vaultID = vaultID
        members = [VaultMember(identity: owner.identity, role: .owner)]; vaultFingerprint = fingerprint
        signature = try owner.sign(VaultCoding.encode(Statement(format: format, vaultID: vaultID, members: members, vaultFingerprint: fingerprint)))
        try validate(vaultID: vaultID)
    }
    public func validate(vaultID: UUID) throws {
        guard format == "mop-membership-v1", self.vaultID == vaultID,
              members.count == 1, members[0].role == .owner,
              VaultTrust.validFingerprint(vaultFingerprint) else { throw MopError.invalidVault }
        try owner.validate()
        guard owner.verifies(signature, data: try VaultCoding.encode(statement)) else { throw MopError.invalidVault }
    }
}
