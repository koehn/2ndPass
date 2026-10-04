import Foundation
import CryptoKit
import MopCore

/// Disposable per-item health evidence, independently signed, encrypted, and synchronized.
public struct ItemHealthEnvelope: Codable, Equatable, Sendable {
    public static func recordID(for item: UUID) -> UUID {
        let bytes = Array(SHA256.hash(data: Data(("2ndpass-item-health-id-1:" + item.uuidString).utf8)).prefix(16))
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
    public struct Header: Codable, Equatable, Sendable {
        public let format: String
        public let vault: UUID
        public let item: UUID
        public let version: UUID
        public let generation: UInt64
        public let base: UUID?
        public let membership: String
        public let author: String
    }
    public let header: Header
    public let ciphertext: Data
    public let envelopes: [String: KeyEnvelope]
    public let signature: Data
    private struct Statement: Encodable {
        let domain = "2ndpass-item-health-signature-1"
        let header: Header; let ciphertext: Data; let envelopes: [String: KeyEnvelope]
    }
    private struct Context: Encodable {
        let domain = "2ndpass-item-health-content-1"
        let header: Header
    }
    private struct RecipientContext: Encodable {
        let domain = "2ndpass-item-health-key-1"
        let header: Header; let recipient: String
    }
    private var statement: Statement { Statement(header: header, ciphertext: ciphertext, envelopes: envelopes) }

    public static func seal(_ checks: [CachedPasswordCheck], vault: UUID, item: UUID, generation: UInt64, version: UUID = UUID(), base: UUID? = nil,
                            membership: Membership, membershipStateDigest: String, signer: any DeviceOperations) throws -> Self {
        for check in checks { try check.validate() }
        guard checks.count <= 4096, Set(checks.map(\.record)).count == checks.count else { throw MopError.invalidVault }
        try membership.validate()
        guard Codec.hash(membershipStateDigest), let role = membership.role(of: signer.identity), role == .owner || role == .editor,
              version != base, generation > 0, generation <= UInt64(Int64.max), (generation == 1) == (base == nil) else { throw MopError.cloudPermission }
        let header = Header(format: "2ndpass-item-health-1", vault: vault, item: item, version: version, generation: generation, base: base,
            membership: membershipStateDigest, author: signer.identity.fingerprint)
        let key = SymmetricKey(size: .bits256)
        var plaintext = try Codec.encode(checks)
        defer { SecretBytes.wipe(&plaintext) }
        guard plaintext.count <= Codec.maximumSize - 28 else { throw PortableArchiveFailure.tooLarge }
        guard let ciphertext = try AES.GCM.seal(plaintext, using: key,
            authenticating: Codec.encode(Context(header: header))).combined else { throw MopError.invalidVault }
        let envelopes = try Dictionary(uniqueKeysWithValues: membership.recipients.map { recipient in
            (recipient.fingerprint, try KeyEnvelope.seal(key, to: recipient.encryption,
                context: Codec.encode(RecipientContext(header: header, recipient: recipient.fingerprint))))
        })
        let statement = Statement(header: header, ciphertext: ciphertext, envelopes: envelopes)
        return Self(header: header, ciphertext: ciphertext, envelopes: envelopes, signature: try signer.sign(Codec.encode(statement)))
    }

    public func verify(vault: UUID, item: UUID, membership: Membership, membershipStateDigest: String) throws {
        try membership.validate()
        guard header.format == "2ndpass-item-health-1", header.vault == vault, header.item == item,
              header.version != header.base, header.generation > 0, header.generation <= UInt64(Int64.max), (header.generation == 1) == (header.base == nil), Codec.hash(membershipStateDigest), header.membership == membershipStateDigest,
              let author = membership.key(header.author), let role = membership.role(of: author),
              role == .owner || role == .editor,
              (28...Codec.maximumSize).contains(ciphertext.count), signature.count == 64,
              Set(envelopes.keys) == Set(membership.recipients.map(\.fingerprint)),
              envelopes.values.allSatisfy({ $0.encapsulatedKey.count == 65 && $0.ciphertext.count == 48 }),
              author.verifies(signature, message: try Codec.encode(statement)) else { throw MopError.vaultUntrusted }
    }

    public func open(device: any DeviceOperations, membership: Membership, membershipStateDigest: String) throws -> [CachedPasswordCheck] {
        try verify(vault: header.vault, item: header.item, membership: membership, membershipStateDigest: membershipStateDigest)
        guard membership.role(of: device.identity) != nil || membership.offlineRecovery == device.identity,
              let envelope = envelopes[device.identity.fingerprint] else { throw MopError.notVaultMember }
        let key = try device.unwrap(envelope,
            context: Codec.encode(RecipientContext(header: header, recipient: device.identity.fingerprint)))
        var bytes = try AES.GCM.open(AES.GCM.SealedBox(combined: ciphertext), using: key,
            authenticating: Codec.encode(Context(header: header)))
        defer { SecretBytes.wipe(&bytes) }
        let result = try JSONDecoder().decode([CachedPasswordCheck].self, from: bytes)
        guard result.count <= 4096, Set(result.map(\.record)).count == result.count else { throw MopError.invalidVault }
        for check in result { try check.validate() }
        return result
    }

    public func encoded() throws -> Data {
        let data = try Codec.encode(self)
        guard data.count <= PortableArchive.maximumSize else { throw PortableArchiveFailure.tooLarge }
        return data
    }
    public static func decode(_ data: Data, vault: UUID, item: UUID, membership: Membership, membershipStateDigest: String) throws -> Self {
        guard data.count <= PortableArchive.maximumSize else { throw PortableArchiveFailure.tooLarge }
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard try Codec.encode(value) == data else { throw MopError.invalidVault }
        try value.verify(vault: vault, item: item, membership: membership, membershipStateDigest: membershipStateDigest)
        return value
    }
}
