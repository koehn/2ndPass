import CryptoKit
import Foundation
import MopCore

/// The preview v3 protocol separates immutable signed content from recipient
/// grants. This type is deliberately distinct from the deployed v2 envelope.
public struct ContentEnvelope: Codable, Equatable, Sendable {
    public struct Header: Codable, Equatable, Sendable {
        public let format: String
        public let vault: UUID
        public let item: UUID
        public let version: UUID
        public let base: UUID?
        public let generation: UInt64
        public let contentRevision: UUID
        public let isTombstone: Bool
        public let keyGeneration: UUID
        public let keyMembership: String
        public let keyAuthor: String
        public let membership: String
        public let author: String
    }
    public let header: Header
    public let components: [String: Data]
    public let signature: Data
    private struct Statement: Encodable {
        let domain = "2ndpass-content-signature-3"
        let header: Header
        let components: [String: Data]
    }
    private struct EncryptionContext: Encodable {
        let domain = "2ndpass-content-component-3"
        let header: Header
        let component: String
    }
    private var statement: Statement { Statement(header: header, components: components) }

    public static func seal(_ plaintext: [String: SecretBytes], vault: UUID, item: UUID,
                            generation: UInt64 = 1, base: UUID? = nil,
                            history: TrustedMembershipHistory, signer: any DeviceOperations, isTombstone: Bool = false) throws -> ContentPublication {
        try seal(plaintext, vault: vault, item: item, generation: generation, base: base,
            contentRevision: UUID(), history: history, signer: signer, isTombstone: isTombstone)
    }

    private static func seal(_ plaintext: [String: SecretBytes], vault: UUID, item: UUID,
                             generation: UInt64, base: UUID?, contentRevision: UUID,
                             history: TrustedMembershipHistory, signer: any DeviceOperations,
                             reusing: (key: SymmetricKey, header: Header)? = nil, isTombstone: Bool = false) throws -> ContentPublication {
        let membership = history.current.membership
        let role = membership.role(of: signer.identity)
        guard history.vault == vault, role == .owner || role == .editor,
              generation > 0, generation <= UInt64(Int64.max), (generation == 1) == (base == nil),
              (isTombstone ? plaintext.isEmpty : !plaintext.isEmpty), plaintext.count <= 262_144,
              plaintext.keys.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 128 }),
              plaintext.values.allSatisfy({ $0.count <= 16 * 1024 * 1024 }) else { throw MopError.invalidVault }
        let header = Header(format: "2ndpass-content-3", vault: vault, item: item, version: UUID(), base: base,
            generation: generation, contentRevision: contentRevision, isTombstone: isTombstone, keyGeneration: reusing?.header.keyGeneration ?? UUID(),
            keyMembership: try reusing?.header.keyMembership ?? history.current.digest(),
            keyAuthor: reusing?.header.keyAuthor ?? signer.identity.fingerprint,
            membership: try history.current.digest(), author: signer.identity.fingerprint)
        let key = reusing?.key ?? SymmetricKey(size: .bits256)
        var components: [String: Data] = [:]
        for (name, bytes) in plaintext {
            components[name] = try bytes.withFoundationData {
                guard let combined = try AES.GCM.seal($0, using: key,
                    authenticating: Codec.encode(EncryptionContext(header: header, component: name))).combined else { throw MopError.invalidVault }
                return combined
            }
        }
        let content = Self(header: header, components: components,
            signature: try signer.sign(Codec.encode(Statement(header: header, components: components))))
        _ = try content.encoded()
        let grants = try (reusing == nil ? membership.recipients : []).map {
            try ContentKeyGrant.seal(key, content: content, recipient: $0, history: history, signer: signer)
        }
        return ContentPublication(content: content, grants: grants)
    }

    public func verify(history: TrustedMembershipHistory, item: UUID) throws {
        let state = try history.state(forDigest: header.membership)
        guard header.format == "2ndpass-content-3", header.vault == history.vault, header.item == item,
              header.version != header.base, header.generation > 0, header.generation <= UInt64(Int64.max),
              (header.generation == 1) == (header.base == nil), Codec.hash(header.membership),
              let author = state.membership.key(header.author),
              state.membership.role(of: author) == .owner || state.membership.role(of: author) == .editor,
              signature.count == 64, (header.isTombstone ? components.isEmpty : !components.isEmpty), components.count <= 262_144,
              components.keys.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 128 }),
              components.values.allSatisfy({ (28...(16 * 1024 * 1024 + 28)).contains($0.count) }),
              components.values.reduce(0, { $0 + $1.count }) <= PortableArchive.maximumSize,
              author.verifies(signature, message: try Codec.encode(statement)) else { throw MopError.vaultUntrusted }
        let keyState = try history.state(forDigest: header.keyMembership)
        guard let keyAuthor = keyState.membership.key(header.keyAuthor),
              keyState.membership.role(of: keyAuthor) == .owner || keyState.membership.role(of: keyAuthor) == .editor else {
            throw MopError.vaultUntrusted
        }
        try history.verifyContentKeyPath(from: header.keyMembership, to: header.membership)
        try history.verifyAccountPath(from: header.membership, allowingDeviceRemoval: true)
    }

    /// Additive grants do not make an already signed publication obsolete.
    /// Recovery or revocation transitions still require a new key generation.
    public func verifyForPublication(history: TrustedMembershipHistory) throws {
        try verify(history: history, item: header.item)
        try history.verifyContentKeyPath(from: header.membership)
    }

    public func open(component: String, grant: ContentKeyGrant, history: TrustedMembershipHistory,
                     device: any DeviceOperations) throws -> SecretBytes {
        try verify(history: history, item: header.item)
        let key = try grant.unwrap(content: self, history: history, device: device)
        return try decrypt(component: component, key: key)
    }
    /// One authorized unwrap for a bounded component projection. No key escapes
    /// this call; callers can read visible fields without opening concealed ones.
    public func open(components names: Set<String>, grant: ContentKeyGrant, history: TrustedMembershipHistory,
                     device: any DeviceOperations) throws -> [String: SecretBytes] {
        try verify(history: history, item: header.item)
        guard names.isSubset(of: Set(components.keys)) else { throw MopError.notFound }
        let key = try grant.unwrap(content: self, history: history, device: device)
        var result: [String: SecretBytes] = [:]
        for name in names {
            try Task.checkCancellation()
            result[name] = try decrypt(component: name, key: key)
        }
        return result
    }

    /// Select visible components from authenticated metadata, sharing one unwrap.
    /// The key stays inside this synchronous call; concealed components need not open.
    public func openProjection<T>(initial: String, grant: ContentKeyGrant, history: TrustedMembershipHistory,
                                  device: any DeviceOperations,
                                  select: (SecretBytes) throws -> (T, Set<String>)) throws -> (T, [String: SecretBytes]) {
        try verify(history: history, item: header.item)
        let key = try grant.unwrap(content: self, history: history, device: device)
        let (projection, names) = try select(decrypt(component: initial, key: key))
        guard names.isSubset(of: Set(components.keys)) else { throw MopError.notFound }
        var values: [String: SecretBytes] = [:]
        for name in names {
            try Task.checkCancellation()
            values[name] = try decrypt(component: name, key: key)
        }
        return (projection, values)
    }

    private func decrypt(component: String, key: SymmetricKey) throws -> SecretBytes {
        guard let ciphertext = components[component] else { throw MopError.notFound }
        var bytes = try AES.GCM.open(AES.GCM.SealedBox(combined: ciphertext), using: key,
            authenticating: Codec.encode(EncryptionContext(header: header, component: component)))
        defer { SecretBytes.wipe(&bytes) }
        return SecretBytes(copying: bytes)
    }

    /// An ordinary edit retains its key generation and existing grants. The caller
    /// persists the returned signed content before publication; retries must reuse it.
    public func editing(_ plaintext: [String: SecretBytes], grant: ContentKeyGrant,
                        history: TrustedMembershipHistory, device: any DeviceOperations) throws -> ContentEnvelope {
        try verifyForPublication(history: history)
        guard !header.isTombstone, header.generation < UInt64(Int64.max) else { throw MopError.invalidVault }
        let key = try grant.unwrap(content: self, history: history, device: device)
        return try Self.seal(plaintext, vault: header.vault, item: header.item,
            generation: header.generation + 1, base: header.version, contentRevision: UUID(),
            history: history, signer: device, reusing: (key, header)).content
    }

    public func deleting(grant: ContentKeyGrant, history: TrustedMembershipHistory,
                         device: any DeviceOperations) throws -> ContentEnvelope {
        try verifyForPublication(history: history)
        guard !header.isTombstone, header.generation < UInt64(Int64.max) else { throw MopError.invalidVault }
        let key = try grant.unwrap(content: self, history: history, device: device)
        return try Self.seal([:], vault: header.vault, item: header.item,
            generation: header.generation + 1, base: header.version, contentRevision: UUID(),
            history: history, signer: device, reusing: (key, header), isTombstone: true).content
    }

    /// Compare authenticated plaintext only in an authorized session. Logical
    /// revision IDs and ciphertext equality alone never establish equivalence.
    public func hasIdenticalContents(to other: ContentEnvelope, grant: ContentKeyGrant,
                                    otherGrant: ContentKeyGrant, history: TrustedMembershipHistory,
                                    device: any DeviceOperations) throws -> Bool {
        try verify(history: history, item: header.item)
        try other.verify(history: history, item: header.item)
        guard history.current.membership.role(of: device.identity) != nil else { throw MopError.notVaultMember }
        let key = try grant.unwrap(content: self, history: history, device: device)
        let otherKey = try otherGrant.unwrap(content: other, history: history, device: device)
        guard header.isTombstone == other.header.isTombstone, Set(components.keys) == Set(other.components.keys) else { return false }
        for component in components.keys {
            guard try decrypt(component: component, key: key) == other.decrypt(component: component, key: otherKey) else { return false }
        }
        return true
    }

    /// Regenerate an offline edit on the accepted rotation only after proving
    /// that the server branch changed access alone. A content conflict is never
    /// silently rebased. The logical revision of the preserved edit stays stable.
    public func rebasingEdit(onto rotated: ContentEnvelope, commonBase: ContentEnvelope,
                             ancestors: [ContentEnvelope] = [], grant: ContentKeyGrant,
                             baseGrant: ContentKeyGrant, rotatedGrant: ContentKeyGrant,
                             history: TrustedMembershipHistory, device: any DeviceOperations) throws -> ContentEnvelope {
        let known = ancestors + [commonBase]
        guard !header.isTombstone, !rotated.header.isTombstone, !commonBase.header.isTombstone,
              try ContentReconciliation.inspect(local: commonBase, remote: self, ancestors: known, history: history) == .acceptRemote,
              try ContentReconciliation.inspect(local: commonBase, remote: rotated, ancestors: known, history: history) == .acceptRemote,
              try ContentReconciliation.inspect(local: self, remote: rotated, ancestors: known, history: history) == .compareContents,
              rotated.header.keyGeneration != commonBase.header.keyGeneration,
              rotated.header.contentRevision == commonBase.header.contentRevision,
              rotated.header.generation < UInt64(Int64.max),
              try commonBase.hasIdenticalContents(to: rotated, grant: baseGrant, otherGrant: rotatedGrant,
                  history: history, device: device) else { throw MopError.vaultUntrusted }
        try rotated.verifyForPublication(history: history)
        let oldKey = try grant.unwrap(content: self, history: history, device: device)
        let currentKey = try rotatedGrant.unwrap(content: rotated, history: history, device: device)
        var plaintext: [String: SecretBytes] = [:]
        for component in components.keys { plaintext[component] = try decrypt(component: component, key: oldKey) }
        return try Self.seal(plaintext, vault: header.vault, item: header.item,
            generation: rotated.header.generation + 1, base: rotated.header.version,
            contentRevision: header.contentRevision, history: history, signer: device,
            reusing: (currentKey, rotated.header)).content
    }

    /// Access-only key rotation advances storage ancestry but preserves the signed
    /// logical revision. Only this verified decrypt/re-encrypt path can preserve it.
    public func rotateKey(grant: ContentKeyGrant, history: TrustedMembershipHistory,
                          decryptor: any DeviceOperations, signer: any DeviceOperations) throws -> ContentPublication {
        guard history.current.membership.role(of: signer.identity) == .owner,
              header.generation < UInt64(Int64.max) else { throw MopError.cloudPermission }
        let key = try grant.unwrap(content: self, history: history, device: decryptor)
        var plaintext: [String: SecretBytes] = [:]
        for component in components.keys { plaintext[component] = try decrypt(component: component, key: key) }
        return try Self.seal(plaintext, vault: header.vault, item: header.item, generation: header.generation + 1,
            base: header.version, contentRevision: header.contentRevision, history: history, signer: signer,
            isTombstone: header.isTombstone)
    }

    /// Rotate the latest local plaintext onto the accepted cloud ancestry. Old
    /// unsent ciphertext must not be published just to fill a revoked-key gap.
    /// The caller atomically supersedes those receipts while preserving this
    /// logical revision. Different accepted content still requires review.
    public func rotatingUnpublishedEdits(accepted: ContentEnvelope?, ancestors: [ContentEnvelope],
                                         grant: ContentKeyGrant, history: TrustedMembershipHistory,
                                         device: any DeviceOperations, decryptor: (any DeviceOperations)? = nil) throws -> ContentPublication {
        try verify(history: history, item: header.item)
        if let accepted {
            let relationship = try ContentReconciliation.inspect(local: accepted, remote: self, ancestors: ancestors, history: history)
            guard relationship == .acceptRemote || relationship == .acknowledgeDuplicate else { throw MopError.vaultConflict }
        }
        guard history.current.membership.role(of: device.identity) == .owner,
              (accepted?.header.generation ?? 0) < UInt64(Int64.max) else { throw MopError.cloudPermission }
        let key = try grant.unwrap(content: self, history: history, device: decryptor ?? device)
        var plaintext: [String: SecretBytes] = [:]
        for component in components.keys { plaintext[component] = try decrypt(component: component, key: key) }
        return try Self.seal(plaintext, vault: header.vault, item: header.item,
            generation: (accepted?.header.generation ?? 0) + 1, base: accepted?.header.version,
            contentRevision: header.contentRevision, history: history, signer: device, isTombstone: header.isTombstone)
    }

    public func encoded() throws -> Data {
        let bytes = try Codec.encode(self)
        guard bytes.count <= PortableArchive.maximumSize else { throw PortableArchiveFailure.tooLarge }
        return bytes
    }
    public static func decode(_ bytes: Data, history: TrustedMembershipHistory, item: UUID) throws -> Self {
        guard bytes.count <= PortableArchive.maximumSize else { throw PortableArchiveFailure.tooLarge }
        let content = try JSONDecoder().decode(Self.self, from: bytes)
        guard try content.encoded() == bytes else { throw MopError.invalidVault }
        try content.verify(history: history, item: item)
        return content
    }
}

public struct ContentPublication: Codable, Equatable, Sendable {
    public let content: ContentEnvelope
    public let grants: [ContentKeyGrant]
}

public struct ContentKeyGrant: Codable, Equatable, Sendable {
    public let vault: UUID
    public let item: UUID
    public let keyGeneration: UUID
    /// Exact immutable content address for grant-before-content reception.
    public let sourceVersion: UUID
    public let recipient: String
    public let membership: String
    public let issuer: String
    public let envelope: KeyEnvelope
    public let signature: Data
    fileprivate struct Context: Encodable {
        let domain = "2ndpass-content-key-grant-3"
        let vault: UUID
        let item: UUID
        let keyGeneration: UUID
        let sourceVersion: UUID
        let recipient: String
        let membership: String
        let issuer: String
    }
    private struct Statement: Encodable { let context: Context; let envelope: KeyEnvelope }
    fileprivate var context: Context {
        Context(vault: vault, item: item, keyGeneration: keyGeneration, sourceVersion: sourceVersion, recipient: recipient, membership: membership, issuer: issuer)
    }
    public var identifier: String { get throws { try Codec.digest(Codec.encode(context)) } }

    fileprivate static func seal(_ key: SymmetricKey, content: ContentEnvelope, recipient: DevicePublicKey,
                                 history: TrustedMembershipHistory, signer: any DeviceOperations) throws -> Self {
        let state = history.current
        guard state.membership.recipients.contains(recipient) else { throw MopError.notVaultMember }
        let context = Context(vault: content.header.vault, item: content.header.item, keyGeneration: content.header.keyGeneration, sourceVersion: content.header.version,
            recipient: recipient.fingerprint, membership: try state.digest(), issuer: signer.identity.fingerprint)
        let envelope = try KeyEnvelope.seal(key, to: recipient.encryption, context: Codec.encode(context))
        return Self(vault: context.vault, item: context.item, keyGeneration: context.keyGeneration, sourceVersion: context.sourceVersion,
            recipient: context.recipient, membership: context.membership, issuer: context.issuer, envelope: envelope,
            signature: try signer.sign(Codec.encode(Statement(context: context, envelope: envelope))))
    }

    /// Public signature check allows a grant to wait for missing content without
    /// treating an unauthenticated recipient or issuer as an established fact.
    public func verifySignature(history: TrustedMembershipHistory) throws {
        let state = try history.state(forDigest: membership)
        guard vault == history.vault, let author = state.membership.key(issuer),
              state.membership.role(of: author) == .owner || state.membership.role(of: author) == .editor,
              state.membership.recipients.contains(where: { $0.fingerprint == recipient }),
              envelope.encapsulatedKey.count == 65, envelope.ciphertext.count == 48, signature.count == 64,
              author.verifies(signature, message: try Codec.encode(Statement(context: context, envelope: envelope))) else { throw MopError.vaultUntrusted }
    }

    public func verify(content: ContentEnvelope, history: TrustedMembershipHistory) throws {
        try content.verify(history: history, item: item)
        try verifyAuthenticatedContent(content, history: history)
    }

    fileprivate func verifyAuthenticatedContent(_ content: ContentEnvelope, history: TrustedMembershipHistory) throws {
        let state = try history.state(forDigest: membership)
        guard vault == history.vault, item == content.header.item, keyGeneration == content.header.keyGeneration,
              let author = state.membership.key(issuer),
              state.membership.recipients.contains(where: { $0.fingerprint == recipient }),
              envelope.encapsulatedKey.count == 65, envelope.ciphertext.count == 48, signature.count == 64 else { throw MopError.vaultUntrusted }
        let owner = state.membership.role(of: author) == .owner
        let originalWriter = issuer == content.header.keyAuthor && membership == content.header.keyMembership
            && state.membership.role(of: author) == .editor
        guard owner || originalWriter,
              author.verifies(signature, message: try Codec.encode(Statement(context: context, envelope: envelope))) else { throw MopError.vaultUntrusted }
        // A grant may be issued after additive admission, but never use a new
        // membership to extend an obsolete key across a security rotation.
        try history.verifyContentKeyPath(from: content.header.keyMembership, to: membership)
    }

    /// Upload checks use only public history. Historical verification remains
    /// available for authorized decryption and rotation, not obsolete publication.
    public func verifyForPublication(content: ContentEnvelope, history: TrustedMembershipHistory) throws {
        try verify(content: content, history: history)
        try content.verifyForPublication(history: history)
        try history.verifyContentKeyPath(from: membership)
        guard history.current.membership.recipients.contains(where: { $0.fingerprint == recipient }) else {
            throw MopError.notVaultMember
        }
    }

    fileprivate func unwrap(content: ContentEnvelope, history: TrustedMembershipHistory,
                            device: any DeviceOperations) throws -> SymmetricKey {
        try verify(content: content, history: history)
        guard device.identity.fingerprint == recipient else { throw MopError.notVaultMember }
        return try device.unwrap(envelope, context: Codec.encode(context))
    }

    public static func extendingAccess(to recipient: DevicePublicKey, content: ContentEnvelope,
                                       existingGrant: ContentKeyGrant, history: TrustedMembershipHistory,
                                       decryptor: any DeviceOperations, signer: any DeviceOperations) throws -> Self {
        guard history.current.membership.role(of: signer.identity) == .owner else { throw MopError.cloudPermission }
        try content.verifyForPublication(history: history)
        let key = try existingGrant.unwrap(content: content, history: history, device: decryptor)
        return try seal(key, content: content, recipient: recipient, history: history, signer: signer)
    }
    public func encoded() throws -> Data { try Codec.encode(self) }
    public static func decode(_ bytes: Data, content: ContentEnvelope, history: TrustedMembershipHistory) throws -> Self {
        guard bytes.count <= 16_384 else { throw MopError.invalidVault }
        let grant = try JSONDecoder().decode(Self.self, from: bytes)
        guard try grant.encoded() == bytes else { throw MopError.invalidVault }
        try grant.verify(content: content, history: history)
        return grant
    }
}

/// Operation-local authentication proof. All fields are immutable and callers
/// cannot construct a publication without validating content and the source grant.
/// No secret key is retained between calls or across an authorized session.
public struct ContentGrantPreparation: Sendable {
    public let content: ContentEnvelope
    private let history: TrustedMembershipHistory
    public init(bytes: Data, item: UUID, history: TrustedMembershipHistory) throws {
        content = try ContentEnvelope.decode(bytes, history: history, item: item)
        try history.verifyContentKeyPath(from: content.header.membership)
        self.history = history
    }

    public func extendingAccess(to recipient: DevicePublicKey, sourceGrantBytes: Data,
                                decryptor: any DeviceOperations, signer: any DeviceOperations) throws -> VerifiedContentGrantPublication {
        guard sourceGrantBytes.count <= 16_384,
              history.current.membership.role(of: signer.identity) == .owner else { throw MopError.cloudPermission }
        let source = try JSONDecoder().decode(ContentKeyGrant.self, from: sourceGrantBytes)
        guard try source.encoded() == sourceGrantBytes else { throw MopError.invalidVault }
        try source.verifyAuthenticatedContent(content, history: history)
        guard decryptor.identity.fingerprint == source.recipient else { throw MopError.notVaultMember }
        let key = try decryptor.unwrap(source.envelope, context: Codec.encode(source.context))
        let grant = try ContentKeyGrant.seal(key, content: content, recipient: recipient, history: history, signer: signer)
        // Verify the signer output and all grant authority/eligibility bindings.
        // The immutable content was authenticated by this context's initializer.
        try grant.verifyAuthenticatedContent(content, history: history)
        try history.verifyContentKeyPath(from: grant.membership)
        return VerifiedContentGrantPublication(content: content, grant: grant, history: history)
    }
}

public struct VerifiedContentGrantPublication: Sendable {
    public let content: ContentEnvelope
    public let grant: ContentKeyGrant
    public let history: TrustedMembershipHistory
    fileprivate init(content: ContentEnvelope, grant: ContentKeyGrant, history: TrustedMembershipHistory) {
        self.content = content; self.grant = grant; self.history = history
    }
}
