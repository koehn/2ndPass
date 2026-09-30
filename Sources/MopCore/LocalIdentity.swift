import Foundation

/// The single, built-in, device-local vault. Its name is a fixed constant, not
/// user input, so it can never be renamed. It is never published to CloudKit,
/// shared, exported, backed up, or recoverable.
public enum LocalVault {
    /// Exact, stable vault name.
    public static let name = "local"
    /// Stable identifier. Chosen so it can never equal a cloud vault UUID.
    public static let id = "local-vault"

    public static func isLocal(_ selection: String) -> Bool {
        selection == name || selection == id
    }

    /// The device-local vault has no rename operation. Any attempt is a hard error
    /// rather than a no-op, so a caller can never silently rename it.
    public static func rename(to name: String) throws {
        throw MopError.localOperationForbidden
    }
}

/// The protocol a hardware identity is bound to. The set is deliberately
/// extensible; the starting surface is SSH, Git signing, and the generic
/// sign/key-agreement abstractions.
public enum LocalIdentityProtocol: String, Codable, CaseIterable, Sendable, Comparable {
    case ssh
    case gitSigning = "git-signing"
    case tlsClient = "tls-client"
    case x509
    case webauthn
    case jwt
    case apiSigning = "api-signing"
    case recovery
    case genericSigning = "generic-signing"
    case genericEcdh = "generic-ecdh"

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }

    /// Whether an identity for this protocol is provisioned as a signing key.
    /// Key-exchange (EC) identities are the only non-signing protocol.
    public var isSigning: Bool { self != .genericEcdh }
}

/// Which curve/key type an identity uses. Only hardware-backed key types are
/// accepted; there is no software algorithm.
public enum LocalIdentityAlgorithm: String, Codable, Sendable, Equatable {
    case p256Signing = "p256-signing"
    case p256KeyAgreement = "p256-key-agreement"

    public var capabilities: LocalIdentityCapabilities {
        switch self {
        case .p256Signing: [.signing, .authentication]
        case .p256KeyAgreement: [.keyAgreement]
        }
    }
    public var supportsSigning: Bool { self == .p256Signing }
    public var supportsKeyAgreement: Bool { self == .p256KeyAgreement }
}

/// Fixed, non-increasing capabilities an identity can perform.
public struct LocalIdentityCapabilities: OptionSet, Codable, Sendable, Equatable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let signing = Self(rawValue: 1 << 0)
    public static let keyAgreement = Self(rawValue: 1 << 1)
    public static let authentication = Self(rawValue: 1 << 2)
    public static let decryption = Self(rawValue: 1 << 3)
}

/// A device-local, hardware-backed asymmetric identity.
///
/// The private key never appears here and never leaves the Secure Enclave. Only
/// the non-sensitive public key (x963) and metadata are persisted; the key itself
/// is referenced by `id` and used exclusively through the Secure Enclave.
public struct LocalIdentity: Codable, Sendable, Equatable, Identifiable {
    public let id: UUID
    public var name: String
    public let algorithm: LocalIdentityAlgorithm
    public let protocolType: LocalIdentityProtocol
    public var capabilities: LocalIdentityCapabilities
    /// x963 public key (65 bytes for P-256: 0x04 || X || Y). Never secret.
    public let publicKey: Data
    public var createdAt: Date
    /// Protocol-specific, non-sensitive metadata (e.g. an SSH comment).
    public var metadata: [String: String]

    public init(
        id: UUID = UUID(),
        name: String,
        algorithm: LocalIdentityAlgorithm,
        protocolType: LocalIdentityProtocol,
        publicKey: Data,
        createdAt: Date = Date(),
        metadata: [String: String] = [:]
    ) throws {
        let validated = try Self.validateName(name)
        // A signing protocol requires a signing key and vice versa. Fail before
        // any key is generated so an inconsistent identity is never persisted.
        guard (protocolType.isSigning && algorithm.supportsSigning) ||
              (!protocolType.isSigning && algorithm.supportsKeyAgreement) else {
            throw MopError.invalidLocalIdentity
        }
        self.id = id
        self.name = validated
        self.algorithm = algorithm
        self.protocolType = protocolType
        self.capabilities = algorithm.capabilities
        self.publicKey = publicKey
        self.createdAt = createdAt
        self.metadata = metadata
    }

    /// Names are trimmed and bounded. They must be non-empty, single-line, and
    /// short enough to display and to reference.
    public static func validateName(_ raw: String) throws -> String {
        let name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 64,
              !name.contains("\n"), !name.contains("\r"),
              !name.contains("\0") else {
            throw MopError.invalidLocalIdentity
        }
        return name
    }

    /// The OpenSSH comment shown for signing identities (falls back to the name).
    public var sshComment: String {
        (metadata["comment"] ?? name).trimmingCharacters(in: .whitespaces)
    }
}
