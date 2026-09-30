import Foundation
import CryptoKit
import MopCore

public enum LocalIdentityProtocol: String, Codable, CaseIterable, Sendable, Comparable {
    case ssh, gitSigning = "git-signing", x509, webauthn
    case genericSigning = "generic-signing", genericEcdh = "generic-ecdh"
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
    public var isSigning: Bool { self != .genericEcdh }
    /// Passkeys are created only by a relying-party registration ceremony.
    public static let creatable: [Self] = [.ssh, .gitSigning, .x509]
}
public enum LocalIdentityAlgorithm: String, Codable, Sendable {
    case p256Signing = "p256-signing", p256KeyAgreement = "p256-key-agreement"
    public var supportsSigning: Bool { self == .p256Signing }
    public var supportsKeyAgreement: Bool { self == .p256KeyAgreement }
    public var capabilities: LocalIdentityCapabilities {
        self == .p256Signing ? [.signing, .authentication] : [.keyAgreement]
    }
}
public struct LocalIdentityCapabilities: OptionSet, Codable, Sendable, Equatable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }
    public static let signing = Self(rawValue: 1)
    public static let keyAgreement = Self(rawValue: 2)
    public static let authentication = Self(rawValue: 4)
}
public enum LocalAccessPolicy: String, Codable, Sendable {
    case session, perOperation
}
public struct PasskeyMetadata: Codable, Equatable, Sendable {
    public let relyingParty: String
    public let userName: String
    public let userHandle: Data
    public let credentialID: Data
    public init(relyingParty: String, userName: String, userHandle: Data, credentialID: Data) throws {
        guard !relyingParty.isEmpty, !relyingParty.contains("/"), !relyingParty.contains(":"),
              !userName.isEmpty, (1...64).contains(userHandle.count), credentialID.count == 32 else { throw MopError.invalidLocalIdentity }
        self.relyingParty = relyingParty; self.userName = userName
        self.userHandle = userHandle; self.credentialID = credentialID
    }
}
public enum LocalProtocolMetadata: Codable, Equatable, Sendable {
    case ssh(comment: String)
    case gitSigning(comment: String)
    case certificate(chain: [Data])
    case passkey(PasskeyMetadata)
    case generic
}

/// Public information only. The Keychain record and opaque enclave reference are
/// deliberately separate types, internal to this module.
public struct LocalIdentity: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let name: String
    public let algorithm: LocalIdentityAlgorithm
    public let protocolType: LocalIdentityProtocol
    public var capabilities: LocalIdentityCapabilities { algorithm.capabilities }
    public let publicKey: Data
    public let createdAt: Date
    public let accessPolicy: LocalAccessPolicy
    public let metadata: LocalProtocolMetadata
    public init(id: UUID = UUID(), name: String, algorithm: LocalIdentityAlgorithm,
                protocolType: LocalIdentityProtocol, publicKey: Data, createdAt: Date = Date(),
                accessPolicy: LocalAccessPolicy? = nil, metadata: LocalProtocolMetadata? = nil) throws {
        self.id = id; self.name = try Self.validateName(name); self.algorithm = algorithm
        self.protocolType = protocolType; self.publicKey = publicKey; self.createdAt = createdAt
        self.accessPolicy = accessPolicy ?? ([.ssh, .gitSigning].contains(protocolType) ? .session : .perOperation)
        switch (protocolType, metadata) {
        case (_, .some(let value)): self.metadata = value
        case (.ssh, nil): self.metadata = .ssh(comment: self.name)
        case (.gitSigning, nil): self.metadata = .gitSigning(comment: self.name)
        case (.x509, nil): self.metadata = .certificate(chain: [])
        case (.genericSigning, nil), (.genericEcdh, nil): self.metadata = .generic
        default: throw MopError.invalidLocalIdentity
        }
        try validate()
    }
    public func validate() throws {
        guard try Self.validateName(name) == name, publicKey.count == 65,
              protocolType.isSigning == algorithm.supportsSigning,
              accessPolicy == ([.ssh, .gitSigning].contains(protocolType) ? .session : .perOperation) else { throw MopError.invalidLocalIdentity }
        _ = try P256.Signing.PublicKey(x963Representation: publicKey)
        switch (protocolType, metadata) {
        case (.ssh, .ssh(let comment)), (.gitSigning, .gitSigning(let comment)):
            guard try Self.validateName(comment) == comment else { throw MopError.invalidLocalIdentity }
        case (.x509, .certificate(let chain)):
            guard chain.count <= 16, chain.allSatisfy({ $0.count <= 1024 * 1024 }) else { throw MopError.invalidLocalIdentity }
            try LocalCertificateValidation.validate(chain: chain, publicKey: publicKey)
        case (.webauthn, .passkey(let data)):
            _ = try PasskeyMetadata(relyingParty: data.relyingParty, userName: data.userName, userHandle: data.userHandle, credentialID: data.credentialID)
        case (.genericSigning, .generic), (.genericEcdh, .generic): break
        default: throw MopError.invalidLocalIdentity
        }
    }
    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(id: values.decode(UUID.self, forKey: .id), name: values.decode(String.self, forKey: .name),
                      algorithm: values.decode(LocalIdentityAlgorithm.self, forKey: .algorithm), protocolType: values.decode(LocalIdentityProtocol.self, forKey: .protocolType),
                      publicKey: values.decode(Data.self, forKey: .publicKey), createdAt: values.decode(Date.self, forKey: .createdAt),
                      accessPolicy: values.decode(LocalAccessPolicy.self, forKey: .accessPolicy), metadata: values.decode(LocalProtocolMetadata.self, forKey: .metadata))
    }
    public static func validateName(_ raw: String) throws -> String {
        let name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 64, !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw MopError.invalidLocalIdentity }
        return name
    }
    public var sshComment: String {
        switch metadata { case .ssh(let comment), .gitSigning(let comment): comment; default: name }
    }
    public var fingerprint: String { "SHA256:" + Data(SHA256.hash(data: (try? SSHPublicKey.wireBlob(x963: publicKey)) ?? publicKey)).base64EncodedString().replacingOccurrences(of: "=", with: "") }
    public var publicKeyText: String {
        if [.ssh, .gitSigning].contains(protocolType) { return (try? SSHPublicKey.openSSH(x963: publicKey, comment: sshComment)) ?? "" }
        return publicKey.base64EncodedString()
    }
}
public struct LocalIdentityCatalog: Encodable, Sendable {
    public let kind = "device-local"
    public let vault = LocalVault.name
    public let identities: [LocalIdentity]
    public init(identities: [LocalIdentity]) { self.identities = identities }
}
public enum LocalIdentityWarning {
    public static let loss = "Identities in local exist only on this device. Private keys cannot be synced, backed up, exported, or restored elsewhere. If this device is lost, erased, or replaced, these identities are permanently lost."
    public static let deletion = "The private key exists only on this device and cannot be recovered. Services using its public key may stop accepting this device."
    public static func redundancy(_ purpose: LocalIdentityProtocol) -> String {
        switch purpose {
        case .ssh, .gitSigning: "Register an independent SSH public key from another device before relying on this identity."
        case .webauthn: "Register another passkey on another device, or keep another sign-in or recovery method supported by the service. Each passkey has an independent private key."
        case .x509: "Ensure the issuing system can issue a replacement certificate or that another authorized identity exists."
        default: "Keep an independent credential or recovery method on another device."
        }
    }
}
