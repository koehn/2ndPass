import Foundation

public enum CredentialAlgorithm: String, Codable, CaseIterable, Sendable { case ed25519, p256, rsa }
public enum CredentialPurpose: String, Codable, CaseIterable, Sendable { case ssh, gitSigning = "git-signing", passkey }
/// Public metadata lives inside the encrypted catalog. Private material is a concealed field.
public struct KeyCredential: Codable, Equatable, Sendable {
    public var version: Int = 1
    public var algorithm: CredentialAlgorithm
    public var publicKey: Data
    public var purposes: [CredentialPurpose]
    public var relyingParty: String?
    public var userName: String?
    public var userHandle: Data?
    public var credentialID: Data?
    public static let privateField = "credentialPrivateKey"
    public init(algorithm: CredentialAlgorithm, publicKey: Data, purposes: [CredentialPurpose], relyingParty: String? = nil, userName: String? = nil, userHandle: Data? = nil, credentialID: Data? = nil) {
        self.algorithm = algorithm; self.publicKey = publicKey; self.purposes = purposes
        self.relyingParty = relyingParty; self.userName = userName; self.userHandle = userHandle; self.credentialID = credentialID
    }
    public func validate() throws {
        guard version == 1, !publicKey.isEmpty, publicKey.count <= 2048,
              !purposes.isEmpty, Set(purposes).count == purposes.count else { throw CredentialFailure.invalid }
        if purposes.contains(.passkey) {
            guard purposes == [.passkey], algorithm == .p256, publicKey.count == 65,
                  let relyingParty, !relyingParty.isEmpty, !relyingParty.contains("/"), !relyingParty.contains(":"),
                  let userName, !userName.isEmpty, let userHandle, (1...64).contains(userHandle.count),
                  credentialID?.count == 32 else { throw CredentialFailure.invalid }
        } else {
            guard relyingParty == nil, userName == nil, userHandle == nil, credentialID == nil else { throw CredentialFailure.invalid }
        }
    }
}
public enum CredentialFailure: Error, LocalizedError, Sendable {
    case invalid, unsupportedFormat, unsupportedAlgorithm, unsupportedEncryption, passphraseRequired, incorrectPassphrase, localImport, offlineCreation
    public var errorDescription: String? {
        switch self {
        case .invalid: "The key credential is malformed or its public and private keys do not match."
        case .unsupportedFormat: "Choose an OpenSSH openssh-key-v1 private-key file. Legacy PEM and hardware-reference files are not supported."
        case .unsupportedAlgorithm: "Supported imports are Ed25519, P-256, and RSA (2048–8192 bits)."
        case .unsupportedEncryption: "Supported encrypted imports use bcrypt and AES-256-CTR, with at most 1024 KDF rounds."
        case .passphraseRequired: "Enter the private-key file’s passphrase."
        case .incorrectPassphrase: "The passphrase is incorrect or the private-key file is damaged."
        case .localImport: "Private keys can only be imported into cloud vaults. Secure Enclave keys must be generated on this device."
        case .offlineCreation: "Connect to iCloud before creating a cloud key credential."
        }
    }
}
