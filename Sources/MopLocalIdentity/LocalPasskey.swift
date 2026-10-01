import CryptoKit
import Foundation
import MopCore
import Security

/// WebAuthn authenticator data for device-bound ES256 credentials. The system
/// supplies the validated RP ID and clientDataHash; we never accept a URL from UI.
public enum LocalWebAuthn {
    public static func authenticatorData(relyingParty: String) -> Data {
        // UP + UV. Hardware keys are neither backup eligible nor backed up.
        // A zero counter means counters are unsupported.
        Data(SHA256.hash(data: Data(relyingParty.utf8))) + Data([0x05, 0, 0, 0, 0])
    }
    public static func registrationData(metadata: PasskeyMetadata, publicKey: Data, backedUp: Bool = false) throws -> Data {
        _ = try P256.Signing.PublicKey(x963Representation: publicKey)
        var data = authenticatorData(relyingParty: metadata.relyingParty)
        data[32] |= 0x40 // AT
        if backedUp { data[32] |= 0x18 }
        data.append(Data(repeating: 0, count: 16)) // no identifying attestation
        data.append(contentsOf: [0, 32]); data.append(metadata.credentialID)
        // COSE EC2, ES256, P-256, x, y. No private key component.
        data.append(contentsOf: [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21])
        data.append(cborBytes(Data(publicKey.dropFirst().prefix(32))))
        data.append(0x22); data.append(cborBytes(Data(publicKey.suffix(32))))
        return data
    }
    public static func attestation(metadata: PasskeyMetadata, publicKey: Data, backedUp: Bool = false) throws -> Data {
        let authData = try registrationData(metadata: metadata, publicKey: publicKey, backedUp: backedUp)
        // {fmt: "none", attStmt: {}, authData: bytes}, RFC 8949 encoding.
        return Data([0xa3]) + cborText("fmt") + cborText("none") + cborText("attStmt") + Data([0xa0]) + cborText("authData") + cborBytes(authData)
    }
    private static func cborText(_ text: String) -> Data { header(major: 3, count: text.utf8.count) + Data(text.utf8) }
    private static func cborBytes(_ bytes: Data) -> Data { header(major: 2, count: bytes.count) + bytes }
    private static func header(major: UInt8, count: Int) -> Data {
        if count < 24 { return Data([major << 5 | UInt8(count)]) }
        if count <= 255 { return Data([major << 5 | 24, UInt8(count)]) }
        return Data([major << 5 | 25, UInt8(count >> 8), UInt8(count & 255)])
    }
    public static func matches(_ identity: LocalIdentity, relyingParty: String, allowedCredentials: [Data]) -> Bool {
        guard identity.protocolType == .webauthn, case .passkey(let metadata) = identity.metadata else { return false }
        return metadata.relyingParty == relyingParty && (allowedCredentials.isEmpty || allowedCredentials.contains(metadata.credentialID))
    }
}

public struct LocalPasskeyAssertion: Sendable {
    public let metadata: PasskeyMetadata
    public let authenticatorData: Data
    public let signature: Data
}

extension LocalIdentityStore {
    /// Registration is available only through an actual WebAuthn ceremony.
    public func registerPasskey(relyingParty: String, userName: String, userHandle: Data, clientDataHash: Data,
                                supportedAlgorithms: [Int], authorization: LocalAuthorization) throws -> LocalIdentity {
        guard clientDataHash.count == 32, supportedAlgorithms.contains(-7) else { throw MopError.localIdentityCapability }
        var credentialID = Data(count: 32)
        let status = credentialID.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        try Self.check(status)
        let metadata = try PasskeyMetadata(relyingParty: relyingParty, userName: userName, userHandle: userHandle, credentialID: credentialID)
        let suffix = credentialID.prefix(6).map { String(format: "%02x", $0) }.joined()
        let name = String((userName + "@" + relyingParty).prefix(50)) + "-" + suffix
        return try create(name: name, protocolType: .webauthn, authorization: authorization, metadata: .passkey(metadata))
    }
    public func assertPasskey(id: UUID, relyingParty: String, allowedCredentials: [Data], clientDataHash: Data,
                              authorization: LocalAuthorization) throws -> LocalPasskeyAssertion {
        let identity = try read(id: id)
        guard clientDataHash.count == 32,
              LocalWebAuthn.matches(identity, relyingParty: relyingParty, allowedCredentials: allowedCredentials),
              case .passkey(let metadata) = identity.metadata else { throw MopError.invalidLocalIdentity }
        let data = LocalWebAuthn.authenticatorData(relyingParty: relyingParty)
        let signature = try sign(id: id, data: data + clientDataHash, authorization: authorization, operation: .passkey)
        try authorization.check()
        return LocalPasskeyAssertion(metadata: metadata, authenticatorData: data, signature: signature)
    }
}
