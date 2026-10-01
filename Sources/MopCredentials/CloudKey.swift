import CryptoKit
import Foundation
import Security
import MopCore

/// Owns normalized private bytes only for the duration of an operation.
public struct CloudKey: Sendable {
    public let algorithm: CredentialAlgorithm
    public let privateBytes: SecretBytes
    public let publicKey: Data
    public init(algorithm: CredentialAlgorithm, privateBytes: SecretBytes) throws {
        self.algorithm = algorithm; self.privateBytes = privateBytes
        publicKey = try privateBytes.withFoundationData { bytes in
            switch algorithm {
            case .ed25519: return SSHWire.text("ssh-ed25519") + SSHWire.string(try Curve25519.Signing.PrivateKey(rawRepresentation: bytes).publicKey.rawRepresentation)
            case .p256: return try P256.Signing.PrivateKey(rawRepresentation: bytes).publicKey.x963Representation
            case .rsa:
                let key = try Self.rsa(bytes)
                guard let pub = SecKeyCopyPublicKey(key), let raw = SecKeyCopyExternalRepresentation(pub, nil) as Data? else { throw CredentialFailure.invalid }
                var r = DERReader(raw); let sequence = try r.value(0x30); var inner = DERReader(sequence)
                let n = try inner.value(2), e = try inner.value(2)
                return SSHWire.text("ssh-rsa") + SSHWire.integer(e) + SSHWire.integer(n)
            }
        }
    }
    public static func generate(_ algorithm: CredentialAlgorithm) throws -> Self {
        var bytes: Data
        switch algorithm {
        case .ed25519: bytes = Curve25519.Signing.PrivateKey().rawRepresentation
        case .p256: bytes = P256.Signing.PrivateKey().rawRepresentation
        case .rsa: throw CredentialFailure.unsupportedAlgorithm
        }
        defer { SecretBytes.wipe(&bytes) }
        return try Self(algorithm: algorithm, privateBytes: SecretBytes(copying: bytes))
    }
    public var sshBlob: Data {
        algorithm == .p256 ? SSHWire.text("ecdsa-sha2-nistp256") + SSHWire.text("nistp256") + SSHWire.string(publicKey) : publicKey
    }
    public var fingerprint: String { Self.fingerprint(sshBlob) }
    public static func fingerprint(_ blob: Data) -> String { "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "") }
    public func sign(_ data: Data, flags: UInt32 = 0) throws -> Data {
        try privateBytes.withFoundationData { bytes in
            switch algorithm {
            case .ed25519:
                guard flags == 0 else { throw CredentialFailure.invalid }
                return SSHWire.text("ssh-ed25519") + SSHWire.string(try Curve25519.Signing.PrivateKey(rawRepresentation: bytes).signature(for: data))
            case .p256:
                guard flags == 0 else { throw CredentialFailure.invalid }
                let signature = try P256.Signing.PrivateKey(rawRepresentation: bytes).signature(for: data).rawRepresentation
                return SSHWire.text("ecdsa-sha2-nistp256") + SSHWire.string(SSHWire.integer(signature.prefix(32)) + SSHWire.integer(signature.suffix(32)))
            case .rsa:
                guard flags == 2 || flags == 4 || flags == 6 else { throw CredentialFailure.unsupportedAlgorithm }
                let algorithm: SecKeyAlgorithm = flags & 4 != 0 ? .rsaSignatureMessagePKCS1v15SHA512 : .rsaSignatureMessagePKCS1v15SHA256
                guard let signature = SecKeyCreateSignature(try Self.rsa(bytes), algorithm, data as CFData, nil) as Data? else { throw CredentialFailure.invalid }
                return SSHWire.text(flags & 4 != 0 ? "rsa-sha2-512" : "rsa-sha2-256") + SSHWire.string(signature)
            }
        }
    }
    public func signPasskey(_ data: Data) throws -> Data {
        guard algorithm == .p256 else { throw CredentialFailure.invalid }
        return try privateBytes.withFoundationData { try P256.Signing.PrivateKey(rawRepresentation: $0).signature(for: data).derRepresentation }
    }
    static func rsa(_ bytes: Data) throws -> SecKey {
        guard let key = SecKeyCreateWithData(bytes as CFData, [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary, nil),
              (2048...8192).contains(SecKeyGetBlockSize(key) * 8) else { throw CredentialFailure.unsupportedAlgorithm }
        return key
    }
    public func item(name: String, purposes: [CredentialPurpose]) throws -> VaultItem {
        var item = VaultItem(name: name, type: .sshKey, fields: [ItemField(path: KeyCredential.privateField, type: .privateKey, value: privateBytes.withFoundationData { $0.base64EncodedString() })])
        item.credential = KeyCredential(algorithm: algorithm, publicKey: publicKey, purposes: purposes)
        try item.credential?.validate()
        return item
    }
    public static func validate(item: VaultItem) throws {
        guard let credential = item.credential else { return }
        try credential.validate()
        switch credential.algorithm {
        case .p256: _ = try P256.Signing.PublicKey(x963Representation: credential.publicKey)
        case .ed25519:
            var wire = SSHReader(data: credential.publicKey)
            guard try wire.text() == "ssh-ed25519" else { throw CredentialFailure.invalid }
            _ = try Curve25519.Signing.PublicKey(rawRepresentation: wire.bytes())
            guard wire.remaining == 0 else { throw CredentialFailure.invalid }
        case .rsa:
            var wire = SSHReader(data: credential.publicKey)
            guard try wire.text() == "ssh-rsa" else { throw CredentialFailure.invalid }
            let e = try wire.integer(), n = try wire.integer()
            guard !e.isEmpty, let first = n.first, (2048...8192).contains(n.count * 8 - first.leadingZeroBitCount), wire.remaining == 0 else { throw CredentialFailure.invalid }
        }
        guard item.type == (credential.purposes == [.passkey] ? .passkey : .sshKey),
              let field = item.fields.first(where: { $0.path == KeyCredential.privateField }), field.type == .privateKey else { throw CredentialFailure.invalid }
        if let value = field.value {
            guard var data = Data(base64Encoded: value) else { throw CredentialFailure.invalid }
            defer { SecretBytes.wipe(&data) }
            let key = try Self(algorithm: credential.algorithm, privateBytes: SecretBytes(copying: data))
            guard key.publicKey == credential.publicKey else { throw CredentialFailure.invalid }
        }
    }
}
struct DERReader {
    let data: Data
    var offset = 0
    init(_ data: Data) { self.data = data }
    mutating func value(_ tag: UInt8) throws -> Data {
        guard offset + 2 <= data.count, data[offset] == tag else { throw CredentialFailure.invalid }; offset += 1
        var length = Int(data[offset]); offset += 1
        if length & 128 != 0 {
            let count = length & 127; length = 0
            guard (1...4).contains(count), offset + count <= data.count else { throw CredentialFailure.invalid }
            for _ in 0..<count { length = length * 256 + Int(data[offset]); offset += 1 }
        }
        guard length <= data.count - offset else { throw CredentialFailure.invalid }
        defer { offset += length }; return data.subdata(in: offset..<offset+length)
    }
}
enum DER {
    static func value(_ tag: UInt8, _ value: Data) -> Data {
        var length = value.count; var bytes = Data()
        repeat { bytes.insert(UInt8(length & 255), at: 0); length >>= 8 } while length > 0
        let prefix = value.count < 128 ? Data([UInt8(value.count)]) : Data([0x80 | UInt8(bytes.count)]) + bytes
        return Data([tag]) + prefix + value
    }
    static func integer(_ value: Data) -> Data {
        var d = Data(value.drop(while: { $0 == 0 })); if d.isEmpty { d = Data([0]) }; if d[0] & 128 != 0 { d.insert(0, at: 0) }; return self.value(2, d)
    }
}
