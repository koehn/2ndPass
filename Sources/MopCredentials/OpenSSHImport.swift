import Foundation
import CryptoKit
import Security
import MopCore
import MopOpenSSH

public enum OpenSSHImport {
    public static func read(_ input: SecretBytes, passphrase: SecretBytes? = nil) throws -> CloudKey {
        guard input.count <= 1024 * 1024 else { throw CredentialFailure.invalid }
        let begin = Data("-----BEGIN OPENSSH PRIVATE KEY-----".utf8), end = Data("-----END OPENSSH PRIVATE KEY-----".utf8)
        func whitespace(_ byte: UInt8) -> Bool { [9, 10, 13, 32].contains(byte) }
        var encoded = Data(input.drop(while: whitespace).reversed().drop(while: whitespace).reversed())
        defer { SecretBytes.wipe(&encoded) }
        guard encoded.starts(with: begin), encoded.suffix(end.count) == end else { throw CredentialFailure.unsupportedFormat }
        var body = Data(encoded.dropFirst(begin.count).dropLast(end.count).filter { !whitespace($0) })
        defer { SecretBytes.wipe(&body) }
        guard var data = Data(base64Encoded: body), data.starts(with: Data("openssh-key-v1\0".utf8)) else { throw CredentialFailure.invalid }
        defer { SecretBytes.wipe(&data) }
        var reader = SSHReader(data: data, offset: 15)
        let cipher = try reader.text(), kdf = try reader.text(), options = try reader.bytes()
        guard try reader.uint32() == 1 else { throw CredentialFailure.unsupportedFormat }
        let publicBlob = try reader.bytes()
        var privateBlob = try reader.bytes()
        defer { SecretBytes.wipe(&privateBlob) }
        guard reader.remaining == 0, privateBlob.count >= 8 else { throw CredentialFailure.invalid }
        if cipher == "none" {
            guard kdf == "none", options.isEmpty, privateBlob.count % 8 == 0 else { throw CredentialFailure.invalid }
        } else {
            guard cipher == "aes256-ctr", kdf == "bcrypt", privateBlob.count % 16 == 0 else { throw CredentialFailure.unsupportedEncryption }
            guard let passphrase, !passphrase.isEmpty else { throw CredentialFailure.passphraseRequired }
            var opt = SSHReader(data: options)
            let salt = try opt.bytes(), rounds = try opt.uint32()
            guard opt.remaining == 0, (1...1024).contains(rounds), (1...1024).contains(salt.count), passphrase.count <= 4096 else { throw CredentialFailure.unsupportedEncryption }
            var material = Data(count: 48), clear = Data(count: privateBlob.count)
            defer { SecretBytes.wipe(&material); SecretBytes.wipe(&clear) }
            let status = material.withUnsafeMutableBytes { out in passphrase.withUnsafeBytes { pass in salt.withUnsafeBytes { salt in
                bcrypt_pbkdf(pass.baseAddress!.assumingMemoryBound(to: CChar.self), pass.count, salt.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count, out.baseAddress!.assumingMemoryBound(to: UInt8.self), 48, rounds)
            } } }
            guard status == 0 else { throw CredentialFailure.invalid }
            let result = clear.withUnsafeMutableBytes { out in material.withUnsafeBytes { key in privateBlob.withUnsafeBytes { input in
                mop_aes_ctr(key.baseAddress!.assumingMemoryBound(to: UInt8.self), key.baseAddress!.advanced(by: 32).assumingMemoryBound(to: UInt8.self), input.baseAddress!.assumingMemoryBound(to: UInt8.self), input.count, out.baseAddress!.assumingMemoryBound(to: UInt8.self))
            } } }
            guard result == 0 else { throw CredentialFailure.invalid }
            privateBlob = clear
        }
        var keyReader = SSHReader(data: privateBlob)
        guard try keyReader.uint32() == keyReader.uint32() else { throw CredentialFailure.incorrectPassphrase }
        let type = try keyReader.text()
        let key: CloudKey
        switch type {
        case "ssh-ed25519":
            let pub = try keyReader.bytes(); var secret = try keyReader.bytes(); defer { SecretBytes.wipe(&secret) }
            guard pub.count == 32, secret.count == 64, secret.suffix(32) == pub else { throw CredentialFailure.invalid }
            key = try CloudKey(algorithm: .ed25519, privateBytes: SecretBytes(copying: secret.prefix(32)))
        case "ecdsa-sha2-nistp256":
            guard try keyReader.text() == "nistp256" else { throw CredentialFailure.unsupportedAlgorithm }
            let pub = try keyReader.bytes(); var scalar = try keyReader.integer(); defer { SecretBytes.wipe(&scalar) }
            guard scalar.count <= 32 else { throw CredentialFailure.invalid }
            scalar = Data(repeating: 0, count: 32 - scalar.count) + scalar
            key = try CloudKey(algorithm: .p256, privateBytes: SecretBytes(copying: scalar))
            guard pub == key.publicKey else { throw CredentialFailure.invalid }
        case "ssh-rsa":
            let n = try keyReader.integer(), e = try keyReader.integer()
            var d = try keyReader.integer(), iqmp = try keyReader.integer(), p = try keyReader.integer(), q = try keyReader.integer()
            defer { SecretBytes.wipe(&d); SecretBytes.wipe(&iqmp); SecretBytes.wipe(&p); SecretBytes.wipe(&q) }
            guard let first = n.first, (2048...8192).contains(n.count * 8 - first.leadingZeroBitCount) else { throw CredentialFailure.unsupportedAlgorithm }
            // OpenSSH omits CRT exponents; reconstruct them for PKCS#1 serialization.
            var dp = try crtExponent(d, prime: p), dq = try crtExponent(d, prime: q)
            defer { SecretBytes.wipe(&dp); SecretBytes.wipe(&dq) }
            var der = DER.value(0x30, [Data([0]), n, e, d, p, q, dp, dq, iqmp].reduce(Data()) { $0 + DER.integer($1) })
            defer { SecretBytes.wipe(&der) }
            key = try CloudKey(algorithm: .rsa, privateBytes: SecretBytes(copying: der))
            let rsa = try CloudKey.rsa(der), message = Data("2ndPass import validation".utf8)
            var error: Unmanaged<CFError>?
            guard let pub = SecKeyCopyPublicKey(rsa), let signature = SecKeyCreateSignature(rsa, .rsaSignatureMessagePKCS1v15SHA256, message as CFData, &error) else { throw error?.takeRetainedValue() as Error? ?? CredentialFailure.invalid }
            guard SecKeyVerifySignature(pub, .rsaSignatureMessagePKCS1v15SHA256, message as CFData, signature, &error) else { throw error?.takeRetainedValue() as Error? ?? CredentialFailure.invalid }
        default: throw CredentialFailure.unsupportedAlgorithm
        }
        _ = try keyReader.bytes() // comment is untrusted display text; caller chooses name
        guard (0..<(cipher == "none" ? 8 : 16)).contains(keyReader.remaining) else { throw CredentialFailure.invalid }
        for index in 0..<keyReader.remaining {
            let expected = index + 1
            guard privateBlob[keyReader.offset] == UInt8(expected) else { throw CredentialFailure.invalid }; keyReader.offset += 1
        }
        guard key.sshBlob == publicBlob else { throw CredentialFailure.invalid }
        return key
    }
}

// Bounded unsigned long division for import-format conversion only. Signing is
// performed exclusively by Security; this is not a cryptographic implementation.
private func crtExponent(_ exponent: Data, prime: Data) throws -> Data {
    guard !prime.isEmpty, prime.count <= 512, exponent.count <= 1024 else { throw CredentialFailure.invalid }
    var modulus = Array(prime), remainder = [UInt8](repeating: 0, count: prime.count + 1)
    defer { modulus.withUnsafeMutableBytes { _ = memset_s($0.baseAddress!, $0.count, 0, $0.count) }; remainder.withUnsafeMutableBytes { _ = memset_s($0.baseAddress!, $0.count, 0, $0.count) } }
    var index = modulus.count - 1
    while modulus[index] == 0 { modulus[index] = 255; guard index > 0 else { throw CredentialFailure.invalid }; index -= 1 }
    modulus[index] -= 1
    modulus.insert(0, at: 0)
    guard modulus.contains(where: { $0 != 0 }) else { throw CredentialFailure.invalid }
    for byte in exponent {
        for bit in (0..<8).reversed() {
            var carry = (byte >> bit) & 1
            for i in remainder.indices.reversed() { let next = remainder[i] >> 7; remainder[i] = (remainder[i] << 1) | carry; carry = next }
            if !remainder.lexicographicallyPrecedes(modulus) {
                var borrow = 0
                for i in remainder.indices.reversed() { let n = Int(remainder[i]) - Int(modulus[i]) - borrow; remainder[i] = UInt8(truncatingIfNeeded: n); borrow = n < 0 ? 1 : 0 }
            }
        }
    }
    return Data(remainder.drop(while: { $0 == 0 }))
}
