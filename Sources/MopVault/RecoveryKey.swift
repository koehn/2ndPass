import CryptoKit
import Foundation
import MopCore

public protocol VaultKeyOpener {
    var publicKey: Data { get }
    func unwrap(_ recipient: VaultRecipient, vaultID: UUID) throws -> SymmetricKey
}

public struct RecoveryKey: VaultSigningOpener {
    public var signingPublicKey: Data { publicKey }
    public func sign(_ data: Data) throws -> Data {
        var raw = key.rawRepresentation
        defer { KeyMaterial.wipe(&raw) }
        return try P256.Signing.PrivateKey(rawRepresentation: raw).signature(for: data).rawRepresentation
    }
    private let key: P256.KeyAgreement.PrivateKey
    public var publicKey: Data { key.publicKey.x963Representation }
    public var request: RecipientKey { try! RecipientKey(name: "Recovery", publicKey: publicKey) }

    public init() { key = P256.KeyAgreement.PrivateKey() }

    public init(file: URL) throws {
        let fileBytes = try SafeFile.readKeyMaterial(file, limit: 1024)
        defer { fileBytes.wipe() }
        self.key = try fileBytes.withUnsafeBytes { contents in
            let prefix = Array("mop-recovery-v1:".utf8)
            guard contents.starts(with: prefix) else { throw MopError.invalidRecovery }
            var payload = contents.dropFirst(prefix.count)
            // Preserve the existing Unicode whitespace trimming without putting key text in a String.
            while let whitespace = Self.whitespace.first(where: { payload.starts(with: $0) }) {
                payload = payload.dropFirst(whitespace.count)
            }
            while let whitespace = Self.whitespace.first(where: { payload.suffix($0.count).elementsEqual($0) }) {
                payload = payload.dropLast(whitespace.count)
            }
            var encoded = Data(payload)
            defer { KeyMaterial.wipe(&encoded) }
            guard var bytes = Data(base64Encoded: encoded) else { throw MopError.invalidRecovery }
            defer { KeyMaterial.wipe(&bytes) }
            guard bytes.count == 32, let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: bytes) else {
                throw MopError.invalidRecovery
            }
            return key
        }
    }

    private static let whitespace: [[UInt8]] = (
        Array(0x09...0x0D) + [0x20, 0x85, 0xA0, 0x1680] + Array(0x2000...0x200B) +
        [0x2028, 0x2029, 0x202F, 0x205F, 0x3000]
    ).compactMap { Unicode.Scalar($0) }.filter { CharacterSet.whitespacesAndNewlines.contains($0) }
        .map { Array(String($0).utf8) }

    public func save(to file: URL) throws {
        try encode { try SafeFile.write($0, to: file) }
    }

    public func export(to output: OutputFile) throws {
        try encode { try output.write($0) }
    }

    private func encode(_ write: (KeyBuffer) throws -> Void) throws {
        var raw = key.rawRepresentation
        defer { KeyMaterial.wipe(&raw) }
        var encoded = raw.base64EncodedData()
        defer { KeyMaterial.wipe(&encoded) }
        let prefix = Array("mop-recovery-v1:".utf8)
        let output = KeyBuffer(capacity: prefix.count + encoded.count + 1)
        defer { output.wipe() }
        output.count = output.capacity
        output.withStorage { destination in
            destination.copyBytes(from: prefix)
            encoded.withUnsafeBytes { source in
                UnsafeMutableRawBufferPointer(rebasing: destination[prefix.count..<(prefix.count + source.count)])
                    .copyMemory(from: source)
            }
            destination[output.count - 1] = 0x0A
        }
        try write(output)
    }

    public func unwrap(_ recipient: VaultRecipient, vaultID: UUID) throws -> SymmetricKey {
        guard recipient.kind == "recovery", recipient.publicKey == publicKey else { throw MopError.invalidRecovery }
        do { return try VaultDocument.unwrap(recipient, vaultID: vaultID, privateKey: key) }
        catch { throw MopError.invalidRecovery }
    }
}
