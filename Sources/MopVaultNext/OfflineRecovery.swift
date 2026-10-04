import CryptoKit
import Foundation
import Synchronization
import MopCore

/// One offline secret, scoped to one authenticated CloudKit account. Neither the
/// scope nor its hash is a second encryption factor when ciphertext is copied.
public struct RecoveryScope: Codable, Equatable, Sendable {
    public let container: String
    public let environment: String
    public let account: String
    public init(container: String, environment: String, account: String) throws {
        guard !container.isEmpty, ["Development", "Production"].contains(environment), !account.isEmpty,
              account != "__defaultOwner__" else { throw MopError.cloudAccount }
        self.container = container; self.environment = environment; self.account = account
    }
    public var member: UUID { AccountScope.member(container: container, environment: environment, account: account) }
    var salt: Data { Data(SHA256.hash(data: try! Codec.encode(self))) }
}

/// The only software provider shipped for cloud vaults. All access is serialized
/// with close(), including cancellation from the session invalidation callback.
public final class OfflineRecoveryKey: DeviceOperations, @unchecked Sendable {
    public let identity: DevicePublicKey
    public let scope: RecoveryScope
    private struct Material {
        var secret: Data
        let encryption: P256.KeyAgreement.PrivateKey
        let signing: P256.Signing.PrivateKey
    }
    private let material: Mutex<Material?>
    public convenience init(scope: RecoveryScope) throws {
        var bytes = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        defer { SecretBytes.wipe(&bytes) }
        try self.init(secret: bytes, scope: scope)
    }
    // Internal for reproducible cryptographic test vectors.
    init(secret: Data, scope: RecoveryScope) throws {
        guard secret.count == 32 else { throw MopError.invalidRecovery }
        func scalar(_ purpose: String) throws -> Data {
            for counter in UInt32(0)..<UInt32.max {
                let info = Data("2ndpass/offline-recovery/v1/\(purpose)/\(counter)".utf8)
                var raw = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: secret), salt: scope.salt,
                                               info: info, outputByteCount: 32).withUnsafeBytes { Data($0) }
                if (try? P256.Signing.PrivateKey(rawRepresentation: raw)) != nil { return raw }
                SecretBytes.wipe(&raw)
            }
            throw MopError.invalidRecovery
        }
        var encryptionBytes = try scalar("agreement"), signingBytes = try scalar("signing")
        defer { SecretBytes.wipe(&encryptionBytes); SecretBytes.wipe(&signingBytes) }
        let encryption = try P256.KeyAgreement.PrivateKey(rawRepresentation: encryptionBytes)
        let signing = try P256.Signing.PrivateKey(rawRepresentation: signingBytes)
        let digest = Codec.digest(Data("2ndpass/offline-recovery/v1/identity".utf8) + encryption.publicKey.x963Representation + signing.publicKey.x963Representation)
        let chars = Array(digest.prefix(32))
        let id = UUID(uuidString: String(chars[0..<8]) + "-" + String(chars[8..<12]) + "-" + String(chars[12..<16]) + "-" + String(chars[16..<20]) + "-" + String(chars[20..<32]))!
        identity = try DevicePublicKey(member: scope.member, device: id, encryption: encryption.publicKey.x963Representation, signing: signing.publicKey.x963Representation)
        self.scope = scope
        material = Mutex(Material(secret: secret, encryption: encryption, signing: signing))
    }
    private struct File: Codable {
        let format: String
        let scope: RecoveryScope
        let fingerprint: String
        let code: String
    }
    public convenience init(document: SecretBytes, scope: RecoveryScope) throws {
        guard document.count <= 8192 else { throw MopError.invalidRecovery }
        var bytes = Data(document)
        defer { SecretBytes.wipe(&bytes) }
        let code: String
        let expected: String?
        if bytes.first == UInt8(ascii: "{") {
            guard let file = try? JSONDecoder().decode(File.self, from: bytes) else { throw MopError.invalidRecovery }
            guard file.format == "2ndpass-recovery-1", file.scope == scope else { throw MopError.invalidRecovery }
            code = file.code; expected = file.fingerprint
        } else { code = String(decoding: bytes, as: UTF8.self); expected = nil }
        let normalized = code.uppercased().filter { !$0.isWhitespace && $0 != "-" }
        guard normalized.hasPrefix("SP1"), normalized.count == 75 else { throw MopError.invalidRecovery }
        let payload = Array(normalized.dropFirst(3))
        var secret = Data()
        defer { SecretBytes.wipe(&secret) }
        for i in stride(from: 0, to: 64, by: 2) {
            guard let byte = UInt8(String(payload[i...i+1]), radix: 16) else { throw MopError.invalidRecovery }
            secret.append(byte)
        }
        guard String(payload[64...]) == Self.checksum(secret) else { throw MopError.invalidRecovery }
        try self.init(secret: secret, scope: scope)
        guard expected == nil || expected == identity.fingerprint else { close(); throw MopError.invalidRecovery }
    }
    private static func checksum(_ secret: Data) -> String {
        String(Codec.digest(Data("2ndpass/recovery-code/v1".utf8) + secret).prefix(8)).uppercased()
    }
    /// Text is created only at the explicit display/export boundary. Swift and OS
    /// text copies cannot be guaranteed wiped; the provider retains no text.
    public func code() throws -> SecretBytes {
        try material.withLock { value in
            guard let value else { throw MopError.authentication }
            let payload = value.secret.map { String(format: "%02X", $0) }.joined() + Self.checksum(value.secret)
            let chars = Array(payload)
            return SecretBytes(utf8: "SP1-" + stride(from: 0, to: chars.count, by: 4).map { String(chars[$0..<min($0+4, chars.count)]) }.joined(separator: "-"))
        }
    }
    public func export() throws -> SecretBytes {
        var data = try Codec.encode(File(format: "2ndpass-recovery-1", scope: scope, fingerprint: identity.fingerprint, code: String(decoding: code(), as: UTF8.self)))
        defer { SecretBytes.wipe(&data) }
        return SecretBytes(copying: data)
    }
    public func sign(_ bytes: Data) throws -> Data {
        try material.withLock { value in
            guard let value else { throw MopError.authentication }
            return try value.signing.signature(for: bytes).rawRepresentation
        }
    }
    public func unwrap(_ envelope: KeyEnvelope, context: Data) throws -> SymmetricKey {
        try material.withLock { value in
            guard let value else { throw MopError.authentication }
            return try envelope.open(using: value.encryption, context: context)
        }
    }
    public func close() {
        material.withLock { value in
            if value != nil { SecretBytes.wipe(&value!.secret) }
            value = nil
        }
    }
    deinit { close() }
}

public struct RecoveryVaultStatus: Codable, Equatable, Sendable, Identifiable {
    public let id: UUID
    public var fingerprint: String?
    public var complete: Bool
    public var issue: String?
    public init(id: UUID, fingerprint: String?, complete: Bool, issue: String? = nil) {
        self.id = id; self.fingerprint = fingerprint; self.complete = complete; self.issue = issue
    }
}
/// Public, account-private progress. Signed vault membership is authoritative.
public struct RecoveryConfiguration: Codable, Equatable, Sendable {
    public let scope: RecoveryScope
    public var active: DevicePublicKey?
    public var target: DevicePublicKey?
    public var operation: UUID?
    public var pendingCreation: Data?
    public var vaults: [RecoveryVaultStatus]
    public init(scope: RecoveryScope, active: DevicePublicKey? = nil) {
        self.scope = scope; self.active = active; target = nil; operation = nil; vaults = []
    }
    public var incomplete: Bool { operation != nil || pendingCreation != nil }
    public func validate() throws {
        guard active == nil || active?.member == scope.member, target == nil || target?.member == scope.member,
              operation != nil || target == nil, operation == nil || pendingCreation == nil,
              Set(vaults.map(\.id)).count == vaults.count else { throw MopError.invalidRecovery }
        try active?.validate(); try target?.validate()
    }
}
