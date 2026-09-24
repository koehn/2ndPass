import CryptoKit
import Foundation
import MopCore

public enum PairingError: Error, LocalizedError, Sendable {
    case invalid, expired, occupied, cancelled
    public var errorDescription: String? {
        switch self {
        case .invalid: "Pairing could not be verified. Start again with a new QR code."
        case .expired: "Pairing expired. Display a new QR code on your Mac."
        case .occupied: "This QR code is already being used. Start a new pairing."
        case .cancelled: "Pairing was cancelled."
        }
    }
}

/// A temporary capability. Never persist or log this value or its QR representation.
public struct PairingInvitation: Codable, Sendable {
    public static let maximumPayload = 8192
    public let version: Int
    public let session: UUID
    public let vault: UUID
    public let container: String
    public let environment: String
    public let expires: Int64
    private let secret: Data

    public init(vault: UUID, container: String, environment: String, now: Date = Date()) {
        version = 1; session = UUID(); self.vault = vault
        self.container = container; self.environment = environment
        expires = Int64(now.timeIntervalSince1970) + 300
        secret = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    }
    public func validate(now: Date = Date()) throws {
        guard version == 1, secret.count == 32, !container.isEmpty, container.utf8.count <= 256,
              ["Development", "Production"].contains(environment) else { throw PairingError.invalid }
        let remaining = Double(expires) - now.timeIntervalSince1970
        guard remaining > 0 else { throw PairingError.expired }
        guard remaining <= 300 else { throw PairingError.invalid }
    }
    public func qr(now: Date = Date()) throws -> String {
        try validate(now: now)
        return "mop-pair:1:" + (try VaultCoding.encode(self)).base64EncodedString()
    }
    public static func parse(_ text: String, now: Date = Date()) throws -> Self {
        guard text.utf8.count <= 2048, text.hasPrefix("mop-pair:1:"),
              let bytes = Data(base64Encoded: String(text.dropFirst(11))),
              let value = try? JSONDecoder().decode(Self.self, from: bytes) else { throw PairingError.invalid }
        try value.validate(now: now); return value
    }
    private struct Context: Codable {
        let version: Int; let session: UUID; let vault: UUID
        let container: String; let environment: String; let expires: Int64; let direction: String
    }
    private func context(_ direction: String) throws -> Data {
        try VaultCoding.encode(Context(version: version, session: session, vault: vault,
                                       container: container, environment: environment, expires: expires, direction: direction))
    }
    private func key(_ direction: String) throws -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: secret),
                              salt: Data("mop-pair-v1".utf8), info: try context(direction), outputByteCount: 32)
    }
    public enum Direction: String, Sendable { case request, response, acknowledgement }
    public func seal<T: Encodable>(_ value: T, direction: Direction, now: Date = Date()) throws -> Data {
        try validate(now: now)
        let bytes = try VaultCoding.encode(value)
        guard bytes.count <= Self.maximumPayload - 28 else { throw PairingError.invalid }
        guard let sealed = try AES.GCM.seal(bytes, using: key(direction.rawValue), authenticating: context(direction.rawValue)).combined else { throw PairingError.invalid }
        return sealed
    }
    public func open<T: Decodable>(_ type: T.Type, bytes: Data, direction: Direction, now: Date = Date()) throws -> T {
        try validate(now: now)
        guard bytes.count <= Self.maximumPayload else { throw PairingError.invalid }
        do {
            let clear = try AES.GCM.open(AES.GCM.SealedBox(combined: bytes), using: key(direction.rawValue), authenticating: context(direction.rawValue))
            return try JSONDecoder().decode(type, from: clear)
        } catch { throw PairingError.invalid }
    }
    public func confirmation(_ request: PairingRequest, now: Date = Date()) throws -> String {
        try validate(now: now); try request.validate()
        let mac = HMAC<SHA256>.authenticationCode(for: try VaultCoding.encode(request), using: try key("confirmation"))
        let number = mac.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } % 1_000_000
        return String(format: "%06u", number)
    }
}

public struct PairingRequest: Codable, Equatable, Sendable {
    public let device: DeviceRequest
    public let nonce: Data
    public init(device: DeviceRequest) {
        self.device = device
        nonce = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    }
    public func validate() throws {
        try device.validate()
        guard nonce.count == 32 else { throw PairingError.invalid }
    }
    public var digest: String { get throws { try VaultCoding.digest(VaultCoding.encode(self)) } }
}

public struct PairingReceipt: Codable, Sendable {
    public let requestDigest: String
    public let deviceFingerprint: String
    public let vaultFingerprint: String
    public let revision: String
    public init(request: PairingRequest, vaultFingerprint: String, revision: String) throws {
        requestDigest = try request.digest; deviceFingerprint = request.device.fingerprint
        self.vaultFingerprint = vaultFingerprint; self.revision = revision
    }
    public func validate(request: PairingRequest) throws {
        guard requestDigest == (try request.digest), deviceFingerprint == request.device.fingerprint,
              VaultTrust.validFingerprint(vaultFingerprint), VaultTrust.validFingerprint(revision) else { throw PairingError.invalid }
    }
}

/// Sent only after the joining device has persisted trust and opened the vault.
public struct PairingAcknowledgement: Codable, Sendable {
    public let receiptDigest: String
    public init(receipt: PairingReceipt) throws {
        receiptDigest = try VaultCoding.digest(VaultCoding.encode(receipt))
    }
    public func validate(receipt: PairingReceipt) throws {
        guard receiptDigest == (try VaultCoding.digest(VaultCoding.encode(receipt))) else { throw PairingError.invalid }
    }
}
