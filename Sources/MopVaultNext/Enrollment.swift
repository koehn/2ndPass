import Foundation
import MopCore

/// Public, self-signed request. Cloud possession is not membership authority.
public struct EnrollmentRequest: Codable, Sendable {
    public let id: UUID
    public let vault: UUID
    public let request: DeviceRequest
    public let name: String
    public let expires: Date
    public let signature: Data
    private struct Statement: Encodable {
        let domain = "mop-v7-cloud-enrollment"
        let id: UUID; let vault: UUID; let request: DeviceRequest; let name: String; let expires: Date
    }
    public init(vault: UUID, request: DeviceRequest, name: String, device: any DeviceOperations) throws {
        id = UUID(); self.vault = vault; self.request = request
        self.name = String(name.prefix(80)); expires = Date().addingTimeInterval(86400)
        guard request.device == device.identity else { throw MopError.invalidIdentity }
        signature = try device.sign(Codec.encode(Statement(id: id, vault: vault, request: request, name: self.name, expires: expires)))
    }
    public func validate(at address: VaultAddress, now: Date = Date()) throws {
        try request.validate()
        guard address.database == .private, address.namespace == .user,
              vault == address.vault, request.account == address.account,
              request.container == address.container, request.environment == address.environment,
              !request.recovery, name.count <= 80, expires > now, expires.timeIntervalSince(now) <= 86500,
              request.device.verifies(signature, message: try Codec.encode(Statement(id: id, vault: vault, request: request, name: name, expires: expires))) else { throw MopError.invalidIdentity }
    }
}
public struct EnrollmentExchange: Codable, Sendable, Identifiable {
    public let request: EnrollmentRequest
    public var invitation: InvitationPacket?
    public var acceptance: Acceptance?
    /// Presence marks publication; membership is verified from the signed revision.
    /// Older clients stored a redundant full checkpoint here.
    public var approved: Data?
    public var rejected = false
    /// Local trust decision only. Never adopt this field from the cloud.
    public var confirmedCode: String?
    /// Durable cleanup intent for requests replaced by an explicit restart.
    public var superseded: [UUID]?
    public var id: UUID { request.id }
    public init(request: EnrollmentRequest) { self.request = request }
    /// A truncated SHA-256 transcript fingerprint (96 bits), compared on both
    /// devices before owner approval. Not a password, locator or decryption key.
    public var verificationCode: String? {
        guard let invitation else { return nil }
        let digest = Codec.digest(Data("mop-v7-enrollment-comparison".utf8) + (try! Codec.encode(request)) + (try! Codec.encode(invitation)))
        let chars = Array(digest.prefix(24).uppercased())
        return stride(from: 0, to: 24, by: 4).map { String(chars[$0..<$0+4]) }.joined(separator: "-")
    }
    public func verifiedInvitation(at address: VaultAddress, referencedCheckpoint: Data? = nil) throws -> VerifiedVault {
        try request.validate(at: address)
        guard let packet = invitation, packet.address == address,
              packet.request.fingerprint == request.request.fingerprint,
              packet.invitation.vault == request.vault,
              packet.invitation.member == request.request.device.member,
              packet.invitation.role == .owner else { throw MopError.vaultUntrusted }
        try packet.invitation.validate(now: Date())
        // Cloud invitations can reference the already-published revision by its
        // signed digest. File invitations and existing requests retain inline data.
        let bytes = packet.checkpoint.isEmpty ? (referencedCheckpoint ?? Data()) : packet.checkpoint
        let root = try VerifiedVault(checkpoint: bytes, independentlyVerifiedDigest: packet.invitation.checkpoint)
        guard root.id == address.vault, root.membership.role(of: packet.invitation.issuer) == .owner,
              root.membership.accounts.first(where: { $0.role == .owner })?.id == request.request.device.member else { throw MopError.vaultUntrusted }
        // This validates structure. Automatic same-account bootstrap trusts the
        // private CloudKit account mailbox for the initial owner checkpoint.
        return root
    }
}
public struct EnrollmentMailbox: Codable, Sendable {
    public var exchanges: [EnrollmentExchange] = []
    public init() {}
    public func encoded() throws -> Data {
        guard exchanges.count <= 32, Set(exchanges.map(\.id)).count == exchanges.count else { throw MopError.invalidVault }
        let bytes = try Codec.encode(self)
        guard bytes.count <= Codec.maximumSize else { throw MopError.invalidVault }
        return bytes
    }
    public static func decode(_ bytes: Data) throws -> Self {
        let value = try ExchangeFile.decode(Self.self, from: bytes)
        _ = try value.encoded(); return value
    }
}
public struct EnrollmentInbox: Sendable {
    public let mailbox: EnrollmentMailbox
    public let version: Data?
    public init(mailbox: EnrollmentMailbox, version: Data?) { self.mailbox = mailbox; self.version = version }
}
