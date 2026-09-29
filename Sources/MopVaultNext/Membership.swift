import Foundation
import MopCore

public enum MemberRole: String, Codable, Sendable { case owner, editor, viewer }

public struct AccountMember: Codable, Equatable, Sendable {
    public let id: UUID
    public let role: MemberRole
    public let devices: [DevicePublicKey]
    public init(id: UUID, role: MemberRole, devices: [DevicePublicKey]) {
        self.id = id; self.role = role; self.devices = devices.sorted { $0.fingerprint < $1.fingerprint }
    }
}

public struct Membership: Codable, Equatable, Sendable {
    public let accounts: [AccountMember]
    public let recovery: DevicePublicKey?
    public let removedDevices: [UUID]?

    public init(accounts: [AccountMember], recovery: DevicePublicKey? = nil, removedDevices: [UUID]? = nil) throws {
        self.accounts = accounts.sorted { $0.id.uuidString < $1.id.uuidString }; self.recovery = recovery
        self.removedDevices = removedDevices
        try validate()
    }
    public var devices: [DevicePublicKey] { accounts.flatMap(\.devices) }
    var recipients: [DevicePublicKey] { (devices + [recovery].compactMap { $0 }).sorted { $0.fingerprint < $1.fingerprint } }
    var owner: UUID { accounts.first { $0.role == .owner }!.id }
    public func role(of key: DevicePublicKey) -> MemberRole? {
        accounts.first { $0.id == key.member && $0.devices.contains(key) }?.role
    }
    func key(_ fingerprint: String) -> DevicePublicKey? {
        recipients.first { $0.fingerprint == fingerprint }
    }
    func validate() throws {
        let removed = removedDevices ?? []
        guard removed.count <= 4096, Set(removed).count == removed.count,
              removed == removed.sorted(by: { $0.uuidString < $1.uuidString }),
              Set(removed).isDisjoint(with: devices.map(\.device)) else { throw MopError.invalidVault }
        guard !accounts.isEmpty, accounts.count <= 32, devices.count <= 128,
              accounts.filter({ $0.role == .owner }).count == 1,
              accounts == accounts.sorted(by: { $0.id.uuidString < $1.id.uuidString }),
              Set(accounts.map(\.id)).count == accounts.count,
              Set(recipients.map(\.device)).count == recipients.count,
              Set(recipients.map(\.encryption)).count == recipients.count,
              Set(recipients.map(\.signing)).count == recipients.count else { throw MopError.invalidVault }
        for account in accounts {
            guard !account.devices.isEmpty,
                  account.devices == account.devices.sorted(by: { $0.fingerprint < $1.fingerprint }),
                  account.devices.allSatisfy({ $0.member == account.id }) else { throw MopError.invalidVault }
        }
        try recipients.forEach { try $0.validate() }
    }
}

/// The transport invitation and this cryptographic invitation are independent.
/// Fingerprints/checkpoints must be compared through an authenticated channel.
public struct Invitation: Codable, Sendable {
    public let vault: UUID
    public let checkpoint: String
    public let nonce: UUID
    public let member: UUID
    public let role: MemberRole
    public let expires: Date
    public let issuer: DevicePublicKey
    public let signature: Data
    private struct Statement: Encodable {
        let domain = "mop-v7-invitation"
        let vault: UUID; let checkpoint: String; let nonce: UUID; let member: UUID
        let role: MemberRole; let expires: Date; let issuer: DevicePublicKey
    }
    private var statement: Statement { Statement(vault: vault, checkpoint: checkpoint, nonce: nonce,
        member: member, role: role, expires: expires, issuer: issuer) }
    var digest: String { Codec.digest(try! Codec.encode(self)) }
    init(vault: UUID, checkpoint: String, member: UUID, role: MemberRole, expires: Date, issuer: any DeviceOperations) throws {
        self.vault = vault; self.checkpoint = checkpoint; nonce = UUID(); self.member = member
        self.role = role; self.expires = expires; self.issuer = issuer.identity
        signature = try issuer.sign(Codec.encode(Statement(vault: vault, checkpoint: checkpoint, nonce: nonce,
            member: member, role: role, expires: expires, issuer: issuer.identity)))
    }
    func validate(now: Date) throws {
        guard Codec.hash(checkpoint), expires.timeIntervalSince1970.isFinite, expires > now,
              issuer.verifies(signature, message: try Codec.encode(statement)) else { throw MopError.invalidIdentity }
    }
}

public struct Acceptance: Codable, Sendable {
    public let invitation: Invitation
    public let device: DevicePublicKey
    public let signature: Data
    private struct Statement: Encodable {
        let domain = "mop-v7-acceptance"
        let invitation: String
        let device: DevicePublicKey
    }
    /// Manual/cross-account callers independently verify the owner's checkpoint.
    /// Automatic same-account callers instead trust the provisioned private
    /// CloudKit bootstrap channel; this check does not authenticate that channel.
    public init(invitation: Invitation, expectedCheckpoint: String, device: any DeviceOperations, now: Date = Date()) throws {
        try invitation.validate(now: now)
        guard invitation.checkpoint == expectedCheckpoint, invitation.member == device.identity.member else { throw MopError.vaultUntrusted }
        self.invitation = invitation; self.device = device.identity
        signature = try device.sign(Codec.encode(Statement(invitation: invitation.digest, device: device.identity)))
    }
    func validate(now: Date) throws {
        try invitation.validate(now: now); try device.validate()
        guard device.member == invitation.member,
              device.verifies(signature, message: try Codec.encode(Statement(invitation: invitation.digest, device: device))) else { throw MopError.invalidIdentity }
    }
}
