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
    public let offlineRecovery: DevicePublicKey?
    public let removedDevices: [UUID]?

    public init(accounts: [AccountMember], offlineRecovery: DevicePublicKey? = nil, removedDevices: [UUID]? = nil) throws {
        self.accounts = accounts.sorted { $0.id.uuidString < $1.id.uuidString }; self.offlineRecovery = offlineRecovery
        self.removedDevices = removedDevices
        try validate()
    }
    private enum CodingKeys: String, CodingKey { case accounts, offlineRecovery, removedDevices, recovery }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        guard !c.contains(.recovery) else { throw MopError.legacyVault }
        accounts = try c.decode([AccountMember].self, forKey: .accounts)
        offlineRecovery = try c.decodeIfPresent(DevicePublicKey.self, forKey: .offlineRecovery)
        removedDevices = try c.decodeIfPresent([UUID].self, forKey: .removedDevices)
        try validate()
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(accounts, forKey: .accounts)
        try c.encodeIfPresent(offlineRecovery, forKey: .offlineRecovery)
        try c.encodeIfPresent(removedDevices, forKey: .removedDevices)
    }
    public var devices: [DevicePublicKey] { accounts.flatMap(\.devices) }
    var recipients: [DevicePublicKey] { (devices + [offlineRecovery].compactMap { $0 }).sorted { $0.fingerprint < $1.fingerprint } }
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
        guard offlineRecovery == nil || offlineRecovery?.member == owner else { throw MopError.invalidRecovery }
        try recipients.forEach { try $0.validate() }
    }
}
