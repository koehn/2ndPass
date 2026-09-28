import Foundation
import MopCore

public enum AccountScope {
    /// A namespace identifier, not an authentication credential or private key.
    public static func member(container: String, environment: String, account: String) -> UUID {
        let hash = Codec.digest(Data(["mop-v7-account", container, environment, account].map { "\($0.utf8.count):\($0)" }.joined().utf8))
        let chars = Array(hash.prefix(32))
        return UUID(uuidString: String(chars[0..<8]) + "-" + String(chars[8..<12]) + "-" + String(chars[12..<16]) + "-" + String(chars[16..<20]) + "-" + String(chars[20..<32]))!
    }
}
public struct DeviceRequest: Codable, Sendable {
    public let container: String
    public let environment: String
    public let account: String
    public let recovery: Bool
    public let device: DevicePublicKey
    public let signature: Data
    private struct Statement: Encodable {
        let domain = "mop-v7-device-request"
        let container: String; let environment: String; let account: String; let recovery: Bool; let device: DevicePublicKey
    }
    public init(container: String, environment: String, account: String, recovery: Bool, device: any DeviceOperations) throws {
        self.container = container; self.environment = environment; self.account = account; self.recovery = recovery; self.device = device.identity
        signature = try device.sign(Codec.encode(Statement(container: container, environment: environment, account: account, recovery: recovery, device: device.identity)))
        try validate()
    }
    public func validate() throws {
        try device.validate()
        guard !account.isEmpty, account != "__defaultOwner__", ["Development", "Production"].contains(environment),
              device.member == AccountScope.member(container: container, environment: environment, account: account),
              device.verifies(signature, message: try Codec.encode(Statement(container: container, environment: environment, account: account, recovery: recovery, device: device))) else { throw MopError.invalidIdentity }
    }
    public var fingerprint: String { Codec.digest(try! Codec.encode(self)) }
}
public struct InvitationPacket: Codable, Sendable {
    public let request: DeviceRequest
    public let invitation: Invitation
    public let address: VaultAddress
    public let checkpoint: Data
    public init(request: DeviceRequest, invitation: Invitation, address: VaultAddress, checkpoint: Data) {
        self.request = request; self.invitation = invitation; self.address = address; self.checkpoint = checkpoint
    }
}
public struct AcceptancePacket: Codable, Sendable {
    public let invitation: InvitationPacket
    public let acceptance: Acceptance
    public init(invitation: InvitationPacket, acceptance: Acceptance) { self.invitation = invitation; self.acceptance = acceptance }
}
public enum ExchangeFile {
    public static func encode<T: Encodable>(_ value: T) throws -> Data { try Codec.encode(value) }
    public static func decode<T: Decodable>(_ type: T.Type, from bytes: Data) throws -> T {
        guard bytes.count <= 24 * 1024 * 1024 else { throw MopError.invalidVault }
        do { return try JSONDecoder().decode(type, from: bytes) } catch { throw MopError.invalidVault }
    }
}
