import Foundation

public struct VaultProvisioningBinding: Codable, Equatable, Sendable {
    public let scope: VaultScope
    public let address: VaultCloudAddress
    public let setupID: String
    public let controlDigest: String
    public init(scope: VaultScope, address: VaultCloudAddress, setupID: String, controlDigest: String) {
        self.scope = scope; self.address = address; self.setupID = setupID; self.controlDigest = controlDigest
    }
}
public enum VaultProvisioningPhase: String, Codable, Sendable { case prepared, commissioningStarted, controlConfirmed, blocked }
public struct VaultProvisioningState: Codable, Equatable, Sendable {
    public let binding: VaultProvisioningBinding
    public let controlBytes: Data
    public let phase: VaultProvisioningPhase
    public let headSystemFields: Data?
}
public enum VaultControlRecordKind: Sendable { case genesis, head }
public struct ProvisioningCloudRecord: Sendable {
    public let bytes: Data
    public let systemFields: Data
    public init(bytes: Data, systemFields: Data) { self.bytes = bytes; self.systemFields = systemFields }
}
public protocol VaultProvisioningTransport: Sendable {
    func zoneExists(binding: VaultProvisioningBinding) async throws -> Bool
    func createZone(binding: VaultProvisioningBinding) async throws
    func readControl(_ kind: VaultControlRecordKind, binding: VaultProvisioningBinding) async throws -> ProvisioningCloudRecord?
    func createControl(_ kind: VaultControlRecordKind, binding: VaultProvisioningBinding, bytes: Data) async throws -> ProvisioningCloudRecord
}
public enum VaultProvisioningError: Error, Equatable, Sendable {
    case invalidBinding, missingInitialization, staleState, blocked, controlMismatch, zoneMissing, operationInterrupted
}
