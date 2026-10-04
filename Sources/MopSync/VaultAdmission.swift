import Foundation

public enum VaultAdmissionPhase: String, Codable, Sendable { case prepared, complete }
/// Durable owner-approved operation. Item ciphertext is staged separately so the
/// journal header never duplicates a complete vault's encrypted attachment data.
public struct VaultAdmissionPlan: Codable, Equatable, Sendable {
    public let scope: VaultScope
    public let requestID: UUID
    public let approval: Data
    public let parentControl: Data
    public let successorControl: Data
    public let expectedVersions: [UUID: UUID]
    public let phase: VaultAdmissionPhase
}
