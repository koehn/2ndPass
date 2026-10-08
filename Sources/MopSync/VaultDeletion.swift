import Foundation

public enum VaultDeletionPhase: String, Codable, Sendable { case prepared, publishing, committed, cloudDeleted, complete }
public struct VaultDeletionState: Codable, Equatable, Sendable {
    public let scope: VaultScope
    public let notice: Data
    public let phase: VaultDeletionPhase
    public let assetVersions: [UUID]
    public init(scope: VaultScope, notice: Data, phase: VaultDeletionPhase, assetVersions: [UUID] = []) {
        self.scope = scope; self.notice = notice; self.phase = phase; self.assetVersions = assetVersions
    }
}
public enum VaultDeletionFailure: Error, LocalizedError, Sendable {
    case deleted, staleState, invalidNotice
    public var errorDescription: String? {
        switch self {
        case .deleted: "This vault is being deleted or has been deleted. Sync to finish any pending cleanup."
        case .staleState: "Vault deletion state changed. Sync to resume the operation."
        case .invalidNotice: "The vault deletion notice could not be verified. No local data was erased."
        }
    }
}
public protocol VaultDeletionTransport: Sendable {
    func read(vaultID: UUID) async throws -> Data?
    /// Create-only. A racing publication returns the existing bytes for validation.
    func publish(vaultID: UUID, notice: Data) async throws -> Data
    func deleteZone(address: VaultCloudAddress) async throws
}
