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
        case .deleted: "This vault is being deleted or has been deleted. Pending cleanup continues automatically."
        case .staleState: "Vault deletion state changed. The operation continues automatically."
        case .invalidNotice: "The vault deletion notice could not be verified. No local data was erased."
        }
    }
}
