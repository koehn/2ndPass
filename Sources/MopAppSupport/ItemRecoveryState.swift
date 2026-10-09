import Foundation
import MopCore
import MopVaultNext

public enum ItemRecoveryPhase: String, Codable, Sendable {
    case preview, enrolling, repairing, verifying, complete
}
/// No secrets: safe to retain across lock, process death, and account changes.
public struct ItemRecoveryState: Codable, Equatable, Sendable {
    public let account: String
    public let operation: UUID
    public var phase: ItemRecoveryPhase
    public var vaults: [UUID]
    public var completed: [UUID]
    public var approvals: [String: Data]
    public var issue: String?
    public init(account: String, vaults: [UUID]) {
        self.account = account; operation = UUID(); phase = .preview
        self.vaults = vaults; completed = []; approvals = [:]
    }
    public var blocksRegularAccess: Bool { phase != .complete }
}

struct ItemRecoveryStateStore: Sendable {
    let directory: URL
    let account: String
    private var location: URL { directory.appendingPathComponent("Recovery").appendingPathComponent(setupHash(Data(account.utf8))) }
    func load() throws -> ItemRecoveryState? {
        let dir = try LocalDirectory(directory: location)
        return try dir.locked {
            let file = location.appendingPathComponent("state.json")
            guard FileManager.default.fileExists(atPath: file.path) else { return nil }
            let state = try JSONDecoder().decode(ItemRecoveryState.self, from: LocalFile.read(file, privateFile: true, limit: 16 * 1024 * 1024))
            guard state.account == account, Set(state.vaults).count == state.vaults.count,
                  Set(state.completed).isSubset(of: Set(state.vaults)) else { throw MopError.invalidRecovery }
            return state
        }
    }
    func save(_ state: ItemRecoveryState) throws {
        guard state.account == account else { throw MopError.cloudAccount }
        let dir = try LocalDirectory(directory: location)
        try dir.locked { try LocalFile.write(JSONEncoder().encode(state), to: location.appendingPathComponent("state.json"), replace: true) }
    }
}
