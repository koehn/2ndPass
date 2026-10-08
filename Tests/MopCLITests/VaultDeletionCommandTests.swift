import Foundation
import Testing
import MopCore
import MopAppSupport
@testable import MopCLI

@Test func vaultDeletionCommandRejectsOfflineLocalSaveAndWrongConfirmation() async throws {
    let id = UUID().uuidString
    for flags in [["--offline"], ["--local-save"], ["--confirm", UUID().uuidString]] {
        let args = ["vault", "delete", "--vault", id] + (flags.first == "--confirm" ? flags : ["--confirm", id] + flags)
        let command = try #require(Mop.parseAsRoot(args) as? Vault.DeleteVault)
        await #expect(throws: (any Error).self) { try await command.run() }
    }
}
private final class DeletionResultService: VaultService, Sendable {
    var authenticatedAt: TimeInterval? { 0 }
    func lock() {}
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult {
        var result = VaultResult(); result.deletionStatus = .committed; result.message = "ignored"
        return result
    }
}
@Test func vaultDeletionCommandUsesDistinctPendingOutcome() async throws {
    let store = CommandStore(options: try VaultOptions.parse([]), service: DeletionResultService())
    await #expect(throws: VaultDeletionPending.self) { _ = try await store.perform(.sync) }
}
