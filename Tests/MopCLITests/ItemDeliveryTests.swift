import Foundation
import Testing
import MopCore
import MopAppSupport
@testable import MopCLI

private final class DeliveryService: VaultService, Sendable {
    let receipt = UUID()
    let status: VaultSaveStatus
    init(status: VaultSaveStatus) { self.status = status }
    var authenticatedAt: TimeInterval? { 0 }
    func lock() {}
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult {
        var result = VaultResult(); result.saveStatus = status; result.mutationIDs = [receipt]
        result.message = "Text is intentionally unrelated to delivery status."
        return result
    }
}

@Test func cliPendingOutcomeCarriesExactReceiptAndDoesNotDependOnMessageText() async throws {
    let pending = DeliveryService(status: .pending)
    let store = CommandStore(options: try VaultOptions.parse([]), service: pending)
    do {
        _ = try await store.perform(.sync)
        Issue.record("A pending mutation must not be reported as a confirmed CLI success")
    } catch let error as CloudConfirmationPending {
        #expect(error.mutationIDs == [pending.receipt])
        #expect(error.message.contains(pending.receipt.uuidString))
        #expect(error.message.contains("Do not repeat the write"))
        #expect(MopError.cloudUncertain.exitCode != 0)
    }
    let confirmed = DeliveryService(status: .cloudConfirmed)
    let confirmedStore = CommandStore(options: try VaultOptions.parse([]), service: confirmed)
    #expect(try await confirmedStore.perform(.sync).mutationIDs == [confirmed.receipt])
}
