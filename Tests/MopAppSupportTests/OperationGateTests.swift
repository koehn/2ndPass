import Foundation
import Synchronization
import Testing
@testable import MopAppSupport

@Test(arguments: ["vault", nil] as [String?])
func catalogPermitExcludesSameVaultAndAccountMutation(next: String?) async throws {
    let gate = OperationGate(), acquired = Mutex(false)
    await gate.enter(vault: "vault")
    let waiting = Task {
        await gate.enter(vault: next)
        acquired.withLock { $0 = true }
        await gate.leave(vault: next)
    }
    try await Task.sleep(for: .milliseconds(30))
    #expect(!acquired.withLock { $0 })
    await gate.leave(vault: "vault")
    await waiting.value
    #expect(acquired.withLock { $0 })
}
