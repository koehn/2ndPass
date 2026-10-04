import Foundation
import Testing
@testable import MopAppSupport

private actor DeliveryBarrier {
    private var continuation: CheckedContinuation<Void, Never>?
    private var enteredWaiter: CheckedContinuation<Void, Never>?
    func wait() async { await withCheckedContinuation { continuation = $0; enteredWaiter?.resume(); enteredWaiter = nil } }
    func entered() async { if continuation == nil { await withCheckedContinuation { enteredWaiter = $0 } } }
    func release() { continuation?.resume(); continuation = nil }
}

@Test func deliveryDeadlineDoesNotAwaitUncooperativeNetworkCallback() async throws {
    let network = DeliveryBarrier(), observation = DeliveryBarrier()
    let waiting = Task {
        try await DeliveryConfirmationWaiter.wait(timeout: .milliseconds(100), request: { await network.wait() }, observe: {
            await observation.wait(); return true
        })
    }
    await network.entered(); await observation.entered()
    let result = try await waiting.value
    #expect(!result)
    // Neither callback can finish until explicitly released after the deadline result.
    await network.release(); await observation.release()
}

@Test func canceledDeliveryWaitReturnsWithoutAwaitingCallbacks() async throws {
    let network = DeliveryBarrier(), observation = DeliveryBarrier()
    let waiting = Task {
        try await DeliveryConfirmationWaiter.wait(timeout: .seconds(30), request: { await network.wait() }, observe: {
            await observation.wait(); return true
        })
    }
    await network.entered(); await observation.entered()
    waiting.cancel()
    await #expect(throws: CancellationError.self) { try await waiting.value }
    await network.release(); await observation.release()
}

@Test func deliveryZeroDeadlineDoesNotStartNetworkWork() async throws {
    #expect(try await !DeliveryConfirmationWaiter.wait(timeout: .zero, request: {
        Issue.record("Zero deadline must not start network work")
    }, observe: {
        Issue.record("Zero deadline must not start observation"); return true
    }))
}
