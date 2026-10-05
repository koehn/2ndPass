import Foundation
import Synchronization
import Testing
@testable import MopAppSupport

@Test func idleQueuePausesBetweenUnitsAndCancelsWaitingWork() async throws {
    let queue = IdleWorkQueue(delay: .milliseconds(80), spacing: .zero)
    let calls = Mutex(0)
    queue.setActive(false)
    let task = Task { try await queue.run { calls.withLock { $0 += 1 } } }
    try await Task.sleep(for: .milliseconds(120))
    #expect(calls.withLock { $0 } == 0)
    queue.setActive(true)
    queue.activity()
    try await Task.sleep(for: .milliseconds(20))
    #expect(calls.withLock { $0 } == 0)
    try await task.value
    #expect(calls.withLock { $0 } == 1)
    queue.setActive(false)
    let canceled = Task { try await queue.run { calls.withLock { $0 += 1 } } }
    canceled.cancel()
    await #expect(throws: CancellationError.self) { try await canceled.value }
    queue.setActive(true)
    try await queue.run { calls.withLock { $0 += 1 } }
    #expect(calls.withLock { $0 } == 2)
}

@Test func idleQueueSerializesWorkAcrossVaults() async throws {
    let queue = IdleWorkQueue(delay: .zero, spacing: .zero)
    let active = Mutex(0), maximum = Mutex(0)
    try await withThrowingTaskGroup(of: Void.self) { group in
        for _ in 0..<4 {
            group.addTask {
                try await queue.run {
                    let count = active.withLock { $0 += 1; return $0 }
                    maximum.withLock { $0 = max($0, count) }
                    try await Task.sleep(for: .milliseconds(10))
                    active.withLock { $0 -= 1 }
                }
            }
        }
        try await group.waitForAll()
    }
    #expect(maximum.withLock { $0 } == 1)
}
