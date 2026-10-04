import Foundation
import Synchronization

/// Serial, cooperative maintenance. Interaction postpones the next unit of work;
/// work already running finishes its bounded unit before yielding to the UI.
final class IdleWorkQueue: Sendable {
    private let gate = OperationGate()
    private let delay: Duration
    private let spacing: Duration
    private struct State {
        var active = true
        var deadline: ContinuousClock.Instant = .now
    }
    private let state = Mutex(State())

    init(delay: Duration = .seconds(3), spacing: Duration = .milliseconds(100)) {
        self.delay = delay; self.spacing = spacing
        activity()
    }
    func activity() { state.withLock { $0.deadline = .now.advanced(by: delay) } }
    func setActive(_ active: Bool) {
        state.withLock { $0.active = active; $0.deadline = .now.advanced(by: delay) }
    }
    func run<T: Sendable>(_ work: @Sendable () async throws -> T) async throws -> T {
        try await gate.enter()
        do {
            while true {
                try Task.checkCancellation()
                let snapshot = state.withLock { ($0.active, $0.deadline) }
                let remaining = ContinuousClock.now.duration(to: snapshot.1)
                if snapshot.0 && remaining <= .zero { break }
                try await Task.sleep(for: snapshot.0 ? min(remaining, .milliseconds(100)) : .milliseconds(100))
            }
            let result = try await work()
            state.withLock { $0.deadline = max($0.deadline, .now.advanced(by: spacing)) }
            await gate.leave()
            return result
        } catch {
            await gate.leave()
            throw error
        }
    }
}
