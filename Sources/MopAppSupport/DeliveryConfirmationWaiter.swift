import Foundation

/// Races local receipt observation against a caller deadline. Network work is
/// canceled on completion but is not awaited: an uncooperative native callback
/// cannot extend the CLI's confirmation timeout. Durable outbox work remains.
public enum DeliveryConfirmationWaiter {
    public static func wait(timeout: Duration,
                            request: @escaping @Sendable () async throws -> Void,
                            observe: @escaping @Sendable () async throws -> Bool) async throws -> Bool {
        try Task.checkCancellation()
        guard timeout > .zero else { return false }
        let completion = DeliveryCompletion()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                completion.install(continuation)
                completion.track(Task {
                    do { try await Task.sleep(for: timeout); completion.finish(.success(false)) }
                    catch { /* cancellation means another outcome already won */ }
                })
                completion.track(Task {
                    do { try Task.checkCancellation(); completion.finish(.success(try await observe())) }
                    catch { completion.finish(.failure(error)) }
                })
                completion.track(Task {
                    // Another lease owner may deliver even when this request fails.
                    // Only durable receipts or the deadline determine the result.
                    do { try Task.checkCancellation(); try await request() } catch {}
                })
            }
        } onCancel: { completion.finish(.failure(CancellationError())) }
    }
}

private final class DeliveryCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Bool, Error>?
    private var outcome: Result<Bool, Error>?
    private var tasks: [Task<Void, Never>] = []
    func install(_ continuation: CheckedContinuation<Bool, Error>) {
        lock.lock()
        if let outcome { lock.unlock(); continuation.resume(with: outcome) }
        else { self.continuation = continuation; lock.unlock() }
    }
    func track(_ task: Task<Void, Never>) {
        lock.lock()
        if outcome != nil { lock.unlock(); task.cancel() }
        else { tasks.append(task); lock.unlock() }
    }
    func finish(_ outcome: Result<Bool, Error>) {
        lock.lock()
        guard self.outcome == nil else { lock.unlock(); return }
        self.outcome = outcome
        let continuation = self.continuation; self.continuation = nil
        let tasks = self.tasks; self.tasks = []
        lock.unlock()
        tasks.forEach { $0.cancel() }
        continuation?.resume(with: outcome)
    }
}
