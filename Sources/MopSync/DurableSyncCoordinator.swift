import Foundation

public enum SyncWakeReason: Sendable {
    case startup, storeChanged, foreground, unlocked, networkRestored, ownerReleased, dependenciesChanged, retry
}

public enum SyncOperationOutcome: Sendable {
    case completed
    /// The engine owns transport retries; retain this undelivered operation.
    case transportOwned
    case waiting(Set<SyncDependency>)
    case authorization
    case retry(SyncFailure, retryAfter: TimeInterval? = nil)
    case attention(SyncFailure)
}

public struct SyncClock: Sendable {
    public var now: @Sendable () -> Date
    public var sleep: @Sendable (Date) async throws -> Void
    public var jitter: @Sendable () -> Double
    public init(now: @escaping @Sendable () -> Date = { Date() },
                sleep: @escaping @Sendable (Date) async throws -> Void = { date in
                    try await Task.sleep(for: .seconds(max(0, date.timeIntervalSinceNow)))
                }, jitter: @escaping @Sendable () -> Double = { Double.random(in: -1...1) }) {
        self.now = now; self.sleep = sleep; self.jitter = jitter
    }
}

/// Runs application-owned durable work, not CKSyncEngine's transport retries.
/// The handler must hold the publication lease and account authorization for any
/// effect. Retrying an interrupted handler must be safe using the operation ID.
public actor DurableSyncCoordinator {
    public typealias Handler = @Sendable (SyncOperation) async -> SyncOperationOutcome
    private let repository: EncryptedItemRepository
    private let account: String
    private let database: String
    private let kinds: Set<SyncOperation.Kind>
    private let coalescesPublicationRegistration: Bool
    private let allowsConcurrentReconciliation: Bool
    private var reconciliationTask: Task<Void, Never>?
    private var reconciliationID: UUID?
    private let clock: SyncClock
    private let handler: Handler
    private let dependencyAvailable: @Sendable (SyncDependency) async throws -> Bool
    private var observer: Task<Void, Never>?
    private var timer: Task<Void, Never>?
    private var timerID = UUID()
    private var generation = 0
    private var running = false
    private var retired = false
    private var draining = false
    private var idleWaiters: [CheckedContinuation<Void, Never>] = []
    private var wakes: [SyncWakeReason] = []
    public private(set) var storageFailure = false

    public init(repository: EncryptedItemRepository, account: String, database: String = "private",
                kinds: Set<SyncOperation.Kind>, clock: SyncClock = SyncClock(),
                allowsConcurrentReconciliation: Bool = false, coalescesPublicationRegistration: Bool = false,
                dependencyAvailable: @escaping @Sendable (SyncDependency) async throws -> Bool,
                handler: @escaping Handler) {
        self.repository = repository; self.account = account; self.database = database
        self.coalescesPublicationRegistration = coalescesPublicationRegistration
        self.allowsConcurrentReconciliation = allowsConcurrentReconciliation
        self.kinds = kinds; self.clock = clock; self.handler = handler; self.dependencyAvailable = dependencyAvailable
    }

    public func start() async {
        guard !running, !retired else { return }
        running = true; generation += 1
        let token = generation
        let changes = await repository.changes()
        guard running, generation == token else { return }
        observer = Task { [weak self] in
            for await _ in changes {
                guard !Task.isCancelled else { return }
                await self?.wake(reason: .storeChanged)
            }
        }
        try? await repository.coalesceReconciliationRequests(account: account, database: database)
        await wake(reason: .startup)
    }

    public func stop() {
        running = false; retired = true; generation += 1; wakes = []
        reconciliationTask?.cancel(); reconciliationTask = nil; reconciliationID = nil
        finishIdleWaiters()
        observer?.cancel(); observer = nil; timer?.cancel(); timer = nil; timerID = UUID()
    }

    public func waitUntilIdle() async {
        if draining || reconciliationTask != nil { await withCheckedContinuation { idleWaiters.append($0) } }
    }

    public func wake(reason: SyncWakeReason) async {
        guard running else { return }
        // Coalesce identical hints while a network handler is awaiting a result.
        if !wakes.contains(where: { $0 == reason }) { wakes.append(reason) }
        guard !draining else { return }
        draining = true
        defer {
            draining = false
            finishIdleWaiters()
        }
        while running, !wakes.isEmpty {
            let reasons = wakes; wakes = []
            let token = generation
            do {
                let resetRetry = reasons.contains { [.foreground, .networkRestored, .ownerReleased].contains($0) }
                let authorization = reasons.contains { [.unlocked, .startup].contains($0) }
                let operations = try await repository.activeOperations(account: account, database: database)
                    .sorted { priority($0) < priority($1) }
                var publicationRegistration: SyncOperationOutcome?
                for operation in operations where kinds.contains(operation.kind) {
                    guard running, generation == token, !Task.isCancelled else { return }
                    if allowsConcurrentReconciliation, operation.kind == .reconcile, reconciliationTask != nil { continue }
                    let publication = [.publishItem, .grant, .publishCoordination, .removeCoordination].contains(operation.kind)
                    let resetOperationRetry = resetRetry || (reasons.contains(.unlocked)
                        && (operation.failure == .authorization || operation.failure == .dependency))
                    switch operation.state {
                    case .completed, .needsAttention: continue
                    case .waitingForAuthorization: if !authorization { continue }
                    case .retryScheduled:
                        if let earliest = operation.retryNotBefore, earliest > clock.now() { continue }
                        let dependencyArrived = operation.failure == .dependency && reasons.contains(.dependenciesChanged)
                        if !resetOperationRetry, !dependencyArrived, let date = operation.nextAttempt, date > clock.now() { continue }
                    case .waitingForDependency:
                        var ready = true
                        for dependency in operation.dependencies {
                            if try await !dependencyAvailable(dependency) { ready = false; break }
                        }
                        if !ready { continue }
                    case .ready: break
                    }
                    guard running, generation == token, !Task.isCancelled else { return }
                    if allowsConcurrentReconciliation, operation.kind == .reconcile {
                        // One network wait may run alongside local inbox/authority
                        // work. Durable intent remains pending until it returns.
                        reconciliationID = operation.id
                        reconciliationTask = Task { [weak self, handler] in
                            let outcome = await handler(operation)
                            await self?.finishReconciliation(outcome, operation: operation, resetRetry: resetOperationRetry, token: token)
                        }
                        continue
                    }
                    // Registration covers all eligible publications. Coalesce
                    // the handler call, not the durable outcome: skipping later
                    // operations strands their old failure/deadline and spins
                    // the timer on an already-expired application retry.
                    let outcome: SyncOperationOutcome
                    if coalescesPublicationRegistration, publication, let registered = publicationRegistration {
                        outcome = registered
                    } else {
                        outcome = await handler(operation)
                        if coalescesPublicationRegistration, publication { publicationRegistration = outcome }
                    }
                    guard running, generation == token, !Task.isCancelled else { return }
                    do { try await commit(outcome, operation: operation, resetRetry: resetOperationRetry) }
                    catch SyncJournalError.staleOperation { /* another authorized worker advanced it */ }
                }
                storageFailure = false
                try await scheduleNext(token: token)
            } catch {
                guard running, generation == token else { return }
                storageFailure = true
                // Storage failures cannot record their own retry; retain all work
                // and use one bounded wake rather than spinning on store events.
                wakes = []
                schedule(clock.now().addingTimeInterval(5), token: token)
            }
        }
    }

    public func health() async -> AsyncStream<SyncHealthSnapshot> {
        let changes = await repository.changes()
        let repository = repository, account = account, database = database
        return AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
            let task = Task {
                for await _ in changes {
                    guard !Task.isCancelled else { break }
                    do { continuation.yield(try await repository.syncHealth(account: account, database: database)) }
                    catch { continuation.yield(SyncHealthSnapshot(pendingCount: 0, oldestPendingAt: nil,
                        lastDeliveryAt: nil, blockedReasons: [.storagePressure])) }
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    private func priority(_ operation: SyncOperation) -> Int {
        switch operation.kind {
        case .applyIncoming, .fetchMembership: 0
        case .enrollment, .membership, .provision, .resolveConflict, .deletion, .recovery: 1
        case .reconcile, .recoverTransport: 2
        default: 3
        }
    }

    private func finishIdleWaiters() {
        guard !draining, reconciliationTask == nil else { return }
        let waiters = idleWaiters; idleWaiters = []
        waiters.forEach { $0.resume() }
    }

    private func finishReconciliation(_ outcome: SyncOperationOutcome, operation: SyncOperation, resetRetry: Bool, token: Int) async {
        guard running, generation == token, reconciliationID == operation.id else { return }
        do { try await commit(outcome, operation: operation, resetRetry: resetRetry) }
        catch SyncJournalError.staleOperation { }
        catch {
            reconciliationTask = nil; reconciliationID = nil
            storageFailure = true; schedule(clock.now().addingTimeInterval(5), token: token)
            finishIdleWaiters(); return
        }
        guard running, generation == token else { return }
        reconciliationTask = nil; reconciliationID = nil
        await wake(reason: .storeChanged)
        finishIdleWaiters()
    }

    private func commit(_ outcome: SyncOperationOutcome, operation: SyncOperation, resetRetry: Bool) async throws {
        let now = clock.now()
        switch outcome {
        case .transportOwned:
            // A successful lease handoff must retire application backoff. Leaving
            // an expired retry deadline here repeatedly fires the account timer.
            if operation.state == .retryScheduled || operation.state == .waitingForAuthorization {
                _ = try await repository.transition(operation, to: .ready, dependencies: operation.dependencies, retryAttempts: resetRetry ? 0 : operation.retryAttempts, now: now)
            }
            return
        case .completed: _ = try await repository.transition(operation, to: .completed, attempted: true, now: now)
        case .waiting(let dependencies):
            _ = try await repository.transition(operation, to: .waitingForDependency, dependencies: dependencies,
                failure: .dependency, attempted: true, now: now)
        case .authorization:
            _ = try await repository.transition(operation, to: .waitingForAuthorization, failure: .authorization, attempted: true, now: now)
        case .attention(let failure):
            _ = try await repository.transition(operation, to: .needsAttention, failure: failure, attempted: true, now: now)
        case .retry(let failure, let after):
            let attempt = resetRetry ? 1 : min(operation.retryAttempts ?? operation.attempts, Int.max - 1) + 1
            let delay = SyncRetryPolicy.delay(attempt: attempt, jitter: clock.jitter(), retryAfter: after)
            let earliest = after.flatMap { $0.isFinite ? now.addingTimeInterval(max(0, $0)) : nil }
            _ = try await repository.transition(operation, to: .retryScheduled, failure: failure,
                nextAttempt: now.addingTimeInterval(delay), retryNotBefore: earliest, retryAttempts: attempt, attempted: true, now: now)
        }
    }
    private func scheduleNext(token: Int) async throws {
        let operations = try await repository.activeOperations(account: account, database: database)
        guard running, generation == token else { return }
        timer?.cancel(); timer = nil; timerID = UUID()
        if let next = operations.filter({ kinds.contains($0.kind)
            && !(allowsConcurrentReconciliation && $0.kind == .reconcile && reconciliationTask != nil)
            && $0.state == .retryScheduled }).compactMap({ operation -> Date? in
                guard let next = operation.nextAttempt else { return operation.retryNotBefore }
                return max(next, operation.retryNotBefore ?? next)
            }).min() {
            schedule(next, token: token)
        }
    }
    private func schedule(_ date: Date, token: Int) {
        timer?.cancel()
        let id = UUID(); timerID = id
        let clock = clock
        timer = Task { [weak self] in
            do { try await clock.sleep(date); try Task.checkCancellation() }
            catch { return }
            await self?.timerFired(id, token: token)
        }
    }
    private func timerFired(_ id: UUID, token: Int) async {
        guard running, generation == token, timerID == id else { return }
        timer = nil
        await wake(reason: .retry)
    }
    deinit { observer?.cancel(); timer?.cancel(); reconciliationTask?.cancel() }
}
