import Foundation
import Testing
import Synchronization
@testable import MopSync

@Suite struct SyncJournalTests: Sendable {
    @Test(arguments: [false, true], [895, 1_000])
    func rotationBatchesBoundWorkAndYieldToEnrollment(retry: Bool, itemCount: Int) async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let now = Date()
        let held = try await repository.enqueue(SyncOperation(account: "a", kind: .rotateContent))
        let throttled = try await repository.transition(held, to: .retryScheduled, failure: .transport,
            nextAttempt: now.addingTimeInterval(600), retryNotBefore: now.addingTimeInterval(600))
        for _ in 0..<itemCount { _ = try await repository.enqueue(SyncOperation(account: "a", kind: .rotateContent)) }
        let batches = Mutex<[Int]>([]), calls = Mutex<[UUID]>([])
        let enrollment = SyncOperation(account: "a", kind: .enrollment)
        let enrollmentAt = Mutex<Int?>(nil)
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a",
            kinds: [.rotateContent, .enrollment],
            clock: SyncClock(now: { now }, sleep: { _ in try await Task.sleep(for: .seconds(60)) }, jitter: { 0 }),
            dependencyAvailable: { _ in true }, rotationBatchHandler: { operations in
                let first = batches.withLock { $0.append(operations.count); return $0.count == 1 }
                calls.withLock { $0.append(contentsOf: operations.map(\.id)) }
                if first { _ = try? await repository.enqueue(enrollment) }
                return operations.map { _ in retry ? .retry(.transport, retryAfter: 600) : .completed }
            }, handler: { operation in
                #expect(operation.kind == .enrollment)
                enrollmentAt.withLock { $0 = calls.withLock { $0.count } }
                return .completed
            })
        await coordinator.start(); await coordinator.waitUntilIdle()
        await coordinator.wake(reason: .foreground); await coordinator.waitUntilIdle()
        await coordinator.stop()
        #expect(batches.withLock { $0.allSatisfy { $0 <= 16 } })
        #expect(batches.withLock { $0.count } == (itemCount + 15) / 16)
        #expect(enrollmentAt.withLock { $0 } == 16)
        #expect(calls.withLock { $0.count } == itemCount)
        #expect(calls.withLock { Set($0).count } == itemCount)
        #expect(!calls.withLock { $0.contains(held.id) })
        let operations = try await repository.operations(account: "a", database: "private")
        #expect(operations.first { $0.id == held.id }?.retryNotBefore == throttled.retryNotBefore)
        #expect(operations.filter { $0.id != held.id && $0.kind == .rotateContent }
            .allSatisfy { $0.state == (retry ? .retryScheduled : .completed) })
    }

    @Test func retryingGrantBacklogCannotStarveInbox() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let now = Date()
        for _ in 0..<830 { _ = try await repository.enqueue(SyncOperation(account: "a", kind: .enrollment)) }
        for _ in 0..<40 { _ = try await repository.enqueue(SyncOperation(account: "a", kind: .applyIncoming)) }
        let order = Mutex<[SyncOperation.Kind]>([])
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a",
            kinds: [.enrollment, .applyIncoming],
            clock: SyncClock(now: { now }, sleep: { _ in try await Task.sleep(for: .seconds(60)) }, jitter: { 0 }),
            dependencyAvailable: { _ in true }, handler: { operation in
                order.withLock { $0.append(operation.kind) }
                return operation.kind == .enrollment ? .retry(.dependency) : .completed
            })
        await coordinator.start(); await coordinator.waitUntilIdle(); await coordinator.stop()
        let calls = order.withLock { $0 }
        #expect(calls.firstIndex(of: .applyIncoming) == 16)
        #expect(calls.filter { $0 == .applyIncoming }.count == 40)
        #expect(calls.filter { $0 == .enrollment }.count == 830)
        var consecutiveRequests = 0, applied = 0
        for kind in calls {
            if kind == .applyIncoming { consecutiveRequests = 0; applied += 1 }
            else if applied < 40 { consecutiveRequests += 1; #expect(consecutiveRequests <= 16) }
        }
    }

    @Test func grantRequestDiagnosticsDistinguishAuthorityFailures() {
        let requested = UUID(), other = UUID()
        #expect(ContentGrantRequestBlockReason.assess(policyMatches: false, recipientIncluded: true, currentGeneration: requested, requestedGeneration: requested) == .policyMismatch)
        #expect(ContentGrantRequestBlockReason.assess(policyMatches: true, recipientIncluded: false, currentGeneration: requested, requestedGeneration: requested) == .recipientExcluded)
        #expect(ContentGrantRequestBlockReason.assess(policyMatches: true, recipientIncluded: true, currentGeneration: nil, requestedGeneration: requested) == .missingKeyState)
        #expect(ContentGrantRequestBlockReason.assess(policyMatches: true, recipientIncluded: true, currentGeneration: other, requestedGeneration: requested) == .generationMismatch)
        #expect(ContentGrantRequestBlockReason.assess(policyMatches: true, recipientIncluded: true, currentGeneration: requested, requestedGeneration: requested) == nil)
    }

    @Test func recoveryAndEnrollmentPrecedePersistedInboxBacklog() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite"))
        for _ in 0..<64 { _ = try await repository.enqueue(SyncOperation(account: "a", kind: .applyIncoming)) }
        for kind: SyncOperation.Kind in [.recoverTransport, .reconcile, .enrollment] {
            _ = try await repository.enqueue(SyncOperation(account: "a", kind: kind))
        }
        let order = Mutex<[SyncOperation.Kind]>([])
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a",
            kinds: [.applyIncoming, .recoverTransport, .reconcile, .enrollment], dependencyAvailable: { _ in true },
            handler: { operation in order.withLock { $0.append(operation.kind) }; return .completed })
        await coordinator.start(); await coordinator.waitUntilIdle(); await coordinator.stop()
        #expect(Array(order.withLock { $0 }.prefix(3)) == [.recoverTransport, .reconcile, .enrollment])
        #expect(order.withLock { $0.count } == 67)
    }

    #if DEBUG
    @Test func debugEnrollmentResetClearsOnlyPreviewStoreAndRequiresPermit() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = SyncStoreLayout.contentPreviewURL(in: root)
        let preview = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        let legacy = try EncryptedItemRepository(storeURL: root.appendingPathComponent("legacy.sqlite"))
        let work = SyncOperation(account: "a", kind: .enrollment, payload: Data([1]))
        _ = try await preview.enqueue(work)
        _ = try await legacy.enqueue(work)
        struct Denied: RepositoryWritePermit {
            func withWritePermission<T>(_ body: () throws -> T) throws -> T { throw ItemRepositoryError.invalidScope }
        }
        await #expect(throws: ItemRepositoryError.invalidScope) { try await preview.debugClearEnrollmentStore(authorization: Denied()) }
        #expect(try await preview.operations(account: "a", database: "private") == [work])
        await #expect(throws: ItemRepositoryError.invalidScope) { try await legacy.debugClearEnrollmentStore(authorization: JournalWritePermit()) }
        try await preview.saveEngineState(Data([9]), account: "a", database: "private")
        _ = try await preview.stageIncoming(incoming("reset-inbox"))
        try await preview.debugClearEnrollmentStore(authorization: JournalWritePermit())
        #expect(try await preview.operations(account: "a", database: "private").isEmpty)
        let reopened = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        #expect(try await reopened.operations(account: "a", database: "private").isEmpty)
        #expect(try await reopened.engineState(account: "a", database: "private") == nil)
        #expect(try await reopened.incomingRecords(account: "a", database: "private").isEmpty)
        #expect(try await legacy.operations(account: "a", database: "private") == [work])
    }
    #endif

    private func journalStore() throws -> (URL, EncryptedItemRepository) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-journal-" + UUID().uuidString)
        return (root, try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite")))
    }
    private func incoming(_ id: String, account: String = "a", bytes: Int = 10) -> IncomingRecord {
        IncomingRecord(id: id, account: account, database: "private", zoneName: "zone", zoneOwner: "owner",
            recordName: id, recordType: "item", bytes: Data(repeating: 1, count: bytes), systemFields: Data())
    }

    @Test func journalPersistsExactPublicationAndRejectsStaleCompletion() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let work = SyncOperation(account: "a", kind: .enrollment, payload: Data([1, 2, 3]))
        #expect(try await repository.enqueue(work) == work)
        let waiting = try await repository.transition(work, to: .retryScheduled, failure: .transport,
            nextAttempt: Date(timeIntervalSince1970: 100), attempted: true)
        let reopened = try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite"))
        #expect(try await reopened.operations(account: "a", database: "private") == [waiting])
        #expect(try await reopened.enqueue(work) == waiting)
        await #expect(throws: SyncJournalError.staleOperation) { try await repository.transition(work, to: .completed) }
        let collision = SyncOperation(id: work.id, account: "a", kind: .enrollment, payload: Data([4]))
        await #expect(throws: SyncJournalError.identityCollision) { try await repository.enqueue(collision) }
        #expect(try await repository.operations(account: "other", database: "private").isEmpty)
    }

    @Test func incomingBudgetNeverEvictsUnappliedRecordsAndAllowsSingleLargeRecord() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let first = incoming("first", bytes: 101)
        _ = try await repository.stageIncoming(first, budget: 100)
        _ = try await repository.stageIncoming(first, budget: 100)
        await #expect(throws: SyncJournalError.inboxFull) { try await repository.stageIncoming(incoming("second"), budget: 100) }
        #expect(try await repository.incomingRecords(account: "a", database: "private") == [first])
        #expect(try await repository.syncHealth(account: "a", database: "private").pendingCount == 1)
        _ = try await repository.stageIncoming(incoming("other", account: "b"), budget: 100)
        let reopened = try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite"))
        #expect(try await reopened.incomingRecords(account: "a", database: "private") == [first])
        try await repository.completeIncoming(first)
        #expect(try await repository.incomingRecords(account: "a", database: "private").isEmpty)
        #expect(try await repository.operations(account: "a", database: "private").first?.state == .completed)
    }

    @Test func independentIncomingWritersCannotExceedAccountBudget() async throws {
        let (root, first) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let second = try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite"))
        async let one: IncomingRecord? = try? first.stageIncoming(incoming("one", bytes: 60), budget: 100)
        async let two: IncomingRecord? = try? second.stageIncoming(incoming("two", bytes: 60), budget: 100)
        let results = await [one, two]
        #expect(results.compactMap { $0 }.count == 1)
        #expect(try await first.incomingRecords(account: "a", database: "private").count == 1)
    }

    @Test func localSaveAndDeliveryUpdateJournalAtomically() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let version = EncryptedItemVersion(scope: ItemScope(account: "a", vaultID: UUID(), itemID: UUID()),
            baseVersionID: nil, ciphertext: Data([1]))
        let mutation = try await repository.commitLocalMutation(version)
        #expect(try await repository.operations(account: "a", database: "private").filter { $0.kind == .publishItem }.map(\.id) == [mutation.id])
        #expect(try await repository.syncHealth(account: "a", database: "private").pendingCount == 2)
        try await repository.acknowledge(mutationID: mutation.id, account: "a", serverSystemFields: Data([2]))
        let health = try await repository.syncHealth(account: "a", database: "private")
        #expect(health.pendingCount == 1) // the account reconciliation wake remains
        #expect(health.lastDeliveryAt != nil)
    }

    @Test func retryPolicyIsBoundedAndHonorsServerThrottle() {
        #expect(SyncRetryPolicy.delay(attempt: 1, jitter: 0) == 2)
        #expect(SyncRetryPolicy.delay(attempt: 2, jitter: 0) == 4)
        #expect(SyncRetryPolicy.delay(attempt: 100, jitter: 1) == 360)
        #expect(SyncRetryPolicy.delay(attempt: 1, jitter: -1) == 1.6)
        #expect(SyncRetryPolicy.delay(attempt: 1, jitter: 0, retryAfter: 900) == 900)
    }

    @Test func quarantineDeduplicatesAndEvictsPayloadWithoutLosingDiagnostics() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        for _ in 0..<2 {
            try await repository.quarantine(Data(repeating: 1, count: 60), account: "a", database: "private",
                zone: "zone", owner: "owner", record: "one", now: Date(timeIntervalSince1970: 1), budget: 100)
        }
        try await repository.quarantine(Data(repeating: 2, count: 60), account: "a", database: "private",
            zone: "zone", owner: "owner", record: "two", now: Date(timeIntervalSince1970: 2), budget: 100)
        let summary = try await repository.quarantineSummary(account: "a")
        #expect(summary.records == 2)
        #expect(summary.retainedBytes == 60)
        #expect(try await repository.quarantineSummary(account: "b").records == 0)
    }

    private actor JournalBarrier {
        private var entered = false
        private var entry: CheckedContinuation<Void, Never>?
        private var resumes: [UUID: CheckedContinuation<Void, Never>] = [:]
        func wait() async {
            let id = UUID()
            entered = true; entry?.resume(); entry = nil
            await withTaskCancellationHandler {
                await withCheckedContinuation { continuation in
                    if Task.isCancelled { continuation.resume() }
                    else { resumes[id] = continuation }
                }
            } onCancel: { Task { await self.cancel(id) } }
        }
        private func cancel(_ id: UUID) { resumes.removeValue(forKey: id)?.resume() }
        func waitForEntry() async { if !entered { await withCheckedContinuation { entry = $0 } } }
        func release() { let all = resumes; resumes = [:]; all.values.forEach { $0.resume() } }
    }

    @Test func stoppedCoordinatorCannotCommitLateHandlerResult() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let work = try await repository.enqueue(SyncOperation(account: "a", kind: .enrollment))
        let barrier = JournalBarrier()
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.enrollment],
            dependencyAvailable: { _ in false }, handler: { _ in await barrier.wait(); return .completed })
        let startup = Task { await coordinator.start() }
        await barrier.waitForEntry()
        await coordinator.stop()
        await barrier.release()
        await startup.value
        await coordinator.waitUntilIdle()
        #expect(try await repository.operations(account: "a", database: "private") == [work])
    }

    @Test func throttleDeadlineCannotScheduleAnExpiredBusyLoop() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let now = Date(timeIntervalSince1970: 100), deadline = Date(timeIntervalSince1970: 1000)
        let operation = try await repository.enqueue(SyncOperation(account: "a", kind: .enrollment))
        _ = try await repository.transition(operation, to: .retryScheduled, failure: .transport,
            nextAttempt: now.addingTimeInterval(-10), retryNotBefore: deadline)
        let timer = JournalBarrier(), scheduled = Mutex<Date?>(nil), calls = Mutex(0)
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.enrollment],
            clock: SyncClock(now: { now }, sleep: { date in
                scheduled.withLock { $0 = date }; await timer.wait()
            }, jitter: { 0 }), dependencyAvailable: { _ in false }, handler: { _ in
                calls.withLock { $0 += 1 }; return .completed
            })
        await coordinator.start()
        await timer.waitForEntry()
        #expect(scheduled.withLock { $0 } == deadline)
        #expect(calls.withLock { $0 } == 0)
        await coordinator.stop()
        await timer.release()
    }

    @Test(arguments: [false, true])
    func timedDependencyWaitResumesOnEvidenceOrDeadline(evidenceArrives: Bool) async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let now = Mutex(Date(timeIntervalSince1970: 100)), available = Mutex(false)
        let deadline = Date(timeIntervalSince1970: 220)
        let dependency = SyncDependency(.grant, identifier: "verified-grant")
        let work = try await repository.enqueue(SyncOperation(account: "a", kind: .prepareGrant))
        let calls = Mutex(0), timer = JournalBarrier(), scheduled = Mutex<Date?>(nil)
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.prepareGrant],
            clock: SyncClock(now: { now.withLock { $0 } }, sleep: { date in
                scheduled.withLock { $0 = date }
                if date > now.withLock({ $0 }) { await timer.wait() }
            }), dependencyAvailable: { _ in available.withLock { $0 } }, handler: { _ in
                calls.withLock { $0 += 1; return $0 } == 1 ? .waitingUntil([dependency], deadline) : .completed
            })
        let changes = await repository.changes()
        await coordinator.start(); await timer.waitForEntry()
        for reason: SyncWakeReason in [.foreground, .unlocked, .storeChanged] { await coordinator.wake(reason: reason) }
        #expect(calls.withLock { $0 } == 1)
        #expect(scheduled.withLock { $0 } == deadline)
        let waiting = try #require(await repository.operations(account: "a", database: "private").first { $0.id == work.id })
        #expect(waiting.state == .waitingForDependency && waiting.nextAttempt == deadline)
        let reopened = try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite"))
        #expect(try await reopened.operations(account: "a", database: "private").first { $0.id == work.id } == waiting)
        if evidenceArrives {
            available.withLock { $0 = true }
            await coordinator.wake(reason: .storeChanged)
        } else {
            now.withLock { $0 = deadline }
            await timer.release()
        }
        for await _ in changes {
            if try await repository.operations(account: "a", database: "private").first { $0.id == work.id }?.state == .completed { break }
        }
        await coordinator.stop(); await timer.release()
        #expect(calls.withLock { $0 } == 2)
    }

    @Test func coordinatorRetriesAutomaticallyAtPersistedDeadline() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let now = Mutex(Date(timeIntervalSince1970: 100))
        let timer = JournalBarrier()
        let calls = Mutex(0)
        let work = try await repository.enqueue(SyncOperation(account: "a", kind: .enrollment))
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.enrollment],
            clock: SyncClock(now: { now.withLock { $0 } }, sleep: { deadline in
                if deadline > now.withLock({ $0 }) { await timer.wait() }
            }, jitter: { 0 }),
            dependencyAvailable: { _ in false }, handler: { _ in
                let count = calls.withLock { $0 += 1; return $0 }
                return count == 1 ? .retry(.transport) : .completed
            })
        let changes = await repository.changes()
        await coordinator.start()
        await timer.waitForEntry()
        let retry = try #require(try await repository.operations(account: "a", database: "private").first)
        #expect(retry.state == .retryScheduled)
        #expect(retry.nextAttempt == Date(timeIntervalSince1970: 102))
        now.withLock { $0 = Date(timeIntervalSince1970: 102) }
        await timer.release()
        for await _ in changes {
            if try await repository.operations(account: "a", database: "private").first?.state == .completed { break }
        }
        await coordinator.stop(); await coordinator.waitUntilIdle()
        #expect(calls.withLock { $0 } == 2)
        #expect(try await repository.operations(account: "a", database: "private").first?.id == work.id)
    }

    @Test func replayAfterCompletedIncomingRearmsDurableApplication() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let record = incoming("replayed")
        _ = try await repository.stageIncoming(record)
        try await repository.completeIncoming(record)
        _ = try await repository.stageIncoming(record)
        #expect(try await repository.operations(account: "a", database: "private").first?.state == .ready)
        #expect(try await repository.incomingRecords(account: "a", database: "private") == [record])
    }

    @Test func quarantinedIncomingRemainsVisibleAsAnActionableHealthFailure() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let record = incoming("untrusted")
        _ = try await repository.stageIncoming(record)
        try await repository.completeIncoming(record, failure: .invalidAuthority)
        let health = try await repository.syncHealth(account: "a", database: "private")
        #expect(health.pendingCount == 1)
        #expect(health.blockedReasons == [.invalidAuthority])
        #expect(try await repository.incomingRecords(account: "a", database: "private").isEmpty)
    }

    @Test func foregroundWakeCannotBypassServerRetryAfter() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        _ = try await repository.enqueue(SyncOperation(account: "a", kind: .enrollment))
        let calls = Mutex(0), now = Date(timeIntervalSince1970: 100)
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.enrollment],
            clock: SyncClock(now: { now }, sleep: { _ in try await Task.sleep(for: .seconds(60)) }, jitter: { 0 }),
            dependencyAvailable: { _ in false }, handler: { _ in
                calls.withLock { $0 += 1 }
                return .retry(.transport, retryAfter: 30)
            })
        await coordinator.start(); await coordinator.waitUntilIdle()
        await coordinator.wake(reason: .foreground); await coordinator.waitUntilIdle()
        #expect(calls.withLock { $0 } == 1)
        #expect(try await repository.operations(account: "a", database: "private").first?.retryNotBefore == now.addingTimeInterval(30))
        await coordinator.stop(); await coordinator.waitUntilIdle()
    }

    private struct JournalWritePermit: RepositoryWritePermit {
        func withWritePermission<T>(_ body: () throws -> T) throws -> T { try body() }
    }

    @Test func receiptExpiryPreservesSupersededVersionReplayProtection() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let scope = ItemScope(account: "a", vaultID: UUID(), itemID: UUID())
        let base = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1]))
        try await repository.applyRemote(base, serverSystemFields: Data([1]))
        let second = EncryptedItemVersion(scope: scope, baseVersionID: base.versionID, ciphertext: Data([2]), generation: 2)
        _ = try await repository.commitLocalMutation(second)
        let third = EncryptedItemVersion(scope: scope, baseVersionID: second.versionID, ciphertext: Data([3]), generation: 3)
        let pending = try await repository.commitLocalMutation(third)
        let remote = EncryptedItemVersion(scope: scope, baseVersionID: base.versionID, ciphertext: Data([4]), generation: 2)
        let conflict = try await repository.recordConflict(remote: remote, serverSystemFields: Data([2]))
        _ = try await repository.resolveConflictUsingRemote(conflict, authorization: JournalWritePermit())
        try await repository.pruneCompletedOperations(account: "a", database: "private", now: Date().addingTimeInterval(31 * 86400))
        #expect(try await repository.mutationReceipt(id: pending.id, account: "a") == nil)
        await #expect(throws: ItemRepositoryError.remoteVersionConflict) {
            try await repository.applyRemote(third, serverSystemFields: Data([3]))
        }
        #expect(try await repository.item(scope) == remote)
    }
}

extension SyncJournalTests {
    @Test func grantRequestWaitsForItsKeyStateAcrossUnrelatedProgressAndRestart() async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let scope = ItemScope(account: "a", vaultID: UUID(), itemID: UUID()), policy = policy()
        let key = UUID(), recipient = try #require(policy.recipients.first)
        let permit = JournalWritePermit()
        try await repository.setContentRecipients(scope: vaultScope(scope), expected: nil, policy: policy, authorization: permit)
        let request = SyncOperation(account: "a", vaultID: scope.vaultID, kind: .enrollment)
        _ = try await repository.enqueue(request)
        let attempts = Mutex(0)
        let expected = SyncDependency(.contentKeyState, identifier: scope.vaultID.uuidString + ":" + scope.itemID.uuidString + ":" + key.uuidString)
        func coordinator(_ store: EncryptedItemRepository) -> DurableSyncCoordinator {
            DurableSyncCoordinator(repository: store, account: "a", kinds: [.enrollment], dependencyAvailable: { dependency in
                guard dependency == expected else { return false }
                return try await store.contentKeyStateAvailable(scope: scope, keyGeneration: key)
            }, handler: { _ in
                attempts.withLock { $0 += 1 }
                do {
                    if let missing = try await store.reconcileContentGrantRequest(scope: scope, keyGeneration: key,
                        recipient: recipient, policy: policy, permit: permit) { return .waiting([missing]) }
                    return .completed
                } catch { Issue.record("Unexpected request failure: \(error)"); return .attention(.invalidAuthority) }
            })
        }
        let first = coordinator(repository)
        await first.start(); await first.waitUntilIdle(); await first.stop()
        let waiting = try #require(await repository.operations(account: "a", database: "private").first { $0.id == request.id })
        #expect(waiting.state == .waitingForDependency && waiting.dependencies == [expected])
        #expect(waiting.nextAttempt == nil)
        let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root), layout: .contentPreview3)
        let resumed = coordinator(reopened)
        await resumed.start(); await resumed.waitUntilIdle()
        let other = ItemScope(account: "a", vaultID: scope.vaultID, itemID: UUID())
        _ = try await repository.commitContent(content(scope: other, policy: policy, key: key), grants: [], expectedPolicy: policy, authorization: permit)
        for _ in 0..<50 {
            await resumed.wake(reason: .dependenciesChanged)
            await resumed.wake(reason: .foreground)
        }
        #expect(attempts.withLock { $0 } == 1)
        #expect(try await !reopened.contentKeyStateAvailable(scope: scope, keyGeneration: key))
        _ = try await repository.commitContent(content(scope: scope, policy: policy, key: key), grants: [], expectedPolicy: policy, authorization: permit)
        #expect(try await !reopened.contentKeyStateAvailable(scope: scope, keyGeneration: UUID()))
        await resumed.wake(reason: .dependenciesChanged); await resumed.waitUntilIdle(); await resumed.stop()
        #expect(attempts.withLock { $0 } == 2)
        #expect(try await reopened.operations(account: "a", database: "private").first { $0.id == request.id }?.state == .completed)
        // Readiness is not authorization: a different policy or recipient still fails.
        await #expect(throws: ContentStoreError.staleAuthority) {
            try await reopened.reconcileContentGrantRequest(scope: scope, keyGeneration: key,
                recipient: "excluded", policy: policy, permit: permit)
        }
        await #expect(throws: ContentStoreError.staleAuthority) {
            try await reopened.reconcileContentGrantRequest(scope: scope, keyGeneration: UUID(),
                recipient: recipient, policy: policy, permit: permit)
        }
    }

    private func previewStore() throws -> (URL, EncryptedItemRepository) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-content-" + UUID().uuidString)
        return (root, try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root), layout: .contentPreview3))
    }
    private func policy(_ membership: Character = "a", recipients: Set<String>? = nil, authority: Character = "a") -> ContentRecipientPolicy {
        ContentRecipientPolicy(membership: String(repeating: membership, count: 64),
            recipients: recipients ?? [String(repeating: "b", count: 64)], keyAuthority: String(repeating: authority, count: 64))
    }
    private func content(scope: ItemScope, policy: ContentRecipientPolicy, base: PreparedContentVersion? = nil,
                         key: UUID? = nil) -> PreparedContentVersion {
        PreparedContentVersion(version: EncryptedItemVersion(scope: scope, baseVersionID: base?.version.versionID,
            ciphertext: Data(UUID().uuidString.utf8), generation: (base?.version.generation ?? 0) + 1),
            keyGeneration: key ?? base?.keyGeneration ?? UUID(), contentRevision: UUID(),
            membership: policy.membership, keyAuthority: policy.keyAuthority)
    }
    private func grant(_ content: PreparedContentVersion, recipient: String = String(repeating: "b", count: 64),
                       id: Character = "c", bytes: Data = Data([1, 2, 3])) -> PreparedContentGrant {
        PreparedContentGrant(scope: content.version.scope, keyGeneration: content.keyGeneration, recipient: recipient,
            identifier: String(repeating: id, count: 64), bytes: bytes)
    }
    private func vaultScope(_ item: ItemScope) -> VaultScope {
        VaultScope(account: item.account, vaultID: item.vaultID, database: item.database, zoneOwner: item.zoneOwner)
    }

    @Test func previewContentAndExactGrantsCommitAndReopenTogether() async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let scope = ItemScope(account: "a", vaultID: UUID(), itemID: UUID()), policy = policy()
        try await repository.setContentRecipients(scope: vaultScope(scope), expected: nil, policy: policy, authorization: JournalWritePermit())
        let content = content(scope: scope, policy: policy), grant = grant(content)
        let prerequisite = SyncOperation(account: scope.account, vaultID: scope.vaultID, kind: .membership, payload: Data([5, 6]))
        let mutation = try await repository.commitContent(content, grants: [grant], expectedPolicy: policy,
            prerequisites: [prerequisite], authorization: JournalWritePermit())
        let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root), layout: .contentPreview3)
        #expect(try await reopened.contentState(scope: scope)?.versionID == content.version.versionID)
        #expect(try await reopened.pendingMutations(account: "a") == [mutation])
        #expect(try await reopened.contentGrants(scope: scope, keyGeneration: content.keyGeneration) == [grant])
        #expect(try await reopened.missingContentGrants(scope: vaultScope(scope)).isEmpty)
        let operations = try await reopened.operations(account: "a", database: "private")
        #expect(try JSONDecoder().decode(PreparedContentGrant.self, from: #require(operations.first { $0.kind == .grant }).payload) == grant)
        #expect(operations.contains(prerequisite))
        let publication = try #require(operations.first { $0.kind == .publishItem })
        #expect(publication.state == .waitingForDependency)
        #expect(publication.dependencies == [SyncDependency(.operation, identifier: prerequisite.id.uuidString)])
        #expect(operations.first { $0.kind == .grant }?.dependencies == publication.dependencies)
        #expect(try await reopened.contentGrantDelivery(grant) == .queued)
        try await reopened.acknowledgeContentGrant(grant, serverSystemFields: Data([9]))
        #expect(try await repository.contentGrantDelivery(grant) == .cloudConfirmed)
        try await reopened.acknowledgeContentGrant(grant, serverSystemFields: Data([9]), now: Date().addingTimeInterval(29 * 86_400))
        #expect(try await repository.contentGrantDelivery(grant, now: Date().addingTimeInterval(31 * 86_400)) == .expiredOrUnknown)
        #expect(try await repository.pendingMutations(account: "a") == [mutation])
    }

    @Test func previewGrantFailureRollsBackContentOutboxAndReceipt() async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let scope = ItemScope(account: "a", vaultID: UUID(), itemID: UUID()), policy = policy()
        try await repository.setContentRecipients(scope: vaultScope(scope), expected: nil, policy: policy, authorization: JournalWritePermit())
        let content = content(scope: scope, policy: policy)
        await #expect(throws: ContentStoreError.invalidRecord) {
            try await repository.commitContent(content, grants: [grant(content, bytes: Data())], expectedPolicy: policy,
                prerequisites: [SyncOperation(account: scope.account, vaultID: scope.vaultID, kind: .provision, payload: Data([7]))],
                authorization: JournalWritePermit())
        }
        #expect(try await repository.contentState(scope: scope) == nil)
        #expect(try await repository.pendingMutations(account: "a").isEmpty)
        #expect(try await repository.operations(account: "a", database: "private").isEmpty)
        #expect(try await repository.contentGrants(scope: scope, keyGeneration: content.keyGeneration).isEmpty)
    }

    @Test func previewEnrollmentIndexesGrantsWithoutReplacingPendingEdits() async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let scope = ItemScope(account: "a", vaultID: UUID(), itemID: UUID()), original = policy()
        let joining = String(repeating: "d", count: 64)
        let admitted = policy("e", recipients: original.recipients.union([joining]))
        try await repository.setContentRecipients(scope: vaultScope(scope), expected: nil, policy: original, authorization: JournalWritePermit())
        let first = content(scope: scope, policy: original)
        _ = try await repository.commitContent(first, grants: [grant(first)], expectedPolicy: original, authorization: JournalWritePermit())
        try await repository.setContentRecipients(scope: vaultScope(scope), expected: original, policy: admitted, authorization: JournalWritePermit())
        let edit = content(scope: scope, policy: admitted, base: first)
        _ = try await repository.commitContent(edit, grants: [], expectedPolicy: admitted, authorization: JournalWritePermit())
        let before = try await repository.pendingMutations(account: "a")
        let missing = try await repository.missingContentGrants(scope: vaultScope(scope))
        #expect(missing.count == 1)
        #expect(missing.first?.recipient == joining)
        let newGrant = grant(edit, recipient: joining, id: "f")
        try await repository.commitContentGrant(newGrant, expectedPolicy: admitted, authorization: JournalWritePermit())
        try await repository.commitContentGrant(newGrant, expectedPolicy: admitted, authorization: JournalWritePermit())
        #expect(try await repository.pendingMutations(account: "a") == before)
        #expect(try await repository.contentState(scope: scope)?.versionID == edit.version.versionID)
        #expect(try await repository.missingContentGrants(scope: vaultScope(scope)).isEmpty)
        let work = try await repository.operations(account: "a", database: "private")
        let preparation = try #require(work.first { $0.id == missing.first?.operationID })
        #expect(preparation.state == .completed && preparation.deliveredAt == nil)
        let nextScope = ItemScope(account: "a", vaultID: scope.vaultID, itemID: UUID())
        let next = content(scope: nextScope, policy: admitted)
        _ = try await repository.commitContent(next, grants: [grant(next)], expectedPolicy: admitted, authorization: JournalWritePermit())
        #expect(try await repository.missingContentGrants(scope: vaultScope(scope)).map(\.scope) == [nextScope])
        await #expect(throws: ContentStoreError.identityCollision) {
            try await repository.commitContentGrant(grant(edit, recipient: joining, id: "f", bytes: Data([99])),
                expectedPolicy: admitted, authorization: JournalWritePermit())
        }
    }

    @Test(arguments: [true, false]) func lateContentRotationChecksCurrentAuthorization(authorized: Bool) async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let scope = ItemScope(account: "a", vaultID: UUID(), itemID: UUID())
        let currentPolicy = policy("d", authority: "d")
        try await repository.setContentRecipients(scope: vaultScope(scope), expected: nil, policy: currentPolicy, authorization: JournalWritePermit())
        let authorization = Mutex(authorized), calls = Mutex(0)
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.rotateContent],
            dependencyAvailable: { _ in false }, handler: { _ in
                calls.withLock { $0 += 1 }
                return authorization.withLock { $0 } ? .completed : .authorization
            })
        await coordinator.start()
        await coordinator.wake(reason: .unlocked)
        await coordinator.waitUntilIdle()

        // The membership/unlock wake has finished before historical content
        // arrives. Its key must still rotate under the current recipient policy.
        let historical = content(scope: scope, policy: policy())
        let incoming = IncomingRecord(id: UUID().uuidString, account: "a", database: "private",
            zoneName: SyncStoreLayout.contentZone(vault: scope.vaultID), zoneOwner: scope.zoneOwner,
            recordName: scope.itemID.uuidString, recordType: ContentRecordKind.head.rawValue,
            bytes: historical.version.ciphertext, systemFields: Data(), vaultID: scope.vaultID)
        try await repository.stageIncoming(incoming, permit: JournalWritePermit())
        try await repository.receiveContent(historical, from: incoming, action: .install,
            expectedHead: nil, expectedPolicy: currentPolicy, permit: JournalWritePermit())
        await coordinator.wake(reason: .storeChanged)
        await coordinator.wake(reason: .dependenciesChanged)
        await coordinator.waitUntilIdle()
        let rotation = try #require(await repository.operations(account: "a", database: "private").first { $0.kind == .rotateContent })
        #expect(calls.withLock { $0 } == 1)
        #expect(rotation.state == (authorized ? .completed : .waitingForAuthorization))

        if !authorized {
            // A real authorization failure stays deferred without repeatedly
            // calling the handler on unrelated store or foreground events.
            await coordinator.wake(reason: .storeChanged)
            await coordinator.wake(reason: .foreground)
            await coordinator.waitUntilIdle()
            #expect(calls.withLock { $0 } == 1)
            authorization.withLock { $0 = true }
            await coordinator.wake(reason: .unlocked)
            await coordinator.waitUntilIdle()
            #expect(calls.withLock { $0 } == 2)
            #expect(try await repository.operations(account: "a", database: "private").first { $0.id == rotation.id }?.state == .completed)
        }
        await coordinator.stop()
    }

    @Test func previewSecurityTransitionRequiresRotationInsteadOfObsoleteGrants() async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let scope = ItemScope(account: "a", vaultID: UUID(), itemID: UUID()), original = policy()
        let rotatedPolicy = policy("d", authority: "d")
        try await repository.setContentRecipients(scope: vaultScope(scope), expected: nil, policy: original, authorization: JournalWritePermit())
        let first = content(scope: scope, policy: original)
        _ = try await repository.commitContent(first, grants: [], expectedPolicy: original, authorization: JournalWritePermit())
        try await repository.setContentRecipients(scope: vaultScope(scope), expected: original, policy: rotatedPolicy, authorization: JournalWritePermit())
        #expect(try await repository.missingContentGrants(scope: vaultScope(scope)).isEmpty)
        let work = try await repository.operations(account: "a", database: "private")
        #expect(work.filter { $0.kind == .rotateContent && $0.state == .ready }.count == 1)
        await #expect(throws: ContentStoreError.staleAuthority) {
            try await repository.commitContentGrant(grant(first), expectedPolicy: rotatedPolicy, authorization: JournalWritePermit())
        }
        await #expect(throws: ContentStoreError.staleAuthority) {
            try await repository.commitContent(content(scope: scope, policy: rotatedPolicy, base: first), grants: [],
                expectedPolicy: rotatedPolicy, authorization: JournalWritePermit())
        }
        let rotated = content(scope: scope, policy: rotatedPolicy, base: first, key: UUID())
        _ = try await repository.commitContent(rotated, grants: [grant(rotated)], expectedPolicy: rotatedPolicy, authorization: JournalWritePermit())
        #expect(try await repository.operations(account: "a", database: "private").filter { $0.kind == .rotateContent }.allSatisfy { $0.state == .completed && $0.deliveredAt == nil })
    }

    @Test func previewStoreCannotOpenOrMigrateLegacyPaths() async throws {
        let (root, legacy) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let scope = ItemScope(account: "a", vaultID: UUID(), itemID: UUID())
        let version = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1]))
        let mutation = try await legacy.commitLocalMutation(version)
        #expect(throws: ContentStoreError.wrongLayout) {
            try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite"), layout: .contentPreview3)
        }
        let preview = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root), layout: .contentPreview3)
        #expect(throws: ContentStoreError.wrongLayout) {
            try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
        }
        #expect(throws: ContentStoreError.wrongLayout) {
            try EncryptedItemRepository(storeURL: root.appendingPathComponent("contentpreview3/content3.sqlite"))
        }
        let copied = root.appendingPathComponent("copied", isDirectory: true)
        try FileManager.default.copyItem(at: SyncStoreLayout.contentPreviewURL(in: root).deletingLastPathComponent(), to: copied)
        for suffix in ["", "-wal", "-shm"] {
            let source = copied.appendingPathComponent("Content3.sqlite" + suffix)
            if FileManager.default.fileExists(atPath: source.path) {
                try FileManager.default.moveItem(at: source, to: copied.appendingPathComponent("items.sqlite" + suffix))
            }
        }
        #expect(throws: ContentStoreError.wrongLayout) {
            try EncryptedItemRepository(storeURL: copied.appendingPathComponent("items.sqlite"))
        }
        await #expect(throws: ContentStoreError.wrongLayout) { try await preview.commitLocalMutation(version) }
        #expect(try await legacy.pendingMutations(account: "a") == [mutation])
        #expect(try await preview.pendingMutations(account: "a").isEmpty)
    }
}

extension SyncJournalTests {
    @Test func previewConcurrentWritersPreserveOneHeadAndRejectStaleAuthority() async throws {
        let (root, first) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let second = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root), layout: .contentPreview3)
        let scope = ItemScope(account: "a", vaultID: UUID(), itemID: UUID()), original = policy()
        try await first.setContentRecipients(scope: vaultScope(scope), expected: nil, policy: original, authorization: JournalWritePermit())
        let base = content(scope: scope, policy: original)
        _ = try await first.commitContent(base, grants: [grant(base)], expectedPolicy: original, authorization: JournalWritePermit())
        let one = content(scope: scope, policy: original, base: base), two = content(scope: scope, policy: original, base: base)
        async let a: PendingItemMutation? = try? first.commitContent(one, grants: [], expectedPolicy: original, authorization: JournalWritePermit())
        async let b: PendingItemMutation? = try? second.commitContent(two, grants: [], expectedPolicy: original, authorization: JournalWritePermit())
        let results = await [a, b].compactMap { $0 }
        #expect(results.count == 1)
        #expect(try await first.contentState(scope: scope)?.versionID == results.first?.version.versionID)
        #expect(try await second.pendingMutations(account: "a").count == 2)
        let next = policy("d", recipients: original.recipients.union([String(repeating: "e", count: 64)]))
        try await first.setContentRecipients(scope: vaultScope(scope), expected: original, policy: next, authorization: JournalWritePermit())
        await #expect(throws: ContentStoreError.staleAuthority) {
            try await second.commitContentGrant(grant(base), expectedPolicy: original, authorization: JournalWritePermit())
        }
        #expect(try await second.contentRecipients(scope: vaultScope(scope)) == next)
    }
}

extension SyncJournalTests {
    @Test func inboxCapacityReadRefreshesAcrossRepositoryInstances() async throws {
        let (root, reader) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let writer = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root), layout: .contentPreview3)
        #expect(try await reader.inboxReadyToResume(account: "a", budget: 100))
        let record = incoming("external-capacity", bytes: 60)
        try await writer.stageIncomingRecords([record], permit: JournalWritePermit(), budget: 100)
        #expect(try await !reader.inboxReadyToResume(account: "a", budget: 100))
        try await writer.completeIncoming(record, failure: nil, permit: JournalWritePermit())
        #expect(try await reader.inboxReadyToResume(account: "a", budget: 100))
    }

    @Test func fullInboxDrainsWhileTransportRecoveryWaitsAndReplaysCheckpoint() async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let permit = JournalWritePermit()
        let first = incoming("capacity-first", bytes: 60)
        let next = incoming("capacity-next", bytes: 60)
        try await repository.saveEngineState(Data([1]), account: "a", database: "private")
        try await repository.stageIncomingRecords([first], permit: permit, budget: 100)
        let state = Mutex(CloudSyncSuspension())
        do {
            try await repository.stageIncomingBatch([next], checkpoint: Data([2]), account: "a",
                database: "private", budget: 100, permit: permit)
            Issue.record("The batch must exceed capacity")
        } catch {
            state.withLock { $0.record(cloudSyncFailure(error, fallback: .storageFailure)) }
        }
        #expect(try await repository.engineState(account: "a", database: "private") == Data([1]))
        #expect(try await !repository.inboxReadyToResume(account: "a", budget: 100))
        // An unrelated account cannot hold this account's recovery closed.
        _ = try await repository.stageIncoming(incoming("other-account", account: "b", bytes: 80), budget: 100)
        let recovery = SyncOperation(account: "a", kind: .recoverTransport)
        _ = try await repository.enqueue(recovery)
        let deferred = Mutex(0)
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a",
            kinds: [.applyIncoming, .recoverTransport],
            clock: SyncClock(sleep: { _ in try await Task.sleep(for: .seconds(600)) }), dependencyAvailable: { dependency in
                #expect(dependency.kind == .inboxCapacity)
                return try await repository.inboxReadyToResume(account: "a", budget: 100)
            }, handler: { operation in
                do {
                    if operation.kind == .recoverTransport {
                        guard try await repository.inboxReadyToResume(account: "a", budget: 100) else {
                            deferred.withLock { $0 += 1 }
                            return .retry(.inboxFull)
                        }
                        // Replay the failed batch only after draining. The old
                        // checkpoint must have survived the entire pause.
                        #expect(try await repository.engineState(account: "a", database: "private") == Data([1]))
                        try await repository.stageIncomingBatch([next], checkpoint: Data([2]), account: "a",
                            database: "private", budget: 100, permit: permit)
                        state.withLock { $0 = CloudSyncSuspension() }
                    } else {
                        try state.withLock { try $0.checkLocalProcessing() }
                        if let id = String(data: operation.payload, encoding: .utf8),
                           let record = try await repository.incomingRecord(id: id, account: "a", database: "private") {
                            try await repository.completeIncoming(record, failure: nil, permit: permit)
                        }
                    }
                    return .completed
                } catch { Issue.record("Capacity recovery failed: \(error)"); return .attention(.processing) }
            })
        await coordinator.start(); await coordinator.waitUntilIdle()
        #expect(deferred.withLock { $0 } >= 1)
        #expect(try await repository.inboxReadyToResume(account: "a", budget: 100))
        // Only store events may release recovery; no user/lifecycle wake.
        await coordinator.wake(reason: .storeChanged); await coordinator.waitUntilIdle()
        // The replay creates a fresh inbox operation; explicitly deliver its
        // store wake rather than racing the asynchronous change observer.
        await coordinator.wake(reason: .storeChanged); await coordinator.waitUntilIdle(); await coordinator.stop()
        let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root), layout: .contentPreview3)
        #expect(try await reopened.engineState(account: "a", database: "private") == Data([2]))
        #expect(try await reopened.incomingRecords(account: "a", database: "private").isEmpty)
        #expect(try await reopened.activeOperations(account: "a", database: "private").isEmpty)
        #expect(try await reopened.incomingRecords(account: "b", database: "private").count == 1)
    }

    @Test func interruptedChunksReplayWithoutAdvancingCheckpoint() async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        try await repository.saveEngineState(Data([9]), account: "a", database: "private")
        let first = incoming("first", bytes: 40)
        try await repository.stageIncomingRecords([first], permit: JournalWritePermit(), budget: 100)
        await #expect(throws: SyncJournalError.inboxFull) {
            try await repository.stageIncomingRecords([incoming("second", bytes: 40), incoming("third", bytes: 40)], permit: JournalWritePermit(), budget: 100)
        }
        let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root), layout: .contentPreview3)
        #expect(try await reopened.incomingRecords(account: "a", database: "private") == [first])
        #expect(try await reopened.engineState(account: "a", database: "private") == Data([9]))
        #expect(try await reopened.activeOperations(account: "a", database: "private").count == 1)
        try await reopened.stageIncomingRecords([first, first], permit: JournalWritePermit(), budget: 100)
        #expect(try await reopened.incomingRecords(account: "a", database: "private") == [first])
        #expect(try await reopened.engineState(account: "a", database: "private") == Data([9]))
    }

    @Test func inboxBatchAndCheckpointRollbackTogetherAtCapacity() async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        try await repository.saveEngineState(Data([1]), account: "a", database: "private")
        await #expect(throws: SyncJournalError.inboxFull) {
            try await repository.stageIncomingBatch([incoming("one", bytes: 60), incoming("two", bytes: 60)],
                checkpoint: Data([2]), account: "a", database: "private", budget: 100, permit: JournalWritePermit())
        }
        #expect(try await repository.incomingRecords(account: "a", database: "private").isEmpty)
        #expect(try await repository.engineState(account: "a", database: "private") == Data([1]))
        try await repository.stageIncomingBatch([incoming("one", bytes: 60)], checkpoint: Data([3]),
            account: "a", database: "private", budget: 100, permit: JournalWritePermit())
        let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root), layout: .contentPreview3)
        #expect(try await reopened.incomingRecords(account: "a", database: "private").count == 1)
        #expect(try await reopened.engineState(account: "a", database: "private") == Data([3]))
    }
}

extension SyncJournalTests {
    @Test func contentDependencyFetchIsAtomicScopedAndDeduplicatedAcrossRestart() async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let vault = UUID(), item = UUID(), version = UUID()
        let dependency = SyncDependency(.content, identifier: vault.uuidString + ":" + item.uuidString + ":" + version.uuidString)
        let input = IncomingRecord(id: "head", account: "a", database: "private", zoneName: SyncStoreLayout.contentZone(vault: vault),
            zoneOwner: "owner", recordName: item.uuidString, recordType: ContentRecordKind.head.rawValue,
            bytes: Data([1]), systemFields: Data(), vaultID: vault)
        let staged = try await repository.stageIncoming(input)
        let foreign = SyncDependency(.content, identifier: UUID().uuidString + ":" + item.uuidString + ":" + version.uuidString)
        await #expect(throws: SyncJournalError.invalidOperation) {
            try await repository.deferContentIncoming(staged, dependencies: [dependency, foreign], permit: JournalWritePermit())
        }
        #expect(try await repository.operations(account: "a", database: "private").allSatisfy { $0.kind != .fetchContentVersion })
        #expect(try await repository.incomingRecord(id: staged.id, account: "a", database: "private")?.dependencies.isEmpty == true)
        try await repository.deferContentIncoming(staged, dependencies: [dependency], permit: JournalWritePermit())
        let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root), layout: .contentPreview3)
        let deferred = try #require(await reopened.incomingRecord(id: staged.id, account: "a", database: "private"))
        #expect(deferred.dependencies == [dependency])
        try await reopened.deferContentIncoming(deferred, dependencies: [dependency], permit: JournalWritePermit())
        let fetches = try await reopened.operations(account: "a", database: "private").filter { $0.kind == .fetchContentVersion }
        #expect(fetches.count == 1)
        let request = try #require(ContentVersionFetch(dependency: dependency))
        #expect(try request.operation(account: "b", owner: "owner").id != fetches.first?.id)
        #expect(try request.operation(account: "a", owner: "other-owner").id != fetches.first?.id)
    }
}

extension SyncJournalTests {
    @Test func blockedContentHeadsCannotStarveAnotherVaultPublication() async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let blockedVault = UUID(), readyVault = UUID(), recipients = policy()
        for vault in [blockedVault, readyVault] {
            try await repository.setContentRecipients(scope: VaultScope(account: "a", vaultID: vault), expected: nil,
                policy: recipients, authorization: JournalWritePermit())
        }
        let prerequisite = SyncOperation(account: "a", vaultID: blockedVault, kind: .provision)
        for _ in 0..<101 {
            let scope = ItemScope(account: "a", vaultID: blockedVault, itemID: UUID())
            _ = try await repository.commitContent(content(scope: scope, policy: recipients), grants: [], expectedPolicy: recipients,
                prerequisites: [prerequisite], authorization: JournalWritePermit())
        }
        let ready = content(scope: ItemScope(account: "a", vaultID: readyVault, itemID: UUID()), policy: recipients)
        _ = try await repository.commitContent(ready, grants: [], expectedPolicy: recipients, authorization: JournalWritePermit())
        let candidates = try await repository.contentPublications(account: "a")
        #expect(candidates.count == 1)
        #expect(candidates.first?.content == ready)
    }
}

extension SyncJournalTests {
    @Test func identicalAcceptedHeadRefreshesChangeTagWithoutConfirmingLaterEdit() async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let recipients = policy(), scope = ItemScope(account: "a", vaultID: UUID(), itemID: UUID())
        try await repository.setContentRecipients(scope: vaultScope(scope), expected: nil, policy: recipients, authorization: JournalWritePermit())
        let first = content(scope: scope, policy: recipients)
        let firstReceipt = try await repository.commitContent(first, grants: [], expectedPolicy: recipients, authorization: JournalWritePermit())
        try await repository.acknowledge(mutationID: firstReceipt.id, account: "a", serverSystemFields: Data([1]))
        let second = content(scope: scope, policy: recipients, base: first)
        let secondReceipt = try await repository.commitContent(second, grants: [], expectedPolicy: recipients, authorization: JournalWritePermit())
        let event = IncomingRecord(id: "same-head-new-change-tag", account: "a", database: "private",
            zoneName: SyncStoreLayout.contentZone(vault: scope.vaultID), zoneOwner: scope.zoneOwner,
            recordName: scope.itemID.uuidString, recordType: ContentRecordKind.head.rawValue, bytes: first.version.ciphertext,
            systemFields: Data([2]), vaultID: scope.vaultID)
        _ = try await repository.stageIncoming(event)
        try await repository.receiveContent(first, from: event, action: .keepLocal, expectedHead: second.version.versionID,
            expectedPolicy: recipients, permit: JournalWritePermit())
        #expect(try await repository.serverSystemFields(scope) == Data([2]))
        #expect(try await repository.item(scope) == second.version)
        #expect(try await repository.mutationReceipt(id: firstReceipt.id, account: "a")?.status == .cloudConfirmed)
        #expect(try await repository.mutationReceipt(id: secondReceipt.id, account: "a")?.status == .queued)
    }
}

@Test func expiredHistoryConsumerRequiresFullProjectionRefresh() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let repository = try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite"))
    try await repository.saveEngineState(Data([1]), account: "a", database: "test")
    let history = try await repository.history(after: nil)
    let token = try #require(history.token)
    try await repository.checkpointHistory(token: token, consumer: "gui", account: "a")
    #expect(try await repository.historyCheckpoint(consumer: "gui", account: "a") == token)
    struct Permit: RepositoryWritePermit { func withWritePermission<T>(_ body: () throws -> T) throws -> T { try body() } }
    try await repository.pruneHistory(permit: Permit(), now: Date().addingTimeInterval(31 * 86400))
    #expect(try await repository.historyCheckpoint(consumer: "gui", account: "a") == nil)
}


extension SyncJournalTests {
    @Test func ownerReleaseResetsBackoffWithoutResettingAttemptDiagnostics() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let now = Mutex(Date(timeIntervalSince1970: 100))
        var operation = try await repository.enqueue(SyncOperation(account: "a", kind: .enrollment))
        for attempt in 1...20 {
            operation = try await repository.transition(operation, to: .retryScheduled, failure: .transport,
                nextAttempt: Date(timeIntervalSince1970: 400), retryAttempts: attempt, attempted: true)
        }
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.enrollment],
            clock: SyncClock(now: { now.withLock { $0 } }, sleep: { _ in try await Task.sleep(for: .seconds(3600)) }, jitter: { 0 }),
            dependencyAvailable: { _ in false }, handler: { _ in .retry(.transport) })
        await coordinator.start()
        await coordinator.wake(reason: .ownerReleased); await coordinator.waitUntilIdle()
        let first = try #require(await repository.operations(account: "a", database: "private").first)
        #expect(first.nextAttempt == Date(timeIntervalSince1970: 102))
        #expect(first.attempts == 21 && first.retryAttempts == 1)
        now.withLock { $0 = Date(timeIntervalSince1970: 102) }
        await coordinator.wake(reason: .retry); await coordinator.waitUntilIdle()
        let second = try #require(await repository.operations(account: "a", database: "private").first)
        #expect(second.nextAttempt == Date(timeIntervalSince1970: 106))
        #expect(second.attempts == 22 && second.retryAttempts == 2)
        await coordinator.stop()
    }

    @Test func unlockAndAuthenticatedArrivalResumeDependencyBackoffImmediately() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let now = Date(timeIntervalSince1970: 100), calls = Mutex(0)
        var operation = try await repository.enqueue(SyncOperation(account: "a", kind: .enrollment))
        operation = try await repository.transition(operation, to: .retryScheduled, failure: .dependency,
            nextAttempt: now.addingTimeInterval(300), retryAttempts: 20, attempted: true)
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.enrollment],
            clock: SyncClock(now: { now }, sleep: { _ in try await Task.sleep(for: .seconds(3600)) }, jitter: { 0 }),
            dependencyAvailable: { _ in false }, handler: { _ in
                let count = calls.withLock { $0 += 1; return $0 }
                return count == 1 ? .retry(.dependency) : .completed
            })
        await coordinator.start()
        #expect(calls.withLock { $0 } == 0)
        await coordinator.wake(reason: .unlocked); await coordinator.waitUntilIdle()
        let pending = try #require(await repository.operations(account: "a", database: "private").first)
        #expect(pending.nextAttempt == now.addingTimeInterval(2))
        await coordinator.wake(reason: .dependenciesChanged); await coordinator.waitUntilIdle()
        #expect(calls.withLock { $0 } == 2)
        #expect(try await repository.operations(account: "a", database: "private").first?.state == .completed)
        await coordinator.stop()
    }

    @Test func transportHandoffClearsExpiredTimerWithoutClaimingDelivery() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        var operation = try await repository.enqueue(SyncOperation(account: "a", kind: .publishCoordination))
        for attempt in 1...5 {
            operation = try await repository.transition(operation, to: .retryScheduled, failure: .transport,
                nextAttempt: .distantPast, retryAttempts: attempt, attempted: true)
        }
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.publishCoordination],
            dependencyAvailable: { _ in false }, handler: { _ in .transportOwned })
        await coordinator.start(); await coordinator.waitUntilIdle()
        let retained = try #require(await repository.operations(account: "a", database: "private").first)
        #expect(retained.state == .ready && retained.nextAttempt == nil && retained.failure == nil)
        #expect(retained.retryAttempts == 5 && retained.deliveredAt == nil && retained.completedAt == nil)
        await coordinator.stop()
    }

    @Test func preflightFailurePersistsThrottleAndLeavesOtherVaultsEligible() async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let blocked = try PreparedCoordinationRecord(account: "a", vault: UUID(), kind: .discovery, identity: UUID(), bytes: Data([1]))
        let other = try PreparedCoordinationRecord(account: "a", vault: UUID(), kind: .discovery, identity: UUID(), bytes: Data([2]))
        _ = try await repository.enqueueCoordination(blocked, authorization: JournalWritePermit())
        _ = try await repository.enqueueCoordination(other, authorization: JournalWritePermit())
        let now = Date()
        try await repository.deferContentUpload(blocked.operationID, account: "a", failure: .transport,
            retryAfter: 900, now: now, permit: JournalWritePermit())
        let pending = try #require(await repository.operations(account: "a", database: "private").first { $0.id == blocked.operationID })
        #expect(pending.state == .retryScheduled && pending.failure == .transport)
        #expect(pending.nextAttempt == now.addingTimeInterval(900) && pending.retryNotBefore == pending.nextAttempt)
        #expect(try await repository.coordinationPublications(account: "a") == [other])
        let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root), layout: .contentPreview3)
        #expect(try await reopened.coordinationPublications(account: "a") == [other])
        #expect(try await !reopened.operationIsDelivered(blocked.operationID, account: "a"))
    }
}


extension SyncJournalTests {
    @Test func serverReadbackPausesPublicationUntilAppliedAcrossRestart() async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let recipients = policy(), scope = ItemScope(account: "a", vaultID: UUID(), itemID: UUID())
        try await repository.setContentRecipients(scope: vaultScope(scope), expected: nil, policy: recipients, authorization: JournalWritePermit())
        let prepared = content(scope: scope, policy: recipients)
        let keyGrant = grant(prepared)
        let receipt = try await repository.commitContent(prepared, grants: [keyGrant], expectedPolicy: recipients, authorization: JournalWritePermit())
        let initial = try await repository.contentPublications(account: "a")
        #expect(initial.count == 2)
        for upload in initial {
            let event = IncomingRecord(id: upload.recordID.recordName, account: "a", database: "private",
                zoneName: upload.recordID.zoneID.zoneName, zoneOwner: upload.recordID.zoneID.ownerName,
                recordName: upload.recordID.recordName, recordType: upload.kind.rawValue,
                bytes: upload.grant?.bytes ?? prepared.version.ciphertext, systemFields: Data([1]), vaultID: scope.vaultID)
            _ = try await repository.stageIncoming(event)
        }
        let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root), layout: .contentPreview3)
        #expect(try await reopened.contentPublications(account: "a").isEmpty)
        #expect(try await reopened.mutationReceipt(id: receipt.id, account: "a")?.status == .queued)
        for event in try await reopened.incomingRecords(account: "a", database: "private") {
            if event.recordType == ContentRecordKind.version.rawValue {
                try await reopened.receiveContent(prepared, from: event, action: .archive, expectedHead: nil, expectedPolicy: recipients, permit: JournalWritePermit())
            } else {
                try await reopened.receiveContentGrant(keyGrant, from: event, expectedPolicy: recipients, permit: JournalWritePermit())
            }
        }
        let next = try await reopened.contentPublications(account: "a")
        #expect(next.count == 1 && next.first?.kind == .head)
        #expect(try await reopened.mutationReceipt(id: receipt.id, account: "a")?.status == .queued)
        let head = try #require(next.first)
        let event = IncomingRecord(id: "head", account: "a", database: "private", zoneName: head.recordID.zoneID.zoneName,
            zoneOwner: scope.zoneOwner, recordName: head.recordID.recordName, recordType: ContentRecordKind.head.rawValue,
            bytes: prepared.version.ciphertext, systemFields: Data([2]), vaultID: scope.vaultID)
        _ = try await reopened.stageIncoming(event)
        #expect(try await reopened.contentPublications(account: "a").isEmpty)
        try await reopened.receiveContent(prepared, from: event, action: .duplicate, expectedHead: prepared.version.versionID,
            expectedPolicy: recipients, permit: JournalWritePermit())
        #expect(try await reopened.mutationReceipt(id: receipt.id, account: "a")?.status == .cloudConfirmed)
    }
}


extension SyncJournalTests {
    @Test func coordinationReadbackDoesNotStarveOtherPublicationsOrClaimDelivery() async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let blocked = try PreparedCoordinationRecord(account: "a", vault: UUID(), kind: .discovery, identity: UUID(), bytes: Data([1]))
        let other = try PreparedCoordinationRecord(account: "a", vault: UUID(), kind: .discovery, identity: UUID(), bytes: Data([2]))
        _ = try await repository.enqueueCoordination(blocked, authorization: JournalWritePermit())
        _ = try await repository.enqueueCoordination(other, authorization: JournalWritePermit())
        let record = try blocked.record(assetDirectory: root)
        let event = try PreparedCoordinationRecord.materialize(record, account: "a")
        _ = try await repository.stageIncoming(event)
        #expect(try await repository.coordinationPublications(account: "a") == [other])
        #expect(try await !repository.operationIsDelivered(blocked.operationID, account: "a"))
        // Rejecting an unauthenticated incoming record must not lose the local publication.
        try await repository.completeIncoming(event, failure: .invalidAuthority)
        #expect(try await repository.coordinationPublications(account: "a").count == 2)
        #expect(try await !repository.operationIsDelivered(blocked.operationID, account: "a"))
    }
}

extension SyncJournalTests {
    @Test(arguments: [false, true]) func enrollmentProceedsWhileBulkTransferWaits(stopBeforeCompletion: Bool) async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let entered = AsyncStream<Void>.makeStream(), release = AsyncStream<Void>.makeStream()
        let admitted = AsyncStream<Void>.makeStream(), returned = AsyncStream<Void>.makeStream()
        let transfer = try await repository.enqueue(SyncOperation(account: "a", kind: .reconcile))
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.reconcile, .enrollment],
            allowsConcurrentReconciliation: true, dependencyAvailable: { _ in true }, handler: { operation in
                if operation.kind == .reconcile {
                    entered.continuation.yield(())
                    for await _ in release.stream { break }
                    returned.continuation.yield(())
                } else { admitted.continuation.yield(()) }
                return .completed
            })
        await coordinator.start()
        for await _ in entered.stream { break }
        let changes = await repository.changes()
        let enrollment = try await repository.enqueue(SyncOperation(account: "a", kind: .enrollment))
        await coordinator.wake(reason: .storeChanged)
        for await _ in admitted.stream { break }
        // Handler entry precedes the coordinator's durable outcome commit.
        // A store-observer wake may already own the drain when our wake returns.
        for await _ in changes {
            if try await repository.operations(account: "a", database: "private")
                .first(where: { $0.id == enrollment.id })?.state == .completed { break }
        }
        let operations = try await repository.operations(account: "a", database: "private")
        #expect(operations.first { $0.id == enrollment.id }?.state == .completed)
        #expect(operations.first { $0.id == transfer.id }?.state == .ready)
        if stopBeforeCompletion { await coordinator.stop() }
        release.continuation.yield(())
        for await _ in returned.stream { break }
        await coordinator.waitUntilIdle()
        let final = try await repository.operations(account: "a", database: "private").first { $0.id == transfer.id }
        #expect(final?.state == (stopBeforeCompletion ? .ready : .completed))
        await coordinator.stop()
    }
}

extension SyncJournalTests {
    @Test func repeatedWakesReplaceOneIntentAndRejectLateCompletion() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let first = try await repository.requestSync(account: "a", database: "private")
        let old = try #require(await repository.operations(account: "a", database: "private").first)
        for _ in 0..<100 { _ = try await repository.requestSync(account: "a", database: "private") }
        let latest = try await repository.operations(account: "a", database: "private")
        #expect(latest.count == 1 && latest.first?.id == old.id && latest.first?.revision != old.revision)
        try await repository.markSyncRequestHandled(first)
        #expect(try await repository.pendingSyncRequests(account: "a", database: "private").first?.generation == 101)
        await #expect(throws: SyncJournalError.staleOperation) {
            try await repository.transition(old, to: .completed)
        }
    }

    @Test func oldReconciliationBacklogCollapsesWithoutConfirmingPublication() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        for generation in 1...100 {
            let request = DurableSyncRequest(account: "a", database: "private", generation: Int64(generation), reason: .localSave)
            _ = try await repository.enqueue(SyncOperation(account: "a", kind: .reconcile, payload: JSONEncoder().encode(request)))
        }
        let publication = try await repository.enqueue(SyncOperation(account: "a", kind: .publishItem))
        try await repository.coalesceReconciliationRequests(account: "a", database: "private")
        let operations = try await repository.operations(account: "a", database: "private")
        let live = operations.filter { $0.kind == .reconcile && $0.state != .completed }
        #expect(live.count == 1)
        #expect(try JSONDecoder().decode(DurableSyncRequest.self, from: #require(live.first).payload).generation == 100)
        #expect(operations.first { $0.id == publication.id } == publication)
        #expect(operations.allSatisfy { $0.deliveredAt == nil })
    }

    @Test func publicationRegistrationIsBatchedAndInboxRunsFirst() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        for _ in 0..<100 { _ = try await repository.enqueue(SyncOperation(account: "a", kind: .publishItem)) }
        _ = try await repository.enqueue(SyncOperation(account: "a", kind: .applyIncoming))
        let calls = Mutex<[SyncOperation.Kind]>([])
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.publishItem, .applyIncoming],
            coalescesPublicationRegistration: true, dependencyAvailable: { _ in true }, handler: { operation in
                calls.withLock { $0.append(operation.kind) }
                return operation.kind == .applyIncoming ? .completed : .transportOwned
            })
        await coordinator.start(); await coordinator.waitUntilIdle(); await coordinator.stop()
        let received = calls.withLock { $0 }
        #expect(received.first == .applyIncoming)
        #expect(received.filter { $0 == .publishItem }.count <= 3)
        #expect(received.contains(.publishItem))
    }

    @Test(arguments: [true, false]) func batchedRegistrationAdvancesEveryEligibleRetry(succeeds: Bool) async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let now = Date(), deadline = now.addingTimeInterval(900)
        var ids = Set<UUID>()
        for _ in 0..<32 {
            let operation = try await repository.enqueue(SyncOperation(account: "a", kind: .publishItem))
            ids.insert(operation.id)
            _ = try await repository.transition(operation, to: .retryScheduled, failure: .storagePressure,
                nextAttempt: now.addingTimeInterval(-60))
        }
        let throttled = try await repository.enqueue(SyncOperation(account: "a", kind: .grant))
        _ = try await repository.transition(throttled, to: .retryScheduled, failure: .transport,
            nextAttempt: deadline, retryNotBefore: deadline)
        let calls = Mutex(0)
        let clock = SyncClock(now: { now }, sleep: { _ in try await Task.sleep(for: .seconds(3600)) }, jitter: { 0 })
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.publishItem, .grant],
            clock: clock, coalescesPublicationRegistration: true, dependencyAvailable: { _ in true }, handler: { _ in
                calls.withLock { $0 += 1 }
                return succeeds ? .transportOwned : .retry(.transport)
            })
        await coordinator.start(); await coordinator.waitUntilIdle(); await coordinator.stop()
        let operations = try await repository.operations(account: "a", database: "private")
        let retried = operations.filter { ids.contains($0.id) }
        #expect(retried.count == 32)
        #expect(retried.allSatisfy { $0.deliveredAt == nil && $0.state != .completed })
        if succeeds {
            #expect(retried.allSatisfy { $0.state == .ready && $0.failure == nil && $0.nextAttempt == nil })
        } else {
            #expect(retried.allSatisfy { $0.state == .retryScheduled && $0.failure == .transport && ($0.nextAttempt ?? .distantPast) > now })
        }
        let untouched = try #require(operations.first { $0.id == throttled.id })
        #expect(untouched.state == .retryScheduled && untouched.retryNotBefore == deadline && untouched.nextAttempt == deadline)
        #expect(calls.withLock { $0 } <= 3)
    }
}

extension SyncJournalTests {
    @Test func newerWakePreservesServerRetryAfter() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        _ = try await repository.requestSync(account: "a", database: "private")
        let old = try #require(await repository.operations(account: "a", database: "private").first)
        let deadline = Date().addingTimeInterval(900)
        _ = try await repository.transition(old, to: .retryScheduled, failure: .transport,
            nextAttempt: deadline, retryNotBefore: deadline, attempted: true)
        _ = try await repository.requestSync(account: "a", database: "private", reason: .localSave)
        let pending = try #require(await repository.operations(account: "a", database: "private").first)
        #expect(pending.state == .retryScheduled && pending.nextAttempt == deadline && pending.retryNotBefore == deadline)
        #expect(try JSONDecoder().decode(DurableSyncRequest.self, from: pending.payload).generation == 2)
    }
}

extension SyncJournalTests {
    @Test func successfulPreparationClearsOldFailureWithoutConfirmingDelivery() async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let record = try PreparedCoordinationRecord(account: "a", vault: UUID(), kind: .discovery, identity: UUID(), bytes: Data([1]))
        _ = try await repository.enqueueCoordination(record, authorization: JournalWritePermit())
        try await repository.deferContentUpload(record.operationID, account: "a", failure: .storagePressure,
            now: Date().addingTimeInterval(-600), permit: JournalWritePermit())
        #expect(try await repository.syncHealth(account: "a", database: "private").blockedReasons.contains(.storagePressure))
        try await repository.setContentUploadBlocked(record.operationID, account: "a", blocked: false, permit: JournalWritePermit())
        let operation = try #require(await repository.operations(account: "a", database: "private").first)
        #expect(operation.state == .ready && operation.failure == nil && operation.nextAttempt == nil)
        #expect(operation.retryAttempts == 1 && operation.deliveredAt == nil)
        #expect(try await repository.syncHealth(account: "a", database: "private").blockedReasons.isEmpty)
        #expect(try await !repository.operationIsDelivered(record.operationID, account: "a"))
        let deadline = Date().addingTimeInterval(900)
        try await repository.deferContentUpload(record.operationID, account: "a", failure: .transport,
            retryAfter: 900, now: deadline.addingTimeInterval(-900), permit: JournalWritePermit())
        try await repository.setContentUploadBlocked(record.operationID, account: "a", blocked: false, permit: JournalWritePermit())
        let throttled = try #require(await repository.operations(account: "a", database: "private").first)
        #expect(throttled.state == .retryScheduled && throttled.retryNotBefore == deadline)
    }
}

extension SyncJournalTests {
    @Test(arguments: [SyncOperation.Kind.enrollment, .prepareGrant])
    func unlockReconsidersAccessWorkBeforeRemainingBulkWork(kind: SyncOperation.Kind) async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let enrollment = try await repository.enqueue(SyncOperation(account: "a", kind: kind))
        var bulk: [SyncOperation] = []
        for _ in 0..<8 {
            bulk.append(try await repository.enqueue(SyncOperation(account: "a", kind: .rotateContent)))
        }
        let authorized = Mutex(false)
        let calls = Mutex<[UUID]>([])
        let bulkCalls = Mutex(0)
        let barrier = JournalBarrier()
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a",
            kinds: [kind, .rotateContent], dependencyAvailable: { _ in true }, handler: { operation in
                calls.withLock { $0.append(operation.id) }
                if operation.kind == kind {
                    return authorized.withLock { $0 } ? .completed : .authorization
                }
                let first = bulkCalls.withLock { $0 += 1; return $0 == 1 }
                if first { await barrier.wait() }
                return .completed
            })
        let startup = Task { await coordinator.start() }
        await barrier.waitForEntry()
        // Enrollment has failed authentication and the first bulk handler is live.
        authorized.withLock { $0 = true }
        await coordinator.wake(reason: .unlocked)
        await barrier.release()
        await startup.value
        await coordinator.waitUntilIdle()
        await coordinator.stop()

        let order = calls.withLock { $0 }
        #expect(order.count == bulk.count + 2)
        #expect(order.first == enrollment.id)
        // Finish and commit the current bulk operation, then retry enrollment
        // before starting any of the seven remaining bulk operations.
        #expect(order.dropFirst(2).first == enrollment.id)
        for operation in bulk { #expect(order.filter { $0 == operation.id }.count == 1) }
        let persisted = try await repository.operations(account: "a", database: "private")
        #expect(persisted.count == bulk.count + 1)
        #expect(persisted.allSatisfy { $0.state == .completed })
    }
}

extension SyncJournalTests {
    @Test(arguments: [false, true]) func accessWorkArrivingDuringRotationsDoesNotWaitForWholeBatch(retry: Bool) async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        var bulk: [SyncOperation] = []
        for _ in 0..<40 {
            bulk.append(try await repository.enqueue(SyncOperation(account: "a", kind: .rotateContent)))
        }
        let calls = Mutex<[UUID]>([])
        let first = Mutex(true)
        let barrier = JournalBarrier()
        let now = Date()
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a",
            kinds: [.rotateContent, .prepareGrant, .grant, .publishCoordination],
            clock: SyncClock(now: { now }, sleep: { _ in try await Task.sleep(for: .seconds(3600)) }, jitter: { 0 }),
            dependencyAvailable: { _ in true }, handler: { operation in
                calls.withLock { $0.append(operation.id) }
                if operation.kind == .rotateContent, first.withLock({ value in
                    let wasFirst = value; value = false; return wasFirst
                }) { await barrier.wait() }
                return retry && operation.kind == .rotateContent ? .retry(.transport) : .completed
            })
        let startup = Task { await coordinator.start() }
        await barrier.waitForEntry()
        var access: [SyncOperation] = []
        for kind in [SyncOperation.Kind.prepareGrant, .grant, .publishCoordination] {
            access.append(try await repository.enqueue(SyncOperation(account: "a", kind: kind)))
        }
        await coordinator.wake(reason: .foreground)
        await barrier.release()
        await startup.value
        await coordinator.waitUntilIdle()
        await coordinator.stop()
        let order = calls.withLock { $0 }
        let bulkIDs = Set(bulk.map(\.id))
        for operation in access {
            let index = try #require(order.firstIndex(of: operation.id))
            // A bounded slice must yield to newly arrived access work even
            // without another unlock; no wall-clock sleeps or ordering ties.
            #expect(order[..<index].filter { bulkIDs.contains($0) }.count <= 16)
        }
        for operation in bulk + access { #expect(order.filter { $0 == operation.id }.count == 1) }
        let persisted = try await repository.operations(account: "a", database: "private")
        #expect(persisted.count == bulk.count + access.count)
        #expect(persisted.allSatisfy { $0.state == (retry && $0.kind == .rotateContent ? .retryScheduled : .completed) })
    }
}

extension SyncJournalTests {
    @Test(arguments: [true, false]) func remoteRotationRetiresWorkOnlyWhenInstalled(installed: Bool) async throws {
        let (root, repository) = try previewStore(); defer { try? FileManager.default.removeItem(at: root) }
        let scope = ItemScope(account: "a", vaultID: UUID(), itemID: UUID())
        let original = policy(), removed = policy("d", authority: "d")
        #expect(try await !repository.contentRotationSatisfied(scope: scope))
        try await repository.setContentRecipients(scope: vaultScope(scope), expected: nil,
            policy: original, authorization: JournalWritePermit())
        let first = content(scope: scope, policy: original)
        _ = try await repository.commitContent(first, grants: [], expectedPolicy: original, authorization: JournalWritePermit())
        try await repository.setContentRecipients(scope: vaultScope(scope), expected: original,
            policy: removed, authorization: JournalWritePermit())
        let rotation = try #require(await repository.operations(account: "a", database: "private")
            .first { $0.kind == .rotateContent })
        #expect(try await !repository.contentRotationSatisfied(scope: scope))
        let remote = content(scope: scope, policy: removed, base: first, key: UUID())
        let incoming = IncomingRecord(id: UUID().uuidString, account: "a", database: "private",
            zoneName: SyncStoreLayout.contentZone(vault: scope.vaultID), zoneOwner: scope.zoneOwner,
            recordName: scope.itemID.uuidString + (installed ? "" : ":" + remote.version.versionID.uuidString),
            recordType: (installed ? ContentRecordKind.head : .version).rawValue,
            bytes: remote.version.ciphertext, systemFields: Data(), vaultID: scope.vaultID)
        try await repository.stageIncoming(incoming, permit: JournalWritePermit())
        try await repository.receiveContent(remote, from: incoming, action: installed ? .supersede : .archive,
            expectedHead: first.version.versionID, expectedPolicy: removed, permit: JournalWritePermit())
        let result = try #require(await repository.operations(account: "a", database: "private").first { $0.id == rotation.id })
        #expect(result.state == (installed ? .completed : .ready))
        #expect(result.deliveredAt == nil)
        #expect(try await repository.contentRotationSatisfied(scope: scope) == installed)
        // Re-admission adds grant recipients but does not undo removal's key authority.
        let readmitted = policy("e", recipients: removed.recipients.union([String(repeating: "f", count: 64)]), authority: "d")
        try await repository.setContentRecipients(scope: vaultScope(scope), expected: removed,
            policy: readmitted, authorization: JournalWritePermit())
        #expect(try await repository.contentRotationSatisfied(scope: scope) == installed)
        #expect(try await repository.operations(account: "a", database: "private")
            .filter { $0.kind == .rotateContent && $0.state != .completed }.count == (installed ? 0 : 1))
    }
}

extension SyncJournalTests {
    @Test func prerequisiteFetchesRunBeforeBulkInboxButCannotStarveIt() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        for _ in 0..<40 { _ = try await repository.enqueue(SyncOperation(account: "a", kind: .applyIncoming)) }
        for _ in 0..<40 { _ = try await repository.enqueue(SyncOperation(account: "a", kind: .fetchContentHead)) }
        let order = Mutex<[SyncOperation.Kind]>([])
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.fetchContentHead, .applyIncoming],
            dependencyAvailable: { _ in true }, handler: { operation in
                order.withLock { $0.append(operation.kind) }; return .completed
            })
        await coordinator.start(); await coordinator.waitUntilIdle(); await coordinator.stop()
        let calls = order.withLock { $0 }
        #expect(calls.first == .fetchContentHead)
        #expect(calls.firstIndex(of: .applyIncoming) == 16)
        #expect(calls.filter { $0 == .fetchContentHead }.count == 40)
        #expect(calls.filter { $0 == .applyIncoming }.count == 40)
    }
}

extension SyncJournalTests {
    @Test func blockedHealthPersistsReasonsAndRetryFloorsWithoutPayloads() async throws {
        let (root, repository) = try journalStore(); defer { try? FileManager.default.removeItem(at: root) }
        let now = Date(timeIntervalSince1970: 100), next = now.addingTimeInterval(10), floor = now.addingTimeInterval(60)
        let waiting = try await repository.enqueue(SyncOperation(account: "a", kind: .rotateContent,
            payload: Data("secret must never appear in health".utf8), dependencies: [.init(.grant, identifier: "private routing")], now: now))
        let retry = try await repository.enqueue(SyncOperation(account: "a", kind: .fetchContentVersion, now: now))
        let scheduled = try await repository.transition(retry, to: .retryScheduled, failure: .transport, nextAttempt: next, retryNotBefore: floor)
        let before = try await repository.syncHealth(account: "a", database: "private")
        #expect(before.blockedWork.first { $0.reason == .missingGrant }?.count == 1)
        #expect(before.blockedWork.first { $0.reason == .missingGrant }?.oldestOperationAt == now)
        #expect(before.blockedWork.first { $0.reason == .transport }?.nextAttempt == floor)
        #expect(!String(describing: before).contains("secret"))
        #expect(!String(describing: before).contains("private routing"))
        let reopened = try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite"))
        #expect(try await reopened.syncHealth(account: "a", database: "private") == before)
        _ = try await repository.transition(waiting, to: .completed)
        _ = try await repository.transition(scheduled, to: .completed)
        #expect(try await repository.syncHealth(account: "a", database: "private").blockedWork.isEmpty)
    }
}
