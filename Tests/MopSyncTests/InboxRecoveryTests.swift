import Foundation
import Testing
import Synchronization
@testable import MopSync

extension EncryptedItemRepository {
    fileprivate func reserveForTest(_ records: [IncomingRecord], kind: SyncOperation.Kind, budget: Int) throws {
        try transaction { try stagePrerequisiteIncomingInTransaction(records, kind: kind, budget: budget) }
    }
}

@Suite struct InboxRecoveryTests {
    private func record(_ id: String, bytes: Int = 60) -> IncomingRecord {
        IncomingRecord(id: id, account: "a", database: "private", zoneName: "z", zoneOwner: "__defaultOwner__",
                       recordName: id, recordType: "test", bytes: Data(repeating: 1, count: bytes), systemFields: Data())
    }

    @Test func fullBulkInboxStillAdmitsBoundedPrerequisitesAndDrainsAfterRestart() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = SyncStoreLayout.contentPreviewURL(in: root)
        let repository = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        let bulk = record("bulk", bytes: 100)
        _ = try await repository.stageIncoming(bulk, budget: 100)
        let version = record("version"), head = record("head"), membership = record("membership")
        try await repository.reserveForTest([version], kind: .fetchContentVersion, budget: 100)
        // A version waiting on membership cannot consume membership's reserve.
        try await repository.reserveForTest([head], kind: .fetchContentHead, budget: 100)
        try await repository.reserveForTest([membership], kind: .fetchMembership, budget: 100)
        await #expect(throws: SyncJournalError.inboxFull) {
            try await repository.reserveForTest([record("another-version")], kind: .fetchContentVersion, budget: 100)
        }
        await #expect(throws: SyncJournalError.inboxFull) { try await repository.stageIncoming(record("more-bulk"), budget: 100) }
        // Replays reuse the durable row and do not consume reserve twice.
        try await repository.reserveForTest([version], kind: .fetchContentVersion, budget: 100)
        let reopened = try EncryptedItemRepository(storeURL: url, layout: .contentPreview3)
        #expect(try await !reopened.prerequisiteInboxReadyToResume(account: "a", kind: .fetchContentVersion))
        #expect(try await reopened.incomingRecords(account: "a", database: "private").count == 4)
        for id in [membership.id, version.id, head.id, bulk.id] {
            let saved = try #require(await reopened.incomingRecord(id: id, account: "a", database: "private"))
            try await reopened.completeIncoming(saved)
        }
        #expect(try await repository.inboxReadyToResume(account: "a", budget: 100))
        #expect(try await repository.prerequisiteInboxReadyToResume(account: "a", kind: .fetchContentVersion))
    }

    @Test func prerequisiteBatchIsAtomicAndOversizedReplayDoesNotConsumeCapacity() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite"))
        let oversized = record("large-membership", bytes: 120)
        try await repository.reserveForTest([oversized], kind: .fetchMembership, budget: 100)
        try await repository.reserveForTest([oversized], kind: .fetchMembership, budget: 100)
        await #expect(throws: SyncJournalError.inboxFull) {
            try await repository.reserveForTest([record("next-membership")], kind: .fetchMembership, budget: 100)
        }
        #expect(try await repository.incomingRecords(account: "a", database: "private").count == 1)
        let saved = try #require(await repository.incomingRecord(id: oversized.id, account: "a", database: "private"))
        try await repository.completeIncoming(saved)
        let invalid = record("invalid", bytes: 0)
        await #expect(throws: SyncJournalError.invalidOperation) {
            try await repository.reserveForTest([record("valid"), invalid], kind: .fetchMembership, budget: 100)
        }
        #expect(try await repository.incomingRecords(account: "a", database: "private").isEmpty)
        #expect(try await repository.prerequisiteInboxReadyToResume(account: "a", kind: .fetchMembership))
    }

    @Test func capacityWaitDoesNotSpinAndStoreDrainReleasesIt() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite"))
        let full = record("full")
        _ = try await repository.stageIncoming(full, budget: 100)
        let recovery = try await repository.enqueue(SyncOperation(account: "a", kind: .recoverTransport))
        let calls = Mutex(0)
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.recoverTransport],
            dependencyAvailable: { _ in try await repository.inboxReadyToResume(account: "a", budget: 100) },
            handler: { _ in
                calls.withLock { $0 += 1 }
                return (try? await repository.inboxReadyToResume(account: "a", budget: 100)) == true ? .completed : .retry(.inboxFull)
            })
        await coordinator.start(); await coordinator.waitUntilIdle()
        for _ in 0..<5 { await coordinator.wake(reason: .storeChanged) }
        #expect(calls.withLock { $0 } == 1)
        let health = try await repository.syncHealth(account: "a", database: "private")
        #expect(health.blockedReasons == [.inboxFull])
        #expect(health.blockedWork.contains { $0.reason == .inboxFull && $0.nextAttempt == nil })
        let waiting = try #require(await repository.operations(account: "a", database: "private").first { $0.id == recovery.id })
        #expect(waiting.state == .waitingForDependency && waiting.nextAttempt == nil)
        try await repository.completeIncoming(full)
        await coordinator.wake(reason: .storeChanged); await coordinator.waitUntilIdle(); await coordinator.stop()
        #expect(calls.withLock { $0 } == 2)
        #expect(try await repository.activeOperations(account: "a", database: "private").isEmpty)
    }

    @Test func legacyRecoveryProbeDoesNotSpinOnRealStorageFailure() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite"))
        let now = Date()
        let operation = try await repository.enqueue(SyncOperation(account: "a", kind: .recoverTransport))
        _ = try await repository.transition(operation, to: .retryScheduled, failure: .storagePressure,
            nextAttempt: now.addingTimeInterval(600))
        let calls = Mutex(0)
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.recoverTransport],
            clock: SyncClock(now: { now }, sleep: { _ in try await Task.sleep(for: .seconds(600)) }),
            dependencyAvailable: { _ in true }, handler: { _ in
                let count = calls.withLock { $0 += 1; return $0 }
                // Bound a regression instead of hanging the test on a retry loop.
                return count > 1 ? .attention(.processing) : .retry(.storagePressure)
            })
        await coordinator.start(); await coordinator.waitUntilIdle()
        for _ in 0..<5 { await coordinator.wake(reason: .storeChanged) }
        await coordinator.stop()
        #expect(calls.withLock { $0 } == 1)
        let pending = try #require(await repository.activeOperations(account: "a", database: "private").first)
        #expect(pending.state == .retryScheduled && pending.failure == .storagePressure)
    }

    @Test(arguments: [false, true])
    func legacyRecoveryBypassesBackoffAfterDrainButHonorsServerFloor(serverFloor: Bool) async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try EncryptedItemRepository(storeURL: root.appendingPathComponent("items.sqlite"))
        let now = Date(), later = now.addingTimeInterval(600)
        let operation = try await repository.enqueue(SyncOperation(account: "a", kind: .recoverTransport))
        _ = try await repository.transition(operation, to: .retryScheduled, failure: .storagePressure,
            nextAttempt: later, retryNotBefore: serverFloor ? later : nil)
        let calls = Mutex(0)
        let coordinator = DurableSyncCoordinator(repository: repository, account: "a", kinds: [.recoverTransport],
            clock: SyncClock(now: { now }, sleep: { _ in try await Task.sleep(for: .seconds(600)) }),
            dependencyAvailable: { _ in try await repository.inboxReadyToResume(account: "a") },
            handler: { _ in calls.withLock { $0 += 1 }; return .completed })
        await coordinator.start(); await coordinator.waitUntilIdle(); await coordinator.stop()
        #expect(calls.withLock { $0 } == (serverFloor ? 0 : 1))
    }
}
