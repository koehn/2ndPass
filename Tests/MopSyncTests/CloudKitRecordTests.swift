import CloudKit
import Foundation
import Testing
import MopCore
@testable import MopSync

@Test func uploadErrorsDoNotMisreportValidationAsDiskExhaustion() {
    #expect(publicationFailure(ContentStoreError.invalidRecord) == .processing)
    #expect(publicationFailure(ContentStoreError.staleAuthority) == .dependency)
    #expect(publicationFailure(MopError.authentication) == .authorization)
    #expect(publicationFailure(CKError(.networkFailure)) == .transport)
    #expect(publicationFailure(CocoaError(.fileWriteOutOfSpace)) == .storagePressure)
    #expect(publicationFailure(NSError(domain: NSPOSIXErrorDomain, code: 28)) == .storagePressure)
    #expect(publicationFailure(SyncJournalError.inboxFull) == .inboxFull)
    #expect(publicationFailure(CloudSyncAdapterError.inboxFull) == .inboxFull)
    #expect(publicationFailure(CocoaError(.fileReadCorruptFile)) == .processing)
}

@Test func cloudFailureDiagnosticsExposeCodesAndThrottleWithoutRecordData() {
    let rejected = CKError(.serverRejectedRequest, userInfo: [NSLocalizedDescriptionKey: "private record contents"])
    let throttled = CKError(.requestRateLimited, userInfo: [CKErrorRetryAfterKey: 120.0])
    let batch = CKError(.partialFailure, userInfo: [CKPartialErrorsByItemIDKey: [
        "private-record-name": rejected, "another-private-record": throttled
    ]])
    #expect(cloudFailureSummary([batch, rejected]) == "CKError codes(counts)=2:1,7:1,15:2 retryAfterSeconds=120.0")
    #expect(cloudFailureSummary([CKError(.networkFailure)]) == "CKError codes(counts)=4:1 retryAfterSeconds=0.0")
}

@Test func transportCancellationDoesNotInterruptDeliveredEventPersistence() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite/ContentPreview3/Content3.sqlite"))
    let entered = AsyncStream<Void>.makeStream()
    let resume = AsyncStream<Void>.makeStream()
    let delivered = Data([1, 2, 3])
    let callback = Task {
        await completeCloudSyncEvent {
            entered.continuation.yield(())
            for await _ in resume.stream { break }
            do {
                try Task.checkCancellation()
                try await repository.saveEngineState(delivered, account: "account", database: "event-test")
            } catch { Issue.record("Delivered event was interrupted: \(error)") }
        }
    }
    for await _ in entered.stream { break }
    // Reproduce cancelOperations cancelling the delegate while it awaits work.
    callback.cancel()
    resume.continuation.yield(())
    await callback.value
    #expect(try await repository.engineState(account: "account", database: "event-test") == delivered)
    entered.continuation.finish(); resume.continuation.finish()
}

@Test func interruptedUploadPreparationStopsBeforeRetryBookkeeping() async throws {
    for error: any Error in [CancellationError(), CKError(.operationCancelled), CloudSyncAdapterError.operationInterrupted] {
        var deferred = 0
        do {
            for _ in 0..<1_000 {
                try checkUploadPreparation(error)
                deferred += 1
            }
            Issue.record("Interrupted batch must exit")
        } catch is CancellationError { }
        #expect(deferred == 0)
    }
    try checkUploadPreparation(CKError(.networkUnavailable))
    try checkUploadPreparation(MopError.cloudPermission)
    let entered = AsyncStream<Void>.makeStream()
    let resume = AsyncStream<Void>.makeStream()
    let task = Task {
        entered.continuation.yield(())
        for await _ in resume.stream { break }
        #expect(throws: CancellationError.self) { try checkUploadPreparation() }
    }
    for await _ in entered.stream { break }
    task.cancel()
    resume.continuation.finish()
    await task.value
    entered.continuation.finish()
}

@Test func cancelledSyncWorkIsNeitherStorageFailureNorUntrustedData() {
    for error: any Error in [CancellationError(), CKError(.operationCancelled)] {
        #expect(cloudSyncFailure(error, fallback: .storageFailure) == .operationInterrupted)
        #expect(cloudSyncFailure(error, fallback: .untrustedRecord) == .operationInterrupted)
    }
    #expect(cloudSyncFailure(CloudSyncAdapterError.untrustedRecord, fallback: .storageFailure) == .untrustedRecord)
    #expect(cloudSyncFailure(CloudSyncAdapterError.accountChanged, fallback: .storageFailure) == .accountChanged)
    #expect(cloudSyncFailure(CocoaError(.fileReadCorruptFile), fallback: .storageFailure) == .storageFailure)
}

@Test func inboxCapacitySuspendsTransportButPreservesLocalProcessing() throws {
    var suspension = CloudSyncSuspension()
    suspension.record(cloudSyncFailure(SyncJournalError.inboxFull, fallback: .storageFailure))
    #expect(throws: CloudSyncAdapterError.inboxFull) { try suspension.check() }
    try suspension.checkLocalProcessing()
    suspension.record(.operationInterrupted)
    try suspension.checkLocalProcessing()
    #expect(suspension.failure == .inboxFull)
}

@Test(arguments: [CloudSyncAdapterError.accountChanged, .storageFailure, .untrustedRecord])
func inboxCapacityCannotMaskRealFailures(_ failure: CloudSyncAdapterError) {
    var suspension = CloudSyncSuspension()
    suspension.record(.inboxFull)
    suspension.record(failure)
    suspension.record(.inboxFull)
    #expect(!suspension.allowsLocalProcessing)
    #expect(throws: failure) { try suspension.checkLocalProcessing() }
    #expect(throws: failure) { try suspension.check() }
}

@Test(arguments: [CloudSyncAdapterError.membershipUnavailable, .storageFailure, .unreadableRemoteRecord])
func syncSuspensionRetainsCauseAcrossInterruptedCallbacks(_ cause: CloudSyncAdapterError) throws {
    var suspension = CloudSyncSuspension()
    try suspension.check()
    suspension.record(cause)
    // Another callback can fail after sync stops while account validation waits.
    suspension.record(.operationInterrupted)
    #expect(throws: cause) { try suspension.check() }
    // A genuinely changed account takes priority and cannot be masked later.
    suspension.record(.accountChanged)
    suspension.record(.storageFailure)
    #expect(throws: CloudSyncAdapterError.accountChanged) { try suspension.check() }
}

@Test func synchronizationLeaseExcludesConcurrentOwnersAndReleases() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-lease-test-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let path = directory.appendingPathComponent("engine.lock")
    var first: SynchronizationLease? = try SynchronizationLease(url: path)
    #expect(first != nil)
    #expect(throws: CloudSyncAdapterError.engineAlreadyOwned) { try SynchronizationLease(url: path) }
    first = nil
    let next = try SynchronizationLease(url: path)
    withExtendedLifetime(next) {}
}

@Test func contentAssetsRetainChunkLimitsAndMaterializeBeforeTemporaryFilesDisappear() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let scope = ItemScope(account: "account", vaultID: UUID(), itemID: UUID())
    let bytes = Data(repeating: 17, count: ContentRecordTransport.assetChunkLimit + 1)
    let version = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: bytes)
    let prepared = PreparedContentVersion(version: version, keyGeneration: UUID(), contentRevision: UUID(), membership: String(repeating: "a", count: 64), keyAuthority: String(repeating: "a", count: 64))
    let upload = ContentUpload(operationID: UUID(), content: prepared, grant: nil, kind: .version, systemFields: nil)
    let record = try upload.record(assetDirectory: root)
    let chunks = try #require(record["assets"] as? [CKAsset])
    #expect(chunks.count == 2 && record["asset"] == nil && record["payload"] == nil)
    let received = try ContentRecordTransport.materialize(record, account: scope.account)
    #expect(received.bytes == bytes)
    for asset in chunks {
        let path = try #require(asset.fileURL)
        #expect(try path.resourceValues(forKeys: [.fileSizeKey]).fileSize! <= ContentRecordTransport.assetChunkLimit)
        try FileManager.default.removeItem(at: path)
    }
    #expect(received.bytes == bytes)
    #expect(throws: (any Error).self) { try ContentRecordTransport.materialize(record, account: scope.account) }
}
