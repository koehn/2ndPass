@preconcurrency import CloudKit
import Foundation
import Synchronization
import Testing
import MopCore
import MopSync
@testable import MopVaultNext
@testable import MopAppSupport

@Test func recoveryStateSurvivesRestartAndRemainsAccountScoped() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-recovery-state-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = ItemRecoveryStateStore(directory: directory, account: "a")
    let vault = UUID()
    var progress = ItemRecoveryState(account: "a", vaults: [vault])
    for phase: ItemRecoveryPhase in [.preview, .enrolling, .repairing, .verifying] {
        progress.phase = phase; try store.save(progress)
        let reopened = try #require(try ItemRecoveryStateStore(directory: directory, account: "a").load())
        #expect(reopened == progress && reopened.blocksRegularAccess)
        #expect(try ItemRecoveryStateStore(directory: directory, account: "b").load() == nil)
    }
    progress.completed = [vault]; progress.phase = .complete; try store.save(progress)
    #expect(try store.load()?.blocksRegularAccess == false)
}

@Test func absentRecoveryReadsDoNotCreateStorageAndObserveAnotherWriter() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("recovery-read-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let reader = ItemRecoveryStateStore(directory: directory, account: "a")
    let start = ContinuousClock.now
    for _ in 0..<1000 { #expect(try reader.load() == nil) }
    print("Absent recovery benchmark: 1000 reads=\(start.duration(to: .now))")
    #expect(!FileManager.default.fileExists(atPath: directory.path))
    let writer = ItemRecoveryStateStore(directory: directory, account: "a")
    let state = ItemRecoveryState(account: "a", vaults: [UUID()])
    try writer.save(state)
    #expect(try reader.load() == state)
}
