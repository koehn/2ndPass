import Darwin
import Foundation
import Testing
import MopCore
@testable import MopVaultNext

private func fixture() throws -> (VerifiedVault, VaultAddress, URL) {
    let vault = try VaultEngine.create(name: "disk", owner: TestDevice(), recovery: TestDevice().identity)
    let address = try VaultAddress(container: "iCloud.example.mop", environment: "Development", account: "a",
                                   database: .private, owner: "owner", vault: vault.id)
    return (vault, address, FileManager.default.temporaryDirectory.appendingPathComponent("mop-v6-state-test-" + UUID().uuidString))
}

@Test func durableJournalSurvivesStoreReopenAndLeaseExcludesOtherWriters() throws {
    let (vault, address, folder) = try fixture()
    defer { try? FileManager.default.removeItem(at: folder) }
    var store: FileVerifiedStateStore? = try FileVerifiedStateStore(directory: folder, address: address)
    #expect(try store!.load(binding: address.binding) == nil)
    #expect(throws: MopError.vaultConflict) { try FileVerifiedStateStore(directory: folder, address: address) }
    let journal = PendingPublication(operation: UUID(), parent: vault.digest, candidate: String(repeating: "a", count: 64))
    let state = VerifiedState(address: address, snapshot: vault.bytes, verifiedDigest: vault.digest, verifiedAt: Date(), pending: journal)
    try store!.save(state, binding: address.binding)
    store = nil
    let reopened = try FileVerifiedStateStore(directory: folder, address: address)
    let loaded = try #require(try reopened.load(binding: address.binding))
    #expect(loaded.snapshot == vault.bytes)
    #expect(loaded.pending?.operation == journal.operation)
    #expect(throws: MopError.vaultUntrusted) { try reopened.load(binding: "../wrong-account") }
}

@Test func durableStateRejectsSymlinksAndInsecureDirectories() throws {
    let (_, address, folder) = try fixture()
    defer { try? FileManager.default.removeItem(at: folder) }
    let store = try FileVerifiedStateStore(directory: folder, address: address)
    let path = folder.appendingPathComponent(address.binding + ".json").path
    #expect(symlink("/dev/null", path) == 0)
    #expect(throws: MopError.filePermissions) { try store.load(binding: address.binding) }
    #expect(chmod(folder.path, 0o755) == 0)
    #expect(throws: MopError.filePermissions) { try FileVerifiedStateStore(directory: folder, address: address) }
}

@Test func durableStateRejectsCorruptCheckpointWithoutReplacingIt() throws {
    let (vault, address, folder) = try fixture()
    defer { try? FileManager.default.removeItem(at: folder) }
    let store = try FileVerifiedStateStore(directory: folder, address: address)
    let valid = VerifiedState(address: address, snapshot: vault.bytes, verifiedDigest: vault.digest, verifiedAt: Date(), pending: nil)
    try store.save(valid, binding: address.binding)
    let bad = VerifiedState(address: address, snapshot: Data("corrupt".utf8), verifiedDigest: vault.digest, verifiedAt: Date(), pending: nil)
    #expect(throws: MopError.vaultUntrusted) { try store.save(bad, binding: address.binding) }
    #expect(try store.load(binding: address.binding)?.snapshot == vault.bytes)
}
