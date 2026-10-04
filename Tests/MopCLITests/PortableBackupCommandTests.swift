import Foundation
import Testing
import MopCore
@testable import MopCLI

private func restoreCommand(archive: URL, key: URL) throws -> Vault.RestoreBackup {
    try #require(Mop.parseAsRoot(["vault", "restore-backup", archive.path,
        "--key-file", key.path, "--name", "restored", "--restore-id",
        "3BF2F4C3-A9EC-4F2E-B8DB-87450A43497B", "--dry-run"]) as? Vault.RestoreBackup)
}

@Test func portableBackupDryRunNeedsOnlyArchiveAndKey() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try LocalFile.privateDirectory(directory)
    defer { try? FileManager.default.removeItem(at: directory) }
    let archive = directory.appendingPathComponent("backup.moparchive")
    let key = directory.appendingPathComponent("backup.key")
    let sealed = try PortableArchive.seal(PortableVaultArchive(name: "personal", items: [], itemIDs: [:], references: [:], records: [:]))
    try LocalFile.write(sealed.data, to: archive)
    try sealed.recoveryKey.withFoundationData { try LocalFile.write($0, to: key) }
    let command = try restoreCommand(archive: archive, key: key)
    #expect(command.dryRun)
    #expect(command.storage.vault == nil)
    try await command.run()
    try FileManager.default.removeItem(at: key)
    await #expect(throws: PortableBackupInputFailure.keyMissing) { try await command.run() }
    try FileManager.default.removeItem(at: archive)
    await #expect(throws: PortableBackupInputFailure.archiveMissing) { try await command.run() }
}
