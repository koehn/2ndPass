import Foundation
import Testing
import MopCore
@testable import MopVaultNext

private actor UploadProbe: RevisionTransport {
    let base: MemoryRevisionTransport
    var active = 0, maximum = 0, started = 0, finished = 0, revisions = 0
    let fail: Bool
    init(_ root: VerifiedVault, fail: Bool = false) { base = MemoryRevisionTransport(root); self.fail = fail }
    func uploadAttachment(_ bytes: Data, digest: String, at address: VaultAddress) async throws {
        active += 1; started += 1; maximum = max(maximum, active)
        defer { active -= 1 }
        try await Task.sleep(for: .milliseconds(30))
        if fail { throw MopError.cloudUnavailable }
        try await base.uploadAttachment(bytes, digest: digest, at: address)
        finished += 1
    }
    func head(at address: VaultAddress) async throws -> RevisionHead { try await base.head(at: address) }
    func revision(_ digest: String, at address: VaultAddress) async throws -> Data { try await base.revision(digest, at: address) }
    func upload(_ bytes: Data, digest: String, at address: VaultAddress) async throws {
        #expect(active == 0)
        revisions += 1
        try await base.upload(bytes, digest: digest, at: address)
    }
    func publish(_ digest: String, expectedVersion: Data, at address: VaultAddress) async throws {
        #expect(active == 0 && revisions == 1)
        try await base.publish(digest, expectedVersion: expectedVersion, at: address)
    }
}

@Test func uploadsAreBoundedAndFailuresCannotPublish() async throws {
    for mode in ["success", "failure", "cancel"] {
        let owner = try TestDevice(), root = try VaultEngine.create(name: "personal", owner: owner)
        let items = try (0..<9).map { n in
            VaultItem(name: "file-\(n)", fields: [.init(path: "file", type: .attachment,
                value: try Attachment(fileName: "file.bin", data: Data(repeating: UInt8(n), count: 128)).encodedValue())])
        }
        let proposal = try VaultEngine.importItems(items, revision: root.digest, in: root, device: owner)
        let address = try VaultAddress(container: "test", environment: "Development", account: "test", database: .private, owner: "test", vault: root.id)
        let transport = UploadProbe(root, fail: mode == "failure"), storage = MemoryVerifiedState()
        let coordinator = try PublicationCoordinator(address: address, checkpoint: root, transport: transport, storage: storage)
        let task = Task { try await coordinator.publish(proposal) }
        if mode == "cancel" {
            while await transport.started < 4 { await Task.yield() }
            task.cancel()
        }
        if mode == "success" {
            try await task.value
            #expect(await transport.finished == 9)
            #expect(await transport.base.publications == 1)
        } else {
            await #expect(throws: (any Error).self) { try await task.value }
            #expect(await transport.revisions == 0)
            #expect(await transport.base.publications == 0)
            #expect(storage.load(binding: address.binding)?.pending == nil)
        }
        #expect(await transport.active == 0)
        #expect(await transport.maximum == 4)
    }
}
