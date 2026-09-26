import Foundation
import Synchronization
import Testing
import MopCore
@testable import MopVaultNext

final class MemoryVerifiedState: VerifiedStateStore, Sendable {
    private let values = Mutex<[String: VerifiedState]>([:])
    func load(binding: String) -> VerifiedState? { values.withLock { $0[binding] } }
    func save(_ state: VerifiedState, binding: String) { values.withLock { $0[binding] = state } }
}

/// Model only: real CloudKit CAS is separately probed in cloud.swift.
actor MemoryRevisionTransport: RevisionTransport {
    enum Fault { case none, upload, lostAcknowledgement, beforeHead }
    let vault: UUID
    private var headDigest: String
    private var version = 1
    private var blobs: [String: Data]
    private var fault = Fault.none
    private(set) var publications = 0
    init(_ root: VerifiedVault) { vault = root.id; headDigest = root.digest; blobs = [root.digest: root.bytes] }
    func setFault(_ value: Fault) { fault = value }
    func head(at address: VaultAddress) throws -> RevisionHead {
        guard address.vault == vault else { throw MopError.vaultMissing }
        return RevisionHead(digest: headDigest, version: Data(String(version).utf8))
    }
    func revision(_ digest: String, at address: VaultAddress) throws -> Data {
        guard address.vault == vault, let bytes = blobs[digest] else { throw MopError.vaultMissing }; return bytes
    }
    func upload(_ bytes: Data, digest: String, at address: VaultAddress) throws {
        if fault == .upload { fault = .none; throw MopError.cloudUnavailable }
        guard address.vault == vault, Codec.digest(bytes) == digest,
              blobs[digest] == nil || blobs[digest] == bytes else { throw MopError.invalidVault }
        blobs[digest] = bytes
    }
    func publish(_ digest: String, expectedVersion: Data, at address: VaultAddress) throws {
        publications += 1
        if fault == .beforeHead { fault = .none; throw MopError.cloudUnavailable }
        guard address.vault == vault, blobs[digest] != nil else { throw MopError.invalidVault }
        guard expectedVersion == Data(String(version).utf8) else { throw MopError.vaultConflict }
        version += 1; headDigest = digest
        if fault == .lostAcknowledgement { fault = .none; throw MopError.cloudUnavailable }
    }
    func forceHead(_ revision: VerifiedVault) { blobs[revision.digest] = revision.bytes; headDigest = revision.digest; version += 1 }
}

private func address(_ vault: VerifiedVault, account: String = "account-a", shared: Bool = false) throws -> VaultAddress {
    try VaultAddress(container: "iCloud.example.mop", environment: "Development", account: account,
                     database: shared ? .shared : .private, owner: "zone-owner-record-id", vault: vault.id)
}

@Test func twoAccountConditionalWritesPreserveOneWinnerAndRejectRollback() async throws {
    let owner = try TestDevice(), editor = try TestDevice(), recovery = try TestDevice()
    let root = try VaultEngine.create(name: "shared", owner: owner, recovery: recovery.identity)
    let invitation = try VaultEngine.invite(member: editor.identity.member, role: .editor, to: root, owner: owner, expires: Date().addingTimeInterval(300))
    let acceptance = try Acceptance(invitation: invitation, expectedCheckpoint: root.digest, device: editor)
    let shared = try VaultEngine.approve(acceptance, expectedDeviceFingerprint: editor.identity.fingerprint, in: root, owner: owner)
    let transport = MemoryRevisionTransport(shared)
    let a = try PublicationCoordinator(address: address(shared), checkpoint: shared, transport: transport, storage: MemoryVerifiedState())
    let b = try PublicationCoordinator(address: address(shared, account: "account-b", shared: true), checkpoint: shared, transport: transport, storage: MemoryVerifiedState())
    let first = try VaultEngine.write("item/password", value: SecretBytes(utf8: "first"), in: shared, device: owner)
    let second = try VaultEngine.write("item/password", value: SecretBytes(utf8: "second"), in: shared, device: editor)
    func attempt(_ coordinator: PublicationCoordinator, _ proposal: VerifiedVault) async throws -> Bool {
        do { try await coordinator.publish(proposal); return true }
        catch MopError.vaultConflict { return false }
    }
    async let one = attempt(a, first)
    async let two = attempt(b, second)
    let results = try await [one, two]
    #expect(results.filter { $0 }.count == 1)
    _ = try await a.refresh(); _ = try await b.refresh()
    let aState = await a.offlineSnapshot().0, bState = await b.offlineSnapshot().0
    #expect(aState.digest == bState.digest)
    #expect([first.digest, second.digest].contains(aState.digest))
    await transport.forceHead(shared)
    await #expect(throws: MopError.vaultUntrusted) { try await a.refresh() }
    #expect(await a.offlineSnapshot().0.digest == aState.digest)
}

@Test func droppedAcknowledgementReconcilesAfterRelaunchWithoutReplay() async throws {
    let owner = try TestDevice(), recovery = try TestDevice()
    let root = try VaultEngine.create(name: "personal", owner: owner, recovery: recovery.identity)
    let transport = MemoryRevisionTransport(root), storage = MemoryVerifiedState()
    let coordinator = try PublicationCoordinator(address: address(root), checkpoint: root, transport: transport, storage: storage)
    let proposal = try VaultEngine.write("item/password", value: SecretBytes(utf8: "next"), in: root, device: owner)
    await transport.setFault(.lostAcknowledgement)
    await #expect(throws: MopError.cloudUncertain) { try await coordinator.publish(proposal) }
    #expect(await coordinator.offlineSnapshot().0.digest == root.digest)
    let relaunched = try PublicationCoordinator(address: address(root), checkpoint: root, transport: transport, storage: storage)
    await #expect(throws: MopError.cloudUncertain) { try await relaunched.publish(proposal) }
    #expect(try await relaunched.refresh() == .committed)
    #expect(await relaunched.offlineSnapshot().0.digest == proposal.digest)
    #expect(await transport.publications == 1)
}

@Test func unchangedHeadKeepsUncertainJournalAndAnotherWinnerResolvesIt() async throws {
    let owner = try TestDevice(), recovery = try TestDevice()
    let root = try VaultEngine.create(name: "personal", owner: owner, recovery: recovery.identity)
    let transport = MemoryRevisionTransport(root), storage = MemoryVerifiedState()
    let a = try PublicationCoordinator(address: address(root), checkpoint: root, transport: transport, storage: storage)
    let b = try PublicationCoordinator(address: address(root), checkpoint: root, transport: transport, storage: MemoryVerifiedState())
    let first = try VaultEngine.write("item/password", value: SecretBytes(utf8: "first"), in: root, device: owner)
    let second = try VaultEngine.write("item/password", value: SecretBytes(utf8: "second"), in: root, device: owner)
    await transport.setFault(.beforeHead)
    await #expect(throws: MopError.cloudUncertain) { try await a.publish(first) }
    #expect(try await a.refresh() == .pending)
    #expect(try storage.load(binding: address(root).binding)?.pending != nil)
    try await b.publish(second)
    #expect(try await a.refresh() == .abandoned)
    #expect(await a.offlineSnapshot().0.digest == second.digest)
    #expect(await transport.publications == 2)
}

@Test func interruptedStagingAndOfflineWritesDoNotPublish() async throws {
    let owner = try TestDevice(), recovery = try TestDevice()
    let root = try VaultEngine.create(name: "personal", owner: owner, recovery: recovery.identity)
    let transport = MemoryRevisionTransport(root), storage = MemoryVerifiedState()
    let coordinator = try PublicationCoordinator(address: address(root), checkpoint: root, transport: transport, storage: storage)
    let proposal = try VaultEngine.write("item/password", value: SecretBytes(utf8: "value"), in: root, device: owner)
    await #expect(throws: MopError.offlineWrite) { try await coordinator.publish(proposal, offline: true) }
    await transport.setFault(.upload)
    await #expect(throws: MopError.cloudUnavailable) { try await coordinator.publish(proposal) }
    #expect(await coordinator.offlineSnapshot().0.digest == root.digest)
    #expect(try storage.load(binding: address(root).binding)?.pending == nil)
    #expect(await transport.publications == 0)
    try await coordinator.publish(proposal)
    #expect(await coordinator.offlineSnapshot().0.digest == proposal.digest)
}

@Test func cacheBindingsSeparateAccountsDatabasesOwnersAndEnvironments() throws {
    let id = UUID()
    let base = try VaultAddress(container: "container", environment: "Development", account: "a", database: .private, owner: "owner", vault: id)
    let variants = try [
        VaultAddress(container: "container", environment: "Development", account: "b", database: .private, owner: "owner", vault: id),
        VaultAddress(container: "container", environment: "Development", account: "a", database: .shared, owner: "owner", vault: id),
        VaultAddress(container: "container", environment: "Production", account: "a", database: .private, owner: "owner", vault: id),
        VaultAddress(container: "container", environment: "Development", account: "a", database: .private, owner: "another-owner", vault: id)
    ]
    #expect(Set(([base] + variants).map(\.binding)).count == 5)
    #expect(throws: MopError.cloudInvalidRequest) {
        try VaultAddress(container: "container", environment: "Development", account: "a", database: .shared, owner: "__defaultOwner__", vault: id)
    }
}

@Test func explicitVersionBarrierResolvesAnUnchangedUncertainHead() async throws {
    let owner = try TestDevice(), recovery = try TestDevice()
    let root = try VaultEngine.create(name: "personal", owner: owner, recovery: recovery.identity)
    let transport = MemoryRevisionTransport(root), storage = MemoryVerifiedState()
    let coordinator = try PublicationCoordinator(address: address(root), checkpoint: root, transport: transport, storage: storage)
    let proposal = try VaultEngine.write("item/password", value: SecretBytes(utf8: "value"), in: root, device: owner)
    let oldHead = try await transport.head(at: address(root))
    await transport.setFault(.beforeHead)
    await #expect(throws: MopError.cloudUncertain) { try await coordinator.publish(proposal) }
    #expect(try await coordinator.refresh() == .pending)
    #expect(try await coordinator.refresh(reconcileUnchangedPending: true) == .abandoned)
    await #expect(throws: MopError.vaultConflict) { try await transport.publish(proposal.digest, expectedVersion: oldHead.version, at: address(root)) }
    #expect(await coordinator.offlineSnapshot().0.digest == root.digest)
    try await coordinator.publish(proposal) // Explicit new user attempt, now safe.
    #expect(await coordinator.offlineSnapshot().0.digest == proposal.digest)
}
