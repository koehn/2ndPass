import CryptoKit
import Foundation
import Synchronization
import Testing
@testable import MopSync

private enum ProvisionTestError: Error { case lostAcknowledgement, denied }
private final class ProvisionPermit: RepositoryWritePermit {
    private let allowed = Mutex(true)
    func revoke() { allowed.withLock { $0 = false } }
    func withWritePermission<T>(_ body: () throws -> T) throws -> T {
        guard allowed.withLock({ $0 }) else { throw ProvisionTestError.denied }
        return try body()
    }
}
private actor ProvisionServer: VaultProvisioningTransport {
    var zone = false
    var records: [String: ProvisioningCloudRecord] = [:]
    var creates = 0
    var controlCreates = 0
    var loseNextControlAcknowledgement = false
    var missingOnRead = false
    var transientOnRead = false
    var hold = false
    var suspended: CheckedContinuation<Void, Never>?
    var arrival: CheckedContinuation<Void, Never>?
    func setLostAcknowledgement() { loseNextControlAcknowledgement = true }
    func deleteZone() { zone = false; records = [:] }
    func corruptHead() { records["head"] = ProvisioningCloudRecord(bytes: Data([99]), systemFields: Data([9])) }
    func setReadFailure(missing: Bool) { missingOnRead = missing; transientOnRead = !missing }
    func holdNextCheck() { hold = true }
    func waitForSuspension() async {
        if suspended != nil { return }
        await withCheckedContinuation { arrival = $0 }
    }
    func release() { suspended?.resume(); suspended = nil }
    func zoneExists(binding: VaultProvisioningBinding) async throws -> Bool {
        if hold {
            hold = false
            await withCheckedContinuation { suspended = $0; arrival?.resume(); arrival = nil }
        }
        return zone
    }
    func createZone(binding: VaultProvisioningBinding) async throws { creates += 1; zone = true }
    private func key(_ kind: VaultControlRecordKind) -> String { switch kind { case .genesis: "genesis"; case .head: "head" } }
    func readControl(_ kind: VaultControlRecordKind, binding: VaultProvisioningBinding) async throws -> ProvisioningCloudRecord? {
        if missingOnRead { throw VaultProvisioningError.zoneMissing }
        if transientOnRead { throw ProvisionTestError.lostAcknowledgement }
        return records[key(kind)]
    }
    func createControl(_ kind: VaultControlRecordKind, binding: VaultProvisioningBinding, bytes: Data) async throws -> ProvisioningCloudRecord {
        controlCreates += 1
        let value = records[key(kind)] ?? ProvisioningCloudRecord(bytes: bytes, systemFields: Data([UInt8(controlCreates)]))
        records[key(kind)] = value
        if loseNextControlAcknowledgement { loseNextControlAcknowledgement = false; throw ProvisionTestError.lostAcknowledgement }
        return value
    }
}
private struct ProvisionFixture {
    let directory: URL
    let repository: EncryptedItemRepository
    let binding: VaultProvisioningBinding
    let control = Data([1, 2, 3])
    let permit = ProvisionPermit()
    let accountPermit = ProvisionPermit()
    let server = ProvisionServer()
    func coordinator(repository replacement: EncryptedItemRepository? = nil, account: @escaping CloudAccountValidator = { true }) -> VaultProvisioningCoordinator {
        VaultProvisioningCoordinator(repository: replacement ?? repository, transport: server,
            leaseURL: directory.appendingPathComponent("lease.lock"), accountValidator: account, accountAuthorization: accountPermit)
    }
}
private func provisioningFixture() async throws -> ProvisionFixture {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-provisioning-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
    let scope = VaultScope(account: "account", vaultID: UUID())
    let control = Data([1, 2, 3])
    let binding = VaultProvisioningBinding(scope: scope, address: VaultCloudAddress(vaultID: scope.vaultID, zoneName: "vault-zone", ownerName: scope.zoneOwner),
        setupID: "setup", controlDigest: SHA256.hash(data: control).map { String(format: "%02x", $0) }.joined())
    let fixture = ProvisionFixture(directory: directory, repository: repository, binding: binding)
    let item = EncryptedItemVersion(scope: ItemScope(account: scope.account, vaultID: scope.vaultID, itemID: UUID()), baseVersionID: nil, ciphertext: Data([4]))
    _ = try await repository.initializeVault(scope: scope, versions: [item], membershipState: control, setupID: "setup", authorization: fixture.permit)
    return fixture
}

@Test func provisioningLostAcknowledgementResumesWithSameControlAndNoDuplicateCreation() async throws {
    let f = try await provisioningFixture()
    defer { try? FileManager.default.removeItem(at: f.directory) }
    await f.server.setLostAcknowledgement()
    await #expect(throws: ProvisionTestError.lostAcknowledgement) {
        try await f.coordinator().provision(binding: f.binding, controlBytes: f.control, authorization: f.permit) { _, _ in }
    }
    #expect(try await f.repository.provisioning(f.binding.scope)?.phase == .commissioningStarted)
    let reopened = try EncryptedItemRepository(storeURL: f.directory.appendingPathComponent("items.sqlite"))
    let result = try await f.coordinator(repository: reopened).provision(binding: f.binding, controlBytes: f.control, authorization: f.permit) { _, _ in }
    #expect(result.phase == .controlConfirmed && result.headSystemFields != nil)
    #expect(await f.server.creates == 1)
    #expect(await f.server.controlCreates == 2)
    #expect(try await reopened.pendingMutations(account: f.binding.scope.account).count == 1)
}

@Test func commissionedZoneLossNeverRecreatesIt() async throws {
    let f = try await provisioningFixture()
    defer { try? FileManager.default.removeItem(at: f.directory) }
    let coordinator = f.coordinator()
    _ = try await coordinator.provision(binding: f.binding, controlBytes: f.control, authorization: f.permit) { _, _ in }
    await f.server.deleteZone()
    await #expect(throws: VaultProvisioningError.zoneMissing) {
        try await coordinator.provision(binding: f.binding, controlBytes: f.control, authorization: f.permit) { _, _ in }
    }
    #expect(await f.server.creates == 1)
    #expect(try await f.repository.provisioning(f.binding.scope)?.phase == .blocked)
    await #expect(throws: VaultProvisioningError.blocked) {
        try await coordinator.provision(binding: f.binding, controlBytes: f.control, authorization: f.permit) { _, _ in }
    }
}

@Test func provisioningLateTransportResponseCannotAdvanceAfterStopOrLock() async throws {
    for interruption in ["stop", "lock", "account"] {
        let f = try await provisioningFixture()
        defer { try? FileManager.default.removeItem(at: f.directory) }
        await f.server.holdNextCheck()
        let coordinator = f.coordinator()
        let operation = Task { try await coordinator.provision(binding: f.binding, controlBytes: f.control, authorization: f.permit) { _, _ in } }
        await f.server.waitForSuspension()
        switch interruption {
        case "lock": f.permit.revoke()
        case "account": f.accountPermit.revoke()
        default: await coordinator.stop()
        }
        await f.server.release()
        await #expect(throws: (any Error).self) { try await operation.value }
        #expect(await f.server.creates == 0)
        #expect(try await f.repository.provisioning(f.binding.scope)?.phase == .prepared)
    }
}

@Test func changedConfirmedControlPermanentlyBlocksWithoutRepairingIt() async throws {
    let f = try await provisioningFixture()
    defer { try? FileManager.default.removeItem(at: f.directory) }
    let coordinator = f.coordinator()
    _ = try await coordinator.provision(binding: f.binding, controlBytes: f.control, authorization: f.permit) { _, _ in }
    await f.server.corruptHead()
    await #expect(throws: VaultProvisioningError.controlMismatch) {
        try await coordinator.provision(binding: f.binding, controlBytes: f.control, authorization: f.permit) { _, _ in }
    }
    #expect(try await f.repository.provisioning(f.binding.scope)?.phase == .blocked)
    #expect(await f.server.controlCreates == 2)
}

@Test func publicationGateRequiresConfirmedExactAuthorityAndScope() async throws {
    let f = try await provisioningFixture()
    defer { try? FileManager.default.removeItem(at: f.directory) }
    let validator: CloudControlValidator = { binding, bytes in
        guard binding == f.binding, bytes == f.control else { throw ProvisionTestError.denied }
    }
    func ready(_ account: String = "account", _ database: String = "private", _ address: VaultCloudAddress? = nil,
               _ verification: CloudControlValidator? = validator) async throws -> Bool {
        try await VaultPublicationGate.isReady(f.binding.scope, repository: f.repository, account: account,
            database: database, addresses: [address ?? f.binding.address], validator: verification)
    }
    #expect(try await !ready())
    let prepared = try await f.repository.prepareProvisioning(binding: f.binding, controlBytes: f.control, authorization: f.permit)
    #expect(try await !ready())
    try await f.server.createZone(binding: f.binding)
    _ = try await f.repository.advanceProvisioning(prepared, to: .commissioningStarted, authorization: f.permit)
    #expect(try await !ready())
    let confirmed = try await f.coordinator().provision(binding: f.binding, controlBytes: f.control, authorization: f.permit) { _, _ in }
    #expect(try await ready())
    #expect(try await !ready("other-account"))
    #expect(try await !ready("account", "shared"))
    #expect(try await !ready("account", "private", VaultCloudAddress(vaultID: f.binding.scope.vaultID, zoneName: "wrong-zone", ownerName: f.binding.scope.zoneOwner)))
    #expect(try await !ready("account", "private", nil, nil))
    _ = try await f.repository.advanceProvisioning(confirmed, to: .blocked, authorization: f.permit)
    #expect(try await !ready())
}

@Test func provisioningSeparatesDeletedZoneDuringReadFromTransientTransportFailure() async throws {
    for missing in [false, true] {
        let f = try await provisioningFixture()
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let coordinator = f.coordinator()
        _ = try await coordinator.provision(binding: f.binding, controlBytes: f.control, authorization: f.permit) { _, _ in }
        await f.server.setReadFailure(missing: missing)
        await #expect(throws: (any Error).self) {
            try await coordinator.provision(binding: f.binding, controlBytes: f.control, authorization: f.permit) { _, _ in }
        }
        #expect(try await f.repository.provisioning(f.binding.scope)?.phase == (missing ? .blocked : .controlConfirmed))
        #expect(await f.server.creates == 1)
        #expect(await f.server.controlCreates == 2)
    }
}

@Test func provisioningRejectsMismatchedAddressAndAccountBeforeCloudWrites() async throws {
    let f = try await provisioningFixture()
    defer { try? FileManager.default.removeItem(at: f.directory) }
    let wrong = VaultProvisioningBinding(scope: f.binding.scope,
        address: VaultCloudAddress(vaultID: UUID(), zoneName: "wrong", ownerName: "other-owner"), setupID: f.binding.setupID, controlDigest: f.binding.controlDigest)
    await #expect(throws: VaultProvisioningError.invalidBinding) {
        try await f.coordinator().provision(binding: wrong, controlBytes: f.control, authorization: f.permit) { _, _ in }
    }
    await #expect(throws: VaultProvisioningError.operationInterrupted) {
        try await f.coordinator(account: { false }).provision(binding: f.binding, controlBytes: f.control, authorization: f.permit) { _, _ in }
    }
    #expect(await f.server.creates == 0)
    #expect(await f.server.controlCreates == 0)
    #expect(try await f.repository.provisioning(f.binding.scope) == nil)
}

@Test func admissionJournalResumesAtomicallyWithoutPublishingBeforeHeadConfirmation() async throws {
    let f = try await provisioningFixture()
    defer { try? FileManager.default.removeItem(at: f.directory) }
    _ = try await f.coordinator().provision(binding: f.binding, controlBytes: f.control, authorization: f.permit) { _, _ in }
    let pending = try #require(try await f.repository.pendingMutations(account: f.binding.scope.account).first)
    try await f.repository.acknowledge(mutationID: pending.id, account: f.binding.scope.account, serverSystemFields: Data([7]))
    let original = pending.version
    let replacement = EncryptedItemVersion(scope: original.scope, baseVersionID: original.versionID, ciphertext: Data([8]), generation: 2)
    let request = UUID(), expected = [original.scope.itemID: original.versionID]
    let plan = try await f.repository.prepareAdmission(scope: f.binding.scope, requestID: request, approval: Data([10]),
        parentControl: f.control, successorControl: Data([11]), expectedVersions: expected, versions: [replacement], authorization: f.permit)
    #expect(try await f.repository.item(original.scope) == original)
    #expect(try await f.repository.pendingMutations(account: original.scope.account).isEmpty)
    await #expect(throws: ItemRepositoryError.pendingLocalChanges) { try await f.repository.commitLocalMutation(replacement) }
    let reopened = try EncryptedItemRepository(storeURL: f.directory.appendingPathComponent("items.sqlite"))
    #expect(try await reopened.admission(scope: f.binding.scope) == plan)
    let retried = try await reopened.prepareAdmission(scope: f.binding.scope, requestID: request, approval: Data([10]),
        parentControl: f.control, successorControl: Data([11]), expectedVersions: expected, versions: [replacement], authorization: f.permit)
    #expect(retried == plan)
    await #expect(throws: ItemRepositoryError.pendingLocalChanges) {
        try await reopened.prepareAdmission(scope: f.binding.scope, requestID: UUID(), approval: Data([12]),
            parentControl: f.control, successorControl: Data([11]), expectedVersions: expected, versions: [replacement], authorization: f.permit)
    }
    let denied = ProvisionPermit(); denied.revoke()
    await #expect(throws: ProvisionTestError.denied) {
        try await reopened.completeAdmission(plan, headSystemFields: Data([13]), authorization: denied)
    }
    #expect(try await reopened.item(original.scope) == original)
    let complete = try await reopened.completeAdmission(plan, headSystemFields: Data([13]), authorization: f.permit)
    #expect(complete.phase == .complete)
    #expect(try await reopened.completeAdmission(plan, headSystemFields: Data([13]), authorization: f.permit) == complete)
    #expect(try await reopened.item(original.scope) == replacement)
    #expect(try await reopened.pendingMutations(account: original.scope.account).count == 1)
    #expect(try await reopened.provisioning(f.binding.scope)?.controlBytes == Data([11]))
}
