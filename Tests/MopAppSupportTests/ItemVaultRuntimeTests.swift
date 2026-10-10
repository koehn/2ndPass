import Foundation
import Synchronization
import Testing
import MopCore
import MopVaultNext
@testable import MopSync
@testable import MopAppSupport

final class MemoryItemInventory: ItemVaultInventoryStore, ItemVaultMembershipTrustStore {
    private let successors = Mutex<[String: [Data]]>([:])
    func membershipHistory(scope: ItemVaultSetupScope) throws -> [Data] {
        let key = try setupHash(setupEncode(scope)); return successors.withLock { $0[key] ?? [] }
    }
    func reserveMembership(scope: ItemVaultSetupScope, successors next: [Data]) throws {
        let key = try setupHash(setupEncode(scope))
        try successors.withLock { values in
            let existing = values[key] ?? []
            guard next.count >= existing.count, Array(next.prefix(existing.count)) == existing else { throw ItemVaultBootstrapFailure.invalidTrust }
            values[key] = next
        }
    }
    private let values = Mutex<[ItemVaultSetupRecord]>([])
    func load(scope: ItemVaultSetupScope) throws -> ItemVaultSetupRecord? { values.withLock { $0.first { $0.scope == scope } } }
    func reserve(_ candidate: ItemVaultSetupRecord) throws -> ItemVaultSetupRecord {
        values.withLock { records in
            if let existing = records.first(where: { $0.scope == candidate.scope }) { return existing }
            records.append(candidate); return candidate
        }
    }
    func records(container: String, environment: String, account: String) throws -> [ItemVaultSetupRecord] {
        values.withLock { $0.filter { $0.scope.container == container && $0.scope.environment == environment && $0.scope.binding.account == account } }
    }
}

private actor AdmissionHeadServer: VaultMembershipTransport {
    private var head: ProvisioningCloudRecord
    private var history: [String: Data] = [:]
    private(set) var headWrites = 0
    init(head: Data) { self.head = ProvisioningCloudRecord(bytes: head, systemFields: Data([1])) }
    func readHead(binding: VaultProvisioningBinding) async throws -> ProvisioningCloudRecord { head }
    func readMembership(binding: VaultProvisioningBinding, digest: String) async throws -> Data {
        guard let value = history[digest] else { throw VaultProvisioningError.controlMismatch }; return value
    }
    func createMembership(binding: VaultProvisioningBinding, digest: String, bytes: Data) async throws {
        if let existing = history[digest], existing != bytes { throw VaultProvisioningError.controlMismatch }
        history[digest] = bytes
    }
    func compareAndSwapHead(binding: VaultProvisioningBinding, bytes: Data, expected: ProvisioningCloudRecord) async throws -> ProvisioningCloudRecord {
        guard expected.bytes == head.bytes, expected.systemFields == head.systemFields else { throw VaultProvisioningError.controlMismatch }
        headWrites += 1
        head = ProvisioningCloudRecord(bytes: bytes, systemFields: Data([2]))
        throw URLError(.networkConnectionLost) // Cloud committed, response was lost.
    }
}

@Test func contentMembershipRecoversLostAcknowledgmentWhileLockedWithoutRewritingItems() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-content-membership-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let repository = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root), layout: .contentPreview3)
    let trust = MemoryItemInventory(), owner = try SessionDevice()
    let scope = ItemVaultSetupScope(container: "iCloud.test", environment: "Development",
        binding: ItemVaultBinding(account: "content-membership", database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
    let bootstrap = try ItemVaultBootstrap(repository: repository, trustStore: trust, scope: scope, device: SessionDevice(copying: owner))
    let session = try await bootstrap.create(name: "admitted")
    let operation = try #require(await repository.operations(account: scope.binding.account, database: "private").first { $0.kind == .provision })
    let provisioner = JournaledContentProvisioner(repository: repository, trustStore: trust, transport: DomainProvisionServer(), accountValidator: { true })
    guard case .completed = await provisioner.handle(operation, permit: DomainAccountAuthorization()) else { Issue.record("Provision failed"); return }
    let pin = try #require(try trust.load(scope: scope))
    let history = try ItemVaultMembershipAuthority.history(record: pin, trustStore: trust)
    let content = try #require(session.contentSession)
    let newcomer = try SessionDevice(member: owner.identity.member)
    let requestScope = EnrollmentScope(container: scope.container, environment: scope.environment, account: scope.binding.account,
        vault: scope.binding.vaultID, member: owner.identity.member)
    let request = try DeviceEnrollmentRequest.create(scope: requestScope, device: newcomer)
    let approval = try await content.prepareEnrollment(request, scope: requestScope, owner: DomainAccountAuthorization())
    let pending = try await repository.pendingMutations(account: scope.binding.account)
    let membership = try #require(await repository.operations(account: scope.binding.account, database: "private").first { $0.kind == .membership })
    session.lock()
    let server = AdmissionHeadServer(head: pin.genesis)
    let committed = Mutex<Int>(0)
    let publisher = JournaledContentMembership(repository: repository, trustStore: trust, transport: server, scope: scope,
        accountValidator: { true }, committed: { _ in committed.withLock { $0 += 1 } })
    guard case .completed = await publisher.handle(membership, permit: DomainAccountAuthorization()) else { Issue.record("Membership failed"); return }
    #expect(await server.headWrites == 1)
    #expect(try trust.membershipHistory(scope: scope).count == 1)
    #expect(try await repository.pendingMutations(account: scope.binding.account).map(\.version) == pending.map(\.version))
    #expect(try await repository.coordinationPublications(account: scope.binding.account) == [approval])
    let policy = try #require(await repository.contentRecipients(scope: scope.repositoryScope))
    #expect(policy.keyAuthority == (try GrantBackedContentStorage.recipientPolicy(history: history)).keyAuthority)
    #expect(policy.recipients.contains(newcomer.identity.fingerprint))
    #expect(try await repository.missingContentGrants(scope: scope.repositoryScope).count == 1)
    #expect(committed.withLock { $0 } == 1)
}

@Test func contentMembershipInboxPinsOnlyACommittedHeadAndReplaysOutOfOrder() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("membership-inbox-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let repository = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root), layout: .contentPreview3)
    let owner = try SessionDevice(), one = try SessionDevice(member: owner.identity.member), two = try SessionDevice(member: owner.identity.member)
    let trust = MemoryItemInventory(), scope = ItemVaultSetupScope(container: "iCloud.test", environment: "Development",
        binding: ItemVaultBinding(account: "membership-inbox", database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
    let session = try await ItemVaultBootstrap(repository: repository, trustStore: trust, scope: scope, device: SessionDevice(copying: owner)).create(name: "test")
    let pin = try #require(try trust.load(scope: scope)), genesis = try MembershipEnvelope.decode(pin.genesis)
    let first = try MembershipEnvelope.successor(of: genesis,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, one.identity])]), owner: owner)
    let second = try MembershipEnvelope.successor(of: first,
        membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, one.identity, two.identity])]), owner: owner)
    func incoming(_ value: MembershipEnvelope, head: Bool) throws -> IncomingRecord {
        let bytes = try value.encoded()
        return IncomingRecord(id: UUID().uuidString, account: scope.binding.account, database: "private",
            zoneName: SyncStoreLayout.contentZone(vault: scope.binding.vaultID), zoneOwner: "__defaultOwner__",
            recordName: head ? "membership-head" : "membership-" + (try value.digest()),
            recordType: NativeVaultProvisioningTransport.recordType, bytes: bytes, systemFields: Data([1]), vaultID: scope.binding.vaultID)
    }
    let head = try incoming(second, head: true), parent = try incoming(first, head: false)
    func operation(_ value: IncomingRecord) -> SyncOperation {
        SyncOperation(id: value.operationID, account: value.account, vaultID: value.vaultID, kind: .applyIncoming, payload: Data(value.id.utf8))
    }
    let handler = GrantBackedMembershipInbox(repository: repository, trustStore: trust, record: pin, committed: { _ in })
    session.lock(); owner.close()
    try await repository.stageIncoming(head, permit: DomainAccountAuthorization())
    guard case .retry(.dependency, _) = await handler.handle(operation(head), permit: DomainAccountAuthorization()) else { Issue.record("Missing parent must defer"); return }
    #expect(try trust.membershipHistory(scope: scope).isEmpty)
    #expect(try await repository.operations(account: scope.binding.account, database: "private").contains { $0.kind == .fetchMembership })
    try await repository.stageIncoming(parent, permit: DomainAccountAuthorization())
    guard case .retry(.dependency, _) = await handler.handle(operation(parent), permit: DomainAccountAuthorization()) else { Issue.record("Uncommitted candidate must stay in the bounded inbox"); return }
    #expect(try trust.membershipHistory(scope: scope).isEmpty)
    guard case .completed = await handler.handle(operation(head), permit: DomainAccountAuthorization()) else { Issue.record("Committed chain did not apply"); return }
    #expect(try trust.membershipHistory(scope: scope) == [first.encoded(), second.encoded()])
    let stale = try incoming(genesis, head: true)
    try await repository.stageIncoming(stale, permit: DomainAccountAuthorization())
    guard case .completed = await handler.handle(operation(stale), permit: DomainAccountAuthorization()) else { Issue.record("Historical head should be harmless"); return }
    #expect(try trust.membershipHistory(scope: scope).count == 2)
    #expect(owner.unwrapCount == 0)
}
