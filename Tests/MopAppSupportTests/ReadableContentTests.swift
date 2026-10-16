import CloudKit
import Foundation
import Testing
import Synchronization
import MopCore
import MopVaultNext
@testable import MopSync
@testable import MopAppSupport

private struct ReadablePermit: RepositoryWritePermit {
    func withWritePermission<T>(_ body: () throws -> T) throws -> T { try body() }
}

@Suite struct ReadableContentTests {
    @Test(arguments: [false, true]) func arrivalOrdersSurviveRestartAndKeepOldReads(grantFirst: Bool) async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = SyncStoreLayout.contentPreviewURL(in: root)
        let repository = try EncryptedItemRepository(storeURL: url)
        let owner = try SessionDevice(), vault = try sessionAuthority(owner: owner)
        let genesis = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
        let history = try TrustedMembershipHistory(genesis: genesis, vault: vault.id, pinnedDigest: genesis.digest())
        let binding = ItemVaultBinding(account: "readable", database: "private", zoneOwner: "__defaultOwner__", vaultID: vault.id)
        try await GrantBackedContentStorage(repository: repository).setAuthority(scope: VaultScope(binding.item(UUID())), expected: nil, history: history, authorization: ReadablePermit())
        let session = try GrantBackedContentSession(repository: repository, binding: binding, history: history, device: SessionDevice(copying: owner))
        let item = UUID(), component = UUID().uuidString
        let created = try await session.create(item: item, components: [component: SecretBytes(utf8: "kept")])
        let initial = try #require(await repository.item(binding.item(item)))
        let envelope = try ContentEnvelope.decode(initial.ciphertext, history: history, item: item)
        let original = try await (envelope, session.grant(for: envelope))
        #expect(try await repository.readableContent(scope: binding.item(item), recipient: owner.identity.fingerprint) == nil)
        try await GrantBackedContentStorage(repository: repository).initializeReadableVersions(scope: VaultScope(binding.item(item)), history: history, permit: ReadablePermit())
        let oldID = original.0.header.version
        #expect(try await repository.readableContent(scope: binding.item(item), recipient: owner.identity.fingerprint)?.version == oldID)
        _ = created
        let rotated = try original.0.rotateKey(grant: original.1, history: history, decryptor: owner, signer: owner)
        let prepared = try GrantBackedContentStorage.prepare(rotated, scope: binding.item(item), history: history)
        let ownGrant = try #require(prepared.grants.first { $0.recipient == owner.identity.fingerprint })
        let grantRecord = try ContentRecordTransport.grant(ownGrant)
        let grantInput = try ContentRecordTransport.materialize(grantRecord, account: binding.account)
        let headInput = try ContentRecordTransport.materialize(ContentRecordTransport.content(prepared.content, kind: .head), account: binding.account)
        let inbox = GrantBackedContentInbox(repository: repository, account: binding.account)
        if grantFirst {
            try await repository.stageIncoming(grantInput, permit: ReadablePermit())
            let outcome = try await inbox.process(id: grantInput.id, history: history, permit: ReadablePermit())
            if case .waiting = outcome {} else { Issue.record("Grant must await its content") }
        }
        try await repository.stageIncoming(headInput, permit: ReadablePermit())
        if case .completed = try await inbox.process(id: headInput.id, history: history, permit: ReadablePermit()) {} else { Issue.record("Head was not applied") }
        #expect(try await session.lastReadable(item: item).0.header.version == oldID)
        #expect(String(decoding: try await session.open(item: item, component: component, expected: oldID).validatedUTF8(), as: UTF8.self) == "kept")
        await #expect(throws: ItemRepositoryError.staleLocalVersion) {
            try await session.edit(item: item, expected: oldID, components: [component: SecretBytes(utf8: "stale")])
        }
        session.lock()
        let reopened = try EncryptedItemRepository(storeURL: url)
        let unwrapCounter = SessionUnwrapCounter()
        let resumed = try GrantBackedContentSession(repository: reopened, binding: binding, history: history, device: SessionDevice(copying: owner, unwrapCounter: unwrapCounter))
        #expect(try await resumed.lastReadable(item: item).0.header.version == oldID)
        let resumedInbox = GrantBackedContentInbox(repository: reopened, account: binding.account)
        if !grantFirst { try await reopened.stageIncoming(grantInput, permit: ReadablePermit()) }
        if case .completed = try await resumedInbox.process(id: grantInput.id, history: history, permit: ReadablePermit()) {} else { Issue.record("Grant was not applied") }
        #expect(try await resumed.lastReadable(item: item).0.header.version == rotated.content.header.version)
        #expect(try await reopened.readableContent(scope: binding.item(item), recipient: owner.identity.fingerprint)?.version == oldID)
        await #expect(throws: MopError.invalidVault) {
            try await resumed.projectReadable(item: item) { _, _, _ -> Int in throw MopError.invalidVault }
        }
        #expect(try await reopened.readableContent(scope: binding.item(item), recipient: owner.identity.fingerprint)?.version == oldID)
        unwrapCounter.failure.withLock { $0 = .authentication }
        await #expect(throws: MopError.authentication) {
            try await resumed.open(item: item, component: component, expected: rotated.content.header.version)
        }
        #expect(try await reopened.readableContent(scope: binding.item(item), recipient: owner.identity.fingerprint)?.version == oldID)
        unwrapCounter.failure.withLock { $0 = nil }
        _ = try await resumed.open(item: item, component: component, expected: rotated.content.header.version)
        #expect(try await reopened.readableContent(scope: binding.item(item), recipient: owner.identity.fingerprint)?.version == rotated.content.header.version)
        #expect(try await reopened.contentVersion(scope: binding.item(item), version: oldID) != nil)
        resumed.lock()
    }

    @Test func grantZoneRecipientMustMatchSignedRecipient() async throws {
        let owner = try SessionDevice(), vault = try sessionAuthority(owner: owner)
        let genesis = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
        let history = try TrustedMembershipHistory(genesis: genesis, vault: vault.id, pinnedDigest: genesis.digest())
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
        let scope = ItemScope(account: "binding", vaultID: vault.id, itemID: UUID())
        try await GrantBackedContentStorage(repository: repository).setAuthority(scope: VaultScope(scope), expected: nil, history: history, authorization: ReadablePermit())
        let publication = try ContentEnvelope.seal(["x": SecretBytes(utf8: "x")], vault: vault.id, item: scope.itemID, history: history, signer: owner)
        let prepared = try GrantBackedContentStorage.prepare(publication, scope: scope, history: history)
        let grant = prepared.grants[0]
        let badZone = try RecipientGrantZone(vault: vault.id, recipient: String(repeating: "f", count: 64)).name
        let incoming = IncomingRecord(id: UUID().uuidString, account: scope.account, database: "private", zoneName: badZone,
            zoneOwner: scope.zoneOwner, recordName: scope.itemID.uuidString + ":" + grant.identifier,
            recordType: ContentRecordKind.grant.rawValue, bytes: grant.bytes, systemFields: Data(), vaultID: vault.id)
        try await repository.stageIncoming(incoming, permit: ReadablePermit())
        if case .attention(.invalidAuthority) = try await GrantBackedContentInbox(repository: repository, account: scope.account)
            .process(id: incoming.id, history: history, permit: ReadablePermit()) {} else { Issue.record("Wrong recipient zone accepted") }
    }
}

extension ReadableContentTests {
    @Test func recoveryRetainsReadablePairUntilItsOwnGrantArrives() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
        let recoveryScope = try RecoveryScope(container: "test-container", environment: "Development", account: "recovery-routing")
        let owner = try SessionDevice(member: recoveryScope.member), recovery = try OfflineRecoveryKey(scope: recoveryScope)
        defer { recovery.close() }
        let vault = UUID(), item = UUID()
        let membership = try Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity])], offlineRecovery: recovery.identity)
        let genesis = try MembershipEnvelope.genesis(vault: vault, membership: membership, owner: owner)
        let history = try TrustedMembershipHistory(genesis: genesis, vault: vault, pinnedDigest: genesis.digest())
        let scope = ItemScope(account: "recovery-routing", vaultID: vault, itemID: item)
        let storage = GrantBackedContentStorage(repository: repository)
        try await storage.setAuthority(scope: VaultScope(scope), expected: nil, history: history, authorization: ReadablePermit())
        let initial = try ContentEnvelope.seal(["value": SecretBytes(utf8: "recoverable")], vault: vault, item: item, history: history, signer: owner)
        _ = try await storage.commit(initial.content, grants: initial.grants, scope: scope, history: history, authorization: ReadablePermit())
        try await storage.initializeReadableVersions(scope: VaultScope(scope), history: history, permit: ReadablePermit())
        let own = try #require(initial.grants.first { $0.recipient == owner.identity.fingerprint })
        let rotated = try initial.content.rotateKey(grant: own, history: history, decryptor: owner, signer: owner)
        let prepared = try GrantBackedContentStorage.prepare(rotated, scope: scope, history: history)
        let head = try ContentRecordTransport.materialize(ContentRecordTransport.content(prepared.content, kind: .head), account: scope.account)
        try await repository.stageIncoming(head, permit: ReadablePermit())
        let inbox = GrantBackedContentInbox(repository: repository, account: scope.account)
        if case .completed = try await inbox.process(id: head.id, history: history, permit: ReadablePermit()) {} else { Issue.record("Head not applied") }
        let pair = try await storage.readablePair(scope: scope, history: history, recipient: recovery.identity.fingerprint)
        #expect(pair.0.header.version == initial.content.header.version)
        #expect(String(decoding: try pair.0.open(component: "value", grant: pair.1, history: history, device: recovery).validatedUTF8(), as: UTF8.self) == "recoverable")
        let grant = try #require(prepared.grants.first { $0.recipient == recovery.identity.fingerprint })
        let incoming = try ContentRecordTransport.materialize(ContentRecordTransport.grant(grant), account: scope.account)
        try await repository.stageIncoming(incoming, permit: ReadablePermit())
        if case .completed = try await inbox.process(id: incoming.id, history: history, permit: ReadablePermit()) {} else { Issue.record("Recovery grant not applied") }
        let updated = try await storage.readablePair(scope: scope, history: history, recipient: recovery.identity.fingerprint)
        #expect(updated.0.header.version == rotated.content.header.version)
        var revoked = history
        try revoked.append(MembershipEnvelope.successor(of: genesis,
            membership: Membership(accounts: membership.accounts, offlineRecovery: nil), owner: owner))
        await #expect(throws: MopError.notVaultMember) {
            try await storage.readablePair(scope: scope, history: revoked, recipient: recovery.identity.fingerprint)
        }
    }
}

private struct ReadableBootstrapFixture {
    let root: URL
    let url: URL
    let repository: EncryptedItemRepository
    let owner: SessionDevice
    let history: TrustedMembershipHistory
    let scope: ItemScope

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        url = SyncStoreLayout.contentPreviewURL(in: root)
        repository = try EncryptedItemRepository(storeURL: url)
        owner = try SessionDevice()
        let vault = try sessionAuthority(owner: owner)
        let genesis = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
        history = try TrustedMembershipHistory(genesis: genesis, vault: vault.id, pinnedDigest: genesis.digest())
        scope = ItemScope(account: "readable-bootstrap", vaultID: vault.id, itemID: UUID())
    }

    func seed() async throws -> ContentPublication {
        let storage = GrantBackedContentStorage(repository: repository)
        try await storage.setAuthority(scope: VaultScope(scope), expected: nil, history: history, authorization: ReadablePermit())
        let publication = try ContentEnvelope.seal(["value": SecretBytes(utf8: "preserved")],
            vault: scope.vaultID, item: scope.itemID, history: history, signer: owner)
        _ = try await storage.commit(publication.content, grants: publication.grants, scope: scope,
            history: history, authorization: ReadablePermit())
        return publication
    }
}

extension ReadableContentTests {
    @Test func completedInitializationSkipsFullScanOnSyncAndRelaunch() async throws {
        let fixture = try ReadableBootstrapFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let publication = try await fixture.seed()
        let scope = VaultScope(fixture.scope), storage = GrantBackedContentStorage(repository: fixture.repository)
        let before = await fixture.repository.itemRevisionIndexReads
        try await storage.initializeReadableVersions(scope: scope, history: fixture.history, permit: ReadablePermit())
        #expect(await fixture.repository.itemRevisionIndexReads == before + 1)
        #expect(try await fixture.repository.readableVersionsInitialized(scope: scope))
        let reference = try #require(await fixture.repository.readableContent(scope: fixture.scope, recipient: fixture.owner.identity.fingerprint))
        #expect(reference.version == publication.content.header.version)

        // Same entry point used by pending-change registration and fetch routing.
        for _ in 0..<5 {
            try await storage.initializeReadableVersions(scope: scope, history: fixture.history, permit: ReadablePermit())
        }
        #expect(await fixture.repository.itemRevisionIndexReads == before + 1)
        let reopened = try EncryptedItemRepository(storeURL: fixture.url)
        let restarted = GrantBackedContentStorage(repository: reopened)
        for _ in 0..<3 {
            try await restarted.initializeReadableVersions(scope: scope, history: fixture.history, permit: ReadablePermit())
        }
        #expect(await reopened.itemRevisionIndexReads == 0)
        #expect(try await reopened.readableContent(scope: fixture.scope, recipient: fixture.owner.identity.fingerprint) == reference)
        #expect(try await !reopened.readableVersionsInitialized(scope: VaultScope(ItemScope(account: "other", vaultID: scope.vaultID, itemID: UUID()))))
        #expect(try await !reopened.readableVersionsInitialized(scope: VaultScope(ItemScope(account: scope.account, vaultID: UUID(), itemID: UUID()))))

        // New items still establish references through normal authenticated reads;
        // completion is not authorization and does not freeze the readable index.
        let binding = ItemVaultBinding(account: scope.account, database: scope.database, zoneOwner: scope.zoneOwner, vaultID: scope.vaultID)
        let session = try GrantBackedContentSession(repository: reopened, binding: binding, history: fixture.history, device: SessionDevice(copying: fixture.owner))
        let newItem = UUID()
        let created = try await session.create(item: newItem, components: ["value": SecretBytes(utf8: "new")])
        _ = try await session.open(item: newItem, component: "value", expected: created.version.versionID)
        #expect(try await reopened.readableContent(scope: binding.item(newItem), recipient: fixture.owner.identity.fingerprint)?.version == created.version.versionID)
        try await restarted.initializeReadableVersions(scope: scope, history: fixture.history, permit: ReadablePermit())
        #expect(await reopened.itemRevisionIndexReads == 0)
        session.lock()
    }

    @Test func bootstrapPreservesExistingReferenceEvenWhenNewerHeadHasGrants() async throws {
        let fixture = try ReadableBootstrapFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let initial = try await fixture.seed()
        let grant = try #require(initial.grants.first { $0.recipient == fixture.owner.identity.fingerprint })
        let old = try ReadableContentReference(version: initial.content.header.version, keyGeneration: initial.content.header.keyGeneration,
            grant: grant.identifier, recipient: grant.recipient)
        try await fixture.repository.rememberReadableContent(scope: fixture.scope, reference: old,
            expectedHead: initial.content.header.version, permit: ReadablePermit())
        let rotated = try initial.content.rotateKey(grant: grant, history: fixture.history, decryptor: fixture.owner, signer: fixture.owner)
        let storage = GrantBackedContentStorage(repository: fixture.repository)
        _ = try await storage.commit(rotated.content, grants: rotated.grants, scope: fixture.scope,
            history: fixture.history, authorization: ReadablePermit())
        try await storage.initializeReadableVersions(scope: VaultScope(fixture.scope), history: fixture.history, permit: ReadablePermit())
        #expect(try await fixture.repository.readableContent(scope: fixture.scope, recipient: grant.recipient) == old)

        // An initializer racing a reader also cannot replace its existing reference.
        let newerGrant = try #require(rotated.grants.first { $0.recipient == grant.recipient })
        let newer = try ReadableContentReference(version: rotated.content.header.version, keyGeneration: rotated.content.header.keyGeneration,
            grant: newerGrant.identifier, recipient: newerGrant.recipient)
        try await fixture.repository.rememberReadableContent(scope: fixture.scope, reference: newer,
            expectedHead: rotated.content.header.version, onlyIfAbsent: true, permit: ReadablePermit())
        #expect(try await fixture.repository.readableContent(scope: fixture.scope, recipient: grant.recipient) == old)
        // Normal verified-read promotion is still allowed.
        try await fixture.repository.rememberReadableContent(scope: fixture.scope, reference: newer,
            expectedHead: rotated.content.header.version, permit: ReadablePermit())
        #expect(try await fixture.repository.readableContent(scope: fixture.scope, recipient: grant.recipient) == newer)
    }

    @Test func interruptedInitializationDoesNotPersistCompletionAndRetriesAfterRestart() async throws {
        let fixture = try ReadableBootstrapFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        _ = try await fixture.seed()
        let scope = VaultScope(fixture.scope)
        let cancelled = Task { [repository = fixture.repository] in
            withUnsafeCurrentTask { $0?.cancel() }
            try await repository.finishReadableVersionInitialization(scope: scope, permit: ReadablePermit())
        }
        await #expect(throws: CancellationError.self) { try await cancelled.value }
        #expect(try await !fixture.repository.readableVersionsInitialized(scope: scope))
        // Permit initial authorization and reference insertion, then revoke access
        // before the completion transaction. Partial references must remain usable.
        let permit = ReadableWriteBudgetPermit()
        await #expect(throws: MopError.authentication) {
            try await GrantBackedContentStorage(repository: fixture.repository)
                .initializeReadableVersions(scope: scope, history: fixture.history, permit: permit)
        }
        #expect(try await !fixture.repository.readableVersionsInitialized(scope: scope))
        let reference = try #require(await fixture.repository.readableContent(scope: fixture.scope, recipient: fixture.owner.identity.fingerprint))
        let reopened = try EncryptedItemRepository(storeURL: fixture.url)
        try await GrantBackedContentStorage(repository: reopened)
            .initializeReadableVersions(scope: scope, history: fixture.history, permit: ReadablePermit())
        #expect(try await reopened.readableVersionsInitialized(scope: scope))
        #expect(try await reopened.readableContent(scope: fixture.scope, recipient: fixture.owner.identity.fingerprint) == reference)
        #expect(await reopened.itemRevisionIndexReads == 1)
    }
}

private final class ReadableWriteBudgetPermit: RepositoryWritePermit, Sendable {
    private let remaining = Synchronization.Mutex(2)
    func withWritePermission<T>(_ body: () throws -> T) throws -> T {
        try remaining.withLock { count in
            guard count > 0 else { throw MopError.authentication }
            count -= 1
            return try body()
        }
    }
}
