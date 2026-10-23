import CryptoKit
import Foundation
import Synchronization
import Testing
import MopCore
@testable import MopVaultNext
@testable import MopSync
@testable import MopAppSupport

@Test func unlockedDeviceCacheSurvivesExpiryAndRevokesDelayedLeases() throws {
    let wrapping = P256.KeyAgreement.PrivateKey(), member = UUID()
    let (created, representation) = try WrappedDevice.seal(member: member, scope: "vault", wrappingPublicKey: wrapping.publicKey, representation: Data())
    created.close()
    let cache = UnlockedDeviceCache()
    var allowed = true, opens = 0
    func open() throws -> any DeviceOperations {
        try cache.open("vault") {
            guard allowed else { throw MopError.authentication }
            opens += 1
            return try WrappedDevice.open(representation, scope: "vault", member: member, using: wrapping)
        }
    }
    let first = try open()
    allowed = false
    first.close()
    let second = try open() // membership reload after enclave authentication expiry
    #expect(opens == 1)
    let bytes = Data("after expiry".utf8)
    #expect(try !second.sign(bytes).isEmpty)
    #expect(throws: MopError.authentication) { try first.sign(bytes) }
    cache.invalidate()
    #expect(throws: MopError.authentication) { try second.sign(bytes) }
    #expect(throws: MopError.authentication) { try second.checkAuthorization() }
    #expect(throws: MopError.authentication) { try open() }
    #expect(opens == 1)
}

@Test(arguments: [false, true]) func wrappedMigrationStagesOnceAndTransfersGrantsAfterConfirmedAdmission(competingAdmission: Bool) async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-wrapped-migration-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let repository = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
    let trust = MemoryItemInventory(), legacy = try SessionDevice()
    let scope = ItemVaultSetupScope(container: "iCloud.test", environment: "Development", binding:
        ItemVaultBinding(account: "migration", database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
    let original = try await ItemVaultBootstrap(repository: repository, trustStore: trust, scope: scope, device: SessionDevice(copying: legacy)).create(name: "preserved")
    let provision = try #require(await repository.operations(account: "migration", database: "private").first { $0.kind == .provision })
    let provisioner = JournaledContentProvisioner(repository: repository, trustStore: trust, transport: DomainProvisionServer(), accountValidator: { true })
    guard case .completed = await provisioner.handle(provision, permit: DomainAccountAuthorization()) else { Issue.record("provision failed"); return }
    let item = UUID()
    let initial = try await original.contentSession.create(item: item, components: ["secret": SecretBytes(utf8: "original")])
    let pending = try await original.contentSession.edit(item: item, expected: initial.version.versionID,
        components: ["secret": SecretBytes(utf8: "keep me")])
    let originalBytes = try #require(await repository.item(scope.binding.item(item))).ciphertext
    let wrapping = P256.KeyAgreement.PrivateKey()
    let (candidate, sealed) = try WrappedDevice.seal(member: legacy.identity.member, scope: "test-vault", wrappingPublicKey: wrapping.publicKey, representation: Data())
    let newIdentity = candidate.identity
    candidate.close()
    func replacement() throws -> WrappedDevice { try WrappedDevice.open(sealed, scope: "test-vault", member: legacy.identity.member, using: wrapping) }
    original.lock()
    let staged = try await WrappedDeviceMigration.open(repository: repository, trust: trust, scope: scope,
        legacy: SessionDevice(copying: legacy), replacement: replacement(), owner: DomainAccountAuthorization())
    #expect(try staged.currentDeviceID == legacy.identity.device)
    staged.lock()
    let retry = try await WrappedDeviceMigration.open(repository: repository, trust: trust, scope: scope,
        legacy: SessionDevice(copying: legacy), replacement: replacement(), owner: DomainAccountAuthorization())
    retry.lock()
    let proposals = try await repository.operations(account: "migration", database: "private").filter { $0.kind == .membership }
    #expect(proposals.count == 1)
    var proposal = try #require(proposals.first)
    let pin = try #require(try trust.load(scope: scope))
    if competingAdmission {
        let peer = try SessionDevice(member: legacy.identity.member)
        let genesis = try MembershipEnvelope.decode(pin.genesis)
        let competing = try MembershipEnvelope.successor(of: genesis,
            membership: Membership(accounts: [AccountMember(id: legacy.identity.member, role: .owner, devices: [legacy.identity, peer.identity])]), owner: legacy)
        try trust.reserveMembership(scope: scope, successors: [competing.encoded()])
        let newer = try ItemVaultMembershipAuthority.history(record: pin, trustStore: trust)
        let policy = try await repository.contentRecipients(scope: scope.repositoryScope)
        try await repository.setContentRecipients(scope: scope.repositoryScope, expected: policy,
            policy: GrantBackedContentStorage.recipientPolicy(history: newer), authorization: DomainAccountAuthorization())
        let rebasing = try GrantBackedContentSession(repository: repository, binding: scope.binding, history: newer, device: SessionDevice(copying: legacy))
        #expect(try await rebasing.reconcileMembership(proposal,
            scope: EnrollmentScope(container: scope.container, environment: scope.environment, account: scope.binding.account,
                vault: scope.binding.vaultID, member: legacy.identity.member), owner: DomainAccountAuthorization()))
        rebasing.lock()
        proposal = try #require(await repository.operations(account: "migration", database: "private").first { $0.id == proposal.id })
        let rebased = try JSONDecoder().decode(ContentMembershipCommit.self, from: proposal.payload).verified()
        #expect(rebased.current.membership.devices.contains(peer.identity))
        #expect(rebased.current.membership.devices.contains(newIdentity))
    }
    // Simulate verified cloud readback, including the crash boundary between the
    // independent pin and recipient-index commit. The production journal does both.
    let commit = try JSONDecoder().decode(ContentMembershipCommit.self, from: proposal.payload)
    let admitted = try commit.verified()
    try trust.reserveMembership(scope: scope, successors: admitted.orderedStates.dropFirst().map { try $0.encoded() })
    let beforePolicy = try await repository.contentRecipients(scope: scope.repositoryScope)
    try await repository.setContentRecipients(scope: scope.repositoryScope, expected: beforePolicy,
        policy: GrantBackedContentStorage.recipientPolicy(history: admitted), authorization: DomainAccountAuthorization())
    try await repository.confirmOperation(proposal, permit: DomainAccountAuthorization())
    let blocked = SessionUnwrapCounter()
    blocked.failure.withLock { $0 = .authentication }
    await #expect(throws: MopError.authentication) {
        try await WrappedDeviceMigration.open(repository: repository, trust: trust, scope: scope,
            legacy: SessionDevice(copying: legacy, unwrapCounter: blocked), replacement: replacement(), owner: DomainAccountAuthorization())
    }
    #expect(try await repository.item(scope.binding.item(item))?.ciphertext == originalBytes)
    let migrated = try await WrappedDeviceMigration.open(repository: repository, trust: trust, scope: scope,
        legacy: SessionDevice(copying: legacy), replacement: replacement(), owner: DomainAccountAuthorization())
    #expect(try migrated.currentDeviceID == newIdentity.device)
    #expect(try await migrated.vaultMetadata().value.name == "preserved")
    let current = try #require(await repository.item(scope.binding.item(item)))
    #expect(current.ciphertext == originalBytes)
    #expect(try await migrated.contentSession.open(item: item, component: "secret", expected: current.versionID) == SecretBytes(utf8: "keep me"))
    #expect(try await repository.pendingMutations(account: "migration").contains { $0.version.versionID == pending.version.versionID })
    #expect(try trust.load(scope: scope)?.genesis == pin.genesis)
    #expect(admitted.current.membership.devices.contains(legacy.identity))
    let grants = try await repository.contentGrants(scope: scope.binding.item(item), keyGeneration: ContentEnvelope.decode(originalBytes, history: admitted, item: item).header.keyGeneration, recipient: newIdentity.fingerprint)
    #expect(grants.count == 1)
    #expect(try ContentKeyGrant.decode(grants[0].bytes, content: ContentEnvelope.decode(originalBytes, history: admitted, item: item), history: admitted).sourceVersion == current.versionID)
    migrated.lock()
    let resumed = try await WrappedDeviceMigration.open(repository: repository, trust: trust, scope: scope,
        legacy: SessionDevice(copying: legacy), replacement: replacement(), owner: DomainAccountAuthorization())
    #expect(try resumed.currentDeviceID == newIdentity.device)
    #expect(try await repository.contentGrants(scope: scope.binding.item(item), keyGeneration: grants[0].keyGeneration, recipient: newIdentity.fingerprint) == grants)
    // An old client can upload an additive-compatible record after initial migration.
    let lateItem = UUID()
    let oldHistory = try TrustedMembershipHistory(genesis: MembershipEnvelope.decode(pin.genesis), vault: scope.binding.vaultID, pinnedDigest: pin.pinnedDigest)
    let late = try ContentEnvelope.seal(["secret": SecretBytes(utf8: "late arrival")], vault: scope.binding.vaultID,
        item: lateItem, history: oldHistory, signer: legacy)
    _ = try await GrantBackedContentStorage(repository: repository).commit(late.content, grants: late.grants,
        scope: scope.binding.item(lateItem), history: admitted, authorization: DomainAccountAuthorization())
    let work = try #require(await repository.operations(account: "migration", database: "private").first {
        guard $0.kind == .prepareGrant, let missing = try? JSONDecoder().decode(MissingContentGrant.self, from: $0.payload) else { return false }
        return missing.scope.itemID == lateItem && missing.recipient == newIdentity.fingerprint
    })
    #expect(try await resumed.contentSession.prepareMigratedGrant(work, legacy: legacy, owner: DomainAccountAuthorization()))
    #expect(try await resumed.contentSession.open(item: lateItem, component: "secret", expected: late.content.header.version) == SecretBytes(utf8: "late arrival"))
    resumed.lock()
    #expect(throws: MopError.authentication) { try resumed.contentSession.permit.check() }
    let retirement = try #require(await repository.operations(account: "migration", database: "private").first { $0.kind == .membership && $0.state != .completed })
    let retired = try JSONDecoder().decode(ContentMembershipCommit.self, from: retirement.payload).verified()
    #expect(retired.current.header.author == newIdentity.fingerprint)
    #expect(!retired.current.membership.devices.contains(legacy.identity))
    #expect(retired.current.membership.devices.contains(newIdentity))
    #expect(retired.current.membership.removedDevices?.contains(legacy.identity.device) == true)
    // A legacy-only grant received before retirement remains usable as a source
    // for rotation afterward, without giving the old identity signing authority.
    let obsoleteItem = UUID()
    let obsolete = try ContentEnvelope.seal(["secret": SecretBytes(utf8: "retained source")], vault: scope.binding.vaultID,
        item: obsoleteItem, history: oldHistory, signer: legacy)
    _ = try await GrantBackedContentStorage(repository: repository).commit(obsolete.content, grants: obsolete.grants,
        scope: scope.binding.item(obsoleteItem), history: admitted, authorization: DomainAccountAuthorization())
    try trust.reserveMembership(scope: scope, successors: retired.orderedStates.dropFirst().map { try $0.encoded() })
    let admittedPolicy = try await repository.contentRecipients(scope: scope.repositoryScope)
    try await repository.setContentRecipients(scope: scope.repositoryScope, expected: admittedPolicy,
        policy: GrantBackedContentStorage.recipientPolicy(history: retired), authorization: DomainAccountAuthorization())
    let rotating = try GrantBackedContentSession(repository: repository, binding: scope.binding, history: retired, device: replacement())
    let rotation = try #require(await repository.operations(account: "migration", database: "private").first {
        $0.kind == .rotateContent && (try? JSONDecoder().decode(ItemScope.self, from: $0.payload)) == scope.binding.item(obsoleteItem)
    })
    guard case .completed = await rotating.handle(rotation, owner: DomainAccountAuthorization(), migration: legacy) else {
        Issue.record("Retired legacy source did not rotate"); return
    }
    let rotated = try #require(await repository.item(scope.binding.item(obsoleteItem)))
    #expect(try await rotating.open(item: obsoleteItem, component: "secret", expected: rotated.versionID) == SecretBytes(utf8: "retained source"))
    #expect(throws: (any Error).self) {
        try ContentEnvelope.seal(["secret": SecretBytes(utf8: "unauthorized")], vault: scope.binding.vaultID,
            item: UUID(), history: retired, signer: legacy)
    }
    rotating.lock()
    // A removed replacement is not automatically re-admitted on a later launch.
    let membershipBeforeRemoval = admitted.current.membership
    let removed = try Membership(accounts: [AccountMember(id: legacy.identity.member, role: .owner, devices: membershipBeforeRemoval.devices.filter { $0 != newIdentity })],
        offlineRecovery: membershipBeforeRemoval.offlineRecovery, removedDevices: [newIdentity.device])
    let removal = try MembershipEnvelope.successor(of: admitted.current, membership: removed, owner: legacy)
    let revokedTrust = MemoryItemInventory()
    _ = try revokedTrust.reserve(pin)
    try revokedTrust.reserveMembership(scope: scope, successors: (admitted.orderedStates.dropFirst() + [removal]).map { try $0.encoded() })
    await #expect(throws: MopError.notVaultMember) {
        try await WrappedDeviceMigration.open(repository: repository, trust: revokedTrust, scope: scope,
            legacy: SessionDevice(copying: legacy), replacement: replacement(), owner: DomainAccountAuthorization())
    }
}

@Test func unlockedDeviceCacheLockWaitsForAdmittedWorkAndRejectsQueuedWork() async throws {
    final class BlockingDevice: DeviceOperations, @unchecked Sendable {
        let identity: DevicePublicKey
        let entered = DispatchSemaphore(value: 0)
        let proceed = DispatchSemaphore(value: 0)
        let closed = Mutex(false)
        init() throws { identity = try SessionDevice().identity }
        func waitForEntry() { entered.wait() }
        func sign(_ bytes: Data) throws -> Data {
            entered.signal(); proceed.wait()
            guard !closed.withLock({ $0 }) else { throw MopError.authentication }
            return bytes
        }
        func unwrap(_ envelope: KeyEnvelope, context: Data) throws -> SymmetricKey { throw MopError.authentication }
        func close() { closed.withLock { $0 = true } }
    }
    let root = try BlockingDevice(), cache = UnlockedDeviceCache()
    // The cache, not Sendable conformance of the provider protocol, serializes access.
    final class Borrow: @unchecked Sendable {
        let device: any DeviceOperations
        init(_ device: any DeviceOperations) { self.device = device }
    }
    let first = Borrow(try cache.open("vault") { root })
    let delayed = Borrow(try cache.open("vault") { throw MopError.invalidIdentity })
    let operation = Task.detached { try first.device.sign(Data([1])) }
    await Task.detached { root.waitForEntry() }.value
    let locking = Task.detached { cache.invalidate() }
    root.proceed.signal()
    #expect(try await operation.value == Data([1]))
    await locking.value
    #expect(root.closed.withLock { $0 })
    #expect(throws: MopError.authentication) { try delayed.device.sign(Data()) }
    #expect(throws: MopError.authentication) { try cache.open("another") { root } }
}

@Test func wrappedMigrationDoesNotRetireBeforeMetadataArrives() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-wrapped-incomplete-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let repository = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
    let trust = MemoryItemInventory(), legacy = try SessionDevice()
    let scope = ItemVaultSetupScope(container: "iCloud.test", environment: "Development", binding:
        ItemVaultBinding(account: "incomplete", database: "private", zoneOwner: "__defaultOwner__", vaultID: UUID()))
    let wrapping = P256.KeyAgreement.PrivateKey()
    let (replacement, _) = try WrappedDevice.seal(member: legacy.identity.member, scope: "incomplete",
        wrappingPublicKey: wrapping.publicKey, representation: Data())
    let genesis = try MembershipEnvelope.genesis(vault: scope.binding.vaultID,
        membership: Membership(accounts: [AccountMember(id: legacy.identity.member, role: .owner, devices: [legacy.identity])]), owner: legacy)
    let successor = try MembershipEnvelope.successor(of: genesis,
        membership: Membership(accounts: [AccountMember(id: legacy.identity.member, role: .owner, devices: [legacy.identity, replacement.identity])]), owner: legacy)
    let pin = try trust.reserve(ItemVaultSetupRecord(scope: scope, sourceDigest: setupHash(Data()), name: "vault",
        genesis: genesis.encoded(), pinnedDigest: genesis.digest()))
    try trust.reserveMembership(scope: scope, successors: [successor.encoded()])
    let history = try ItemVaultMembershipAuthority.history(record: pin, trustStore: trust)
    _ = try await repository.initializeEnrolledContentVault(scope: scope.repositoryScope,
        policy: GrantBackedContentStorage.recipientPolicy(history: history), expectedItemCount: 5,
        enrollmentRecipient: replacement.identity.fingerprint, membershipState: pin.genesis,
        currentControl: history.current.encoded(), setupID: pin.setupID, authorization: DomainAccountAuthorization())
    let session = try await WrappedDeviceMigration.open(repository: repository, trust: trust, scope: scope,
        legacy: legacy, replacement: replacement, owner: DomainAccountAuthorization())
    defer { session.lock() }
    #expect(try await repository.operations(account: "incomplete", database: "private").allSatisfy { $0.kind != .membership })
    #expect(try session.currentDeviceID == replacement.identity.device)
}
