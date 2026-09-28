import CryptoKit
import Foundation
import LocalAuthentication
import Synchronization
import Testing
import MopCore
@testable import MopVaultNext
@testable import MopAppSupport

// Software fixtures test application behavior only, never hardware protection.
private final class Material {
    let encryption = P256.KeyAgreement.PrivateKey(), signing = P256.Signing.PrivateKey()
    let member: UUID, id = UUID()
    init(_ member: UUID) { self.member = member }
    var identity: DevicePublicKey { try! DevicePublicKey(member: member, device: id, encryption: encryption.publicKey.x963Representation, signing: signing.publicKey.x963Representation) }
}
private final class TestHandle: DeviceOperations {
    let material: Material
    let unwraps: Counter
    var closed = false
    init(_ material: Material, unwraps: Counter) { self.material = material; self.unwraps = unwraps }
    var identity: DevicePublicKey { material.identity }
    func sign(_ bytes: Data) throws -> Data { guard !closed else { throw MopError.authentication }; return try material.signing.signature(for: bytes).rawRepresentation }
    func unwrap(_ envelope: KeyEnvelope, context: Data) throws -> SymmetricKey { unwraps.withLock { $0 += 1 }; guard !closed else { throw MopError.authentication }; return try envelope.open(using: material.encryption, context: context) }
    func close() { closed = true }
}
private final class TestHardware: @unchecked Sendable {
    let unwraps = Counter()
    private let lock = NSLock()
    private var keys: [String: Material] = [:]
    private var deletionBlocked = false
    func blockDeletion(_ blocked: Bool) { lock.lock(); defer { lock.unlock() }; deletionBlocked = blocked }
    func remove(_ scope: String, _ member: UUID) throws {
        lock.lock(); defer { lock.unlock() }
        guard !deletionBlocked else { throw MopError.keychain(-1) }
        keys.removeValue(forKey: scope + member.uuidString)
    }
    func open(_ scope: String, _ member: UUID, _ context: LAContext, _ create: Bool) throws -> any DeviceOperations {
        lock.lock(); defer { lock.unlock() }
        let id = scope + member.uuidString
        if keys[id] == nil { guard create else { throw MopError.invalidIdentity }; keys[id] = Material(member) }
        return TestHandle(keys[id]!, unwraps: unwraps)
    }
}
private actor Server {
    var readRequests = 0
    var readGate: AuthenticationGate?
    func setReadGate(_ gate: AuthenticationGate?) { readGate = gate }
    func recordReadRequest() async {
        readRequests += 1
        if let readGate { await readGate.wait() }
    }
    struct State { var head: String; var version: Int; var revisions: [String: Data] }
    var vaults: [UUID: State] = [:]
    var attachments: [UUID: [String: Data]] = [:]
    var attachmentReads = 0
    func attachment(_ digest: String, _ id: UUID) throws -> Data {
        attachmentReads += 1
        guard let bytes = attachments[id]?[digest] else { throw AttachmentFailure.unavailable }
        return bytes
    }
    func uploadAttachment(_ bytes: Data, _ digest: String, _ id: UUID) { attachments[id, default: [:]][digest] = bytes }
    var inboxes: [String: (EnrollmentMailbox, Int)] = [:]
    func enrollment(_ address: VaultAddress) -> EnrollmentInbox {
        let saved = inboxes[address.binding]
        return EnrollmentInbox(mailbox: saved?.0 ?? EnrollmentMailbox(), version: saved.map { Data(String($0.1).utf8) })
    }
    func saveEnrollment(_ value: EnrollmentMailbox, _ version: Data?, _ address: VaultAddress) throws {
        guard enrollment(address).version == version else { throw MopError.vaultConflict }
        // Exercise the same serialization and size boundary as CloudKit.
        let persisted = try EnrollmentMailbox.decode(value.encoded())
        inboxes[address.binding] = (persisted, (inboxes[address.binding]?.1 ?? 0) + 1)
    }
    var addresses: [UUID: VaultAddress] = [:]
    func discover(_ account: String) -> [VaultAddress] { addresses.values.filter { $0.account == account } }
    func remember(_ address: VaultAddress) { addresses[address.vault] = address }
    var dropAcknowledgement = false
    var rejectAfter: Int?
    func rejectPublication(after successful: Int) { rejectAfter = successful }
    func initialize(_ root: VerifiedVault) throws {
        guard vaults[root.id] == nil else { throw MopError.vaultConflict }
        vaults[root.id] = State(head: root.digest, version: 1, revisions: [root.digest: root.bytes])
    }
    func head(_ id: UUID) throws -> RevisionHead { guard let value = vaults[id] else { throw MopError.vaultMissing }; return RevisionHead(digest: value.head, version: Data(String(value.version).utf8)) }
    func revision(_ digest: String, _ id: UUID) throws -> Data { guard let bytes = vaults[id]?.revisions[digest] else { throw MopError.vaultMissing }; return bytes }
    func upload(_ bytes: Data, _ digest: String, _ id: UUID) throws { guard vaults[id] != nil, Codec.digest(bytes) == digest else { throw MopError.invalidVault }; vaults[id]!.revisions[digest] = bytes }
    func publish(_ digest: String, _ version: Data, _ id: UUID) throws {
        if let remaining = rejectAfter {
            if remaining == 0 { rejectAfter = nil; throw MopError.cloudUnavailable }
            rejectAfter = remaining - 1
        }
        guard var value = vaults[id], version == Data(String(value.version).utf8) else { throw MopError.vaultConflict }
        guard value.revisions[digest] != nil else { throw MopError.invalidVault }
        value.head = digest; value.version += 1; vaults[id] = value
        if dropAcknowledgement { dropAcknowledgement = false; throw MopError.cloudUnavailable }
    }
    func dropNext() { dropAcknowledgement = true }
    func delete(_ id: UUID) { vaults[id] = nil }
}
private struct Transport: VaultTransport {
    let server: Server, accountID: String
    func attachment(_ digest: String, at address: VaultAddress) async throws -> Data { await server.recordReadRequest(); return try await server.attachment(digest, address.vault) }
    func uploadAttachment(_ bytes: Data, digest: String, at address: VaultAddress) async throws { await server.uploadAttachment(bytes, digest, address.vault) }
    func enrollment(at address: VaultAddress) async throws -> EnrollmentInbox { await server.enrollment(address) }
    func saveEnrollment(_ mailbox: EnrollmentMailbox, version: Data?, at address: VaultAddress) async throws { try await server.saveEnrollment(mailbox, version, address) }
    func discover() async throws -> [VaultAddress] { await server.discover(accountID) }
    func account() async throws -> String { await server.recordReadRequest(); return accountID }
    func validateOfflineAccount() async throws { await server.recordReadRequest() }
    func initialize(_ genesis: VerifiedVault, at address: VaultAddress) async throws { try await server.initialize(genesis); await server.remember(address) }
    func head(at address: VaultAddress) async throws -> RevisionHead { await server.recordReadRequest(); return try await server.head(address.vault) }
    func revision(_ digest: String, at address: VaultAddress) async throws -> Data { await server.recordReadRequest(); return try await server.revision(digest, address.vault) }
    func upload(_ bytes: Data, digest: String, at address: VaultAddress) async throws { try await server.upload(bytes, digest, address.vault) }
    func publish(_ digest: String, expectedVersion: Data, at address: VaultAddress) async throws { try await server.publish(digest, expectedVersion, address.vault) }
    func share(with account: String, role: MemberRole, at address: VaultAddress) async throws -> URL { URL(string: "https://www.icloud.com/share/model")! }
    func reconcileShare(_ membership: Membership, at address: VaultAddress) async throws {}
    func acceptShare(_ url: URL, vault: UUID, expectedOwner: String) async throws -> VaultAddress { try VaultAddress(container: "iCloud.test", environment: "Development", account: accountID, database: .shared, owner: "a", vault: vault) }
    func delete(at address: VaultAddress) async throws { await server.delete(address.vault) }
}
private struct Configuration: VaultPlatformConfiguration {
    let stateDirectory: URL
    func cloudConfiguration() -> (container: String, environment: String) { ("iCloud.test", "Development") }
}
private final class Counter: @unchecked Sendable {
    private let mutex = NSLock()
    private var value = 0
    func withLock<T>(_ body: (inout Int) -> T) -> T { mutex.lock(); defer { mutex.unlock() }; return body(&value) }
}
private final class Client {
    let state = FileManager.default.temporaryDirectory.appendingPathComponent("mop-v7-service-test-" + UUID().uuidString)
    let hardware = TestHardware()
    let calls = Counter()
    let server: Server, account: String
    var service: NativeVaultService!
    init(_ server: Server, _ account: String) {
        self.server = server; self.account = account
        reopen()
    }
    func reopen(allowsAttachments: Bool = true, duringSync: Bool = false) {
        let hardware = hardware, calls = calls
        service = NativeVaultService(state: state, configuration: Configuration(stateDirectory: state), transport: Transport(server: server, accountID: account), allowsAttachments: allowsAttachments, attachmentSyncOverride: duringSync,
            openDevice: { try hardware.open($0, $1, $2, $3) }, deleteDevice: { try hardware.remove($0, $1) }, authenticate: { callback in
                calls.withLock { $0 += 1 }; let context = LAContext(); try callback(context); return context
            })
    }
    deinit { try? FileManager.default.removeItem(at: state) }
    func request(_ recovery: Bool = false) async throws -> (Data, DeviceRequest) {
        let result = try await service.execute(.manage(.deviceRequest(recovery: recovery)), vault: nil)
        let bytes = try #require(result.document)
        return (bytes, try ExchangeFile.decode(DeviceRequest.self, from: bytes))
    }
}
private func create(_ owner: Client, recovery: Client) async throws -> String {
    let (bytes, request) = try await recovery.request(true)
    try FileManager.default.createDirectory(at: owner.state, withIntermediateDirectories: true)
    let file = owner.state.appendingPathComponent("recovery-request.json"); try bytes.write(to: file)
    let id = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "personal", recovery: file, fingerprint: request.fingerprint), vault: id)
    return id
}
private func enroll(_ client: Client, owner: Client, vault: String, role: MemberRole) async throws {
    let (request, info) = try await client.request()
    let invitation = try await owner.service.execute(.manage(.invite(request: request, fingerprint: info.fingerprint, role: role)), vault: vault)
    let bytes = try #require(invitation.document), packet = try ExchangeFile.decode(InvitationPacket.self, from: bytes)
    let accepted = try await client.service.execute(.manage(.accept(packet: bytes, checkpoint: packet.invitation.checkpoint, shareURL: URL(string: "https://www.icloud.com/share/model"))), vault: nil)
    _ = try await owner.service.execute(.manage(.approve(packet: #require(accepted.document), fingerprint: info.fingerprint)), vault: vault)
}

@Test func integratedTwoAccountsFourDevicesRemovalAndHardwareRecoveryModel() async throws {
    let cloud = Server()
    let owner = Client(cloud, "a"), a2 = Client(cloud, "a"), b1 = Client(cloud, "b"), b2 = Client(cloud, "b"), recovery = Client(cloud, "a")
    let id = try await create(owner, recovery: recovery)
    let reference = try SecretReference("secondpass://personal/login/password")
    _ = try await owner.service.execute(.write(reference, SecretBytes(utf8: "secret"), replace: false), vault: id)
    try await enroll(a2, owner: owner, vault: id, role: .owner)
    try await enroll(b1, owner: owner, vault: id, role: .editor)
    try await enroll(b2, owner: owner, vault: id, role: .editor)
    #expect(try await b1.service.execute(.read(reference), vault: id).value == SecretBytes(utf8: "secret"))
    let (_, b1Request) = try await b1.request()
    _ = try await owner.service.execute(.manage(.removeDevice(b1Request.device.device)), vault: id)
    await #expect(throws: MopError.deviceRemoved) { try await b1.service.execute(.read(reference), vault: id) }
    #expect(try await b2.service.execute(.read(reference), vault: id).value == SecretBytes(utf8: "secret"))
    _ = try await owner.service.execute(.manage(.removeMember(b1Request.device.member)), vault: id)
    await #expect(throws: MopError.deviceRemoved) { try await b2.service.execute(.read(reference), vault: id) }
    let backup = FileManager.default.temporaryDirectory.appendingPathComponent("mop-v7-backup-test-" + UUID().uuidString + ".json")
    defer { try? FileManager.default.removeItem(at: backup) }
    _ = try await owner.service.execute(.export(backup), vault: id)
    let checkpoint = try await owner.service.execute(.manage(.fingerprint), vault: id).message
    let replacement = Client(cloud, "a"), nextRecovery = Client(cloud, "a")
    let ownerRequest = try await replacement.request().0, recoveryRequest = try await nextRecovery.request(true).0
    let recovered = try await recovery.service.execute(.manage(.recoverHardware(backup: Data(contentsOf: backup), checkpoint: checkpoint,
        owner: ownerRequest, recovery: recoveryRequest, copy: false)), vault: nil)
    let bytes = try #require(recovered.document)
    _ = try await replacement.service.execute(.manage(.importCheckpoint(document: bytes, fingerprint: Codec.digest(bytes), sharedOwner: nil)), vault: nil)
    #expect(try await replacement.service.execute(.read(reference), vault: id).value == SecretBytes(utf8: "secret"))
    await #expect(throws: MopError.deviceRemoved) { try await owner.service.execute(.read(reference), vault: id) }
}

@Test func integratedTypedCatalogAutoFillAndConflicts() async throws {
    let cloud = Server(), owner = Client(cloud, "a"), recovery = Client(cloud, "a")
    let id = try await create(owner, recovery: recovery)
    let initial = try await owner.service.execute(.catalog, vault: id).requireCatalog()
    var item = VaultItem(name: "login", type: .login, fields: [ItemField(path: "username", type: .username, value: "alice"), ItemField(path: "website", type: .website, value: "https://example.com"), ItemField(path: "password", type: .password, value: "secret")])
    item.autoFill = AutoFillMapping(username: "username", password: "password")
    let edit = ItemEdit(revision: initial.revision, item: item, create: true)
    let saved = try await owner.service.execute(.save(edit), vault: id).requireCatalog()
    #expect(saved.items[0].autoFill == item.autoFill)
    #expect(saved.items[0].fields.first { $0.type == .password }?.value == nil)
    let entry = try #require(AutoFillEntry.entries(catalog: saved, vaultID: id).first)
    let before = owner.calls.withLock { $0 }
    let credential = try await AutoFillAccess.credential(recordIdentifier: entry.recordIdentifier, service: owner.service)
    #expect(credential.user == "alice" && credential.password == "secret")
    #expect(owner.calls.withLock { $0 } > before)
    #expect(!owner.service.isAuthenticated)
    await #expect(throws: MopError.vaultConflict) { try await owner.service.execute(.save(edit), vault: id) }
    let reference = try SecretReference("secondpass://personal/login/username")
    let changed = try await owner.service.execute(.write(reference, SecretBytes(utf8: "bob"), replace: true), vault: id).requireCatalog()
    #expect(changed.items[0].fields.first { $0.type == .username }?.value == "bob")
    await #expect(throws: MopError.notFound) { try await AutoFillAccess.credential(recordIdentifier: entry.recordIdentifier, service: owner.service) }
    let deleted = try await owner.service.execute(.trashItem(name: "login", revision: changed.revision), vault: id)
    #expect(deleted.catalog?.items.isEmpty == true)
    let tombstone = try #require(deleted.deletedCatalog?.items.first?.deletion)
    let restored = try await owner.service.execute(.restoreItem(id: tombstone.id, revision: deleted.requireCatalog().revision), vault: id)
    #expect(restored.catalog?.items.first?.name == "login")
    #expect(restored.catalog?.items.first?.autoFill == item.autoFill)
}

@Test func integratedUncertainWriteOfflineAccountInvalidationAndReopen() async throws {
    let cloud = Server(), owner = Client(cloud, "a"), recovery = Client(cloud, "a")
    let id = try await create(owner, recovery: recovery), reference = try SecretReference("secondpass://personal/item/password")
    await cloud.dropNext()
    await #expect(throws: MopError.cloudUncertain) { try await owner.service.execute(.write(reference, SecretBytes(utf8: "committed"), replace: false), vault: id) }
    owner.reopen()
    _ = try await owner.service.execute(.sync, vault: id)
    #expect(try await owner.service.execute(.read(reference), vault: id, offline: true).value == SecretBytes(utf8: "committed"))
    await #expect(throws: MopError.offlineWrite) { try await owner.service.execute(.delete(reference), vault: id, offline: true) }
    try NextAccountBinding.invalidate(state: owner.state)
    await #expect(throws: MopError.cloudAccount) { try await owner.service.execute(.read(reference), vault: id, offline: true) }
}

@Test func invitationAddressCannotSubstituteAnotherCloudOwner() async throws {
    let cloud = Server(), owner = Client(cloud, "a"), recipient = Client(cloud, "b"), recovery = Client(cloud, "a")
    let id = try await create(owner, recovery: recovery)
    let (request, identity) = try await recipient.request()
    let issued = try await owner.service.execute(.manage(.invite(request: request, fingerprint: identity.fingerprint, role: .editor)), vault: id)
    let packet = try ExchangeFile.decode(InvitationPacket.self, from: #require(issued.document))
    let address = try VaultAddress(container: "iCloud.test", environment: "Development", account: "attacker", database: .private, owner: "__defaultOwner__", vault: packet.address.vault)
    let forged = InvitationPacket(request: packet.request, invitation: packet.invitation, address: address, checkpoint: packet.checkpoint)
    await #expect(throws: MopError.vaultUntrusted) {
        try await recipient.service.execute(.manage(.accept(packet: ExchangeFile.encode(forged), checkpoint: packet.invitation.checkpoint, shareURL: URL(string: "https://www.icloud.com/share/model"))), vault: nil)
    }
}

private actor AuthenticationGate {
    var entered = false
    var isWaiting: Bool { continuation != nil }
    private var continuation: CheckedContinuation<Void, Never>?
    func wait() async { entered = true; await withCheckedContinuation { continuation = $0 } }
    func release() { continuation?.resume(); continuation = nil }
}
@Test func lockingDuringAuthenticationNeverOpensDeviceKeysOrReturnsLateAuthorization() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-v7-auth-test-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let gate = AuthenticationGate(), opened = Counter()
    let service = NativeVaultService(state: directory, configuration: Configuration(stateDirectory: directory), transport: Transport(server: Server(), accountID: "a"), openDevice: { _, _, _, _ in
        opened.withLock { $0 += 1 }; throw MopError.invalidIdentity
    }, authenticate: { callback in
        let context = LAContext(); try callback(context); await gate.wait(); return context
    })
    let task = Task { try await service.execute(.manage(.deviceRequest(recovery: false)), vault: nil) }
    while !(await gate.entered) { await Task.yield() }
    service.lock(); await gate.release()
    await #expect(throws: MopError.authentication) { try await task.value }
    #expect(opened.withLock { $0 } == 0)
    #expect(!service.isAuthenticated)
}

@Test func firstDeviceCreatesWithoutRecoveryAndDiscoveryDoesNotGrantAccess() async throws {
    let server = Server(), owner = Client(server, "a"), newDevice = Client(server, "a"), other = Client(server, "b")
    #expect(try await owner.service.execute(.discover, vault: nil).vaults.isEmpty)
    let id = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    let reference = try SecretReference("secondpass://personal/login/password")
    _ = try await owner.service.execute(.write(reference, SecretBytes(utf8: "hello"), replace: false), vault: id)
    let discovery = try await newDevice.service.execute(.discover, vault: nil)
    #expect(discovery.vaults.count == 1)
    #expect(discovery.vaults[0].id == id && !discovery.vaults[0].enrolled)
    #expect(discovery.defaultVault == nil)
    #expect(newDevice.calls.withLock { $0 } == 0)
    #expect(try await other.service.execute(.discover, vault: nil).vaults.isEmpty)
    let (request, info) = try await other.request()
    await #expect(throws: MopError.invalidIdentity) {
        try await owner.service.execute(.manage(.inviteOwnDevice(request: request, fingerprint: info.fingerprint)), vault: id)
    }
    let (ownRequest, ownInfo) = try await newDevice.request()
    await #expect(throws: MopError.invalidIdentity) {
        try await owner.service.execute(.manage(.inviteAccount(request: ownRequest, fingerprint: ownInfo.fingerprint, role: .editor)), vault: id)
    }
    try await enroll(newDevice, owner: owner, vault: id, role: .owner)
    #expect(try await newDevice.service.execute(.read(reference), vault: id).value == SecretBytes(utf8: "hello"))
    let recovery = Client(server, "a")
    let (recoveryRequest, recoveryInfo) = try await recovery.request(true)
    _ = try await owner.service.execute(.manage(.replaceRecovery(request: recoveryRequest, fingerprint: recoveryInfo.fingerprint)), vault: id)
    #expect(try await owner.service.execute(.members, vault: id).members.contains { $0.role.hasPrefix("hardware recovery") })
}

@Test func cloudEnrollmentNeedsOwnerApprovalAndSurvivesReopening() async throws {
    let server = Server(), owner = Client(server, "a"), newDevice = Client(server, "a")
    let id = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    let reference = try SecretReference("secondpass://personal/login/password")
    _ = try await owner.service.execute(.write(reference, SecretBytes(utf8: "hello"), replace: false), vault: id)
    let request = try await newDevice.service.execute(.manage(.requestEnrollment(name: "New Mac")), vault: id)
    #expect(request.enrollments.count == 1)
    let offer = try await owner.service.execute(.manage(.enrollmentInbox), vault: id)
    #expect(offer.enrollments.count == 1 && offer.enrollments[0].acceptance == nil)
    let response = try await newDevice.service.execute(.manage(.checkEnrollment), vault: id)
    #expect(response.enrollments[0].verificationCode == offer.enrollments[0].verificationCode)
    #expect(try await newDevice.service.execute(.discover, vault: nil).vaults[0].enrolled == false)
    let pending = try await owner.service.execute(.manage(.enrollmentInbox), vault: id)
    let exchange = try #require(pending.enrollments.first), code = try #require(exchange.verificationCode)
    await #expect(throws: MopError.vaultConflict) { try await owner.service.execute(.manage(.approveEnrollment(id: exchange.id, code: "wrong")), vault: id) }
    #expect(try await newDevice.service.execute(.manage(.checkEnrollment), vault: id).enrollmentCompleted == false)
    _ = try await newDevice.service.execute(.manage(.confirmEnrollment(code: code)), vault: id)
    newDevice.reopen()
    _ = try await owner.service.execute(.manage(.approveEnrollment(id: exchange.id, code: code)), vault: id)
    #expect(try await newDevice.service.execute(.manage(.checkEnrollment), vault: id).enrollmentCompleted)
    #expect(try await newDevice.service.execute(.read(reference), vault: id).value == SecretBytes(utf8: "hello"))
}

@Test func cloudEnrollmentConflictsRequireFreshComparisonAndDeclineGrantsNothing() async throws {
    let server = Server(), owner = Client(server, "a"), newDevice = Client(server, "a"), stranger = Client(server, "b")
    let id = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    await #expect(throws: MopError.vaultMissing) { try await stranger.service.execute(.manage(.requestEnrollment(name: "stranger")), vault: id) }
    _ = try await newDevice.service.execute(.manage(.requestEnrollment(name: "New Mac")), vault: id)
    _ = try await owner.service.execute(.manage(.enrollmentInbox), vault: id)
    let first = try await newDevice.service.execute(.manage(.checkEnrollment), vault: id).enrollments[0]
    let reference = try SecretReference("secondpass://personal/login/password")
    _ = try await owner.service.execute(.write(reference, SecretBytes(utf8: "change"), replace: false), vault: id)
    await #expect(throws: MopError.vaultConflict) { try await owner.service.execute(.manage(.approveEnrollment(id: first.id, code: first.verificationCode!)), vault: id) }
    _ = try await owner.service.execute(.manage(.enrollmentInbox), vault: id)
    let second = try await newDevice.service.execute(.manage(.checkEnrollment), vault: id).enrollments[0]
    #expect(first.verificationCode != second.verificationCode)
    _ = try await owner.service.execute(.manage(.rejectEnrollment(id: second.id)), vault: id)
    #expect(try await newDevice.service.execute(.manage(.checkEnrollment), vault: id).enrollmentCompleted == false)
    #expect(try await owner.service.execute(.manage(.enrollmentInbox), vault: id).enrollments.isEmpty)
}

@Test func anotherOwnerCanApproveAndRetryAnUncertainEnrollmentCommit() async throws {
    let server = Server(), owner = Client(server, "a"), approver = Client(server, "a"), newDevice = Client(server, "a")
    let id = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    try await enroll(approver, owner: owner, vault: id, role: .owner)
    _ = try await newDevice.service.execute(.manage(.requestEnrollment(name: "New Mac")), vault: id)
    _ = try await owner.service.execute(.manage(.enrollmentInbox), vault: id)
    let reply = try await newDevice.service.execute(.manage(.checkEnrollment), vault: id).enrollments[0]
    _ = try await newDevice.service.execute(.manage(.confirmEnrollment(code: reply.verificationCode!)), vault: id)
    await server.dropNext()
    await #expect(throws: (any Error).self) { try await approver.service.execute(.manage(.approveEnrollment(id: reply.id, code: reply.verificationCode!)), vault: id) }
    #expect(try await newDevice.service.execute(.manage(.checkEnrollment), vault: id).enrollmentCompleted == false)
    _ = try await approver.service.execute(.manage(.approveEnrollment(id: reply.id, code: reply.verificationCode!)), vault: id)
    #expect(try await newDevice.service.execute(.manage(.checkEnrollment), vault: id).enrollmentCompleted)
}

@Test func sameAccountCloudApprovalCompletesWithoutConfirmation() async throws {
    let server = Server(), owner = Client(server, "a"), newDevice = Client(server, "a")
    let id = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    _ = try await newDevice.service.execute(.manage(.requestEnrollment(name: "New Mac")), vault: id)
    _ = try await owner.service.execute(.manage(.enrollmentInbox), vault: id)
    let response = try await newDevice.service.execute(.manage(.checkEnrollment), vault: id).enrollments[0]
    _ = try await owner.service.execute(.manage(.approveEnrollment(id: response.id, code: response.verificationCode!)), vault: id)
    let address = try #require(await server.discover("a").first)
    let inbox = await server.enrollment(address)
    var forged = inbox.mailbox
    forged.exchanges[0].confirmedCode = response.verificationCode
    try await server.saveEnrollment(forged, inbox.version, address)
    #expect(try await newDevice.service.execute(.manage(.checkEnrollment), vault: id).enrollmentCompleted)
    #expect(try await newDevice.service.execute(.discover, vault: nil).vaults[0].enrolled == true)
}

@Test func malformedRegistryFailsWithTypedErrorAndPreservesItsBytes() async throws {
    let server = Server(), owner = Client(server, "a")
    _ = try await owner.service.execute(.create(name: "personal"), vault: UUID().uuidString)
    let member = AccountScope.member(container: "iCloud.test", environment: "Development", account: "a")
    let file = owner.state.appendingPathComponent("v7/" + member.uuidString + "/vaults.json")
    var rows = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as! [[String: Any]]
    var address = rows[0]["address"] as! [String: Any]
    address.removeValue(forKey: "namespace"); rows[0]["address"] = address
    let bytes = try JSONSerialization.data(withJSONObject: rows)
    try LocalFile.write(bytes, to: file, replace: true)
    await #expect(throws: MopError.invalidVault) { try await owner.service.execute(.discover, vault: nil) }
    #expect(try Data(contentsOf: file) == bytes)
}

@Test func enrollmentRestartRetiresOldRequestAndPreservesDeviceKeys() async throws {
    let server = Server(), owner = Client(server, "a"), newDevice = Client(server, "a")
    let id = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    _ = try await newDevice.service.execute(.manage(.requestEnrollment(name: "iPad")), vault: id)
    _ = try await owner.service.execute(.manage(.enrollmentInbox), vault: id)
    let old = try await newDevice.service.execute(.manage(.checkEnrollment), vault: id).enrollments[0]
    _ = try await newDevice.service.execute(.manage(.confirmEnrollment(code: old.verificationCode!)), vault: id)
    let fresh = try await newDevice.service.execute(.manage(.restartEnrollment(name: "iPad")), vault: id).enrollments[0]
    #expect(fresh.id != old.id)
    #expect(fresh.request.request.device == old.request.request.device)
    #expect(fresh.confirmedCode == nil && fresh.verificationCode == nil)
    let pending = try await owner.service.execute(.manage(.enrollmentInbox), vault: id)
    #expect(pending.enrollments.map(\.id) == [fresh.id])
    await #expect(throws: MopError.invalidIdentity) { try await owner.service.execute(.manage(.approveEnrollment(id: old.id, code: old.verificationCode!)), vault: id) }
    _ = try await newDevice.service.execute(.manage(.cancelEnrollment), vault: id)
    newDevice.reopen()
    let cancelled = try await newDevice.service.execute(.manage(.requestEnrollment(name: "iPad")), vault: id)
    #expect(cancelled.enrollments[0].rejected)
    #expect(try await owner.service.execute(.manage(.enrollmentInbox), vault: id).enrollments.isEmpty)
    let retry = try await newDevice.service.execute(.manage(.restartEnrollment(name: "iPad")), vault: id).enrollments[0]
    #expect(retry.id != fresh.id && retry.request.request.device == fresh.request.request.device)
}

@Test func removedCloudInvitationClearsTheCachedComparisonCode() async throws {
    let server = Server(), owner = Client(server, "a"), newDevice = Client(server, "a")
    let id = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    _ = try await newDevice.service.execute(.manage(.requestEnrollment(name: "iPad")), vault: id)
    _ = try await owner.service.execute(.manage(.enrollmentInbox), vault: id)
    let offer = try await newDevice.service.execute(.manage(.checkEnrollment), vault: id).enrollments[0]
    _ = try await newDevice.service.execute(.manage(.confirmEnrollment(code: offer.verificationCode!)), vault: id)
    let address = try #require(await server.discover("a").first)
    let inbox = await server.enrollment(address)
    var mailbox = inbox.mailbox
    mailbox.exchanges[0].invitation = nil; mailbox.exchanges[0].acceptance = nil
    try await server.saveEnrollment(mailbox, inbox.version, address)
    let result = try await newDevice.service.execute(.manage(.checkEnrollment), vault: id)
    #expect(result.enrollments[0].verificationCode == nil)
    #expect(result.enrollments[0].confirmedCode == nil)
    #expect(!result.enrollmentCompleted)
}

@Test func automaticEnrollmentWaitsForUnlockAndGrantsWithoutConfirmation() async throws {
    let server = Server(), owner = Client(server, "a"), newDevice = Client(server, "a")
    let id = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    let reference = try SecretReference("secondpass://personal/login/password")
    _ = try await owner.service.execute(.write(reference, SecretBytes(utf8: "hello"), replace: false), vault: id)
    _ = try await newDevice.service.execute(.manage(.requestEnrollment(name: "iPad")), vault: id)
    owner.service.lock()
    let calls = owner.calls.withLock { $0 }
    await #expect(throws: MopError.authentication) {
        try await owner.service.execute(.manage(.automaticEnrollment), vault: id)
    }
    #expect(owner.calls.withLock { $0 } == calls)
    _ = try await owner.service.execute(.catalog, vault: id)
    _ = try await owner.service.execute(.manage(.automaticEnrollment), vault: id)
    _ = try await newDevice.service.execute(.manage(.checkEnrollment), vault: id)
    let granted = try await owner.service.execute(.manage(.automaticEnrollment), vault: id)
    #expect(granted.addedDevices.count == 1)
    #expect(try await newDevice.service.execute(.manage(.checkEnrollment), vault: id).enrollmentCompleted)
    #expect(try await newDevice.service.execute(.read(reference), vault: id).value == SecretBytes(utf8: "hello"))
    let repeated = try await owner.service.execute(.manage(.automaticEnrollment), vault: id)
    #expect(repeated.addedDevices == granted.addedDevices)
}

@Test func largeVaultEnrollsTwoDevicesWithoutDuplicatingCheckpointsInMailbox() async throws {
    let server = Server(), owner = Client(server, "a"), phone = Client(server, "a"), tablet = Client(server, "a")
    let id = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    let reference = try SecretReference("secondpass://personal/large/password")
    let secret = SecretBytes(utf8: String(repeating: "x", count: 5 * 1024 * 1024))
    _ = try await owner.service.execute(.write(reference, secret, replace: false), vault: id)
    let address = try #require(await server.discover("a").first)
    let head = try await server.head(address.vault)
    let checkpoint = try await server.revision(head.digest, address.vault)
    // Two base64-encoded inline invitations would exceed the real 16 MiB limit.
    #expect(checkpoint.base64EncodedData().count * 2 > Codec.maximumSize)
    _ = try await phone.service.execute(.manage(.requestEnrollment(name: "iPhone")), vault: id)
    _ = try await tablet.service.execute(.manage(.requestEnrollment(name: "iPad")), vault: id)
    var phoneReady = false, tabletReady = false
    for _ in 0..<8 {
        _ = try await owner.service.execute(.manage(.automaticEnrollment), vault: id)
        let mailbox = await server.enrollment(address).mailbox
        #expect(try mailbox.encoded().count < 64 * 1024)
        #expect(mailbox.exchanges.allSatisfy { $0.invitation?.checkpoint.isEmpty != false && $0.approved?.isEmpty != false })
        if !phoneReady { phoneReady = try await phone.service.execute(.manage(.checkEnrollment), vault: id).enrollmentCompleted }
        if !tabletReady { tabletReady = try await tablet.service.execute(.manage(.checkEnrollment), vault: id).enrollmentCompleted }
        if phoneReady && tabletReady { break }
    }
    #expect(phoneReady && tabletReady)
    #expect(try await phone.service.execute(.read(reference), vault: id).value == secret)
    #expect(try await tablet.service.execute(.read(reference), vault: id).value == secret)
}

@Test func deviceRemovalClearsAccountAndRequiresExplicitFreshKeyReconnect() async throws {
    let server = Server(), owner = Client(server, "a"), tablet = Client(server, "a")
    let first = UUID().uuidString, second = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "one"), vault: first)
    _ = try await owner.service.execute(.create(name: "two"), vault: second)
    for id in [first, second] { try await enroll(tablet, owner: owner, vault: id, role: .owner) }
    let old = try await tablet.request().1.device
    let devices = try await owner.service.execute(.manage(.devices), vault: first).devices
    #expect(devices.count == 2)
    #expect(devices.first(where: { $0.id == old.device })?.isCurrent == false)
    #expect(devices.first(where: { $0.id == old.device })?.vaultNames.count == 2)
    _ = try await owner.service.execute(.manage(.removeAccountDevice(old.device)), vault: first)
    // Retrying a completed account removal is harmless.
    _ = try await owner.service.execute(.manage(.removeAccountDevice(old.device)), vault: first)
    for id in [first, second] {
        #expect(try await owner.service.execute(.members, vault: id).devices.count == 1)
    }
    await #expect(throws: MopError.deviceRemoved) {
        try await tablet.service.execute(.sync, vault: first)
    }
    tablet.reopen()
    #expect(try await tablet.service.execute(.discover, vault: nil).deviceRemoved)
    let registry = try NextRegistry(state: tablet.state, container: "iCloud.test", environment: "Development", account: "a")
    #expect(try registry.entries().isEmpty)
    let checkpointFiles = try FileManager.default.contentsOfDirectory(atPath: registry.cache.directory.appendingPathComponent("checkpoints").path)
    #expect(!checkpointFiles.contains { $0.hasSuffix(".json") })
    await #expect(throws: MopError.deviceRemoved) {
        try await tablet.service.execute(.manage(.requestEnrollment(name: "iPad")), vault: first)
    }
    await #expect(throws: MopError.deviceRemoved) {
        try await tablet.service.execute(.catalog, vault: second, offline: true)
    }
    #expect(throws: MopError.invalidIdentity) {
        try tablet.hardware.open("iCloud.test/Development/device", registry.member, LAContext(), false)
    }
    _ = try await tablet.service.execute(.manage(.reconnect), vault: nil)
    _ = try await tablet.service.execute(.manage(.requestEnrollment(name: "iPad")), vault: first)
    let fresh = try await tablet.request().1.device
    #expect(fresh.device != old.device && fresh.encryption != old.encryption)
    _ = try await owner.service.execute(.manage(.automaticEnrollment), vault: first)
    _ = try await tablet.service.execute(.manage(.checkEnrollment), vault: first)
    _ = try await owner.service.execute(.manage(.automaticEnrollment), vault: first)
    #expect(try await tablet.service.execute(.manage(.checkEnrollment), vault: first).enrollmentCompleted)
}

@Test func interruptedRemovalCleanupRemainsBlockedAcrossRelaunch() async throws {
    let server = Server(), owner = Client(server, "a"), tablet = Client(server, "a")
    let id = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    try await enroll(tablet, owner: owner, vault: id, role: .owner)
    let old = try await tablet.request().1.device
    // A second outstanding request using the old keys must never restore access.
    _ = try await tablet.service.execute(.manage(.requestEnrollment(name: "iPad")), vault: id)
    _ = try await owner.service.execute(.manage(.enrollmentInbox), vault: id)
    _ = try await tablet.service.execute(.manage(.checkEnrollment), vault: id)
    await server.dropNext()
    await #expect(throws: MopError.cloudUncertain) {
        try await owner.service.execute(.manage(.removeAccountDevice(old.device)), vault: id)
    }
    _ = try await owner.service.execute(.manage(.removeAccountDevice(old.device)), vault: id)
    let inbox = try await owner.service.execute(.manage(.automaticEnrollment), vault: id)
    #expect(inbox.enrollments.isEmpty)
    #expect(try await owner.service.execute(.members, vault: id).devices.count == 1)
    tablet.hardware.blockDeletion(true)
    await #expect(throws: MopError.deviceRemovalPending) {
        try await tablet.service.execute(.catalog, vault: id)
    }
    tablet.reopen()
    await #expect(throws: MopError.deviceRemovalPending) {
        try await tablet.service.execute(.discover, vault: nil)
    }
    tablet.hardware.blockDeletion(false)
    #expect(try await tablet.service.execute(.discover, vault: nil).deviceRemoved)
    await #expect(throws: MopError.deviceRemoved) {
        try await tablet.service.execute(.manage(.restartEnrollment(name: "iPad")), vault: id)
    }
}

@Test func removingThisDeviceAndLastOwnerProtection() async throws {
    let server = Server(), owner = Client(server, "a"), tablet = Client(server, "a")
    let id = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    let own = try await owner.request().1.device
    await #expect(throws: MopError.lastOwnerDevice) {
        try await owner.service.execute(.manage(.removeAccountDevice(own.device)), vault: id)
    }
    try await enroll(tablet, owner: owner, vault: id, role: .owner)
    await #expect(throws: MopError.deviceRemoved) {
        try await owner.service.execute(.manage(.removeAccountDevice(own.device)), vault: id)
    }
    #expect(try await owner.service.execute(.discover, vault: nil).deviceRemoved)
    #expect(try await tablet.service.execute(.members, vault: id).devices.count == 1)
}

@Test func deviceRemovalReportsConfirmedVaultsBeforeLaterFailure() async throws {
    let server = Server(), owner = Client(server, "a"), tablet = Client(server, "a")
    let first = UUID().uuidString, second = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "one"), vault: first)
    _ = try await owner.service.execute(.create(name: "two"), vault: second)
    for id in [first, second] { try await enroll(tablet, owner: owner, vault: id, role: .owner) }
    let device = try await tablet.request().1.device
    await server.rejectPublication(after: 1)
    let result = try await owner.service.execute(.manage(.removeAccountDevice(device.device)), vault: first)
    #expect(result.deviceRemovalIncomplete)
    #expect(result.message.contains("Removed from:") && result.message.contains("not confirmed"))
    #expect(result.devices.first { $0.id == device.device }?.vaultNames.count == 1)
    // A retry reconciles the pending publication and safely completes the remaining scope.
    _ = try await owner.service.execute(.manage(.removeAccountDevice(device.device)), vault: first)
    for id in [first, second] { #expect(try await owner.service.execute(.members, vault: id).devices.count == 1) }
}

@Test func importServicePublishesOnceAndRejectsStalePreview() async throws {
    let cloud = Server(), owner = Client(cloud, "a"), viewer = Client(cloud, "b")
    let id = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    let bytes = Data("Title,URL,Username,Password\nA,https://a.test,u,p\nB,https://b.test,u,q\n".utf8)
    let document = try PasswordImport.parse(bytes)
    let preview = try #require(try await owner.service.execute(.previewImport(document, selected: nil), vault: id).importPreview)
    let before = try await cloud.head(preview.vault)
    let result = try await owner.service.execute(.commitImport(document, selected: [1, 2], vault: preview.vault, revision: preview.revision), vault: id)
    #expect(result.importReport?.imported == 2)
    #expect(try await cloud.head(preview.vault).version == Data("2".utf8))
    #expect(before.version == Data("1".utf8))
    await #expect(throws: MopError.vaultConflict) {
        try await owner.service.execute(.commitImport(document, selected: [1, 2], vault: preview.vault, revision: preview.revision), vault: id)
    }
    let again = try #require(try await owner.service.execute(.previewImport(document, selected: nil), vault: id).importPreview)
    #expect(again.report.rows.allSatisfy { $0.disposition == .duplicate })
    await #expect(throws: MopError.offlineWrite) { try await owner.service.execute(.previewImport(document, selected: nil), vault: id, offline: true) }
    try await enroll(viewer, owner: owner, vault: id, role: .viewer)
    await #expect(throws: MopError.cloudPermission) { try await viewer.service.execute(.previewImport(document, selected: nil), vault: id) }
}

@Test func uncertainImportReconcilesWithoutDuplicatingItems() async throws {
    let cloud = Server(), owner = Client(cloud, "a")
    let id = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    let document = try PasswordImport.parse(Data("url,username,password\nhttps://a.test,u,p\n".utf8))
    let preview = try #require(try await owner.service.execute(.previewImport(document, selected: nil), vault: id).importPreview)
    await cloud.dropNext()
    await #expect(throws: MopError.cloudUncertain) {
        try await owner.service.execute(.commitImport(document, selected: [1], vault: preview.vault, revision: preview.revision), vault: id)
    }
    owner.reopen()
    let recovered = try #require(try await owner.service.execute(.previewImport(document, selected: nil), vault: id).importPreview)
    #expect(recovered.report.rows[0].disposition == .duplicate)
    #expect(try await owner.service.execute(.catalog, vault: id).catalog?.items.count == 1)
}

@Test func attachmentDownloadsAreOnDemandCachedAndExcludedFromAutoFill() async throws {
    let cloud = Server()
    let writer = Client(cloud, "a"), reader = Client(cloud, "a"), recovery = Client(cloud, "a")
    let id = try await create(writer, recovery: recovery)
    let catalog = try #require(try await writer.service.execute(.catalog, vault: id).catalog)
    let file = try Attachment(fileName: "proof.dat", data: Data([0, 128, 255]))
    let item = VaultItem(name: "Proof", type: .document, fields: [.init(path: "file", type: .attachment, value: try file.encodedValue())])
    _ = try await writer.service.execute(.save(.init(revision: catalog.revision, item: item, create: true)), vault: id)
    try await enroll(reader, owner: writer, vault: id, role: .owner)
    let reference = try SecretReference("secondpass://personal/Proof/file")
    reader.reopen(allowsAttachments: false, duringSync: true)
    _ = try await reader.service.execute(.catalog, vault: id)
    await #expect(throws: MopError.notFound) { try await reader.service.execute(.read(reference), vault: id) }
    #expect(await cloud.attachmentReads == 0)
    reader.reopen()
    _ = try await reader.service.execute(.sync, vault: id)
    #expect(await cloud.attachmentReads == 0)
    await #expect(throws: AttachmentFailure.unavailable) { try await reader.service.execute(.read(reference), vault: id, offline: true) }
    let value = try #require(try await reader.service.execute(.read(reference), vault: id).value)
    #expect(try Attachment.decode(String(decoding: value, as: UTF8.self)) == file)
    #expect(await cloud.attachmentReads == 1)
    _ = try await reader.service.execute(.read(reference), vault: id, offline: true)
    #expect(await cloud.attachmentReads == 1)
    let syncReader = Client(cloud, "a")
    try await enroll(syncReader, owner: writer, vault: id, role: .owner)
    syncReader.reopen(duringSync: true)
    _ = try await syncReader.service.execute(.sync, vault: id)
    #expect(await cloud.attachmentReads == 2)
    _ = try await syncReader.service.execute(.read(reference), vault: id, offline: true)
    #expect(await cloud.attachmentReads == 2)
    let (_, readerIdentity) = try await reader.request()
    _ = try await writer.service.execute(.manage(.removeDevice(readerIdentity.device.device)), vault: id)
    await #expect(throws: MopError.deviceRemoved) { try await reader.service.execute(.read(reference), vault: id) }
    let rotated = try #require(try await syncReader.service.execute(.read(reference), vault: id).value)
    #expect(try Attachment.decode(String(decoding: rotated, as: UTF8.self)) == file)
    #expect(await cloud.attachmentReads == 3)
}

@Test func rejectedPublicationDoesNotChangeCachedItemDates() async throws {
    let server = Server(), owner = Client(server, "a")
    let id = UUID().uuidString
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    let reference = try SecretReference("secondpass://personal/login/password")
    let saved = try await owner.service.execute(.write(reference, SecretBytes(utf8: "first"), replace: false), vault: id)
    let before = try #require(saved.catalog?.items.first)
    #expect(before.metadata?.createdAt != nil)
    await server.rejectPublication(after: 0)
    do {
        _ = try await owner.service.execute(.write(reference, SecretBytes(utf8: "rejected"), replace: true), vault: id)
        Issue.record("Publication should fail")
    } catch {}
    let cached = try await owner.service.execute(.catalog, vault: id, offline: true)
    #expect(cached.catalog?.items.first?.metadata == before.metadata)
    #expect(cached.catalog?.items.first?.storageID == before.storageID)
}

@Test func unlockedLocalReadsNeverContactCloudOrAuthenticateAgain() async throws {
    let server = Server(), owner = Client(server, "a")
    let id = UUID().uuidString, reference = try SecretReference("secondpass://personal/login/password")
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    _ = try await owner.service.execute(.write(reference, "secret", replace: false), vault: id)
    let requests = await server.readRequests, authentications = owner.calls.withLock { $0 }
    let unwraps = owner.hardware.unwraps.withLock { $0 }
    let result = try await owner.service.readLocal(reference, vault: id)
    #expect(owner.hardware.unwraps.withLock { $0 } == unwraps + 1)
    #expect(result.value == SecretBytes(utf8: "secret"))
    #expect(result.usageIdentity != nil)
    #expect(await server.readRequests == requests)
    #expect(owner.calls.withLock { $0 } == authentications)
    try NextAccountBinding.invalidate(state: owner.state)
    await #expect(throws: MopError.cloudAccount) { try await owner.service.readLocal(reference, vault: id) }
    owner.service.lock()
    await #expect(throws: MopError.authentication) { try await owner.service.readLocal(reference, vault: id) }
    #expect(await server.readRequests == requests)
}

@Test func localReadDoesNotWaitBehindCloudRefresh() async throws {
    let server = Server(), owner = Client(server, "a"), barrier = AuthenticationGate()
    let id = UUID().uuidString, reference = try SecretReference("secondpass://personal/login/password")
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    _ = try await owner.service.execute(.write(reference, "secret", replace: false), vault: id)
    await server.setReadGate(barrier)
    let service = owner.service!
    let refresh = Task { try await service.execute(.sync, vault: id) }
    while !(await barrier.entered) { await Task.yield() }
    // Prevent a regression from hanging the test process indefinitely.
    let watchdog = Task {
        do { try await Task.sleep(for: .seconds(5)) } catch { return }
        await server.setReadGate(nil); await barrier.release()
    }
    let unwraps = owner.hardware.unwraps.withLock { $0 }
    let result = try await owner.service.readLocal(reference, vault: id)
    #expect(owner.hardware.unwraps.withLock { $0 } == unwraps + 1)
    #expect(result.value == SecretBytes(utf8: "secret"))
    #expect(await barrier.isWaiting)
    watchdog.cancel()
    await server.setReadGate(nil); await barrier.release()
    _ = try await refresh.value
}

@Test func localReadSnapshotTracksCommittedEditsAndDeletion() async throws {
    let owner = Client(Server(), "a"), id = UUID().uuidString
    let reference = try SecretReference("secondpass://personal/login/password")
    _ = try await owner.service.execute(.create(name: "personal"), vault: id)
    _ = try await owner.service.execute(.write(reference, "first", replace: false), vault: id)
    #expect(try await owner.service.readLocal(reference, vault: id).value == SecretBytes(utf8: "first"))
    _ = try await owner.service.execute(.write(reference, "second", replace: true), vault: id)
    let result = try await owner.service.readLocal(reference, vault: id)
    #expect(result.value == SecretBytes(utf8: "second"))
    #expect(result.offlineDate != nil)
    _ = try await owner.service.execute(.delete(reference), vault: id)
    await #expect(throws: MopError.notFound) { try await owner.service.readLocal(reference, vault: id) }
}
