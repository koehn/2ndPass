import Foundation
import CryptoKit
import Synchronization
import Testing
import MopCore
import MopVaultNext
@testable import MopSync
@testable import MopAppSupport

private struct GrantBenchmarkPermit: RepositoryWritePermit {
    func withWritePermission<T>(_ body: () throws -> T) throws -> T { try body() }
}
private final class GrantBenchmarkDevice: DeviceOperations {
    let underlying: SessionDevice
    let signatures = Mutex(0)
    let unwraps = Mutex(0)
    var identity: DevicePublicKey { underlying.identity }
    init(_ owner: SessionDevice) { underlying = SessionDevice(copying: owner) }
    func sign(_ bytes: Data) throws -> Data { signatures.withLock { $0 += 1 }; return try underlying.sign(bytes) }
    func unwrap(_ envelope: KeyEnvelope, context: Data) throws -> SymmetricKey { unwraps.withLock { $0 += 1 }; return try underlying.unwrap(envelope, context: context) }
    func close() { underlying.close() }
}
extension EncryptedItemRepository {
    fileprivate func preparationMetrics() -> (reads: Int, rows: Int, scans: Int) {
        (grantPreparationReads, grantPreparationRows, missingGrantScanRows)
    }
    fileprivate func seedProgressHint(scope: VaultScope, count: Int) throws {
        try transaction { try writeJournal(count, entity: "StateBlob", key: "enrollment-progress-total:" + scope.storageKey) }
    }
}

@Suite(.serialized) struct GrantGenerationPerformanceTests {
    @Test func displayProjectionUsesOneUnwrapPerItem() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try EncryptedItemRepository(storeURL: root.appendingPathComponent("ContentPreview3/Content3.sqlite"))
        let owner = try SessionDevice(), vault = try sessionAuthority(owner: owner)
        let genesis = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
        let history = try TrustedMembershipHistory(genesis: genesis, vault: vault.id, pinnedDigest: genesis.digest())
        let scope = VaultScope(account: "display", vaultID: vault.id)
        try await GrantBackedContentStorage(repository: repository).setAuthority(scope: scope, expected: nil, history: history, authorization: GrantBenchmarkPermit())
        let device = GrantBenchmarkDevice(owner)
        let session = try GrantBackedContentSession(repository: repository,
            binding: ItemVaultBinding(account: scope.account, database: scope.database, zoneOwner: scope.zoneOwner, vaultID: vault.id), history: history, device: device)
        var ids: [UUID] = []
        for _ in 0..<100 {
            let id = UUID(), secret = UUID().uuidString, visible = UUID().uuidString
            let archive = PortableVaultArchive(name: "display", items: [VaultItem(name: "Login", type: .login,
                fields: [ItemField(path: "password", type: .password), ItemField(path: "username", type: .text)])],
                itemIDs: ["Login": id.uuidString], references: ["Login/password": secret, "Login/username": visible],
                records: [secret: PortableArchiveRecord(itemID: id.uuidString, bytes: SecretBytes(utf8: "concealed")),
                          visible: PortableArchiveRecord(itemID: id.uuidString, bytes: SecretBytes(utf8: "alice"))])
            _ = try await session.save(archive, expectedBase: nil); ids.append(id)
        }
        let before = device.unwraps.withLock { $0 }, start = ContinuousClock.now
        for id in ids {
            let row = try await session.displayItem(itemID: id)
            #expect(row.item.fields.first { $0.path == "username" }?.value == "alice")
            #expect(row.item.fields.first { $0.path == "password" }?.value == nil)
        }
        #expect(device.unwraps.withLock { $0 } - before == ids.count)
        print("Display projection benchmark: 100 items=\(start.duration(to: .now)); unwraps=100")
        session.lock()
        await #expect(throws: MopError.authentication) { try await session.displayItem(itemID: ids[0]) }
    }

    @Test func actualGrantGenerationScalesLinearly() async throws {
        var durations: [Int: Double] = [:]
        for count in [100, 500, 1000] {
            let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: root) }
            let repository = try EncryptedItemRepository(storeURL: root.appendingPathComponent("ContentPreview3/Content3.sqlite"))
            let owner = try SessionDevice(), joining = try SessionDevice(member: owner.identity.member)
            let vault = try sessionAuthority(owner: owner)
            let genesis = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
            let original = try TrustedMembershipHistory(genesis: genesis, vault: vault.id, pinnedDigest: genesis.digest())
            let scope = VaultScope(account: "benchmark", vaultID: vault.id)
            let binding = ItemVaultBinding(account: scope.account, database: scope.database, zoneOwner: scope.zoneOwner, vaultID: vault.id)
            let storage = GrantBackedContentStorage(repository: repository)
            try await storage.setAuthority(scope: scope, expected: nil, history: original, authorization: GrantBenchmarkPermit())
            let source = try GrantBackedContentSession(repository: repository, binding: binding, history: original, device: SessionDevice(copying: owner))
            var revisions: [UUID: UUID] = [:]
            for index in 0..<count {
                let item = UUID()
                // Include larger ciphertext so repeated full-content verification
                // cannot hide behind a tiny password-only fixture.
                let bytes = SecretBytes(copying: Data(repeating: UInt8(index % 255), count: index % 10 == 0 ? 65_536 : 1024))
                revisions[item] = try await source.create(item: item, components: ["password": bytes]).version.versionID
            }
            var history = original
            try history.append(MembershipEnvelope.successor(of: genesis,
                membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])]), owner: owner))
            try await storage.setAuthority(scope: scope, expected: original, history: history, authorization: GrantBenchmarkPermit())
            let device = GrantBenchmarkDevice(owner)
            let sender = try GrantBackedContentSession(repository: repository, binding: binding, history: history, device: device)
            let work = try await repository.activeOperations(account: scope.account, database: scope.database).filter { $0.kind == .prepareGrant }
            #expect(work.count == count)
            let before = await repository.preparationMetrics(), clock = ContinuousClock(), start = clock.now
            for operation in work {
                guard case .completed = await sender.handle(operation, owner: GrantBenchmarkPermit()) else { Issue.record("Grant generation failed"); return }
            }
            let elapsed = start.duration(to: clock.now)
            let seconds = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
            durations[count] = seconds
            let after = await repository.preparationMetrics()
            #expect(after.reads - before.reads == count)
            #expect(after.rows - before.rows == count * 4)
            #expect(after.scans == before.scans)
            #expect(device.underlying.unwrapCount == count)
            #expect(device.signatures.withLock { $0 } == count)
            #expect(try await repository.itemRevisionIndex(account: scope.account, vaultID: vault.id) == revisions)
            #expect(try await repository.activeOperations(account: scope.account, database: scope.database).filter { $0.kind == .grant }.count == count * 2)
            let receiver = try GrantBackedContentSession(repository: repository, binding: binding, history: history, device: SessionDevice(copying: joining))
            // Every produced grant must actually open the unchanged content.
            for (item, version) in revisions {
                #expect(try await receiver.open(item: item, component: "password", expected: version).count >= 1024)
            }
            let replayStart = device.underlying.unwrapCount
            for operation in work { _ = await sender.handle(operation, owner: GrantBenchmarkPermit()) }
            #expect(device.underlying.unwrapCount == replayStart)
            #expect(device.signatures.withLock { $0 } == count)
            print("Sender grant benchmark: items=\(count), elapsed=\(elapsed), ms/item=\(seconds * 1000 / Double(count)), preparation rows=\(after.rows - before.rows), vault scan rows=0, unwraps=\(count), signatures=\(count)")
        }
        // Deterministic row/crypto counts above establish linear work. This loose
        // wall-clock guard additionally catches gross regressions without treating
        // scheduler jitter as a precise performance contract.
        #expect(durations[500]! <= durations[100]! * 7.5 + 1)
        #expect(durations[1000]! <= durations[500]! * 3 + 1)
    }

    @Test(arguments: [false, true]) func preparedGrantCannotBypassLockOrAuthorityChange(lock: Bool) async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try EncryptedItemRepository(storeURL: root.appendingPathComponent("ContentPreview3/Content3.sqlite"))
        let owner = try SessionDevice(), joining = try SessionDevice(member: owner.identity.member)
        let vault = try sessionAuthority(owner: owner)
        let genesis = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
        let original = try TrustedMembershipHistory(genesis: genesis, vault: vault.id, pinnedDigest: genesis.digest())
        let vaultScope = VaultScope(account: "a", vaultID: vault.id)
        let scope = ItemScope(account: "a", vaultID: vault.id, itemID: UUID())
        let storage = GrantBackedContentStorage(repository: repository)
        try await storage.setAuthority(scope: vaultScope, expected: nil, history: original, authorization: GrantBenchmarkPermit())
        let publication = try ContentEnvelope.seal(["password": "unchanged"], vault: vault.id, item: scope.itemID, history: original, signer: owner)
        _ = try await storage.commit(publication.content, grants: publication.grants, scope: scope, history: original, authorization: GrantBenchmarkPermit())
        var admitted = original
        try admitted.append(MembershipEnvelope.successor(of: genesis,
            membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])]), owner: owner))
        try await storage.setAuthority(scope: vaultScope, expected: original, history: admitted, authorization: GrantBenchmarkPermit())
        let verified = try ContentGrantPreparation(bytes: publication.content.encoded(), item: scope.itemID, history: admitted)
        let source = try #require(publication.grants.first)
        #expect(throws: (any Error).self) {
            try verified.extendingAccess(to: joining.identity, sourceGrantBytes: Data("bad grant".utf8), decryptor: owner, signer: owner)
        }
        #expect(throws: (any Error).self) {
            try verified.extendingAccess(to: joining.identity, sourceGrantBytes: source.encoded(), decryptor: joining, signer: owner)
        }
        let prepared = try verified.extendingAccess(to: joining.identity, sourceGrantBytes: source.encoded(), decryptor: owner, signer: owner)
        let permit = ItemVaultPermit(device: SessionDevice(copying: owner))
        if lock {
            permit.invalidate()
        } else {
            // Warm path checks before revocation; the successor must discard them.
            try admitted.verifyContentKeyPath(from: genesis.digest())
            var revoked = admitted
            try revoked.append(MembershipEnvelope.successor(of: admitted.current,
                membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity])], removedDevices: [joining.identity.device]), owner: owner))
            #expect(throws: (any Error).self) { try revoked.verifyContentKeyPath(from: genesis.digest()) }
            try await storage.setAuthority(scope: vaultScope, expected: admitted, history: revoked, authorization: GrantBenchmarkPermit())
        }
        await #expect(throws: (any Error).self) { try await storage.commitGrant(prepared, scope: scope, authorization: permit) }
        #expect(try await repository.contentGrants(scope: scope, keyGeneration: publication.content.header.keyGeneration).count == 1)
        #expect(try await repository.item(scope)?.versionID == publication.content.header.version)
    }

    @Test func enrollmentProgressRequiresMatchingGrantsAndMetadata() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try EncryptedItemRepository(storeURL: root.appendingPathComponent("ContentPreview3/Content3.sqlite"))
        let owner = try SessionDevice(), joining = try SessionDevice(member: owner.identity.member)
        let vault = try sessionAuthority(owner: owner)
        let genesis = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
        let original = try TrustedMembershipHistory(genesis: genesis, vault: vault.id, pinnedDigest: genesis.digest())
        let scope = VaultScope(account: "a", vaultID: vault.id), metadata = UUID(), item = UUID()
        let binding = ItemVaultBinding(account: "a", database: "private", zoneOwner: scope.zoneOwner, vaultID: vault.id)
        let storage = GrantBackedContentStorage(repository: repository)
        try await storage.setAuthority(scope: scope, expected: nil, history: original, authorization: GrantBenchmarkPermit())
        let source = try GrantBackedContentSession(repository: repository, binding: binding, history: original, device: SessionDevice(copying: owner))
        _ = try await source.create(item: item, components: ["password": "one"])
        _ = try await source.create(item: UUID(), components: ["password": "arrived after approval"])
        try await repository.seedProgressHint(scope: scope, count: 1)
        let before = try #require(await repository.enrollmentDownloadProgress(scope: scope, recipient: joining.identity.fingerprint, metadata: metadata))
        #expect(before.ready == 0 && before.total == 3) // Reserve space for missing metadata.
        _ = try await source.create(item: metadata, components: ["password": "metadata"])
        var history = original
        try history.append(MembershipEnvelope.successor(of: genesis,
            membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])]), owner: owner))
        try await storage.setAuthority(scope: scope, expected: original, history: history, authorization: GrantBenchmarkPermit())
        let sender = try GrantBackedContentSession(repository: repository, binding: binding, history: history, device: SessionDevice(copying: owner))
        let work = try await repository.activeOperations(account: "a", database: "private").filter { $0.kind == .prepareGrant }
        _ = await sender.handle(work[0], owner: GrantBenchmarkPermit())
        let partial = try #require(await repository.enrollmentDownloadProgress(scope: scope, recipient: joining.identity.fingerprint, metadata: metadata))
        #expect(partial.ready == 1 && partial.total == 3)
        let reopened = try EncryptedItemRepository(storeURL: root.appendingPathComponent("ContentPreview3/Content3.sqlite"))
        #expect(try await reopened.enrollmentDownloadProgress(scope: scope, recipient: joining.identity.fingerprint, metadata: metadata)?.ready == 1)
        for operation in work.dropFirst() { _ = await sender.handle(operation, owner: GrantBenchmarkPermit()) }
        #expect(try await reopened.enrollmentDownloadProgress(scope: scope, recipient: joining.identity.fingerprint, metadata: metadata) == nil)
    }
}

extension GrantGenerationPerformanceTests {
    /// Local crypto/journal benchmark, deliberately without CloudKit or Keychain.
    /// 895 user records; production metadata is an additional encrypted record.
    @Test func removeReadd895ItemsWithRestart() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("ContentPreview3/Content3.sqlite")
        var repository = try EncryptedItemRepository(storeURL: url)
        let mac = try SessionDevice(), ipad = try SessionDevice(member: mac.identity.member)
        let oldPhone = try SessionDevice(member: mac.identity.member), newPhone = try SessionDevice(member: mac.identity.member)
        let vault = UUID(), permit = GrantBenchmarkPermit()
        let scope = VaultScope(account: "audit", vaultID: vault)
        let binding = ItemVaultBinding(account: scope.account, database: scope.database, zoneOwner: scope.zoneOwner, vaultID: vault)
        let genesis = try MembershipEnvelope.genesis(vault: vault,
            membership: Membership(accounts: [.init(id: mac.identity.member, role: .owner,
                devices: [mac.identity, ipad.identity, oldPhone.identity])]), owner: mac)
        let original = try TrustedMembershipHistory(genesis: genesis, vault: vault, pinnedDigest: genesis.digest())
        var storage = GrantBackedContentStorage(repository: repository)
        try await storage.setAuthority(scope: scope, expected: nil, history: original, authorization: permit)
        var session = try GrantBackedContentSession(repository: repository, binding: binding, history: original, device: SessionDevice(copying: mac))
        for _ in 0..<895 {
            _ = try await session.create(item: UUID(), components: ["password": SecretBytes(copying: Data(repeating: 42, count: 1024))])
        }
        var removed = original
        try removed.append(MembershipEnvelope.successor(of: genesis,
            membership: Membership(accounts: [.init(id: mac.identity.member, role: .owner, devices: [mac.identity, ipad.identity])],
                removedDevices: [oldPhone.identity.device]), owner: mac))
        try await storage.setAuthority(scope: scope, expected: original, history: removed, authorization: permit)
        let rotations = try await repository.activeOperations(account: scope.account, database: scope.database).filter { $0.kind == .rotateContent }
        #expect(rotations.count == 895)
        session = try GrantBackedContentSession(repository: repository, binding: binding, history: removed, device: SessionDevice(copying: mac))
        let start = ContinuousClock.now
        for (index, operation) in rotations.enumerated() {
            if index == 447 {
                // Reopen durable storage mid-cycle; never reset its journal.
                session.lock()
                repository = try EncryptedItemRepository(storeURL: url)
                storage = GrantBackedContentStorage(repository: repository)
                session = try GrantBackedContentSession(repository: repository, binding: binding, history: removed, device: SessionDevice(copying: mac))
                #expect(try await repository.activeOperations(account: scope.account, database: scope.database).filter { $0.kind == .rotateContent }.count == 448)
            }
            guard case .completed = await session.handle(operation, owner: permit) else { Issue.record("Rotation failed"); return }
        }
        let rotationDuration = start.duration(to: .now)
        let revisions = try await repository.itemRevisionIndex(account: scope.account, vaultID: vault)
        let firstBatch = try await repository.contentPublications(account: scope.account)
        #expect(firstBatch.count == 100)
        #expect(firstBatch.allSatisfy { $0.kind == .version }) // sources precede grants
        // Enumerate current publication payloads, not the bounded 100-record selector.
        func projectedUploads(_ repository: EncryptedItemRepository) async throws -> [ContentUpload] {
            var result: [ContentUpload] = []
            for (item, version) in revisions {
                let itemScope = binding.item(item)
                let content = try #require(await repository.contentVersion(scope: itemScope, version: version))
                for kind in [ContentRecordKind.version, .head] {
                    result.append(ContentUpload(operationID: UUID(), content: content, grant: nil, kind: kind, systemFields: nil))
                }
                for grant in try await repository.contentGrants(scope: itemScope, keyGeneration: content.keyGeneration) {
                    result.append(ContentUpload(operationID: UUID(), content: content, grant: grant, kind: .grant, systemFields: nil))
                }
            }
            return result
        }
        let rotatedUploads = try await projectedUploads(repository)
        let rotationBytes = rotatedUploads.reduce(0) { $0 + $1.byteCount }
        #expect(rotatedUploads.filter { $0.kind == .head }.count == 895)
        #expect(rotatedUploads.filter { $0.kind == .grant }.count == 1790)
        for operation in rotations { _ = await session.handle(operation, owner: permit) }
        #expect(try await repository.itemRevisionIndex(account: scope.account, vaultID: vault) == revisions)
        var admitted = removed
        try admitted.append(MembershipEnvelope.successor(of: removed.current,
            membership: Membership(accounts: [.init(id: mac.identity.member, role: .owner, devices: [mac.identity, ipad.identity, newPhone.identity])],
                removedDevices: [oldPhone.identity.device]), owner: mac))
        #expect(try GrantBackedContentStorage.recipientPolicy(history: admitted).keyAuthority == GrantBackedContentStorage.recipientPolicy(history: removed).keyAuthority)
        try await storage.setAuthority(scope: scope, expected: removed, history: admitted, authorization: permit)
        let work = try await repository.activeOperations(account: scope.account, database: scope.database)
        #expect(work.filter { $0.kind == .rotateContent }.isEmpty)
        let grants = work.filter { $0.kind == .prepareGrant }
        #expect(grants.count == 895)
        let device = GrantBenchmarkDevice(mac)
        session = try GrantBackedContentSession(repository: repository, binding: binding, history: admitted, device: device)
        let grantStart = ContinuousClock.now
        for operation in grants {
            guard case .completed = await session.handle(operation, owner: permit) else { Issue.record("Grant failed"); return }
        }
        let grantDuration = grantStart.duration(to: .now)
        let uploads = try await projectedUploads(repository)
        let newGrants = uploads.filter { $0.grant?.recipient == newPhone.identity.fingerprint }
        #expect(newGrants.count == 895)
        #expect(device.signatures.withLock { $0 } == 895)
        #expect(try await repository.itemRevisionIndex(account: scope.account, vaultID: vault) == revisions)
        // A second issuer can generate a distinct, valid record for identical access.
        let first = try #require(newGrants.first)
        let prepared = try ContentGrantPreparation(bytes: first.content.version.ciphertext, item: first.scope.itemID, history: admitted)
        let ipadGrant = try #require(await repository.contentGrants(scope: first.scope, keyGeneration: first.content.keyGeneration, recipient: ipad.identity.fingerprint).first)
        let duplicate = try prepared.extendingAccess(to: newPhone.identity, sourceGrantBytes: ipadGrant.bytes, decryptor: ipad, signer: ipad)
        #expect(try duplicate.grant.identifier != first.grant?.identifier)
        let phone = try GrantBackedContentSession(repository: repository, binding: binding, history: admitted, device: SessionDevice(copying: newPhone))
        for (item, version) in revisions {
            #expect(try await phone.open(item: item, component: "password", expected: version).count == 1024)
        }
        for operation in grants { _ = await session.handle(operation, owner: permit) }
        #expect(device.signatures.withLock { $0 } == 895)
        print("AUDIT895 rotation=\(rotationDuration) rotationUploadRecords=\(rotatedUploads.count) rotationPayloadBytes=\(rotationBytes) grants=\(grantDuration) newGrantRecords=\(newGrants.count) newGrantPayloadBytes=\(newGrants.reduce(0) { $0 + $1.byteCount }) replaySignatures=0 reEnrollmentRotations=0")
    }
}
