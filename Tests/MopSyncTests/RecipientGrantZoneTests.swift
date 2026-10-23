import CloudKit
import Foundation
import Testing
@testable import MopSync

private struct RecipientPermit: RepositoryWritePermit {
    func withWritePermission<T>(_ body: () throws -> T) throws -> T { try body() }
}

@Suite struct RecipientGrantZoneTests {
    @Test func zoneRegistrationDoesNotRequeueAfterCheckpointOrCompletedSend() {
        let a = CKRecordZone.ID(zoneName: "a", ownerName: CKCurrentUserDefaultName)
        let b = CKRecordZone.ID(zoneName: "b", ownerName: CKCurrentUserDefaultName)
        var registration = GrantZoneRegistration()
        #expect(registration.newlyRequired([a]) == [a])
        // Once CloudKit removes a successful database change, checkpoint wakes
        // still ask for the same zone while its grant records remain pending.
        for _ in 0..<100 { #expect(registration.newlyRequired([a]).isEmpty) }
        #expect(registration.newlyRequired([a, b]) == [b])
        #expect(registration.newlyRequired([]).isEmpty)
        #expect(registration.newlyRequired([a]).isEmpty)
        registration.invalidate(a)
        #expect(registration.newlyRequired([a, b]) == [a])
        #expect(registration.newlyRequired([a, b]).isEmpty)
        // A fresh engine reconstructs requirements without treating memory as a
        // durable receipt. A changed owner is a distinct destination as well.
        registration = GrantZoneRegistration()
        #expect(registration.newlyRequired([a, b]) == [a, b])
        let otherOwner = CKRecordZone.ID(zoneName: "a", ownerName: "other-owner")
        #expect(registration.newlyRequired([a, otherOwner]) == [otherOwner])
    }

    func fixture() async throws -> (URL, EncryptedItemRepository, VaultScope, [PreparedContentGrant]) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let repository = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
        let scope = VaultScope(account: "recipient-account", vaultID: UUID())
        let recipients = [String(repeating: "a", count: 64), String(repeating: "b", count: 64)]
        let policy = ContentRecipientPolicy(membership: String(repeating: "c", count: 64), recipients: Set(recipients), keyAuthority: String(repeating: "c", count: 64))
        try await repository.setContentRecipients(scope: scope, expected: nil, policy: policy, authorization: RecipientPermit())
        let item = ItemScope(account: scope.account, vaultID: scope.vaultID, itemID: UUID())
        let content = PreparedContentVersion(version: EncryptedItemVersion(scope: item, baseVersionID: nil, ciphertext: Data([1]), generation: 1),
            keyGeneration: UUID(), contentRevision: UUID(), membership: policy.membership, keyAuthority: policy.keyAuthority)
        let grants = recipients.enumerated().map { index, recipient in
            PreparedContentGrant(scope: item, keyGeneration: content.keyGeneration, recipient: recipient,
                identifier: String(repeating: index == 0 ? "d" : "e", count: 64), bytes: Data([UInt8(index + 1)]))
        }
        _ = try await repository.commitContent(content, grants: grants, expectedPolicy: policy, authorization: RecipientPermit())
        return (root, repository, scope, grants)
    }

@Test func recipientDownloadsExcludePublishTargetsAndFollowIdentityAndRecovery() throws {
    let vault = UUID(), a = String(repeating: "a", count: 64), b = String(repeating: "b", count: 64), r = String(repeating: "c", count: 64)
    let own = try RecipientGrantZone(vault: vault, recipient: a).name
    let recovery = try RecipientGrantZone(vault: vault, recipient: r).name
    #expect(try RecipientGrantZone.downloads(vault: vault, devices: [a, b], local: a, recovery: r, presentedRecovery: nil) == [own])
    #expect(try RecipientGrantZone.downloads(vault: vault, devices: [b], local: a, recovery: r, presentedRecovery: nil).isEmpty)
    #expect(try RecipientGrantZone.downloads(vault: vault, devices: [a, b], local: b, recovery: r, presentedRecovery: nil) == [RecipientGrantZone(vault: vault, recipient: b).name])
    #expect(try RecipientGrantZone.downloads(vault: vault, devices: [b], local: nil, recovery: r, presentedRecovery: r) == [recovery])
    #expect(try RecipientGrantZone.downloads(vault: vault, devices: [b], local: nil, recovery: nil, presentedRecovery: r).isEmpty)
}

@Test func vaultRetirementMatchesContentAndAllRecipientZoneWorkOnly() throws {
    let vault = UUID(), owner = "__defaultOwner__"
    let address = VaultCloudAddress(vaultID: vault, zoneName: SyncStoreLayout.contentZone(vault: vault), ownerName: owner)
    let grant = CKRecordZone.ID(zoneName: try RecipientGrantZone(vault: vault, recipient: String(repeating: "a", count: 64)).name, ownerName: owner)
    let other = CKRecordZone.ID(zoneName: try RecipientGrantZone(vault: UUID(), recipient: String(repeating: "a", count: 64)).name, ownerName: owner)
    let otherOwner = CKRecordZone.ID(zoneName: grant.zoneName, ownerName: "another-owner")
    #expect(ContentZoneRouting.belongs(.saveZone(CKRecordZone(zoneID: grant)), to: address))
    #expect(ContentZoneRouting.belongs(.saveRecord(CKRecord.ID(recordName: "grant", zoneID: grant)), to: address))
    #expect(ContentZoneRouting.belongs(.deleteRecord(CKRecord.ID(recordName: "grant", zoneID: grant)), to: address))
    #expect(!ContentZoneRouting.belongs(.saveZone(CKRecordZone(zoneID: other)), to: address))
    #expect(!ContentZoneRouting.belongs(.deleteZone(otherOwner), to: address))
}

@Test func readableReferenceCASRejectsChangedHeadAndWrongRecipient() async throws {
        let (root, repository, scope, grants) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let grant = grants[0], head = try #require(await repository.item(grants[0].scope))
        let reference = ReadableContentReference(version: head.versionID, keyGeneration: grant.keyGeneration,
            grant: grant.identifier, recipient: grant.recipient)
        await #expect(throws: ItemRepositoryError.staleLocalVersion) {
            try await repository.rememberReadableContent(scope: grant.scope, reference: reference, expectedHead: UUID(), permit: RecipientPermit())
        }
        let wrong = ReadableContentReference(version: head.versionID, keyGeneration: grant.keyGeneration,
            grant: grant.identifier, recipient: grants[1].recipient)
        await #expect(throws: ContentStoreError.invalidRecord) {
            try await repository.rememberReadableContent(scope: grant.scope, reference: wrong, expectedHead: head.versionID, permit: RecipientPermit())
        }
        try await repository.rememberReadableContent(scope: grant.scope, reference: reference, expectedHead: head.versionID, permit: RecipientPermit())
        let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
        #expect(try await reopened.readableContent(scope: grant.scope, recipient: grant.recipient) == reference)
        let other = ItemScope(account: scope.account + "-other", vaultID: scope.vaultID, itemID: grant.scope.itemID)
        #expect(try await reopened.readableContent(scope: other, recipient: grant.recipient) == nil)
    }

@Test func refreshedDiscoveryFindsReplacementWithoutRevivingDeletedVault() async throws {
        let (root, repository, scope, _) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let checkpoint = Data([1, 2, 3])
        try await repository.saveEngineState(checkpoint, account: scope.account, database: "discovery-test")
        _ = try await repository.saveDeletion(scope: scope, notice: Data([9]), phase: .prepared, authorization: RecipientPermit())
        let replacement = UUID()
        let hints = [scope.vaultID, replacement].map {
            VaultCloudAddress(vaultID: $0, zoneName: SyncStoreLayout.contentZone(vault: $0), ownerName: "__defaultOwner__")
        }
        for _ in 0..<2 {
            try await repository.retainContentDiscovery(account: scope.account, addresses: hints, authorization: RecipientPermit())
        }
        let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
        #expect(try await reopened.contentDiscovery(account: scope.account).map(\.vaultID) == [replacement])
        #expect(try await reopened.engineState(account: scope.account, database: "discovery-test") == checkpoint)
    }

    @Test func batchedReadsMatchIndividualReadsAndIsolateScopes() async throws {
        let (root, repository, _, grants) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let grant = grants[0], scope = grants[0].scope
        let state = try #require(await repository.contentState(scope: scope))
        let other = ItemScope(account: "other-account", vaultID: scope.vaultID, itemID: scope.itemID,
            database: scope.database, zoneOwner: scope.zoneOwner)
        let queries = [
            ContentReadinessQuery(scope: scope, observedVersion: state.versionID, recipient: grant.recipient, keyGeneration: grant.keyGeneration, missingVersion: nil),
            ContentReadinessQuery(scope: scope, observedVersion: state.versionID, recipient: "missing", keyGeneration: grant.keyGeneration, missingVersion: nil),
            ContentReadinessQuery(scope: scope, observedVersion: UUID(), recipient: nil, keyGeneration: nil, missingVersion: nil),
            ContentReadinessQuery(scope: other, observedVersion: nil, recipient: grant.recipient, keyGeneration: grant.keyGeneration, missingVersion: state.versionID),
            ContentReadinessQuery(scope: scope, observedVersion: state.versionID, recipient: nil, keyGeneration: nil, missingVersion: state.versionID),
            ContentReadinessQuery(scope: scope, observedVersion: state.versionID, recipient: nil, keyGeneration: nil, missingVersion: UUID())
        ]
        #expect(try await repository.contentReadiness(queries) == [true, false, true, false, true, false])
        #expect(try await repository.contentReadiness([]).isEmpty)
        #expect(try await repository.contentReadiness(Array(repeating: queries[0], count: 64)).allSatisfy { $0 })
        await #expect(throws: ContentStoreError.invalidRecord) {
            try await repository.contentReadiness(Array(repeating: queries[0], count: 65))
        }
        let snapshot = try await repository.contentMigrationReads(scopes: [scope, other], recipients: [grant.recipient])
        #expect(snapshot[other]?.versions.isEmpty == true && snapshot[other]?.grants.isEmpty == true)
        #expect(Set(snapshot[scope]!.versions.map { $0.version.versionID }) == Set(try await repository.contentVersions(scope: scope).map { $0.version.versionID }))
        #expect(snapshot[scope]?.grants == [grant])
        await #expect(throws: ContentStoreError.invalidRecord) {
            try await repository.contentMigrationReads(scopes: Array(repeating: scope, count: 17), recipients: [grant.recipient])
        }
    }

    @Test func recipientGrantRoutingRejectsRetiredContentZone() async throws {
        let (root, _, scope, grants) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let grant = grants[0], record = try ContentRecordTransport.grant(grants[0])
        let zone = try RecipientGrantZone(vault: scope.vaultID, recipient: grant.recipient)
        let address = try ContentRecordAddress(recordType: record.recordType, zone: zone.name, record: record.recordID.recordName)
        #expect(address.recipient == grant.recipient && address.vault == scope.vaultID)
        #expect(throws: (any Error).self) {
            try ContentRecordAddress(recordType: record.recordType, zone: SyncStoreLayout.contentZone(vault: scope.vaultID), record: record.recordID.recordName)
        }
    }

    @Test(arguments: [false, true]) func targetedRepairSurvivesRestartAndPreservesOtherRecipients(exact: Bool) async throws {
        let (root, repository, scope, grants) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        for grant in grants { try await repository.acknowledgeContentGrant(grant, serverSystemFields: Data([1])) }
        let before = try await repository.item(grants[0].scope)
        if exact {
            try await repository.repairGrantDelivery(grants[0], permit: RecipientPermit())
            try await repository.repairGrantDelivery(grants[0], permit: RecipientPermit())
        } else {
            try await repository.invalidateGrantDestination(scope: scope, recipient: grants[0].recipient, identifier: grants[0].identifier, permit: RecipientPermit())
        }
        let reopened = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: root))
        #expect(try await reopened.hasGrantDestinationRepairs(scope: scope, recipient: grants[0].recipient))
        #expect(try await reopened.contentGrantDelivery(grants[1]) == .cloudConfirmed)
        #expect(try await reopened.item(grants[0].scope) == before)
        #expect(try await reopened.contentGrants(scope: grants[0].scope, keyGeneration: grants[0].keyGeneration).count == 2)
        try await reopened.acknowledgeContentGrant(grants[0], serverSystemFields: Data([2]))
        #expect(try await !reopened.hasGrantDestinationRepairs(scope: scope, recipient: grants[0].recipient))
        #expect(try await reopened.contentGrantDelivery(grants[0]) == .cloudConfirmed)
    }
}
