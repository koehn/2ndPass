import Foundation
import Testing
import MopCore
import MopCredentials
import MopSync
@testable import MopVaultNext

private func portableArchiveFixture(owner: TestDevice) throws -> PortableVaultArchive {
    var login = VaultItem(name: "Login", type: .login, fields: [ItemField(path: "username", type: .username, value: "alice"), ItemField(path: "password", type: .password, value: "current-secret")])
    login.metadata = ItemMetadata(tags: ["work", "important"], favorite: true, archived: true,
        source: ImportSourceIdentity(provider: "fixture", container: "source", item: "login"), createdAt: Date(timeIntervalSince1970: 1_700_000_000))
    let file = try Attachment(fileName: "fixture.bin", data: Data([0, 13, 10, 128, 255]))
    let document = VaultItem(name: "File", type: .document, fields: [.init(path: "file", type: .attachment, value: try file.encodedValue())])
    var trashed = VaultItem(name: "Deleted", type: .secureNote, fields: [.init(path: "note", type: .concealed, value: "retained-trash-secret")])
    trashed.deletion = ItemDeletion(originalName: "Deleted", deletedAt: Date(timeIntervalSince1970: 100))
    let key = try CloudKey.generate(.p256)
    var passkey = try key.item(name: "Passkey", purposes: [.ssh]); passkey.type = .passkey
    passkey.credential = KeyCredential(algorithm: .p256, publicKey: key.publicKey, purposes: [.passkey], relyingParty: "example.com", userName: "alice", userHandle: Data([1]), credentialID: Data(repeating: 7, count: 32))
    var archive = try portableDocument(name: "portable-fixture", items: [login, document, trashed, passkey])
    let itemID = try #require(archive.itemIDs["Login"]), oldID = UUID().uuidString
    let history = SecretFieldHistory(itemID: itemID, path: "password", entries: [SecretHistoryEntry(id: oldID, replacedAt: Date(timeIntervalSince1970: 100))])
    archive.items[0].fields[1].historyID = history.id
    archive.records[oldID] = PortableArchiveRecord(itemID: itemID, bytes: SecretBytes(utf8: "old-secret"))
    var account = CredentialAccount(service: "example.com", account: "alice")
    account.registrations = [CredentialRegistration(protocolName: "webauthn", publicIdentifier: "hardware-key", deviceID: owner.identity.device.uuidString, deviceLabel: "Original device", localIdentityID: UUID())]
    var security = VaultSecurityMetadata(); security.histories = [history]; security.accounts = [account]; archive.security = security
    try archive.validate(); return archive
}



@Test func portableArchiveRejectsWrongKeyTamperAndTruncation() throws {
    let owner = try TestDevice()
    let source = try portableArchiveFixture(owner: owner)
    let archive = try PortableArchive.seal(source)
    let other = try PortableArchive.seal(source)
    #expect(throws: (any Error).self) { try PortableArchive.open(archive.data, recoveryKey: other.recoveryKey) }
    var altered = archive.data
    altered[altered.count / 2] ^= 1
    #expect(throws: (any Error).self) { try PortableArchive.open(altered, recoveryKey: archive.recoveryKey) }
    #expect(throws: (any Error).self) { try PortableArchive.open(Data(archive.data.dropLast()), recoveryKey: archive.recoveryKey) }
}



@Test func portableArchiveRejectsMissingOrUnreferencedLogicalRecords() throws {
    let owner = try TestDevice()
    let source = try portableArchiveFixture(owner: owner)
    let complete = try source
    var missing = complete
    missing.records.removeValue(forKey: try #require(missing.references.values.first))
    #expect(throws: (any Error).self) { try PortableArchive.seal(missing) }
    var extra = complete
    extra.records[UUID().uuidString] = PortableArchiveRecord(itemID: try #require(complete.itemIDs.values.first), bytes: SecretBytes(utf8: "orphan"))
    #expect(throws: (any Error).self) { try PortableArchive.seal(extra) }
    var duplicated = complete
    duplicated.items.append(try #require(complete.items.first))
    #expect(throws: (any Error).self) { try PortableArchive.seal(duplicated) }
}



@Test func portableArchiveRoundTripsIndependentEncryptedItemsForFreshOwner() throws {
    let owner = try TestDevice(), nextOwner = try TestDevice()
    let source = try portableArchiveFixture(owner: owner)
    let original = try source
    let newRoot = try testAuthority(owner: nextOwner)
    let membershipState = try MembershipEnvelope.genesis(vault: newRoot.id, membership: newRoot.membership, owner: nextOwner).digest()
    let items = try PortableItemEnvelopeSet.seal(original, vault: newRoot.id, membership: newRoot.membership, membershipStateDigest: membershipState, signer: nextOwner)
    #expect(items.items.count == original.items.count)
    let reconstructed = try items.portableArchive(device: nextOwner, membership: newRoot.membership, membershipStateDigest: membershipState)
    #expect(reconstructed == original)
    let archive = try PortableArchive.seal(reconstructed)
    owner.close(); nextOwner.close()
    let decoded = try PortableArchive.open(archive.data, recoveryKey: archive.recoveryKey)
    #expect(decoded == original)

}

@Test func independentItemEnvelopeRejectsTamperingDestinationAndUnauthorizedWriter() throws {
    let owner = try TestDevice(), viewer = try TestDevice()
    let source = try portableArchiveFixture(owner: owner)
    var root = try testAuthority(owner: owner)
    root.membership = try Membership(accounts: root.membership.accounts + [AccountMember(id: viewer.identity.member, role: .viewer, devices: [viewer.identity])])
    let archive = try source
    let membershipState = try MembershipEnvelope.genesis(vault: root.id, membership: root.membership, owner: owner).digest()
    let set = try PortableItemEnvelopeSet.seal(archive, vault: root.id, membership: root.membership, membershipStateDigest: membershipState, signer: owner)
    let item = try #require(set.items.first { try $0.catalog(device: owner, membership: root.membership, membershipStateDigest: membershipState).item.name == "Login" })
    let catalog = try item.catalog(device: viewer, membership: root.membership, membershipStateDigest: membershipState)
    #expect(catalog.item.fields.first { $0.path == "password" }?.value == nil)
    let passwordID = try #require(catalog.references["Login/password"])
    #expect(try item.read(record: passwordID, device: viewer, membership: root.membership, membershipStateDigest: membershipState) == SecretBytes(utf8: "current-secret"))
    let bytes = try item.encoded()
    #expect(try ItemEnvelope.decode(bytes, vault: root.id, item: item.header.item, membership: root.membership, membershipStateDigest: membershipState) == item)
    #expect(throws: (any Error).self) { try ItemEnvelope.decode(bytes, vault: UUID(), item: item.header.item, membership: root.membership, membershipStateDigest: membershipState) }
    #expect(throws: (any Error).self) { try ItemEnvelope.decode(bytes, vault: root.id, item: UUID(), membership: root.membership, membershipStateDigest: membershipState) }
    #expect(throws: (any Error).self) { try item.verify(vault: root.id, item: item.header.item, membership: testAuthority(owner: owner).membership, membershipStateDigest: membershipState) }
    #expect(throws: (any Error).self) {
        try item.verify(vault: root.id, item: item.header.item, membership: root.membership, membershipStateDigest: String(repeating: "0", count: 64))
    }
    var tampered = bytes; tampered[tampered.count / 2] ^= 1
    #expect(throws: (any Error).self) { try ItemEnvelope.decode(tampered, vault: root.id, item: item.header.item, membership: root.membership, membershipStateDigest: membershipState) }
    #expect(throws: MopError.cloudPermission) { try PortableItemEnvelopeSet.seal(archive, vault: root.id, membership: root.membership, membershipStateDigest: membershipState, signer: viewer) }
}

@Test func independentEncryptedItemsAndMetadataSurviveSQLiteReopenAndPortableReexport() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-envelope-store-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let storeURL = directory.appendingPathComponent("items.sqlite")
    let owner = try TestDevice(), nextOwner = try TestDevice()
    let original = try portableArchiveFixture(owner: owner)
    let root = try testAuthority(owner: nextOwner)
    let membershipState = try MembershipEnvelope.genesis(vault: root.id, membership: root.membership, owner: nextOwner).digest()
    let converted = try PortableItemEnvelopeSet.seal(original, vault: root.id, membership: root.membership, membershipStateDigest: membershipState, signer: nextOwner)
    let repository = try EncryptedItemRepository(storeURL: storeURL)
    for envelope in converted.items {
        let scope = ItemScope(account: "new-account", vaultID: root.id, itemID: envelope.header.item)
        _ = try await repository.commitLocalMutation(EncryptedItemVersion(scope: scope, versionID: envelope.header.version,
            baseVersionID: envelope.header.base, ciphertext: envelope.encoded()))
    }
    let metadata = try converted.metadataEnvelope(membership: root.membership, membershipStateDigest: membershipState, signer: nextOwner)
    let metadataNamespace = "vault-metadata:" + root.id.uuidString
    try await repository.saveEngineState(metadata.encoded(), account: "new-account", database: metadataNamespace)
    owner.close()
    let reopened = try EncryptedItemRepository(storeURL: storeURL)
    let stored = try await reopened.items(account: "new-account", vaultID: root.id)
    let settingsBytes = try #require(try await reopened.engineState(account: "new-account", database: metadataNamespace))
    let settings = try VaultMetadataEnvelope.decode(settingsBytes, vault: root.id, membership: root.membership, membershipStateDigest: membershipState)
    let envelopes = try stored.map { try ItemEnvelope.decode($0.ciphertext, vault: root.id, item: $0.scope.itemID, membership: root.membership, membershipStateDigest: membershipState) }
    let reconstructed = try PortableItemEnvelopeSet(vault: root.id, metadata: settings, items: envelopes, device: nextOwner, membership: root.membership, membershipStateDigest: membershipState)
    let archive = try reconstructed.portableArchive(device: nextOwner, membership: root.membership, membershipStateDigest: membershipState)
    #expect(archive.records == original.records)
    #expect(archive.itemIDs == original.itemIDs)
    #expect(archive.security == original.security)
    let exported = try PortableArchive.seal(archive)
    nextOwner.close()
    let decoded = try PortableArchive.open(exported.data, recoveryKey: exported.recoveryKey)
    #expect(decoded.records == original.records)
    #expect(decoded.items.filter { $0.deletion != nil }.count == 1)

}

@Test func independentItemGenerationIsSignedAndRequiresConsistentPredecessor() throws {
    let owner = try TestDevice()
    var source = try testAuthority(owner: owner)
    let archive = try portableDocument(items: [VaultItem(name: "Login", fields: [ItemField(path: "password", type: .password, value: "secret")])])
    let authority = try MembershipEnvelope.genesis(vault: source.id, membership: source.membership, owner: owner)
    let state = try authority.digest()
    let first = try ItemEnvelope.seal(archive, vault: source.id, generation: 1, membership: source.membership, membershipStateDigest: state, signer: owner)
    let next = try ItemEnvelope.seal(archive, vault: source.id, generation: 2, base: first.header.version,
        membership: source.membership, membershipStateDigest: state, signer: owner)
    try next.verify(vault: source.id, item: first.header.item, membership: source.membership, membershipStateDigest: state)
    #expect(next.header.generation == 2)
    #expect(throws: (any Error).self) {
        try ItemEnvelope.seal(archive, vault: source.id, generation: 2, membership: source.membership, membershipStateDigest: state, signer: owner)
    }
    #expect(throws: (any Error).self) {
        try ItemEnvelope.seal(archive, vault: source.id, generation: 1, base: first.header.version,
            membership: source.membership, membershipStateDigest: state, signer: owner)
    }
    var raw = try #require(JSONSerialization.jsonObject(with: next.encoded()) as? [String: Any])
    var header = try #require(raw["header"] as? [String: Any])
    header["generation"] = 3; raw["header"] = header
    let altered = try JSONDecoder().decode(ItemEnvelope.self, from: JSONSerialization.data(withJSONObject: raw))
    #expect(throws: (any Error).self) {
        try altered.verify(vault: source.id, item: first.header.item, membership: source.membership, membershipStateDigest: state)
    }
}
