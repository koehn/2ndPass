import CryptoKit
import Foundation
import Testing
import MopCore
@testable import MopVaultNext

/// Software keys deliberately exist only in this test target. These tests do not
/// establish Enclave behavior, Apple Account identity, or CloudKit permissions.
final class TestDevice: DeviceOperations {
    let identity: DevicePublicKey
    private var encryption: P256.KeyAgreement.PrivateKey?
    private var signing: P256.Signing.PrivateKey?
    var unwrappedContexts: [Data] = []
    init(member: UUID = UUID(), deviceID: UUID = UUID()) throws {
        let encryption = P256.KeyAgreement.PrivateKey(), signing = P256.Signing.PrivateKey()
        identity = try DevicePublicKey(member: member, device: deviceID, encryption: encryption.publicKey.x963Representation, signing: signing.publicKey.x963Representation)
        self.encryption = encryption; self.signing = signing
    }
    func sign(_ bytes: Data) throws -> Data {
        guard let signing else { throw MopError.authentication }
        return try signing.signature(for: bytes).rawRepresentation
    }
    func unwrap(_ envelope: KeyEnvelope, context: Data) throws -> SymmetricKey {
        guard let encryption else { throw MopError.authentication }
        unwrappedContexts.append(context)
        return try envelope.open(using: encryption, context: context)
    }
    func close() { encryption = nil; signing = nil }
}

func testAuthority(owner: TestDevice) throws -> (id: UUID, membership: Membership) {
    (UUID(), try Membership(accounts: [AccountMember(id: owner.identity.member, role: .owner, devices: [owner.identity])]))
}

func portableDocument(name: String = "fixture", items: [VaultItem]) throws -> PortableVaultArchive {
    var document = PortableVaultArchive(name: name, items: items, itemIDs: [:], references: [:], records: [:])
    for index in document.items.indices {
        let itemID = UUID().uuidString
        document.itemIDs[items[index].name] = itemID
        for fieldIndex in items[index].fields.indices {
            let field = items[index].fields[fieldIndex], recordID = UUID().uuidString
            document.references[SecretReference.encode(items[index].name) + "/" + field.path] = recordID
            document.records[recordID] = PortableArchiveRecord(itemID: itemID, bytes: SecretBytes(utf8: field.value ?? ""))
            if field.type.concealed { document.items[index].fields[fieldIndex].value = nil }
        }
    }
    try document.validate()
    return document
}
