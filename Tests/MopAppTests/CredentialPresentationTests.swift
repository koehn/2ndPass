import CryptoKit
import Foundation
import Testing
import MopCore
import MopLocalIdentity
import MopAppSupport
@testable import MopUI

@Test func sshPresentationSharesActionsAcrossStorage() throws {
    let key = P256.Signing.PrivateKey()
    let local = try LocalIdentity(name: "server", algorithm: .p256Signing, protocolType: .ssh, publicKey: key.publicKey.x963Representation)
    var item = VaultItem(name: "server", type: .sshKey, fields: [ItemField(path: KeyCredential.privateField, type: .privateKey)])
    item.credential = KeyCredential(algorithm: .p256, publicKey: key.publicKey.x963Representation, purposes: [.ssh])
    let device = CredentialPresentation(identity: local)
    let cloud = CredentialPresentation(record: try CloudCredentialRecord(vault: "personal", item: item))
    #expect(device.title == cloud.title && device.label == cloud.label && device.symbol == cloud.symbol)
    #expect(device.algorithm == cloud.algorithm && device.fingerprint == cloud.fingerprint)
    #expect(device.publicKey == cloud.publicKey)
    #expect(device.setup?.contains("--vault 'local'") == true)
    #expect(cloud.setup?.contains("--vault 'personal'") == true)
}

@Test func passkeyPresentationUsesWebsiteAndAccountForBothBackends() throws {
    let key = P256.Signing.PrivateKey()
    let metadata = try PasskeyMetadata(relyingParty: "example.com", userName: "alice", userHandle: Data([1]), credentialID: Data(repeating: 1, count: 32))
    let local = try LocalIdentity(name: "internal", algorithm: .p256Signing, protocolType: .webauthn,
        publicKey: key.publicKey.x963Representation, metadata: .passkey(metadata))
    var item = VaultItem(name: "alice@example.com-1234ABCD", type: .passkey, fields: [ItemField(path: KeyCredential.privateField, type: .privateKey)])
    item.credential = KeyCredential(algorithm: .p256, publicKey: key.publicKey.x963Representation, purposes: [.passkey],
        relyingParty: metadata.relyingParty, userName: metadata.userName, userHandle: metadata.userHandle, credentialID: metadata.credentialID)
    let device = CredentialPresentation(identity: local)
    let cloud = CredentialPresentation(record: try CloudCredentialRecord(vault: "personal", item: item))
    #expect(device.title == "example.com" && device.title == cloud.title)
    #expect(device.website == cloud.website && device.account == cloud.account)
    #expect(device.publicKey == nil && cloud.publicKey == nil)
    #expect(device.fingerprint == nil && cloud.fingerprint == nil)
    #expect(device.setup == nil && cloud.setup == nil)
}
