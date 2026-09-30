import CryptoKit
import Foundation
import Testing
import MopCore
@testable import MopLocalIdentity

/// Opt-in only, from a properly signed test host with the application's Keychain
/// access group. Unsigned swift test and simulators are not hardware evidence.
@Test(.enabled(if: ProcessInfo.processInfo.environment["MOP_LOCAL_HARDWARE_TESTS"] == "1"))
func physicalEnclaveSigningPersistenceAgreementAndDeletion() throws {
    try #require(LocalIdentityStore.isAvailable)
    let store = try LocalIdentityStore.open()
    for purpose: LocalIdentityProtocol in [.genericSigning, .genericEcdh] {
        let creation = try LocalAuthorization.authorize(reason: "create disposable hardware acceptance identity", ids: [], purposes: [purpose], operations: [.create])
        defer { creation.revoke() }
        let row = try store.create(name: "acceptance-" + UUID().uuidString, protocolType: purpose, authorization: creation)
        // This is deliberately printed so an interrupted test never loses track of
        // the disposable record. Never touch pre-existing development identities.
        print("Disposable hardware acceptance identity: \(row.name) [\(row.id)]")
        let reopened = try LocalIdentityStore.open()
        #expect(try reopened.read(id: row.id).publicKey == row.publicKey)
        let operation: LocalKeyOperation = purpose == .genericSigning ? .sign : .keyAgreement
        let authorization = try LocalAuthorization.authorize(reason: "verify hardware acceptance operation", ids: [row.id], purposes: [purpose], operations: [operation])
        defer { authorization.revoke() }
        if purpose == .genericSigning {
            let data = Data("2ndPass physical hardware acceptance".utf8)
            let signature = try reopened.sign(id: row.id, data: data, authorization: authorization)
            #expect(try P256.Signing.PublicKey(x963Representation: row.publicKey).isValidSignature(P256.Signing.ECDSASignature(derRepresentation: signature), for: data))
        } else {
            let peer = P256.KeyAgreement.PrivateKey()
            let result = try reopened.deriveSharedSecret(id: row.id, peerPublicKey: peer.publicKey.x963Representation, authorization: authorization)
            let expected = try peer.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: row.publicKey))
            #expect(result.withUnsafeBytes { Data($0) } == expected.withUnsafeBytes { Data($0) })
        }
        authorization.revoke()
        #expect(throws: MopError.authentication) { try authorization.check() }
        let deletion = try LocalAuthorization.authorize(reason: "delete disposable hardware acceptance identity", ids: [row.id], purposes: [purpose], operations: [.delete])
        defer { deletion.revoke() }
        try reopened.delete(id: row.id, authorization: deletion)
        #expect(throws: MopError.notFound) { try reopened.read(id: row.id) }
    }
}
