import CryptoKit
import Foundation
import LocalAuthentication
import Testing
import MopCore
@testable import MopLocalIdentity

@Test func passkeysHaveTruthfulDeviceBoundFlagsAndCOSEPublicKey() throws {
    let publicKey = P256.Signing.PrivateKey().publicKey.x963Representation
    let metadata = try PasskeyMetadata(relyingParty: "example.com", userName: "alice", userHandle: Data([1]), credentialID: Data(repeating: 7, count: 32))
    let registration = try LocalWebAuthn.registrationData(metadata: metadata, publicKey: publicKey)
    #expect(registration.prefix(32) == Data(SHA256.hash(data: Data("example.com".utf8))))
    #expect(registration[32] == 0x45) // UP, UV, AT; never BE/BS
    #expect(registration[33..<37] == Data(repeating: 0, count: 4))
    #expect(registration[53..<55] == Data([0, 32]))
    #expect(registration[55..<87] == metadata.credentialID)
    #expect(registration.suffix(32) == publicKey.suffix(32))
    #expect(LocalWebAuthn.authenticatorData(relyingParty: "example.com")[32] == 0x05)
    let attestation = try LocalWebAuthn.attestation(metadata: metadata, publicKey: publicKey)
    #expect(attestation.contains(Data("none".utf8)))
    #expect(attestation.contains(registration))
}

@Test func passkeySelectionNeverCrossesRelyingPartiesOrCredentialIDs() throws {
    let metadata = try PasskeyMetadata(relyingParty: "example.com", userName: "alice", userHandle: Data([1]), credentialID: Data(repeating: 7, count: 32))
    let identity = try LocalIdentity(name: "passkey", algorithm: .p256Signing, protocolType: .webauthn, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation, metadata: .passkey(metadata))
    #expect(LocalWebAuthn.matches(identity, relyingParty: "example.com", allowedCredentials: []))
    #expect(LocalWebAuthn.matches(identity, relyingParty: "example.com", allowedCredentials: [metadata.credentialID]))
    #expect(!LocalWebAuthn.matches(identity, relyingParty: "evil.example.com", allowedCredentials: []))
    #expect(!LocalWebAuthn.matches(identity, relyingParty: "example.com", allowedCredentials: [Data([0])]))
    #expect(throws: (any Error).self) { try LocalIdentity(name: "fake", algorithm: .p256Signing, protocolType: .webauthn, publicKey: identity.publicKey) }
    #expect(throws: (any Error).self) { try SSHSigningPolicy.validate(data: Data(), key: identity.publicKey, purpose: .webauthn) }
}

@Test func authorizationIsScopedOneShotExpiringAndRevocable() throws {
    let id = UUID()
    let token = LocalAuthorization(context: LAContext(), ids: [id], purposes: [.webauthn], operations: [.passkey], oneShot: true)
    #expect(throws: MopError.authentication) { try token.begin(id: UUID(), purpose: .webauthn, operation: .passkey) }
    #expect(throws: MopError.authentication) { try token.begin(id: id, purpose: .ssh, operation: .sign) }
    try token.begin(id: id, purpose: .webauthn, operation: .passkey)
    #expect(throws: MopError.authentication) { try token.begin(id: id, purpose: .webauthn, operation: .passkey) }
    token.revoke()
    #expect(throws: MopError.authentication) { try token.check() }
    let expired = LocalAuthorization(context: LAContext(), ids: [id], purposes: [.ssh], operations: [.sign], expires: .distantPast)
    #expect(throws: MopError.authentication) { try expired.begin(id: id, purpose: .ssh, operation: .sign) }
}

@Test func decodedRecordsRejectPolicyAndMetadataTampering() throws {
    let identity = try LocalIdentity(name: "ssh", algorithm: .p256Signing, protocolType: .ssh, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
    var json = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(identity)) as? [String: Any])
    json["accessPolicy"] = "perOperation"
    #expect(throws: (any Error).self) { try JSONDecoder().decode(LocalIdentity.self, from: JSONSerialization.data(withJSONObject: json)) }
    #expect(throws: MopError.localOperationForbidden) { try CloudVaultBoundary.requireCloud("local") }
    #expect(throws: MopError.localOperationForbidden) { try CloudVaultBoundary.validateName("local") }
}

@Test func passkeysCannotUseReusableAuthorization() throws {
    let id = UUID()
    let token = LocalAuthorization(context: LAContext(), ids: [id], purposes: [.webauthn], operations: [.passkey], oneShot: false)
    #expect(throws: MopError.authentication) { try token.begin(id: id, purpose: .webauthn, operation: .passkey) }
}
