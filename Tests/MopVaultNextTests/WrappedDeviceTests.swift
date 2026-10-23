import CryptoKit
import Foundation
import Testing
import MopCore
@testable import MopVaultNext

@Test func wrappedDeviceUnlockExpiryLockAndReunlock() throws {
    let hardware = P256.KeyAgreement.PrivateKey(), member = UUID(), scope = "test/account/vault"
    let (created, saved) = try WrappedDevice.seal(member: member, scope: scope, wrappingPublicKey: hardware.publicKey, representation: Data())
    let identity = created.identity
    created.close()
    var authenticated = true
    var unwraps = 0
    func unlock() throws -> WrappedDevice {
        guard authenticated else { throw MopError.authentication }
        unwraps += 1
        return try WrappedDevice.open(saved, scope: scope, member: member, using: hardware)
    }
    let session = try unlock()
    authenticated = false // the hardware gate now rejects any further unlock
    let message = Data("signed write after expiry".utf8), info = Data("test content key".utf8)
    let key = SymmetricKey(size: .bits256)
    let envelope = try KeyEnvelope.seal(key, to: identity.encryption, context: info)
    let ciphertext = try AES.GCM.seal(message, using: key)
    let unwrapped = try session.unwrap(envelope, context: info)
    #expect(try AES.GCM.open(ciphertext, using: unwrapped) == message)
    let signature = try session.sign(message)
    #expect(identity.verifies(signature, message: message))
    #expect(unwraps == 1)
    #expect(throws: MopError.authentication) { try unlock() }
    session.close()
    #expect(throws: MopError.authentication) { try session.checkAuthorization() }
    #expect(throws: MopError.authentication) { try session.sign(message) }
    #expect(throws: MopError.authentication) { try session.unwrap(envelope, context: info) }
    #expect(throws: MopError.authentication) { try unlock() }
    authenticated = true
    let fresh = try unlock(); defer { fresh.close() }
    #expect(fresh.identity == identity)
    #expect(try AES.GCM.open(ciphertext, using: fresh.unwrap(envelope, context: info)) == message)
    #expect(unwraps == 2)
    #expect(throws: MopError.authentication) { try session.sign(message) }
}

@Test func wrappedDeviceRejectsWrongBindingWrappingKeyAndTampering() throws {
    let wrapping = P256.KeyAgreement.PrivateKey(), member = UUID()
    let (device, representation) = try WrappedDevice.seal(member: member, scope: "account/vault",
        wrappingPublicKey: wrapping.publicKey, representation: Data())
    defer { device.close() }
    #expect(throws: (any Error).self) { try WrappedDevice.open(representation, scope: "other/vault", member: member, using: wrapping) }
    #expect(throws: (any Error).self) { try WrappedDevice.open(representation, scope: "account/vault", member: UUID(), using: wrapping) }
    #expect(throws: (any Error).self) { try WrappedDevice.open(representation, scope: "account/vault", member: member, using: P256.KeyAgreement.PrivateKey()) }
    let encoded = try JSONEncoder().encode(representation)
    var json = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    var ciphertext = representation.ciphertext; ciphertext[ciphertext.startIndex] ^= 1
    json["ciphertext"] = ciphertext.base64EncodedString()
    let tampered = try JSONDecoder().decode(WrappedDevice.Representation.self, from: JSONSerialization.data(withJSONObject: json))
    #expect(throws: (any Error).self) { try WrappedDevice.open(tampered, scope: "account/vault", member: member, using: wrapping) }
    json["version"] = 2
    let future = try JSONDecoder().decode(WrappedDevice.Representation.self, from: JSONSerialization.data(withJSONObject: json))
    #expect(throws: MopError.invalidIdentity) { try WrappedDevice.open(future, scope: "account/vault", member: member, using: wrapping) }
}
