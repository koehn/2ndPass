import Foundation
import Testing
import MopCore

@Test func localVaultNameIsFixedAndNotRenameable() {
    #expect(LocalVault.name == "local")
    #expect(throws: MopError.localOperationForbidden) { try LocalVault.rename(to: "anything") }
    #expect(LocalVault.isLocal("local"))
    #expect(LocalVault.isLocal("local-vault"))
    #expect(!LocalVault.isLocal("Local"))
    #expect(!LocalVault.isLocal("local-"))
    #expect(!LocalVault.isLocal("localvault"))
}

@Test func identityRequiresConsistentAlgorithmAndProtocol() throws {
    let ssh = try LocalIdentity(name: "deploy", algorithm: .p256Signing, protocolType: .ssh,
                                publicKey: Data(repeating: 1, count: 65))
    #expect(ssh.capabilities == [.signing, .authentication])
    #expect(ssh.protocolType == .ssh)

    let ecdh = try LocalIdentity(name: "agreement", algorithm: .p256KeyAgreement, protocolType: .genericEcdh,
                                 publicKey: Data(repeating: 2, count: 65))
    #expect(ecdh.capabilities == [.keyAgreement])
    #expect(!ecdh.protocolType.isSigning)

    // A signing protocol cannot be bound to a key-agreement key.
    #expect(throws: MopError.invalidLocalIdentity) {
        try LocalIdentity(name: "bad", algorithm: .p256KeyAgreement, protocolType: .ssh,
                          publicKey: Data(repeating: 3, count: 65))
    }
    // A key-agreement protocol cannot be bound to a signing key.
    #expect(throws: MopError.invalidLocalIdentity) {
        try LocalIdentity(name: "bad", algorithm: .p256Signing, protocolType: .genericEcdh,
                          publicKey: Data(repeating: 4, count: 65))
    }
}

@Test func identityNameIsTrimmedAndValidated() throws {
    #expect(try LocalIdentity.validateName("  deploy ") == "deploy")
    #expect(throws: MopError.invalidLocalIdentity) { try LocalIdentity.validateName("") }
    #expect(throws: MopError.invalidLocalIdentity) { try LocalIdentity.validateName("   ") }
    #expect(throws: MopError.invalidLocalIdentity) { try LocalIdentity.validateName("a\nb") }
    #expect(throws: MopError.invalidLocalIdentity) { try LocalIdentity.validateName(String(repeating: "a", count: 65)) }
}

@Test func identityOnlyPersistsPublicMaterial() throws {
    let identity = try LocalIdentity(name: "deploy", algorithm: .p256Signing, protocolType: .ssh,
                                     publicKey: Data([0x04, 1, 2, 3]))
    let encoded = String(decoding: try JSONEncoder().encode(identity), as: UTF8.self)
    // There is no field that can carry an exportable private key.
    #expect(!encoded.lowercased().contains("private"))
    #expect(!encoded.lowercased().contains("secret"))
    #expect(encoded.contains("publicKey"))
    // Round-trip preserves identity.
    let decoded = try JSONDecoder().decode(LocalIdentity.self, from: Data(encoded.utf8))
    #expect(decoded == identity)
}

@Test func localErrorsHaveStableExitCodes() {
    #expect(MopError.enclaveUnavailable.exitCode == 31)
    #expect(MopError.localOperationForbidden.exitCode == 32)
    #expect(MopError.localIdentityCapability.exitCode == 33)
    #expect(MopError.invalidLocalIdentity.exitCode == 34)
    #expect(MopError.localOperationForbidden.errorDescription?.contains("device-local") == true)
    #expect(MopError.enclaveUnavailable.errorDescription?.contains("No software fallback") == true)
}
