import MopLocalIdentity
import Testing
import Foundation
import MopCore
import MopAppSupport

@Suite struct LocalVaultServiceTests {
    /// The P-256 generator point, as an x963 (uncompressed) encoding: 0x04 || X || Y.
    private var p256Generator: Data {
        let hex = "04"
            + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
            + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
        let bytes = hex
        var data = Data()
        var i = bytes.startIndex
        while i < bytes.endIndex {
            let j = bytes.index(i, offsetBy: 2)
            data.append(UInt8(bytes[i..<j], radix: 16)!)
            i = j
        }
        return data
    }

    @Test func buildProjectsPublicKeysOnly() throws {
        let signing = try LocalIdentity(
            name: "deploy",
            algorithm: .p256Signing,
            protocolType: .ssh,
            publicKey: p256Generator
        )
        let agreement = try LocalIdentity(
            name: "mesh",
            algorithm: .p256KeyAgreement,
            protocolType: .genericEcdh,
            publicKey: p256Generator
        )
        let catalog = LocalIdentityCatalog(identities: [signing, agreement])
        #expect(catalog.vault == "local")
        #expect(catalog.kind == "device-local")
        #expect(catalog.identities == [signing, agreement])
        let json = String(decoding: try JSONEncoder().encode(catalog), as: UTF8.self)
        #expect(!json.contains("opaqueKey"))
        #expect(!json.contains("fields"))
        #expect(signing.publicKeyText.hasPrefix("ecdsa-sha2-nistp256 "))
    }

    @Test func policyAllowsCoreAndBlocksForbidden() {
        for allowed in [LocalVaultOperation.list, .create, .deleteItem, .publicKey, .sign] {
            #expect(LocalVaultPolicy.isAllowed(allowed))
            #expect(LocalVaultPolicy.disallowedReason(allowed) == nil)
        }
        for forbidden in [LocalVaultOperation.renameVault, .renameItem, .export, .share, .deleteVault] {
            #expect(!LocalVaultPolicy.isAllowed(forbidden))
            #expect((LocalVaultPolicy.disallowedReason(forbidden))?.isEmpty == false)
        }
    }
}
@Test func localReferencesAreRejectedBeforeCloudOrAuthentication() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let service = NativeVaultService(state: directory)
    for operation: VaultOperation in [.catalog, .members, .sync, .export(directory), .manage(.devices), .deleteVault, .rename("other")] {
        await #expect(throws: MopError.localOperationForbidden) { try await service.execute(operation, vault: "local", offline: false) }
    }
    await #expect(throws: MopError.localOperationForbidden) { try await service.execute(.create(name: "local"), vault: nil, offline: false) }
    let ref = try SecretReference(vault: "local", relativePath: "test/password")
    await #expect(throws: MopError.localOperationForbidden) { try await service.readLocal(ref, vault: UUID().uuidString) }
    #expect(!FileManager.default.fileExists(atPath: directory.path))
    #expect(service.authenticatedAt == nil)
}
