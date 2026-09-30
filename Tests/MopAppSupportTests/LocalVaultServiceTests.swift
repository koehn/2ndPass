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
        let catalog = LocalIdentityCatalog.build(identities: [signing, agreement])

        #expect(catalog.vault == "local")
        #expect(catalog.revision == LocalIdentityCatalog.revision)
        #expect(catalog.canEdit == false)
        #expect(catalog.items.count == 2)

        for item in catalog.items {
            #expect(item.type == .sshKey)
            // The private key must never appear as a field.
            #expect(!item.fields.contains { $0.path == "privateKey" || $0.type == .privateKey })
            // The keychain UUID is carried for sign/delete resolution.
            #expect(item.storageID != nil)
            #expect(item.fields.contains { $0.path == "publicKey" && $0.type == .text })
        }

        let deploy = catalog.items[0]
        #expect(deploy.storageID == signing.id.uuidString)
        // A signing key shows the OpenSSH public line.
        let publicKey = deploy.fields.first { $0.path == "publicKey" }
        #expect(publicKey?.value?.hasPrefix("ecdsa-sha2-nistp256 ") == true)
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