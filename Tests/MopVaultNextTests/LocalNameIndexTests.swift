import Foundation
import Testing
import MopCore
@testable import MopVaultNext

@Test func localNameIndexAuthenticatesDeviceAndScopeBeforeDecrypting() throws {
    let owner = try TestDevice(), other = try TestDevice(), id = UUID(), version = UUID()
    let index = LocalNameIndex(entries: [id: .init(version: version, name: "private-example-account", deleted: false)])
    let context = Data("container/account/private/owner/vault/state".utf8)
    let sealed = try index.sealed(context: context, device: owner)
    #expect(!String(decoding: sealed, as: UTF8.self).contains("private-example-account"))
    let opened = try LocalNameIndex.open(sealed, context: context, device: owner)
    #expect(opened.entries[id]?.name == "private-example-account" && opened.entries[id]?.version == version)
    let count = owner.unwrappedContexts.count
    #expect(throws: MopError.vaultUntrusted) { try LocalNameIndex.open(sealed, context: Data("other-account-or-vault".utf8), device: owner) }
    #expect(throws: MopError.vaultUntrusted) { try LocalNameIndex.open(sealed, context: context, device: other) }
    var forged = try #require(JSONSerialization.jsonObject(with: sealed) as? [String: Any])
    // An attacker can construct ciphertext and wrapped keys from public keys;
    // replacing either still requires the enrolled device's signing key.
    forged["ciphertext"] = Data(repeating: 42, count: 64).base64EncodedString()
    let changed = try JSONSerialization.data(withJSONObject: forged, options: [.sortedKeys])
    #expect(throws: MopError.vaultUntrusted) { try LocalNameIndex.open(changed, context: context, device: owner) }
    #expect(owner.unwrappedContexts.count == count && other.unwrappedContexts.isEmpty)
}
