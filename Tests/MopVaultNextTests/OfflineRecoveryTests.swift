import CryptoKit
import Foundation
import Testing
import MopCore
@testable import MopVaultNext

private func recoveryScope(_ account: String = "a") throws -> RecoveryScope {
    try RecoveryScope(container: "iCloud.test", environment: "Development", account: account)
}
private func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

@Test func offlineRecoveryInteroperabilityVectorAndPaperRoundTrip() throws {
    // Independently calculated using Python hashlib/HMAC and affine P-256 arithmetic.
    let scope = try recoveryScope(), key = try OfflineRecoveryKey(secret: Data(0..<32), scope: scope)
    defer { key.close() }
    #expect(hex(key.identity.encryption) == "0421af83d7e75c3c7a72f9bdbbf1a8333c2e58f0b251f9b4c0535c88f7755e8661c915fc118d9dcf8501f2224965e21db75dfc36274e35858fcad088853cc2ea16")
    #expect(hex(key.identity.signing) == "0457bbe7e2489d270a9a08c38a37cbb1330f6da6a6b220ea012ce9c95d6cc24aac5b9b50c215f797aade61a4d49b2ac01464ac39db8af49aa2be57a5cb7c6fc87e")
    let code = try key.code()
    #expect(String(decoding: code, as: UTF8.self).hasSuffix("CEB8-52E0"))
    let paper = try OfflineRecoveryKey(document: code, scope: scope)
    defer { paper.close() }
    #expect(paper.identity == key.identity)
    let imported = try OfflineRecoveryKey(document: key.export(), scope: scope)
    defer { imported.close() }
    #expect(imported.identity == key.identity)
    let message = Data("recovery signature".utf8)
    #expect(key.identity.verifies(try imported.sign(message), message: message))
}

@Test func offlineRecoveryRejectsBadCopyAndDifferentAccount() throws {
    let scope = try recoveryScope(), key = try OfflineRecoveryKey(scope: scope)
    defer { key.close() }
    let code = String(decoding: try key.code(), as: UTF8.self)
    let damaged = SecretBytes(utf8: String(code.dropLast()) + (code.last == "0" ? "1" : "0"))
    #expect(throws: MopError.invalidRecovery) { try OfflineRecoveryKey(document: damaged, scope: scope) }
    #expect(throws: MopError.invalidRecovery) { try OfflineRecoveryKey(document: "SP1-1234", scope: scope) }
    #expect(throws: MopError.invalidRecovery) { try OfflineRecoveryKey(document: key.export(), scope: recoveryScope("b")) }
    let other = try OfflineRecoveryKey(document: key.code(), scope: recoveryScope("b"))
    defer { other.close() }
    #expect(other.identity != key.identity)
    key.close()
    #expect(throws: MopError.authentication) { try key.sign(Data()) }
    #expect(throws: MopError.authentication) { try key.code() }
}

@Test func offlineRecoveryCoversExistingFutureDataAndRotatesOnRemoval() throws {
    let scope = try recoveryScope(), owner = try TestDevice(member: scope.member)
    let key = try OfflineRecoveryKey(scope: scope), replacement = try OfflineRecoveryKey(scope: scope)
    defer { key.close(); replacement.close() }
    var vault = try VaultEngine.create(name: "personal", owner: owner)
    vault = try VaultEngine.write("login/password", value: "before", in: vault, device: owner)
    vault = try VaultEngine.setOfflineRecovery(key.identity, in: vault, owner: owner)
    #expect(vault.revision.header.requiredFeatures?.contains("offline-recovery-1") == true)
    #expect(try VaultEngine.read("login/password", in: vault, device: key) == "before")
    vault = try VaultEngine.write("next/password", value: "after", in: vault, device: owner)
    #expect(try VaultEngine.read("next/password", in: vault, device: key) == "after")
    let historical = vault
    vault = try VaultEngine.setOfflineRecovery(replacement.identity, in: vault, owner: owner)
    #expect(throws: MopError.notVaultMember) { try VaultEngine.read("next/password", in: vault, device: key) }
    #expect(try VaultEngine.read("next/password", in: historical, device: key) == "after")
    #expect(try VaultEngine.read("next/password", in: vault, device: replacement) == "after")
    vault = try VaultEngine.setOfflineRecovery(nil, in: vault, owner: owner)
    #expect(throws: MopError.notVaultMember) { try VaultEngine.read("next/password", in: vault, device: replacement) }
}

@Test func retiredRecipientIsRejectedAndAbsentRecipientStillDecodes() throws {
    let owner = try TestDevice(), vault = try VaultEngine.create(name: "personal", owner: owner)
    #expect(try Revision.decode(vault.bytes).header.membership.offlineRecovery == nil)
    var object = try JSONSerialization.jsonObject(with: vault.bytes) as! [String: Any]
    var header = object["header"] as! [String: Any]
    var membership = header["membership"] as! [String: Any]
    membership["recovery"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(owner.identity))
    header["membership"] = membership; object["header"] = header
    let bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    #expect(throws: MopError.legacyVault) { try Revision.decode(bytes) }
}
