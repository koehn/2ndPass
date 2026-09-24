import CryptoKit
import Foundation
import Testing
import MopCore
@testable import MopVault

@Test func keyBufferWipesUnusedCapacityAndDataWipesVisibleBytes() {
    let buffer = KeyBuffer(capacity: 128)
    _ = buffer.withStorage { $0.initializeMemory(as: UInt8.self, repeating: 0xA5) }
    buffer.count = 32
    buffer.wipe()
    #expect(buffer.withStorage { $0.allSatisfy { $0 == 0 } })
    for size in [0, 1, 14, 32, 1024] {
        var data = Data(repeating: 0xA5, count: size)
        KeyMaterial.wipe(&data)
        #expect(data.count == size)
        #expect(data.allSatisfy { $0 == 0 })
    }
}

@Test func recoveryEncodingRemainsCompatibleAndFailureLeavesNoTemporaryFile() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try SafeFile.privateDirectory(directory)
    defer { try? FileManager.default.removeItem(at: directory) }
    let file = directory.appendingPathComponent("recovery")
    let recovery = RecoveryKey()
    try recovery.save(to: file)
    let original = try SafeFile.read(file, privateFile: true)
    #expect(original.count == 61)
    #expect(original.starts(with: Data("mop-recovery-v1:".utf8)))
    #expect(original.last == 10)
    let raw = try #require(Data(base64Encoded: original.dropFirst(16).dropLast()))
    #expect(try P256.KeyAgreement.PrivateKey(rawRepresentation: raw).publicKey.x963Representation == recovery.publicKey)
    #expect(try RecoveryKey(file: file).publicKey == recovery.publicKey)
    #expect(throws: MopError.duplicate) { try recovery.save(to: file) }
    #expect(try SafeFile.read(file) == original)
    #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["recovery"])

    // Older readers accepted every Foundation whitespace scalar around base64.
    let whitespace = (0...0x3000).compactMap(Unicode.Scalar.init)
        .filter { CharacterSet.whitespacesAndNewlines.contains($0) }
        .map { String($0) }.joined()
    let padded = Data("mop-recovery-v1:".utf8) + Data(whitespace.utf8) +
        original.dropFirst(16).dropLast() + Data(whitespace.utf8)
    try SafeFile.write(padded, to: file, replace: true)
    #expect(try RecoveryKey(file: file).publicKey == recovery.publicKey)

    for invalid in [Data(), Data("wrong-prefix:".utf8) + original.dropFirst(16),
                    Data("mop-recovery-v1:!!!!".utf8),
                    Data("mop-recovery-v1:".utf8) + Data(repeating: 0, count: 31).base64EncodedData(),
                    Data("mop-recovery-v1:".utf8) + Data(repeating: 0, count: 32).base64EncodedData()] {
        try SafeFile.write(invalid, to: file, replace: true)
        #expect(throws: MopError.invalidRecovery) { try RecoveryKey(file: file) }
    }
    try SafeFile.write(Data(repeating: 65, count: 1025), to: file, replace: true)
    #expect(throws: MopError.invalidVault) { try RecoveryKey(file: file) }
}

@Test func borrowedKeyWrappingAndIncrementalTrustRemainCompatible() throws {
    let privateKey = P256.KeyAgreement.PrivateKey()
    let request = try RecipientKey(name: "Test", publicKey: privateKey.publicKey.x963Representation)
    let vaultID = UUID()
    let raw = Data(0..<32)
    let key = SymmetricKey(data: raw)
    let slot = try VaultDocument.wrap(key: key, request: request, kind: "device", vaultID: vaultID)
    #expect(try VaultDocument.unwrap(slot, vaultID: vaultID, privateKey: privateKey) == key)
    let document = VaultDocument(header: VaultHeader(format: "mop-vault-v4", vaultID: vaultID, name: "v",
        generation: 1, parent: nil, recipients: [slot]), sealed: Data())
    let legacy = VaultCoding.digest(Data("mop-vault-trust-v1:\(vaultID.uuidString):".utf8) + raw)
    #expect(VaultTrust.fingerprint(document: document, key: key) == legacy)

    let short = try VaultDocument.wrap(key: SymmetricKey(size: .bits128), request: request,
                                      kind: "device", vaultID: vaultID)
    #expect(throws: MopError.invalidVault) {
        try VaultDocument.unwrap(short, vaultID: vaultID, privateKey: privateKey)
    }
}
