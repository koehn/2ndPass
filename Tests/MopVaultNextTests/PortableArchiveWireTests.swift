import CryptoKit
import Foundation
import Testing
import MopCore

// Construct the wire format without PortableArchive.seal or model encoders, so
// shared encoder/decoder changes cannot silently redefine this rescue format.
@Test func portableArchiveOpensIndependentVersionOneWireFixture() throws {
    let payload = Data(#"{"version":1,"name":"rescue","items":[{"name":"Login","type":"login","fields":[{"path":"password","type":"password"}]}],"itemIDs":{"Login":"11111111-1111-4111-8111-111111111111"},"references":{"Login/password":"22222222-2222-4222-8222-222222222222"},"records":{"22222222-2222-4222-8222-222222222222":{"itemID":"11111111-1111-4111-8111-111111111111","bytes":"AP9B"}},"exclusions":[]}"#.utf8)
    let header = Data("2NDPASS-PORTABLE-ARCHIVE-1\n".utf8)
    let key = SymmetricKey(data: Data(repeating: 0x41, count: 32))
    let nonce = try AES.GCM.Nonce(data: Data(repeating: 0x13, count: 12))
    let box = try AES.GCM.seal(payload, using: key, nonce: nonce, authenticating: header)
    let wire = header + Data(nonce) + box.ciphertext + box.tag
    let printableKey = SecretBytes(utf8: "2ndpass-archive-key-v1:" + String(repeating: "41", count: 32))
    let decoded = try PortableArchive.open(wire, recoveryKey: printableKey)
    #expect(decoded.name == "rescue")
    #expect(decoded.items[0].fields[0].value == nil)
    #expect(decoded.records["22222222-2222-4222-8222-222222222222"]?.bytes == SecretBytes(copying: [0, 255, 65]))
    // The clear version header is authenticated associated data, not ciphertext.
    #expect(throws: (any Error).self) {
        try AES.GCM.open(box, using: key, authenticating: Data("different-header".utf8))
    }
}

@Test func portableArchiveWriterMatchesDocumentedEnvelopeAndRawKeyEncoding() throws {
    let document = PortableVaultArchive(name: "independent", items: [], itemIDs: [:], references: [:], records: [:])
    let export = try PortableArchive.seal(document)
    let header = Data("2NDPASS-PORTABLE-ARCHIVE-1\n".utf8)
    #expect(export.data.starts(with: header))
    let text = String(decoding: export.recoveryKey, as: UTF8.self)
    #expect(text.hasPrefix("2ndpass-archive-key-v1:"))
    let hex = Array(text.dropFirst("2ndpass-archive-key-v1:".count))
    #expect(hex.count == 64)
    let raw = try stride(from: 0, to: hex.count, by: 2).map { i in
        try #require(UInt8(String(hex[i...i + 1]), radix: 16))
    }
    let box = try AES.GCM.SealedBox(combined: export.data.dropFirst(header.count))
    let plaintext = try AES.GCM.open(box, using: SymmetricKey(data: raw), authenticating: header)
    let json = try #require(JSONSerialization.jsonObject(with: plaintext) as? [String: Any])
    #expect(json["version"] as? Int == 1)
    #expect(json["name"] as? String == "independent")
    #expect((json["records"] as? [String: Any])?.isEmpty == true)
}
