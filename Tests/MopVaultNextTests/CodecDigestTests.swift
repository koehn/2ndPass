import CryptoKit
import Foundation
import Testing
@testable import MopVaultNext

@Test func digestEncodingPreservesPersistedIdentifiers() {
    let inputs = [Data(), Data("abc".utf8), Data((0...255).map(UInt8.init)), Data(repeating: 0xff, count: 4096)]
    for input in inputs {
        let reference = SHA256.hash(data: input).map { String(format: "%02x", $0) }.joined()
        #expect(Codec.digest(input) == reference)
        #expect(Codec.hash(Codec.digest(input)))
    }
    #expect(Codec.digest(Data("abc".utf8)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
}
