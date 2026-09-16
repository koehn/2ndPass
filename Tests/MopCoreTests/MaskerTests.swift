import Foundation
import Testing
@testable import MopCore

@Test func masksAcrossEveryChunkBoundary() {
    let patterns = MaskPatterns(secrets: ["abc", "abcd", "bc", "🔒\n秘密", "x", "", "abc"])
    let input = Data("-abcd-abc-🔒\n秘密-x-ab".utf8) + Data([0xff, 0x00])
    let expected = Data("-[concealed by mop]-[concealed by mop]-[concealed by mop]-[concealed by mop]-ab".utf8) + Data([0xff, 0x00])
    for boundary in 0...input.count {
        var filter = SecretMasker(patterns: patterns)
        let first = filter.consume(Data(input.prefix(boundary)))
        let second = filter.consume(Data(input.dropFirst(boundary)), final: true)
        #expect(first + second == expected)
    }
    var filter = SecretMasker(patterns: patterns)
    var output = Data()
    for byte in input { output += filter.consume(Data([byte])) }
    output += filter.consume(Data(), final: true)
    #expect(output == expected)
}

@Test func masksLongestOverlapsWithoutMaskingReplacement() {
    var filter = SecretMasker(patterns: MaskPatterns(secrets: ["ab", "aba", "bab", "mop"]))
    #expect(String(decoding: filter.consume(Data("abab mop".utf8), final: true), as: UTF8.self)
            == "[concealed by mop]b [concealed by mop]")
    var empty = SecretMasker(patterns: MaskPatterns(secrets: [""]))
    #expect(empty.consume(Data("literal".utf8), final: true) == Data("literal".utf8))
}

@Test func filtersKeepStreamsIndependentAndFlushPrefixes() {
    let patterns = MaskPatterns(secrets: ["secret", "sec"])
    var out = SecretMasker(patterns: patterns)
    var err = SecretMasker(patterns: patterns)
    #expect(out.consume(Data("se".utf8)).isEmpty)
    #expect(err.consume(Data("cret".utf8), final: true) == Data("cret".utf8))
    #expect(out.consume(Data(), final: true) == Data("se".utf8))
    var prefix = SecretMasker(patterns: patterns)
    #expect(prefix.consume(Data("sec".utf8)).isEmpty)
    #expect(prefix.consume(Data(), final: true) == Data("[concealed by mop]".utf8))
}

@Test func masksCanonicallyEquivalentButByteDistinctSecrets() {
    let composed = "audit-\u{e9}-token"
    let decomposed = "audit-e\u{301}-token"
    #expect(composed == decomposed)
    #expect(Data(composed.utf8) != Data(decomposed.utf8))
    let input = Data((composed + "|" + decomposed).utf8)
    let expected = Data("[concealed by mop]|[concealed by mop]".utf8)
    for boundary in 0...input.count {
        var masker = SecretMasker(patterns: MaskPatterns(secrets: [composed, decomposed, composed]))
        let first = masker.consume(Data(input.prefix(boundary)))
        #expect(first + masker.consume(Data(input.dropFirst(boundary)), final: true) == expected)
    }
}
