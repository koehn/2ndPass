import Foundation
import Testing
@testable import MopCore

@Test func masksAcrossEveryChunkBoundary() {
    let patterns = MaskPatterns(secrets: ["abc", "abcd", "bc", "🔒\n秘密", "x", "", "abc"])
    let input = SecretBytes(copying: "-abcd-abc-🔒\n秘密-x-ab".utf8) + SecretBytes(copying: [0xff, 0x00])
    let expected = SecretBytes(copying: "-[concealed by sp]-[concealed by sp]-[concealed by sp]-[concealed by sp]-ab".utf8) + SecretBytes(copying: [0xff, 0x00])
    for boundary in 0...input.count {
        var filter = SecretMasker(patterns: patterns)
        let first = filter.consume(SecretBytes(copying: input.prefix(boundary)))
        let second = filter.consume(SecretBytes(copying: input.dropFirst(boundary)), final: true)
        #expect(first + second == expected)
    }
    var filter = SecretMasker(patterns: patterns)
    var output = SecretBytes(utf8: "")
    for byte in input { output = output + filter.consume(SecretBytes(copying: [byte])) }
    output = output + filter.consume(SecretBytes(utf8: ""), final: true)
    #expect(output == expected)
}

@Test func masksLongestOverlapsWithoutMaskingReplacement() {
    var filter = SecretMasker(patterns: MaskPatterns(secrets: ["ab", "aba", "bab", "mop"]))
    #expect(String(decoding: filter.consume(SecretBytes(copying: "abab mop".utf8), final: true), as: UTF8.self)
            == "[concealed by sp]b [concealed by sp]")
    var empty = SecretMasker(patterns: MaskPatterns(secrets: [""]))
    #expect(empty.consume(SecretBytes(copying: "literal".utf8), final: true) == SecretBytes(copying: "literal".utf8))
}

@Test func filtersKeepStreamsIndependentAndFlushPrefixes() {
    let patterns = MaskPatterns(secrets: ["secret", "sec"])
    var out = SecretMasker(patterns: patterns)
    var err = SecretMasker(patterns: patterns)
    #expect(out.consume(SecretBytes(copying: "se".utf8)).isEmpty)
    #expect(err.consume(SecretBytes(copying: "cret".utf8), final: true) == SecretBytes(copying: "cret".utf8))
    #expect(out.consume(SecretBytes(utf8: ""), final: true) == SecretBytes(copying: "se".utf8))
    var prefix = SecretMasker(patterns: patterns)
    #expect(prefix.consume(SecretBytes(copying: "sec".utf8)).isEmpty)
    #expect(prefix.consume(SecretBytes(utf8: ""), final: true) == SecretBytes(copying: "[concealed by sp]".utf8))
}

@Test func masksCanonicallyEquivalentButByteDistinctSecrets() {
    let composed = "audit-\u{e9}-token"
    let decomposed = "audit-e\u{301}-token"
    #expect(composed == decomposed)
    #expect(SecretBytes(copying: composed.utf8) != SecretBytes(copying: decomposed.utf8))
    let input = SecretBytes(copying: (composed + "|" + decomposed).utf8)
    let expected = SecretBytes(copying: "[concealed by sp]|[concealed by sp]".utf8)
    for boundary in 0...input.count {
        var masker = SecretMasker(patterns: MaskPatterns(secrets: [composed, decomposed, composed].map { SecretBytes(utf8: $0) }))
        let first = masker.consume(SecretBytes(copying: input.prefix(boundary)))
        #expect(first + masker.consume(SecretBytes(copying: input.dropFirst(boundary)), final: true) == expected)
    }
}
