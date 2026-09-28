import Foundation
import Testing
@testable import MopCore

private final class MemoryStore: SecretStore {
    var values: [SecretReference: SecretBytes] = [:]
    var reads: [SecretReference] = []
    var closes = 0
    func read(_ reference: SecretReference) throws -> SecretBytes {
        reads.append(reference)
        guard let value = values[reference] else { throw MopError.notFound }
        return value
    }
    func write(_ reference: SecretReference, value: SecretBytes, replace: Bool) throws {
        if replace && values[reference] == nil { throw MopError.notFound }
        if !replace && values[reference] != nil { throw MopError.duplicate }
        values[reference] = value
    }
    func list(vault: String?) throws -> [SecretReference] { values.keys.filter { vault == nil || $0.vault == vault } }
    func delete(_ reference: SecretReference) throws {
        guard values.removeValue(forKey: reference) != nil else { throw MopError.notFound }
    }
    func close() { closes += 1 }
}

@Test func referenceItemsAreCaseSensitiveAndUnambiguous() throws {
    let ref = try SecretReference("secondpass://personal/an%2Fitem/%E2%9C%93%20token")
    #expect(ref.vault == "personal")
    #expect(ref.item == "an/item")
    #expect(ref.field == "✓ token")
    #expect(ref.description == "secondpass://personal/an%2Fitem/%E2%9C%93%20token")
    #expect(try SecretReference("secondpass://v/i/%74oken") == SecretReference("secondpass://v/i/token"))
    #expect(try SecretReference("secondpass://v/i/token") != SecretReference("secondpass://v/I/token"))
    #expect(try SecretReference("secondpass://v/i/%252F").field == "%2F")
    let composed = try SecretReference("secondpass://v/%C3%A9/f")
    let decomposed = try SecretReference("secondpass://v/e%CC%81/f")
    #expect(composed == decomposed)
    #expect(composed.description == decomposed.description)
}

@Test(arguments: ["op://v/i/f", "MOP://v/i/f", "secondpass://v/i", "secondpass://v/i/s/f/x", "secondpass:///i/f", "secondpass://v//f", "secondpass://v/i/", "secondpass://v/i/f?q", "secondpass://v/i/f#x", "secondpass://v/i/a b", "secondpass://v/i/%", "secondpass://v/i/%XZ", "secondpass://v/i/%FF", "secondpass://v/i/%00", "secondpass://v/i/é", "secondpass://user@v/i/f"])
func invalidReferences(_ token: String) {
    #expect(throws: MopError.invalidReference) { try SecretReference(token) }
}

@Test func literalDotenv() throws {
    let result = try DotEnv.parse("""
    # comment
    A=literal # comment
    B='${A} $(echo unsafe)' # still literal
    C="a\\nb"
    D=a#b
    EMPTY=
    A=last
    """)
    #expect(result == ["A": "last", "B": "${A} $(echo unsafe)", "C": "a\\nb", "D": "a#b", "EMPTY": ""])
    #expect(try DotEnv.parse("A=x\r\nB=y\r\n") == ["A": "x", "B": "y"])
}

@Test(arguments: ["A", "export A=x", "1A=x", "A-B=x", "A='unterminated", "A=\"x\"junk", "A=\0"])
func rejectsInvalidDotenv(_ input: String) {
    #expect(throws: MopError.invalidEnvironment(line: 1)) { try DotEnv.parse(SecretBytes(utf8: input)) }
}

@Test func serviceCRUDAndSessionLifetimes() throws {
    let store = MemoryStore()
    var opens = 0
    let service = SecretService { opens += 1; return store }
    let ref = try SecretReference("secondpass://v/i/f")
    try service.write(ref, value: "one\ntwo\n", replace: false)
    #expect(try service.read(ref) == "one\ntwo\n")
    #expect(throws: MopError.duplicate) { try service.write(ref, value: "wrong", replace: false) }
    try service.write(ref, value: "", replace: true)
    #expect(try service.read(ref) == "")
    #expect(try service.list(vault: "v") == [ref])
    #expect(try service.list(vault: "other").isEmpty)
    try service.delete(ref)
    #expect(throws: MopError.notFound) { try service.read(ref) }
    #expect(throws: MopError.notFound) { try service.write(ref, value: "missing", replace: true) }
    #expect(opens == 10)
    #expect(store.closes == opens)
}

@Test func environmentPrecedenceAndDeduplication() throws {
    let store = MemoryStore()
    let ref = try SecretReference("secondpass://v/i/f")
    store.values[ref] = "secret\nvalue"
    var opens = 0
    let service = SecretService { opens += 1; return store }
    let result = try service.environment(inherited: ["A": "old", "UNCHANGED": "keep"], files: [
        "A=first\nB=secondpass://v/i/f", "A=secondpass://v/i/%66\nC=prefix secondpass://v/i/f"
    ])
    #expect(result == ["A": "secret\nvalue", "B": "secret\nvalue", "C": "prefix secondpass://v/i/f", "UNCHANGED": "keep"])
    #expect(opens == 1)
    #expect(store.reads == [ref])
    #expect(store.closes == 1)
}

@Test func templatesPreserveUnicodeAndDoNotRecursivelyExpand() throws {
    let store = MemoryStore()
    let ref = try SecretReference("secondpass://v/i/f")
    store.values[ref] = "{{ secondpass://not/another/lookup }}\n🔒"
    let service = SecretService { store }
    let output = try service.inject("前 {{ secondpass://v/i/f }} {{secondpass://v/i/%66}} {{ unrelated }} 後")
    #expect(output == "前 {{ secondpass://not/another/lookup }}\n🔒 {{ secondpass://not/another/lookup }}\n🔒 {{ unrelated }} 後")
    #expect(store.reads == [ref])
    #expect(store.closes == 1)
}

@Test func missingSecretsProduceNoResultAndCloseSession() throws {
    let store = MemoryStore()
    store.values[try SecretReference("secondpass://v/i/a")] = "must not escape"
    let service = SecretService { store }
    var output: SecretBytes?
    #expect(throws: MopError.notFound) { output = try service.inject("{{secondpass://v/i/a}}{{secondpass://v/i/b}}") }
    #expect(output == nil)
    #expect(store.closes == 1)
    var environment: [String: SecretBytes]?
    #expect(throws: MopError.notFound) {
        environment = try service.environment(inherited: ["A": "secondpass://v/i/a", "B": "secondpass://v/i/b"], files: [])
    }
    #expect(environment == nil)
    #expect(store.closes == 2)
}

@Test func validateBeforeAuthenticationAndSkipUnusedStore() throws {
    var opens = 0
    let service = SecretService { opens += 1; throw MopError.authentication }
    #expect(try service.inject("literal {{ unrelated }}") == "literal {{ unrelated }}")
    #expect(try service.environment(inherited: ["A": "literal"], files: []) == ["A": "literal"])
    #expect(throws: MopError.invalidReference) { try service.inject("{{ secondpass://v/i/f }} {{ secondpass://invalid }}") }
    #expect(throws: MopError.invalidTemplate) { try service.inject("{{ secondpass://v/i/f") }
    #expect(throws: MopError.invalidReference) { try service.environment(inherited: ["A": "secondpass://invalid"], files: []) }
    #expect(opens == 0)
    #expect(throws: MopError.authentication) { try service.inject("{{secondpass://v/i/f}}") }
    #expect(opens == 1)
}

@Test func nulInSecretCannotBecomeEnvironment() throws {
    let store = MemoryStore()
    store.values[try SecretReference("secondpass://v/i/f")] = "a\0b"
    let service = SecretService { store }
    #expect(throws: MopError.invalidProcess) { try service.environment(inherited: ["A": "secondpass://v/i/f"], files: []) }
    #expect(store.closes == 1)
}

@Test func sectionsAndComponentExpansion() throws {
    let plain = try SecretReference("secondpass://v/i/f")
    let section = try SecretReference("secondpass://v/i/s/f")
    #expect(plain != section)
    #expect(section.section == "s")
    #expect(section.description == "secondpass://v/i/s/f")
    let expanded = try ReferenceExpansion.resolve("secondpass://$VAULT/i/${SECTION}/pre-${FIELD}", variables: [
        "VAULT": "a-b", "SECTION": "多 行", "FIELD": "${LITERAL}?/#"
    ])
    #expect(expanded.vault == "a-b")
    #expect(expanded.section == "多 行")
    #expect(expanded.field == "pre-${LITERAL}?/#")
    #expect(try ReferenceExpansion.resolve("secondpass://v/i/%24NAME", variables: [:]).field == "$NAME")
    for token in ["secondpass://$MISSING/i/f", "secondpass://v/i/${}", "secondpass://v/i/$1", "secondpass://v/i/$(false)",
                  "secondpass://v/i/${A:-x}", "secondpass://v/i/$", "secondpass://v/i/${A", "secondpass://v/i/$EMPTY", "secondpass://v/i//f"] {
        #expect(throws: MopError.invalidReference) { try ReferenceExpansion.resolve(token, variables: ["EMPTY": ""]) }
    }
}

@Test func expansionUsesMergedEnvironmentAndResolvesOnce() throws {
    let store = MemoryStore()
    let reference = try SecretReference("secondpass://prod/i/section/token")
    store.values[reference] = "value"
    let service = SecretService { store }
    let result = try service.resolvedEnvironment(inherited: ["V": "dev"], files: [
        "V=staging\nTOKEN=secondpass://$V/i/section/token", "V=prod\nALSO=secondpass://${V}/i/section/%74oken\nLITERAL=$V"
    ])
    #expect(result.variables["TOKEN"] == "value")
    #expect(result.variables["ALSO"] == "value")
    #expect(result.variables["LITERAL"] == "$V")
    #expect(result.secrets == ["value"])
    #expect(store.reads == [reference])
    #expect(store.closes == 1)
    #expect(try service.inject("{{secondpass://prod/i/${S}/${F}}} $F {{ unrelated }}", variables: ["S": "section", "F": "token"])
            == "value $F {{ unrelated }}")
}

@Test func expansionFailurePrecedesAuthentication() throws {
    var opens = 0
    let service = SecretService { opens += 1; throw MopError.authentication }
    #expect(throws: MopError.invalidReference) {
        try service.inject("{{secondpass://v/i/f}} {{secondpass://$MISSING/i/f}}")
    }
    #expect(throws: MopError.invalidReference) {
        try service.resolvedEnvironment(inherited: ["A": "secondpass://v/i/f", "B": "secondpass://$MISSING/i/f"], files: [])
    }
    #expect(opens == 0)
}

@Test func environmentMaskingPreservesAllSecretBytes() throws {
    let store = MemoryStore()
    let first = try SecretReference("secondpass://v/i/a")
    let second = try SecretReference("secondpass://v/i/b")
    store.values[first] = "audit-\u{e9}-token"
    store.values[second] = "audit-e\u{301}-token"
    let result = try SecretService { store }.resolvedEnvironment(inherited: ["A": first.description, "B": second.description], files: [])
    #expect(Set(result.secrets.map { Data($0.utf8) }).count == 2)
    var masker = SecretMasker(patterns: MaskPatterns(secrets: result.secrets))
    let input = Data((result.variables["A"]! + "|" + result.variables["B"]!).utf8)
    #expect(masker.consume(SecretBytes(copying: input), final: true) == "[concealed by 2ndpass]|[concealed by 2ndpass]")
}

@Test func namedVaultValidationAndRelativePaths() throws {
    for name in ["personal", "work-prod", "1", String(repeating: "a", count: 63)] {
        try VaultName.validate(name)
    }
    for name in ["", "Personal", "a b", "a/b", "-a", "a-", "a--b", "é", "a\n", String(repeating: "a", count: 64)] {
        #expect(throws: MopError.invalidVaultName) { try VaultName.validate(name) }
    }
    let ref = try SecretReference("secondpass://personal/my%2Fcloud/a%20section/%E2%9C%93")
    #expect(ref.relativePath == "my%2Fcloud/a%20section/%E2%9C%93")
    #expect(try SecretReference(vault: "private", relativePath: ref.relativePath).vault == "private")
    #expect(throws: MopError.invalidReference) { try SecretReference(vault: "personal", relativePath: "item/%74oken") }
}

@Test func legacyReferencesResolveAlongsideSecondPassReferences() throws {
    let expected = try SecretReference("secondpass://personal/item/token")
    #expect(try SecretReference("mop://personal/item/token") == expected)
    #expect(try SecretReference("mop://personal/item/token").description == expected.description)
    let environment = ["VAULT": SecretBytes(utf8: "personal"),
                       "OLD": SecretBytes(utf8: "mop://${VAULT}/item/token"),
                       "NEW": SecretBytes(utf8: "secondpass://${VAULT}/item/token")]
    let references = try SecretParsing.references(in: environment)
    #expect(references["OLD"] == expected)
    #expect(references["NEW"] == expected)
    let template = SecretBytes(utf8: "{{ mop://${VAULT}/item/token }} {{ secondpass://${VAULT}/item/token }}")
    let placeholders = try SecretParsing.placeholders(template, variables: ["VAULT": "personal"])
    #expect(placeholders.count == 2)
    #expect(placeholders.allSatisfy { $0.1 == expected })
    #expect(throws: MopError.invalidTemplate) {
        try SecretParsing.placeholders(SecretBytes(utf8: "{{ mop://personal/item/token"), variables: [:])
    }
    #expect(throws: MopError.invalidReference) { try SecretReference("2ndpass://personal/item/token") }
}
