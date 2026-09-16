import Foundation
import Testing
@testable import MopCore

private final class MemoryStore: SecretStore {
    var values: [SecretReference: String] = [:]
    var reads: [SecretReference] = []
    var closes = 0
    func read(_ reference: SecretReference) throws -> String {
        reads.append(reference)
        guard let value = values[reference] else { throw MopError.notFound }
        return value
    }
    func write(_ reference: SecretReference, value: String, replace: Bool) throws {
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

@Test func referencesAreCaseSensitiveAndUnambiguous() throws {
    let ref = try SecretReference("mop://Personal/an%2Fitem/%E2%9C%93%20token")
    #expect(ref.vault == "Personal")
    #expect(ref.item == "an/item")
    #expect(ref.field == "✓ token")
    #expect(ref.description == "mop://Personal/an%2Fitem/%E2%9C%93%20token")
    #expect(try SecretReference("mop://v/i/%74oken") == SecretReference("mop://v/i/token"))
    #expect(try SecretReference("mop://v/i/token") != SecretReference("mop://V/i/token"))
    #expect(try SecretReference("mop://v/i/%252F").field == "%2F")
    let composed = try SecretReference("mop://v/%C3%A9/f")
    let decomposed = try SecretReference("mop://v/e%CC%81/f")
    #expect(composed == decomposed)
    #expect(composed.description == decomposed.description)
}

@Test(arguments: ["op://v/i/f", "MOP://v/i/f", "mop://v/i", "mop://v/i/s/f/x", "mop:///i/f", "mop://v//f", "mop://v/i/", "mop://v/i/f?q", "mop://v/i/f#x", "mop://v/i/a b", "mop://v/i/%", "mop://v/i/%XZ", "mop://v/i/%FF", "mop://v/i/%00", "mop://v/i/é", "mop://user@v/i/f"])
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
    #expect(throws: MopError.invalidEnvironment(line: 1)) { try DotEnv.parse(input) }
}

@Test func serviceCRUDAndSessionLifetimes() throws {
    let store = MemoryStore()
    var opens = 0
    let service = SecretService { opens += 1; return store }
    let ref = try SecretReference("mop://v/i/f")
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
    let ref = try SecretReference("mop://v/i/f")
    store.values[ref] = "secret\nvalue"
    var opens = 0
    let service = SecretService { opens += 1; return store }
    let result = try service.environment(inherited: ["A": "old", "UNCHANGED": "keep"], files: [
        "A=first\nB=mop://v/i/f", "A=mop://v/i/%66\nC=prefix mop://v/i/f"
    ])
    #expect(result == ["A": "secret\nvalue", "B": "secret\nvalue", "C": "prefix mop://v/i/f", "UNCHANGED": "keep"])
    #expect(opens == 1)
    #expect(store.reads == [ref])
    #expect(store.closes == 1)
}

@Test func templatesPreserveUnicodeAndDoNotRecursivelyExpand() throws {
    let store = MemoryStore()
    let ref = try SecretReference("mop://v/i/f")
    store.values[ref] = "{{ mop://not/another/lookup }}\n🔒"
    let service = SecretService { store }
    let output = try service.inject("前 {{ mop://v/i/f }} {{mop://v/i/%66}} {{ unrelated }} 後")
    #expect(output == "前 {{ mop://not/another/lookup }}\n🔒 {{ mop://not/another/lookup }}\n🔒 {{ unrelated }} 後")
    #expect(store.reads == [ref])
    #expect(store.closes == 1)
}

@Test func missingSecretsProduceNoResultAndCloseSession() throws {
    let store = MemoryStore()
    store.values[try SecretReference("mop://v/i/a")] = "must not escape"
    let service = SecretService { store }
    var output: String?
    #expect(throws: MopError.notFound) { output = try service.inject("{{mop://v/i/a}}{{mop://v/i/b}}") }
    #expect(output == nil)
    #expect(store.closes == 1)
    var environment: [String: String]?
    #expect(throws: MopError.notFound) {
        environment = try service.environment(inherited: ["A": "mop://v/i/a", "B": "mop://v/i/b"], files: [])
    }
    #expect(environment == nil)
    #expect(store.closes == 2)
}

@Test func validateBeforeAuthenticationAndSkipUnusedStore() throws {
    var opens = 0
    let service = SecretService { opens += 1; throw MopError.authentication }
    #expect(try service.inject("literal {{ unrelated }}") == "literal {{ unrelated }}")
    #expect(try service.environment(inherited: ["A": "literal"], files: []) == ["A": "literal"])
    #expect(throws: MopError.invalidReference) { try service.inject("{{ mop://v/i/f }} {{ mop://invalid }}") }
    #expect(throws: MopError.invalidTemplate) { try service.inject("{{ mop://v/i/f") }
    #expect(throws: MopError.invalidReference) { try service.environment(inherited: ["A": "mop://invalid"], files: []) }
    #expect(opens == 0)
    #expect(throws: MopError.authentication) { try service.inject("{{mop://v/i/f}}") }
    #expect(opens == 1)
}

@Test func nulInSecretCannotBecomeEnvironment() throws {
    let store = MemoryStore()
    store.values[try SecretReference("mop://v/i/f")] = "a\0b"
    let service = SecretService { store }
    #expect(throws: MopError.invalidProcess) { try service.environment(inherited: ["A": "mop://v/i/f"], files: []) }
    #expect(store.closes == 1)
}

@Test func sectionsAndComponentExpansion() throws {
    let plain = try SecretReference("mop://v/i/f")
    let section = try SecretReference("mop://v/i/s/f")
    #expect(plain != section)
    #expect(section.section == "s")
    #expect(section.description == "mop://v/i/s/f")
    let expanded = try ReferenceExpansion.resolve("mop://$VAULT/i/${SECTION}/pre-${FIELD}", variables: [
        "VAULT": "a/b", "SECTION": "多 行", "FIELD": "${LITERAL}?/#"
    ])
    #expect(expanded.vault == "a/b")
    #expect(expanded.section == "多 行")
    #expect(expanded.field == "pre-${LITERAL}?/#")
    #expect(try ReferenceExpansion.resolve("mop://v/i/%24NAME", variables: [:]).field == "$NAME")
    for token in ["mop://$MISSING/i/f", "mop://v/i/${}", "mop://v/i/$1", "mop://v/i/$(false)",
                  "mop://v/i/${A:-x}", "mop://v/i/$", "mop://v/i/${A", "mop://v/i/$EMPTY", "mop://v/i//f"] {
        #expect(throws: MopError.invalidReference) { try ReferenceExpansion.resolve(token, variables: ["EMPTY": ""]) }
    }
}

@Test func expansionUsesMergedEnvironmentAndResolvesOnce() throws {
    let store = MemoryStore()
    let reference = try SecretReference("mop://prod/i/section/token")
    store.values[reference] = "value"
    let service = SecretService { store }
    let result = try service.resolvedEnvironment(inherited: ["V": "dev"], files: [
        "V=staging\nTOKEN=mop://$V/i/section/token", "V=prod\nALSO=mop://${V}/i/section/%74oken\nLITERAL=$V"
    ])
    #expect(result.variables["TOKEN"] == "value")
    #expect(result.variables["ALSO"] == "value")
    #expect(result.variables["LITERAL"] == "$V")
    #expect(result.secrets == ["value"])
    #expect(store.reads == [reference])
    #expect(store.closes == 1)
    #expect(try service.inject("{{mop://prod/i/${S}/${F}}} $F {{ unrelated }}", variables: ["S": "section", "F": "token"])
            == "value $F {{ unrelated }}")
}

@Test func expansionFailurePrecedesAuthentication() throws {
    var opens = 0
    let service = SecretService { opens += 1; throw MopError.authentication }
    #expect(throws: MopError.invalidReference) {
        try service.inject("{{mop://v/i/f}} {{mop://$MISSING/i/f}}")
    }
    #expect(throws: MopError.invalidReference) {
        try service.resolvedEnvironment(inherited: ["A": "mop://v/i/f", "B": "mop://$MISSING/i/f"], files: [])
    }
    #expect(opens == 0)
}

@Test func environmentMaskingPreservesAllSecretBytes() throws {
    let store = MemoryStore()
    let first = try SecretReference("mop://v/i/a")
    let second = try SecretReference("mop://v/i/b")
    store.values[first] = "audit-\u{e9}-token"
    store.values[second] = "audit-e\u{301}-token"
    let result = try SecretService { store }.resolvedEnvironment(inherited: ["A": first.description, "B": second.description], files: [])
    #expect(Set(result.secrets.map { Data($0.utf8) }).count == 2)
    var masker = SecretMasker(patterns: MaskPatterns(secrets: result.secrets))
    let input = Data((result.variables["A"]! + "|" + result.variables["B"]!).utf8)
    #expect(masker.consume(input, final: true) == Data("[concealed by mop]|[concealed by mop]".utf8))
}
