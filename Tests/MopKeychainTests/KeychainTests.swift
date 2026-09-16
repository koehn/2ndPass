import LocalAuthentication
import Testing
import Security
import MopCore
@testable import MopKeychain

@Test func keychainIdentifiersDoNotCollide() throws {
    let a = try SecretReference(vault: "a/b", item: "c", field: "token")
    let b = try SecretReference(vault: "a", item: "b/c", field: "token")
    #expect(KeychainStore.service(for: a) != KeychainStore.service(for: b))
    #expect(KeychainStore.service(for: a) == "mop.v1/a%2Fb/c")
}

@Test func statusErrorsHaveStableCodesWithoutOSDescriptions() {
    #expect(throws: MopError.notFound) { try KeychainStore.check(errSecItemNotFound) }
    #expect(throws: MopError.duplicate) { try KeychainStore.check(errSecDuplicateItem) }
    #expect(throws: MopError.authentication) { try KeychainStore.check(errSecInteractionNotAllowed) }
    #expect(throws: MopError.authentication) { try KeychainStore.check(errSecUserCanceled) }
    #expect(throws: MopError.signing) { try KeychainStore.check(errSecMissingEntitlement) }
    #expect(MopError.authentication.exitCode == 3)
    #expect(MopError.notFound.exitCode == 4)
}


@Test func legacyBackendRejectsSectionsBeforeKeychainAccess() throws {
    let store = KeychainStore(accessGroup: "unused-test-group", context: LAContext())
    defer { store.close() }
    let reference = try SecretReference("mop://v/i/section/field")
    #expect(throws: MopError.invalidReference) { try store.read(reference) }
    #expect(throws: MopError.invalidReference) { try store.write(reference, value: "unused", replace: false) }
    #expect(throws: MopError.invalidReference) { try store.delete(reference) }
}
