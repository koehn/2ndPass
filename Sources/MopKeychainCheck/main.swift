import Foundation
import LocalAuthentication
import MopCore
import MopKeychain
import MopAuth
import Security

// An opt-in, separately packaged integration executable. Never run by swift test.
func verify(_ condition: @autoclosure () -> Bool) throws {
    guard condition() else { throw MopError.keychain(errSecInternalError) }
}

func suite() throws {
    let group = try SigningIdentity.accessGroup()
    let context = try Authentication.authorize()
    let store = KeychainStore(accessGroup: group, context: context)
    let vault = "integration-" + UUID().uuidString
    let first = try SecretReference(vault: vault, item: "test/item", field: "first")
    let second = try SecretReference(vault: vault, item: "test/item", field: "second")
    var remaining: Set<SecretReference> = []
    defer {
        // Cleanup touches only entries successfully created by this invocation.
        for reference in remaining {
            do { try store.delete(reference) }
            catch { fputs("Cleanup failed for disposable reference: \(reference)\n", stderr) }
        }
        store.close()
    }
    try store.write(first, value: "disposable\nfirst\n", replace: false)
    remaining.insert(first)
    try store.write(second, value: "disposable second", replace: false)
    remaining.insert(second)
    let original = try store.read(first)
    try verify(original == "disposable\nfirst\n")
    let secondValue = try store.read(second)
    try verify(secondValue == "disposable second")
    let listed = try store.list(vault: vault)
    try verify(Set(listed) == [first, second])
    do {
        try store.write(first, value: "must not replace", replace: false)
        throw MopError.keychain(errSecInternalError)
    } catch MopError.duplicate { }
    try store.write(first, value: "updated", replace: true)
    let updated = try store.read(first)
    try verify(updated == "updated")

    // No LA evaluatePolicy call: Keychain itself must deny the protected read.
    let unauthenticated = LAContext()
    unauthenticated.interactionNotAllowed = true
    unauthenticated.touchIDAuthenticationAllowableReuseDuration = 0
    let deniedStore = KeychainStore(accessGroup: group, context: unauthenticated)
    defer { deniedStore.close() }
    do {
        _ = try deniedStore.read(first)
        throw MopError.keychain(errSecInternalError)
    } catch MopError.authentication { }

    // An explicitly unentitled group must not grant access, even in this process.
    let foreignContext = LAContext()
    foreignContext.interactionNotAllowed = true
    let foreign = KeychainStore(accessGroup: group + ".unentitled", context: foreignContext)
    defer { foreign.close() }
    do {
        _ = try foreign.read(first)
        throw MopError.keychain(errSecInternalError)
    } catch MopError.signing { }

    try store.delete(first)
    remaining.remove(first)
    do {
        _ = try store.read(first)
        throw MopError.keychain(errSecInternalError)
    } catch MopError.notFound { }
    try store.delete(second)
    remaining.remove(second)
    print("PASS: CRUD, batch access, metadata listing, protected-read denial, and access-group denial. Disposable entries removed.")
}

do {
    guard CommandLine.arguments == [CommandLine.arguments[0], "--run"] else {
        print("Usage: mop-keychain-check --run\nCreates and removes disposable Keychain entries and requires macOS authentication. See docs/VALIDATION.md.")
        exit(0)
    }
    try suite()
} catch let error as MopError {
    fputs("Keychain check failed: \(error.errorDescription ?? "Unknown failure")\n", stderr)
    exit(error.exitCode)
} catch {
    fputs("Keychain check failed.\n", stderr)
    exit(1)
}
