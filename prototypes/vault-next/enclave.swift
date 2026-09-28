// Standalone platform probe. No Mop identity, vault, or Keychain item is opened.
// swiftc -module-cache-path /tmp/mop-next-module-cache enclave.swift -o /tmp/mop-enclave-probe
import CryptoKit
import Foundation
import LocalAuthentication
import Security

func check(_ condition: Bool, _ message: String) throws {
    if !condition { throw NSError(domain: "MopEnclaveProbe", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    print("PASS: \(message)")
}

func run() throws {
    print("OS: \(ProcessInfo.processInfo.operatingSystemVersionString)")
    print("SecureEnclave.isAvailable: \(SecureEnclave.isAvailable)")
    guard SecureEnclave.isAvailable else {
        print("BLOCKED: hardware unavailable to this process; no software fallback")
        exit(77)
    }
    let deny = CommandLine.arguments.contains("--deny")
    let preauthorize = CommandLine.arguments.contains("--preauthorize")
    let presence = deny || preauthorize || CommandLine.arguments.contains("--presence")
    let context = LAContext()
    context.localizedReason = "validate Mop's disposable Secure Enclave prototype keys"
    context.interactionNotAllowed = deny || !presence
    defer { context.invalidate() }
    var error: Unmanaged<CFError>?
    guard let acl = SecAccessControlCreateWithFlags(nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        presence ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage], &error) else {
        throw error!.takeRetainedValue()
    }
    print("ACL userPresence: \(presence); creating ephemeral hardware keys")
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: acl, authenticationContext: context)
    let signing = try SecureEnclave.P256.Signing.PrivateKey(accessControl: acl, authenticationContext: context)
    let info = Data("mop-v7-prototype:disposable-record:device".utf8)
    if preauthorize {
        let semaphore = DispatchSemaphore(value: 0)
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: context.localizedReason) { _, _ in semaphore.signal() }
        guard semaphore.wait(timeout: .now() + 45) == .success else { throw NSError(domain: "MopProbeAuthenticationTimeout", code: 1) }
        context.interactionNotAllowed = true
    }
    var sender = try HPKE.Sender(recipientKey: key.publicKey, ciphersuite: .P256_SHA256_AES_GCM_256, info: info)
    let secret = SymmetricKey(size: .bits256)
    let wrapped = try secret.withUnsafeBytes { try sender.seal($0) }
    let reopened = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: key.dataRepresentation, authenticationContext: context)
    try check(reopened.publicKey.x963Representation == key.publicKey.x963Representation, "opaque representation reload preserves public identity")
    if deny {
        do {
            _ = try HPKE.Recipient(privateKey: reopened, ciphersuite: .P256_SHA256_AES_GCM_256, info: info, encapsulatedKey: sender.encapsulatedKey)
        } catch {
            print("PASS: unapproved no-interaction HPKE refused (\((error as NSError).domain), \((error as NSError).code))")
            return
        }
        throw NSError(domain: "MopProbeUnexpectedUnapprovedAccess", code: 1)
    }
    var recipient = try HPKE.Recipient(privateKey: reopened, ciphersuite: .P256_SHA256_AES_GCM_256, info: info, encapsulatedKey: sender.encapsulatedKey)
    var unwrapped = try recipient.open(wrapped)
    defer { unwrapped.resetBytes(in: 0..<unwrapped.count) }
    try check(secret.withUnsafeBytes { unwrapped.elementsEqual($0) }, "HPKE round trip uses hardware private key")
    do {
        var wrong = try HPKE.Recipient(privateKey: reopened, ciphersuite: .P256_SHA256_AES_GCM_256, info: Data("wrong-purpose".utf8), encapsulatedKey: sender.encapsulatedKey)
        _ = try wrong.open(wrapped)
        throw NSError(domain: "MopEnclaveProbe", code: 2)
    } catch is CryptoKitError { print("PASS: changed HPKE context rejected") }
    let restoredSigning = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: signing.dataRepresentation, authenticationContext: context)
    let signature = try restoredSigning.signature(for: info)
    try check(signing.publicKey.isValidSignature(signature, for: info), "hardware signing after representation reload")
    if preauthorize {
        print("PASS: device-owner policy preauthorization permits HPKE and signing with interaction disabled")
        context.invalidate()
        var signingStillUsable = false
        do {
            _ = try restoredSigning.signature(for: Data("after-invalidation".utf8))
            signingStillUsable = true
        } catch {
            print("OBSERVED: invalidated context refuses signing (\((error as NSError).domain), \((error as NSError).code))")
        }
        if signingStillUsable { print("OBSERVED: existing signing handle remains usable after LAContext.invalidate(); application must close provider and release handles") }
        do {
            var after = try HPKE.Recipient(privateKey: reopened, ciphersuite: .P256_SHA256_AES_GCM_256, info: info, encapsulatedKey: sender.encapsulatedKey)
            var bytes = try after.open(wrapped)
            defer { bytes.resetBytes(in: 0..<bytes.count) }
            print("OBSERVED: existing agreement handle remains usable after LAContext.invalidate()")
        } catch { print("OBSERVED: invalidated context refuses a new HPKE recipient (\((error as NSError).domain), \((error as NSError).code))") }
        print("NOT TESTED: lock screen, cross-device restore, relaunch, Keychain access groups, biometric changes, AutoFill")
        return
    }
    print("NOT TESTED: cross-device restore, process relaunch, Keychain groups, device lock, biometric changes, AutoFill")
    print("NOT TESTED: LAContext policy preauthorization/reuse and invalidation enforcement")
}

do { try run() }
catch {
    let error = error as NSError
    // No key/ciphertext/plaintext values are logged.
    print("BLOCKED/FAIL: \(error.domain) code \(error.code)")
    exit(1)
}
