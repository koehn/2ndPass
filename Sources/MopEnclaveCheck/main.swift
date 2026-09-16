import CryptoKit
import Foundation
import LocalAuthentication
import MopCore
import MopAuth
import Security

struct Fixture: Codable {
    let blob: Data
    let encapsulated: Data
    let ciphertext: Data
}

do {
    let arguments = CommandLine.arguments
    guard arguments.count == 3, ["create", "open", "deny"].contains(arguments[1]) else {
        print("Usage: mop-enclave-check create|open|deny FILE (disposable test data only)")
        exit(0)
    }
    guard SecureEnclave.isAvailable else { throw MopError.authentication }
    let url = URL(fileURLWithPath: arguments[2])
    let info = Data("mop-provisioning-free-probe-v1".utf8)
    if arguments[1] == "create" {
        guard !FileManager.default.fileExists(atPath: url.path) else { throw MopError.duplicate }
        let context = try Authentication.authorize()
        defer { context.invalidate() }
        let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], nil)!
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access, authenticationContext: context)
        var sender = try HPKE.Sender(recipientKey: key.publicKey, ciphersuite: .P256_SHA256_AES_GCM_256, info: info)
        let ciphertext = try sender.seal(Data("disposable probe payload".utf8))
        let fixture = Fixture(blob: key.dataRepresentation, encapsulated: sender.encapsulatedKey, ciphertext: ciphertext)
        try JSONEncoder().encode(fixture).write(to: url, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        print("PASS: created a protected Secure Enclave key and stored its opaque blob without provisioning.")
    } else {
        let fixture = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
        let context: LAContext
        if arguments[1] == "deny" {
            context = LAContext()
            context.interactionNotAllowed = true
            context.touchIDAuthenticationAllowableReuseDuration = 0
        } else { context = try Authentication.authorize() }
        defer { context.invalidate() }
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: fixture.blob, authenticationContext: context)
            var recipient = try HPKE.Recipient(privateKey: key, ciphersuite: .P256_SHA256_AES_GCM_256, info: info, encapsulatedKey: fixture.encapsulated)
            let plaintext = try recipient.open(fixture.ciphertext)
            if arguments[1] == "deny" { fputs("FAIL: private-key operation succeeded without authentication.\n", stderr); exit(1) }
            guard plaintext == Data("disposable probe payload".utf8) else { exit(1) }
            print("PASS: reopened the device-bound key and decrypted after authentication in a new process.")
        } catch {
            if arguments[1] == "deny" {
                let ns = error as NSError
                guard (ns.domain == NSOSStatusErrorDomain &&
                      [Int(errSecInteractionNotAllowed), Int(errSecAuthFailed), Int(errSecUserCanceled)].contains(ns.code)) ||
                      (ns.domain == LAError.errorDomain && ns.code == LAError.Code.notInteractive.rawValue) else {
                    fputs("Probe failed for a reason other than authentication (domain \(ns.domain), code \(ns.code)).\n", stderr)
                    exit(1)
                }
                print("PASS: Secure Enclave denied access without authentication.")
            } else { throw error }
        }
    }
} catch {
    let ns = error as NSError
    fputs("Probe failed (domain \(ns.domain), code \(ns.code)).\n", stderr)
    exit(1)
}
