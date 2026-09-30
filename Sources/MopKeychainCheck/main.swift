import CryptoKit
import Foundation
import MopAuth
import MopCore
import MopVaultNext

// Explicit hardware check. Only a unique disposable v6 key scope is accessed.
do {
    guard CommandLine.arguments.dropFirst().elementsEqual(["--run"]) else {
        print("Usage: sp-keychain-check --run\nCreates and retains a disposable device-only hardware identity; requires authentication.")
        exit(0)
    }
    let scope = "mop-v7-keychain-check-" + UUID().uuidString, member = UUID()
    let context = try Authentication.authorize(reason: "validate disposable 2ndPass hardware keys")
    let first = try DeviceKeychain.open(scope: scope, member: member, context: context, create: true)
    let identity = first.identity
    let second = try DeviceKeychain.open(scope: scope, member: member, context: context)
    let message = Data("mop-v7-keychain-check".utf8), signature = try second.sign(message)
    guard second.identity == identity,
          try P256.Signing.PublicKey(x963Representation: identity.signing).isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: signature), for: message) else { throw MopError.invalidIdentity }
    first.close(); second.close(); context.invalidate()
    print("PASS: hardware identity creation, device-local opaque Keychain reload, signature verification. Retained scope \(scope), member \(member). No old identity accessed or deleted.")
} catch {
    fputs("Hardware check failed; no software fallback.\n", stderr); exit(1)
}
