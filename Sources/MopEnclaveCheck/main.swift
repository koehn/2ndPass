import CryptoKit
import Foundation
import LocalAuthentication
import MopCore
import MopVault
import MopKeychain
import Security

// Disposable, explicitly invoked hardware checks. Uses the production backend.
private struct Probe: Codable {
    let vaultID: UUID
    let slot: VaultRecipient
}
private struct DeviceMetadata: Decodable { let keyID: UUID }

do {
    let args = CommandLine.arguments
    guard args.count >= 3, ["create", "create-strict", "open", "deny", "foreign"].contains(args[1]),
          args.count == (args[1] == "foreign" ? 4 : 3) else {
        print("Usage: mop-enclave-check create|create-strict|open|deny DIRECTORY\n       mop-enclave-check foreign DIRECTORY OTHER_APP_ACCESS_GROUP\nUse disposable directories. Requires a signed, provisioned probe application.")
        exit(0)
    }
    let directory = URL(fileURLWithPath: args[2], isDirectory: true)
    let file = directory.appendingPathComponent("probe.json")
    if args[1] == "create" || args[1] == "create-strict" {
        guard !FileManager.default.fileExists(atPath: directory.path) else { throw MopError.duplicate }
        let device = try LocalDevice.open(directory: directory, create: true, name: "Disposable probe",
                                          strictBiometrics: args[1] == "create-strict")
        defer { device.close() }
        let id = UUID()
        let slot = try VaultDocument.wrap(key: SymmetricKey(data: Data(repeating: 0x42, count: 32)), request: device.request, kind: "device", vaultID: id)
        try SafeFile.write(VaultCoding.encode(Probe(vaultID: id, slot: slot)), to: file)
        print("PASS: created an application-bound device key. device.json contains no key blob.")
    } else if args[1] == "open" {
        let probe = try JSONDecoder().decode(Probe.self, from: SafeFile.read(file, privateFile: true))
        let device = try LocalDevice.open(directory: directory)
        defer { device.close() }
        guard try device.unwrap(probe.slot, vaultID: probe.vaultID) == SymmetricKey(data: Data(repeating: 0x42, count: 32)) else { throw MopError.invalidVault }
        print("PASS: reopened through the application's Keychain group and authenticated enclave operation.")
    } else {
        let ownGroup = try SigningIdentity.accessGroup()
        let group = args[1] == "foreign" ? args[3] : ownGroup
        guard args[1] != "foreign" || group != ownGroup else { throw MopError.invalidProcess }
        let metadata = try JSONDecoder().decode(DeviceMetadata.self, from: SafeFile.read(directory.appendingPathComponent("device.json"), privateFile: true))
        let context = LAContext()
        context.interactionNotAllowed = true
        context.touchIDAuthenticationAllowableReuseDuration = 0
        defer { context.invalidate() }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true, kSecAttrSynchronizable as String: false,
            kSecAttrAccessGroup as String: group, kSecAttrService as String: "mop.device-key.v2",
            kSecAttrAccount as String: metadata.keyID.uuidString, kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: context]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if args[1] == "foreign" {
            guard status == errSecMissingEntitlement else { throw MopError.keychain(status) }
            print("PASS: the OS rejected a foreign application's Keychain access group.")
        } else {
            guard [errSecInteractionNotAllowed, errSecAuthFailed].contains(status) else { throw MopError.keychain(status) }
            print("PASS: the OS denied key retrieval without authentication.")
        }
    }
} catch {
    fputs("Probe failed: \((error as? MopError)?.errorDescription ?? "Unexpected failure").\n", stderr)
    exit(1)
}
