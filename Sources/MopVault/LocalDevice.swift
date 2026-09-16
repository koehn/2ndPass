import CryptoKit
import Foundation
import LocalAuthentication
import MopCore
import MopAuth
import Security

public protocol VaultKeyOpener {
    var publicKey: Data { get }
    func unwrap(_ recipient: VaultRecipient, vaultID: UUID) throws -> SymmetricKey
}

public final class LocalDevice: VaultKeyOpener {
    private struct Record: Codable {
        let format: String
        let name: String
        let publicKey: Data
        let blob: Data
    }

    public let publicKey: Data
    public let name: String
    private let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    private let context: LAContext
    public var request: DeviceRequest { try! DeviceRequest(name: name, publicKey: publicKey) }

    private init(record: Record, key: SecureEnclave.P256.KeyAgreement.PrivateKey, context: LAContext) {
        self.publicKey = record.publicKey
        self.name = record.name
        self.key = key
        self.context = context
    }

    public static func open(directory: URL, create: Bool = false, name: String = "Mac") throws -> LocalDevice {
        guard SecureEnclave.isAvailable else { throw MopError.deviceUnavailable }
        let path = directory.appendingPathComponent("device.json")
        let exists = FileManager.default.fileExists(atPath: path.path)
        guard exists || create else { throw MopError.deviceNotEnrolled }
        let saved: Record?
        if exists {
            try SafeFile.privateDirectory(directory)
            do {
                saved = try JSONDecoder().decode(Record.self, from: SafeFile.read(path, privateFile: true, limit: 64 * 1024))
                guard saved?.format == "mop-local-device-v1" else { throw MopError.invalidDevice }
            } catch let error as MopError { throw error }
              catch { throw MopError.invalidDevice }
        } else { saved = nil }
        let context = try Authentication.authorize()
        do {
            let key: SecureEnclave.P256.KeyAgreement.PrivateKey
            let record: Record
            if let saved {
                _ = try DeviceRequest(name: saved.name, publicKey: saved.publicKey)
                key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: saved.blob, authenticationContext: context)
                guard key.publicKey.x963Representation == saved.publicKey else { throw MopError.invalidDevice }
                record = saved
            } else {
                guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                                  [.privateKeyUsage, .userPresence], nil) else { throw MopError.invalidDevice }
                key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access, authenticationContext: context)
                _ = try DeviceRequest(name: name, publicKey: key.publicKey.x963Representation)
                record = Record(format: "mop-local-device-v1", name: name, publicKey: key.publicKey.x963Representation, blob: key.dataRepresentation)
            }
            let device = LocalDevice(record: record, key: key, context: context)
            // Prove actual private-key access, including for public-only management commands.
            let testKey = SymmetricKey(size: .bits256)
            let vaultID = UUID()
            let slot = try VaultDocument.wrap(key: testKey, request: device.request, kind: "device", vaultID: vaultID)
            let unwrapped = try device.unwrap(slot, vaultID: vaultID)
            guard unwrapped == testKey else { throw MopError.invalidDevice }
            if !exists {
                try SafeFile.privateDirectory(directory)
                try SafeFile.write(VaultCoding.encode(record), to: path)
            }
            return device
        } catch {
            context.invalidate()
            throw mapError(error)
        }
    }

    public func unwrap(_ recipient: VaultRecipient, vaultID: UUID) throws -> SymmetricKey {
        guard recipient.publicKey == publicKey else { throw MopError.deviceNotEnrolled }
        do { return try VaultDocument.unwrap(recipient, vaultID: vaultID, privateKey: key) }
        catch { throw Self.mapError(error) }
    }

    private static func mapError(_ error: Error) -> MopError {
        if let error = error as? MopError { return error }
        let ns = error as NSError
        if ns.domain == LAError.errorDomain || (ns.domain == NSOSStatusErrorDomain &&
            [Int(errSecInteractionNotAllowed), Int(errSecUserCanceled), Int(errSecAuthFailed)].contains(ns.code)) {
            return .authentication
        }
        return .invalidDevice
    }

    public func close() { context.invalidate() }
    deinit { context.invalidate() }
}

public struct RecoveryKey: VaultKeyOpener {
    private let key: P256.KeyAgreement.PrivateKey
    public var publicKey: Data { key.publicKey.x963Representation }
    public var request: DeviceRequest { try! DeviceRequest(name: "Recovery", publicKey: publicKey) }

    public init() { key = P256.KeyAgreement.PrivateKey() }

    public init(file: URL) throws {
        let data = try SafeFile.read(file, privateFile: true, limit: 1024)
        guard let text = String(data: data, encoding: .utf8), text.hasPrefix("mop-recovery-v1:"),
              let bytes = Data(base64Encoded: String(text.dropFirst(16)).trimmingCharacters(in: .whitespacesAndNewlines)),
              bytes.count == 32, let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: bytes) else { throw MopError.invalidRecovery }
        self.key = key
    }

    public func save(to file: URL) throws {
        try SafeFile.write(Data(("mop-recovery-v1:" + key.rawRepresentation.base64EncodedString() + "\n").utf8), to: file)
    }

    public func unwrap(_ recipient: VaultRecipient, vaultID: UUID) throws -> SymmetricKey {
        guard recipient.kind == "recovery", recipient.publicKey == publicKey else { throw MopError.invalidRecovery }
        do { return try VaultDocument.unwrap(recipient, vaultID: vaultID, privateKey: key) }
        catch { throw MopError.invalidRecovery }
    }
}
