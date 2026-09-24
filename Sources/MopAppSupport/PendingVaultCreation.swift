import Foundation
import MopCore
import MopVault

/// Durable local intent. Recovery material and the initial encrypted snapshot are
/// never regenerated after export/publication. One pending creation at a time.
public struct PendingVaultCreation: Codable, Sendable {
    public let id: UUID
    public let name: String
    public let deviceName: String
    public let strict: Bool
    public var exported = false
    public var account: String?
    public var snapshot: Data?
    public var fingerprint: String?
    public var submitted = false

    public static func directory(state: URL) -> URL { state.appendingPathComponent("pending-creation", isDirectory: true) }
    public static func recoveryURL(state: URL) -> URL { directory(state: state).appendingPathComponent("recovery.key") }

    public static func load(state: URL) throws -> Self? {
        let url = directory(state: state).appendingPathComponent("intent.json")
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try JSONDecoder().decode(Self.self, from: SafeFile.read(url, privateFile: true))
    }

    public static func prepare(name: String, deviceName: String, strict: Bool, state: URL) throws -> Self {
        try VaultName.validate(name)
        guard !deviceName.isEmpty else { throw MopError.invalidDevice }
        try SafeFile.privateDirectory(state)
        try SafeFile.privateDirectory(directory(state: state))
        let intent: Self
        if let existing = try load(state: state) {
            guard existing.name == name, existing.deviceName == deviceName, existing.strict == strict else { throw MopError.duplicate }
            intent = existing
        } else {
            intent = Self(id: UUID(), name: name, deviceName: deviceName, strict: strict)
            try intent.save(state: state)
        }
        let key = recoveryURL(state: state)
        if !FileManager.default.fileExists(atPath: key.path) {
            guard !intent.exported, intent.snapshot == nil, !intent.submitted else { throw MopError.invalidRecovery }
            try RecoveryKey().save(to: key)
        }
        return intent
    }

    public func save(state: URL) throws {
        let url = Self.directory(state: state).appendingPathComponent("intent.json")
        try SafeFile.write(JSONEncoder().encode(self), to: url, replace: FileManager.default.fileExists(atPath: url.path))
    }

    public mutating func export(to url: URL, state: URL) throws {
        let output = try OutputFile(url: url, force: false, mode: 0o600, protectedFiles: [], protectedDirectories: [state])
        // RecoveryKey parses into owned, wiped buffers, avoiding plaintext Data copies.
        let recovery = try RecoveryKey(file: Self.recoveryURL(state: state))
        try recovery.export(to: output)
        exported = true
        try save(state: state)
    }

    public static func finish(state: URL) throws {
        try FileManager.default.removeItem(at: directory(state: state))
    }

    public static func discardUnsubmitted(state: URL) throws {
        guard let intent = try load(state: state), !intent.submitted else { throw MopError.cloudUncertain }
        try finish(state: state)
    }
}
