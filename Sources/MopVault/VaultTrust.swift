import CryptoKit
import Foundation
import MopCore

/// Local trust is deliberately separate from the replaceable/synced ciphertext.
/// A pin commits to both the vault identity and its high-entropy encryption key.
public struct VaultTrust {
    private struct Record: Codable {
        let format: String
        let active: String
        let previous: [String]
        let cloudBinding: String?
    }

    private let directory: URL
    private let file: URL
    private let cloudBinding: String?

    public init(vault: URL, directory: URL) {
        self.directory = directory
        self.cloudBinding = nil
        let path = vault.standardizedFileURL.resolvingSymlinksInPath().path
        self.file = directory.appendingPathComponent(VaultCoding.digest(Data(path.utf8)) + ".json")
    }

    /// Cloud trust is scoped to container, environment, account and vault, not an
    /// installation's absolute sandbox path. The directory must be dedicated to
    /// this one cloud vault. Legacy pins are accepted only from that directory.
    public init(cloudBinding: String, directory: URL) {
        self.directory = directory
        self.cloudBinding = VaultCoding.digest(Data(cloudBinding.utf8))
        self.file = directory.appendingPathComponent("cloud.json")
    }

    public static func fingerprint(document: VaultDocument, key: SymmetricKey) -> String {
        var hash = SHA256()
        hash.update(data: Data("mop-vault-trust-v1:\(document.header.vaultID.uuidString):".utf8))
        key.withUnsafeBytes { hash.update(bufferPointer: $0) }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private func load() throws -> Record {
        var source = file
        if !FileManager.default.fileExists(atPath: source.path), cloudBinding != nil {
            guard FileManager.default.fileExists(atPath: directory.path) else { throw MopError.vaultUntrusted }
            try SafeFile.privateDirectory(directory)
            let legacy = try FileManager.default.contentsOfDirectory(atPath: directory.path).filter {
                $0.hasSuffix(".json") && Self.validFingerprint(String($0.dropLast(5)))
            }
            guard legacy.count == 1 else { throw MopError.vaultUntrusted }
            source = directory.appendingPathComponent(legacy[0])
        }
        guard FileManager.default.fileExists(atPath: source.path) else { throw MopError.vaultUntrusted }
        try SafeFile.privateDirectory(directory)
        do {
            let record = try JSONDecoder().decode(Record.self, from: SafeFile.read(source, privateFile: true, limit: 64 * 1024))
            guard record.format == "mop-vault-trust-v1",
                  (source == file ? record.cloudBinding == cloudBinding : record.cloudBinding == nil),
                  ([record.active] + record.previous).allSatisfy(Self.validFingerprint) else { throw MopError.vaultUntrusted }
            return record
        } catch let error as MopError { throw error }
          catch { throw MopError.vaultUntrusted }
    }

    public static func validFingerprint(_ text: String) -> Bool {
        text.utf8.count == 64 && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    public func verify(document: VaultDocument, key: SymmetricKey, historical: Bool = false) throws {
        let record = try load()
        let fingerprint = Self.fingerprint(document: document, key: key)
        guard record.active == fingerprint || (historical && record.previous.contains(fingerprint)) else {
            throw MopError.vaultUntrusted
        }
        // Migrate only after the existing local pin verifies the decrypted key.
        // Never bootstrap trust from a downloaded header or snapshot.
        if cloudBinding != nil, !FileManager.default.fileExists(atPath: file.path) {
            let migrated = Record(format: record.format, active: record.active,
                                  previous: record.previous, cloudBinding: cloudBinding)
            let bytes = try VaultCoding.encode(migrated)
            guard bytes.count <= 64 * 1024 else { throw MopError.vaultUntrusted }
            try SafeFile.write(bytes, to: file, replace: false)
        }
    }

    /// Call only after creating a vault, a verified key rotation, or explicit
    /// comparison with independently trusted fingerprint/revision evidence.
    func pin(document: VaultDocument, key: SymmetricKey) throws {
        try SafeFile.privateDirectory(directory)
        let exists = FileManager.default.fileExists(atPath: file.path)
        let names = cloudBinding != nil ? try FileManager.default.contentsOfDirectory(atPath: directory.path) : []
        let hasLegacy = names.contains {
            $0.hasSuffix(".json") && Self.validFingerprint(String($0.dropLast(5)))
        }
        let old = (exists || hasLegacy) ? try load() : nil
        let fingerprint = Self.fingerprint(document: document, key: key)
        let previous = Set((old?.previous ?? []) + (old.map { [$0.active] } ?? [])).subtracting([fingerprint]).sorted()
        let record = Record(format: "mop-vault-trust-v1", active: fingerprint, previous: previous, cloudBinding: cloudBinding)
        let bytes = try VaultCoding.encode(record)
        guard bytes.count <= 64 * 1024 else { throw MopError.vaultUntrusted }
        try SafeFile.write(bytes, to: file, replace: exists)
    }
}
