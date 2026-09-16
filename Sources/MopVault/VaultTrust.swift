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
    }

    private let directory: URL
    private let file: URL

    public init(vault: URL, directory: URL) {
        self.directory = directory
        let path = vault.standardizedFileURL.resolvingSymlinksInPath().path
        self.file = directory.appendingPathComponent(VaultCoding.digest(Data(path.utf8)) + ".json")
    }

    public static func fingerprint(document: VaultDocument, key: SymmetricKey) -> String {
        var bytes = Data("mop-vault-trust-v1:\(document.header.vaultID.uuidString):".utf8)
        key.withUnsafeBytes { bytes.append(contentsOf: $0) }
        return VaultCoding.digest(bytes)
    }

    private func load() throws -> Record {
        guard FileManager.default.fileExists(atPath: file.path) else { throw MopError.vaultUntrusted }
        try SafeFile.privateDirectory(directory)
        do {
            let record = try JSONDecoder().decode(Record.self, from: SafeFile.read(file, privateFile: true, limit: 64 * 1024))
            guard record.format == "mop-vault-trust-v1",
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
    }

    /// Call only after creating a vault, a verified key rotation, or explicit
    /// comparison with independently trusted fingerprint/revision evidence.
    func pin(document: VaultDocument, key: SymmetricKey) throws {
        try SafeFile.privateDirectory(directory)
        let exists = FileManager.default.fileExists(atPath: file.path)
        let old = exists ? try load() : nil
        let fingerprint = Self.fingerprint(document: document, key: key)
        let previous = Set((old?.previous ?? []) + (old.map { [$0.active] } ?? [])).subtracting([fingerprint]).sorted()
        let record = Record(format: "mop-vault-trust-v1", active: fingerprint, previous: previous)
        let bytes = try VaultCoding.encode(record)
        guard bytes.count <= 64 * 1024 else { throw MopError.vaultUntrusted }
        try SafeFile.write(bytes, to: file, replace: exists)
    }
}
