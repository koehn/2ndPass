import CryptoKit
import Foundation
import MopCore

/// A decrypted snapshot lives only for this command. Commits compare the exact
/// encrypted snapshot read earlier, under filesystem coordination.
public final class FileSecretStore: SecretStore {
    private let disk: VaultDisk
    private var snapshot: Data
    private var document: VaultDocument
    private var key: SymmetricKey?
    private var secrets: [String: String]
    private var onClose: (() -> Void)?

    public init(disk: VaultDisk, snapshot: Data, opener: any VaultKeyOpener, onClose: @escaping () -> Void = {}) throws {
        let document = try VaultDocument.decode(snapshot)
        guard let slot = document.header.recipients.first(where: { $0.publicKey == opener.publicKey }) else { throw MopError.deviceNotEnrolled }
        let key = try opener.unwrap(slot, vaultID: document.header.vaultID)
        try disk.trust.verify(document: document, key: key)
        let secrets = try document.decrypt(key: key)
        self.disk = disk
        self.snapshot = snapshot
        self.document = document
        self.key = key
        self.secrets = secrets
        self.onClose = onClose
    }

    public static func open(file: URL, stateDirectory: URL) throws -> FileSecretStore {
        let disk = VaultDisk(url: file, trustDirectory: stateDirectory.appendingPathComponent("trust"))
        let snapshot = try disk.read()
        _ = try VaultDocument.decode(snapshot)
        let device = try LocalDevice.open(directory: stateDirectory)
        do { return try FileSecretStore(disk: disk, snapshot: snapshot, opener: device, onClose: { device.close() }) }
        catch { device.close(); throw error }
    }

    private func requireKey() throws -> SymmetricKey {
        guard let key else { throw MopError.authentication }
        return key
    }

    public func read(_ reference: SecretReference) throws -> String {
        _ = try requireKey()
        guard let value = secrets[reference.description] else { throw MopError.notFound }
        return value
    }

    public func write(_ reference: SecretReference, value: String, replace: Bool) throws {
        _ = try requireKey()
        let exists = secrets[reference.description] != nil
        if exists && !replace { throw MopError.duplicate }
        if !exists && replace { throw MopError.notFound }
        var changed = secrets
        changed[reference.description] = value
        try commit(secrets: changed)
    }

    public func delete(_ reference: SecretReference) throws {
        _ = try requireKey()
        var changed = secrets
        guard changed.removeValue(forKey: reference.description) != nil else { throw MopError.notFound }
        try commit(secrets: changed)
    }

    public func list(vault: String?) throws -> [SecretReference] {
        _ = try requireKey()
        return try secrets.keys.map { try SecretReference($0) }.filter { vault == nil || $0.vault == vault }.sorted()
    }

    public func recipients() throws -> [DeviceRequest] {
        _ = try requireKey()
        return try document.header.recipients.filter { $0.kind == "device" }.map { try DeviceRequest(name: $0.name, publicKey: $0.publicKey) }
    }

    public func enroll(_ request: DeviceRequest, expectedFingerprint: String) throws {
        let key = try requireKey()
        try request.validate()
        guard request.fingerprint == expectedFingerprint else { throw MopError.invalidDevice }
        guard !document.header.recipients.contains(where: { $0.fingerprint == request.fingerprint }) else { throw MopError.duplicate }
        guard document.header.recipients.count < 64 else { throw MopError.invalidVault }
        var header = document.header
        header.recipients.append(try VaultDocument.wrap(key: key, request: request, kind: "device", vaultID: header.vaultID))
        try commit(secrets: secrets, header: header)
    }

    public func revoke(_ fingerprint: String, currentDevice: Data) throws {
        _ = try requireKey()
        guard fingerprint != VaultCoding.digest(currentDevice),
              document.header.recipients.contains(where: { $0.kind == "device" && $0.fingerprint == fingerprint }) else { throw MopError.invalidDevice }
        var header = document.header
        let newKey = SymmetricKey(size: .bits256)
        header.recipients = try header.recipients.filter { $0.fingerprint != fingerprint }.map {
            try VaultDocument.wrap(key: newKey, request: DeviceRequest(name: $0.name, publicKey: $0.publicKey), kind: $0.kind, vaultID: header.vaultID)
        }
        try commit(secrets: secrets, header: header, newKey: newKey)
    }

    private func commit(secrets: [String: String], header: VaultHeader? = nil, newKey: SymmetricKey? = nil) throws {
        let selectedKey = try newKey ?? requireKey()
        var next = header ?? document.header
        guard next.generation < UInt64.max else { throw MopError.invalidVault }
        if try secrets.keys.contains(where: { try SecretReference($0).section != nil }) { next.format = "mop-vault-v2" }
        next.generation += 1
        next.parent = VaultCoding.digest(snapshot)
        next.recipients.sort { $0.fingerprint < $1.fingerprint }
        let document = try VaultDocument.seal(header: next, secrets: secrets, key: selectedKey)
        let bytes = try VaultCoding.encode(document)
        try disk.commit(expected: snapshot, replacement: bytes)
        if newKey != nil { try disk.trust.pin(document: document, key: selectedKey) }
        self.document = document
        self.snapshot = bytes
        self.secrets = secrets
        self.key = selectedKey
    }

    @discardableResult
    public static func initialize(disk: VaultDisk, device: DeviceRequest, recovery: RecoveryKey) throws -> String {
        let id = UUID()
        let key = SymmetricKey(size: .bits256)
        let recipients = try [
            VaultDocument.wrap(key: key, request: device, kind: "device", vaultID: id),
            VaultDocument.wrap(key: key, request: recovery.request, kind: "recovery", vaultID: id),
        ].sorted { $0.fingerprint < $1.fingerprint }
        let header = VaultHeader(format: "mop-vault-v2", vaultID: id, generation: 1, parent: nil, recipients: recipients)
        let document = try VaultDocument.seal(header: header, secrets: [:], key: key)
        try disk.create(VaultCoding.encode(document))
        try disk.trust.pin(document: document, key: key)
        return VaultTrust.fingerprint(document: document, key: key)
    }

    public static func resolve(disk: VaultDisk, revision: String, opener: any VaultKeyOpener) throws {
        let selected = try disk.revision(revision)
        try disk.resolve(selected: selected) { selected, current in
            var document = try VaultDocument.decode(selected)
            let currentDocument = try VaultDocument.decode(current)
            guard document.header.vaultID == currentDocument.header.vaultID,
                  let selectedSlot = document.header.recipients.first(where: { $0.publicKey == opener.publicKey }),
                  let currentSlot = currentDocument.header.recipients.first(where: { $0.publicKey == opener.publicKey && $0.kind == "device" }) else {
                throw MopError.deviceNotEnrolled
            }
            // A revoked device cannot authorize restoring itself from an old snapshot.
            let currentKey = try opener.unwrap(currentSlot, vaultID: currentDocument.header.vaultID)
            try disk.trust.verify(document: currentDocument, key: currentKey)
            _ = try currentDocument.decrypt(key: currentKey)
            let selectedKey = try opener.unwrap(selectedSlot, vaultID: document.header.vaultID)
            try disk.trust.verify(document: document, key: selectedKey, historical: true)
            let secrets = try document.decrypt(key: selectedKey)
            guard max(document.header.generation, currentDocument.header.generation) < UInt64.max else { throw MopError.invalidVault }
            if currentDocument.header.format == "mop-vault-v2" { document.header.format = "mop-vault-v2" }
            document.header.generation = max(document.header.generation, currentDocument.header.generation) + 1
            document.header.parent = VaultCoding.digest(current)
            // Keep the current recipient authorization and key, restoring only selected contents.
            document.header.recipients = currentDocument.header.recipients
            return try VaultCoding.encode(VaultDocument.seal(header: document.header, secrets: secrets, key: currentKey))
        }
    }

    public func close() {
        key = nil
        secrets.removeAll(keepingCapacity: false)
        onClose?()
        onClose = nil
    }

    public func fingerprint() throws -> String {
        VaultTrust.fingerprint(document: document, key: try requireKey())
    }

    /// Bootstrap trust only with evidence supplied through an independent trusted
    /// channel. Never derive that evidence from the currently untrusted file.
    public static func establishTrust(disk: VaultDisk, opener: any VaultKeyOpener,
                                      fingerprint: String? = nil, revision: String? = nil) throws {
        guard (fingerprint == nil) != (revision == nil),
              VaultTrust.validFingerprint(fingerprint ?? revision ?? "") else { throw MopError.vaultUntrusted }
        let bytes = try disk.read()
        if let revision { guard VaultCoding.digest(bytes) == revision else { throw MopError.vaultUntrusted } }
        let document = try VaultDocument.decode(bytes)
        guard let slot = document.header.recipients.first(where: { $0.publicKey == opener.publicKey }) else { throw MopError.deviceNotEnrolled }
        let key = try opener.unwrap(slot, vaultID: document.header.vaultID)
        if let fingerprint {
            guard VaultTrust.fingerprint(document: document, key: key) == fingerprint else { throw MopError.vaultUntrusted }
        }
        _ = try document.decrypt(key: key)
        try disk.trust.pin(document: document, key: key)
    }

    deinit { close() }
}
