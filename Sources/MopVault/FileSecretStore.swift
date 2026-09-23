import CryptoKit
import Foundation
import MopCore

/// Storage-independent name for new integrations; FileSecretStore remains the legacy adapter API.
public typealias VaultSession = FileSecretStore

/// Only the index is decrypted at open. Record keys and values are opened on demand.
/// The legacy disk adapter compares snapshots under filesystem coordination;
/// cloud callers publish the resulting snapshot with their own conditional commit.
public final class FileSecretStore: SecretStore {
    private let trust: VaultTrust
    private let persist: (Data, Data) throws -> Void
    private let pinAfterCommit: Bool
    public private(set) var snapshot: Data
    private var document: VaultDocument
    private var key: SymmetricKey?
    private var index: [String: String]
    private var opener: (any VaultKeyOpener)?
    private var onClose: (() -> Void)?

    public convenience init(disk: VaultDisk, snapshot: Data, opener: any VaultKeyOpener, onClose: @escaping () -> Void = {}) throws {
        try self.init(snapshot: snapshot, trust: disk.trust, opener: opener,
                      persist: { try disk.commit(expected: $0, replacement: $1) }, pinAfterCommit: true, onClose: onClose)
    }

    /// Cryptographic session independent of storage. Cloud commits are published
    /// asynchronously by the caller; trust is advanced only after confirmation.
    public init(snapshot: Data, trust: VaultTrust, opener: any VaultKeyOpener,
                persist: @escaping (Data, Data) throws -> Void = { _, _ in },
                pinAfterCommit: Bool = false, onClose: @escaping () -> Void = {}) throws {
        let document = try VaultDocument.decode(snapshot)
        guard let slot = document.header.recipients.first(where: { $0.publicKey == opener.publicKey }) else { throw MopError.deviceNotEnrolled }
        let key = try opener.unwrap(slot, vaultID: document.header.vaultID)
        try trust.verify(document: document, key: key)
        let index = try document.decryptIndex(key: key)
        self.trust = trust
        self.persist = persist
        self.pinAfterCommit = pinAfterCommit
        self.snapshot = snapshot
        self.document = document
        self.key = key
        self.index = index
        self.opener = opener
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
        guard let id = index[reference.description], let record = document.records[id] else { throw MopError.notFound }
        return try record.read(id: id, vaultID: document.header.vaultID, opener: requireOpener())
    }

    private func requireOpener() throws -> any VaultKeyOpener {
        guard let opener else { throw MopError.authentication }
        return opener
    }

    public func write(_ reference: SecretReference, value: String, replace: Bool) throws {
        _ = try requireKey()
        let exists = index[reference.description] != nil
        if exists && !replace { throw MopError.duplicate }
        if !exists && replace { throw MopError.notFound }
        var index = self.index
        var records = document.records
        if let old = index[reference.description] { records.removeValue(forKey: old) }
        let id = UUID().uuidString
        index[reference.description] = id
        records[id] = try VaultRecord.create(value: value, id: id, header: document.header)
        try commit(index: index, records: records)
    }

    public func delete(_ reference: SecretReference) throws {
        _ = try requireKey()
        var index = self.index
        guard let id = index.removeValue(forKey: reference.description) else { throw MopError.notFound }
        var records = document.records
        records.removeValue(forKey: id)
        try commit(index: index, records: records)
    }

    public func list(vault: String?) throws -> [SecretReference] {
        _ = try requireKey()
        return try index.keys.map { try SecretReference($0) }.filter { vault == nil || $0.vault == vault }.sorted()
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
        let opener = try requireOpener()
        var records = document.records
        for (id, record) in records {
            records[id] = try record.enrolling(request, id: id, vaultID: header.vaultID, opener: opener)
        }
        try commit(index: index, records: records, header: header)
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
        // Rotate every value key: deleting recipient slots alone leaves old keys useful.
        var records: [String: VaultRecord] = [:]
        let opener = try requireOpener()
        for (id, record) in document.records {
            let value = try record.read(id: id, vaultID: header.vaultID, opener: opener)
            records[id] = try VaultRecord.create(value: value, id: id, header: header)
        }
        try commit(index: index, records: records, header: header, newKey: newKey)
    }

    private func commit(index: [String: String], records: [String: VaultRecord], header: VaultHeader? = nil, newKey: SymmetricKey? = nil) throws {
        let selectedKey = try newKey ?? requireKey()
        var next = header ?? document.header
        guard next.generation < UInt64.max else { throw MopError.invalidVault }
        next.generation += 1
        next.parent = VaultCoding.digest(snapshot)
        next.recipients.sort { $0.fingerprint < $1.fingerprint }
        let document = try VaultDocument.seal(header: next, index: index, records: records, key: selectedKey)
        let bytes = try VaultCoding.encode(document)
        try persist(snapshot, bytes)
        if newKey != nil && pinAfterCommit { try trust.pin(document: document, key: selectedKey) }
        self.document = document
        self.snapshot = bytes
        self.index = index
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
        let header = VaultHeader(format: "mop-vault-v3", vaultID: id, generation: 1, parent: nil, recipients: recipients)
        let document = try VaultDocument.seal(header: header, index: [:], records: [:], key: key)
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
            _ = try currentDocument.decryptIndex(key: currentKey)
            let selectedKey = try opener.unwrap(selectedSlot, vaultID: document.header.vaultID)
            try disk.trust.verify(document: document, key: selectedKey, historical: true)
            let index = try document.decryptIndex(key: selectedKey)
            guard max(document.header.generation, currentDocument.header.generation) < UInt64.max else { throw MopError.invalidVault }
            document.header.generation = max(document.header.generation, currentDocument.header.generation) + 1
            document.header.parent = VaultCoding.digest(current)
            // Keep the current recipient authorization and key, restoring only selected contents.
            document.header.recipients = currentDocument.header.recipients
            var records: [String: VaultRecord] = [:]
            for (id, record) in document.records {
                let value = try record.read(id: id, vaultID: document.header.vaultID, opener: opener)
                records[id] = try VaultRecord.create(value: value, id: id, header: document.header)
            }
            return try VaultCoding.encode(VaultDocument.seal(header: document.header, index: index, records: records, key: currentKey))
        }
    }

    public func close() {
        key = nil
        index.removeAll(keepingCapacity: false)
        opener = nil
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
        _ = try document.decryptIndex(key: key)
        try disk.trust.pin(document: document, key: key)
    }

    public func pinCommittedKey() throws {
        try trust.pin(document: document, key: requireKey())
    }

    public static func createSnapshot(id: UUID = UUID(), device: DeviceRequest, recovery: RecoveryKey) throws -> Data {
        let key = SymmetricKey(size: .bits256)
        let recipients = try [
            VaultDocument.wrap(key: key, request: device, kind: "device", vaultID: id),
            VaultDocument.wrap(key: key, request: recovery.request, kind: "recovery", vaultID: id)
        ].sorted { $0.fingerprint < $1.fingerprint }
        let header = VaultHeader(format: "mop-vault-v3", vaultID: id, generation: 1, parent: nil, recipients: recipients)
        return try VaultCoding.encode(VaultDocument.seal(header: header, index: [:], records: [:], key: key))
    }

    public static func trustSnapshot(_ bytes: Data, trust: VaultTrust, opener: any VaultKeyOpener,
                                     fingerprint: String? = nil, revision: String? = nil) throws {
        guard (fingerprint == nil) != (revision == nil),
              VaultTrust.validFingerprint(fingerprint ?? revision ?? "") else { throw MopError.vaultUntrusted }
        if let revision { guard VaultCoding.digest(bytes) == revision else { throw MopError.vaultUntrusted } }
        let doc = try VaultDocument.decode(bytes)
        guard let slot = doc.header.recipients.first(where: { $0.publicKey == opener.publicKey }) else { throw MopError.deviceNotEnrolled }
        let key = try opener.unwrap(slot, vaultID: doc.header.vaultID)
        if let fingerprint { guard VaultTrust.fingerprint(document: doc, key: key) == fingerprint else { throw MopError.vaultUntrusted } }
        _ = try doc.decryptIndex(key: key)
        try trust.pin(document: doc, key: key)
    }

    public func restore(_ bytes: Data) throws {
        let selected = try VaultDocument.decode(bytes)
        guard selected.header.vaultID == document.header.vaultID,
              let slot = selected.header.recipients.first(where: { $0.publicKey == opener?.publicKey }),
              document.header.recipients.contains(where: { $0.publicKey == opener?.publicKey && $0.kind == "device" }) else { throw MopError.deviceNotEnrolled }
        let opener = try requireOpener()
        let oldKey = try opener.unwrap(slot, vaultID: document.header.vaultID)
        try trust.verify(document: selected, key: oldKey, historical: true)
        let index = try selected.decryptIndex(key: oldKey)
        var records: [String: VaultRecord] = [:]
        for (id, record) in selected.records {
            records[id] = try VaultRecord.create(value: record.read(id: id, vaultID: document.header.vaultID, opener: opener), id: id, header: document.header)
        }
        try commit(index: index, records: records)
    }

    deinit { close() }
}
