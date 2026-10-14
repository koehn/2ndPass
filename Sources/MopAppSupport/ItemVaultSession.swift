import Foundation
#if os(iOS)
import UIKit
#elseif os(macOS)
import SystemConfiguration
#endif
import Synchronization
import MopCore
import MopAuth
import MopSync
import MopVaultNext

public struct ItemVaultBinding: Codable, Equatable, Sendable {
    public let account: String
    public let database: String
    public let zoneOwner: String
    public let vaultID: UUID
    public init(account: String, database: String, zoneOwner: String, vaultID: UUID) {
        self.account = account; self.database = database; self.zoneOwner = zoneOwner; self.vaultID = vaultID
    }
    public func item(_ id: UUID) -> ItemScope {
        ItemScope(account: account, vaultID: vaultID, itemID: id, database: database, zoneOwner: zoneOwner)
    }
    fileprivate func contains(_ scope: ItemScope) -> Bool {
        scope.account == account && scope.database == database && scope.zoneOwner == zoneOwner && scope.vaultID == vaultID
    }
}

public struct ItemVaultCatalogEntry: Codable, Sendable {
    public let itemID: UUID
    public let versionID: UUID
    public let catalog: ItemEnvelopeCatalog
}

public struct ItemVaultDisplayEntry: Codable, Sendable {
    public let entry: ItemVaultCatalogEntry
    public let item: VaultItem
}

public enum ItemVaultConflictSide: String, Hashable, Sendable { case local, remote }

public struct ItemVaultConflictPreview: Sendable {
    public let conflict: EncryptedItemConflict
    public let local: ItemEnvelopeCatalog
    public let remote: ItemEnvelopeCatalog
    public var localAuthorName: String? = nil
    public var remoteAuthorName: String? = nil
    public var localDeviceName: String { local.editOrigin?.deviceName ?? localAuthorName ?? "Device name unavailable (local version)" }
    public var remoteDeviceName: String { remote.editOrigin?.deviceName ?? remoteAuthorName ?? "Device name unavailable (cloud version)" }
    public var localUpdatedAt: Date? { local.editOrigin?.updatedAt ?? local.item.metadata?.updatedAt }
    public var remoteUpdatedAt: Date? { remote.editOrigin?.updatedAt ?? remote.item.metadata?.updatedAt }
}

public struct ItemVaultDisplayBatch: Sendable {
    public let rows: [ItemVaultDisplayEntry]
    public let waiting: [UUID: UUID]
}

public enum ItemVaultSessionFailure: Error, Equatable, Sendable {
    case invalidBinding
    case staleMembershipState
    case invalidEnvelopeBinding
    case missingVaultMetadata
    case unsupportedTombstone
    case pendingAdmission
}

/// A scoped authorized view of local ciphertext. The supplied history must be
/// rooted in an independently obtained enrollment pin, not a cloud-provided pin.
/// Transfer exclusive use of the device provider to this session. Every device
/// operation and durable local commit is serialized against synchronous lock().
///
/// History is immutable for this session: membership observers must stop the old
/// adapter, invalidate this authority, and replace it before accepting subsequent
/// authority. Ordinary lock closes device keys but public-key ingress verification
/// remains available for encrypted background downloads. Sending/receiving only
/// accepts the current membership state; historical cached records remain readable
/// by currently authorized devices. New-client historical rollover is not provided
/// here. This facade does not perform discovery, enrollment, or cloud publication.
public final class ItemVaultSession: @unchecked Sendable {
    public static let metadataRecordID = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
    public let binding: ItemVaultBinding
    private let repository: EncryptedItemRepository
    private let history: TrustedMembershipHistory
    private let currentDigest: String
    private let identity: DevicePublicKey
    private let permit: ItemVaultPermit
    private let authorityValid = ItemVaultAuthority()
    let contentSession: GrantBackedContentSession?

    public convenience init(repository: EncryptedItemRepository, binding: ItemVaultBinding,
                            history: TrustedMembershipHistory, device: any DeviceOperations) throws {
        try self.init(repository: repository, binding: binding, history: history, permit: ItemVaultPermit(device: device))
    }

    init(repository: EncryptedItemRepository, binding: ItemVaultBinding,
         history: TrustedMembershipHistory, permit: ItemVaultPermit) throws {
        let identity = try permit.withDevice { $0.identity }
        guard !binding.account.isEmpty, ["private", "shared"].contains(binding.database),
              !binding.zoneOwner.isEmpty, history.vault == binding.vaultID else { throw ItemVaultSessionFailure.invalidBinding }
        guard history.current.membership.role(of: identity) != nil else { throw MopError.notVaultMember }
        self.repository = repository; self.binding = binding; self.history = history
        currentDigest = try history.current.digest()
        self.identity = identity
        self.permit = permit
        contentSession = repository.layout == .contentPreview3 ? try GrantBackedContentSession(repository: repository, binding: binding, history: history, permit: permit) : nil
    }

    private let displayContinuity = Mutex(UUID())
    var displayContinuityID: UUID { displayContinuity.withLock { $0 } }

    /// Display-only continuity across an authenticated successor. Old keys and
    /// readers are still invalidated; this does not authorize reads or writes.
    func inheritDisplayContinuity(from previous: ItemVaultSession) {
        guard isUnlocked, previous.isUnlocked, binding == previous.binding, identity == previous.identity,
              previous.isAuthorized(by: history), history.count >= previous.history.count,
              Array(history.orderedStates.prefix(previous.history.count)) == previous.history.orderedStates,
              history.orderedStates.dropFirst(previous.history.count).allSatisfy({ $0.membership.role(of: identity) == .owner }),
              (try? history.verifyAccountPath(from: previous.currentDigest, allowingDeviceRemoval: true)) != nil else { return }
        let identifier = previous.displayContinuityID
        displayContinuity.withLock { $0 = identifier }
    }

    public func lock() { permit.invalidate() }
    public var isUnlocked: Bool { permit.isValid }
    /// Account changes, membership replacement, and verified removal retire the
    /// public verifier as well as the device session. Stop the old adapter first.
    public func invalidate() {
        authorityValid.withLock { valid in valid = false; permit.invalidate() }
    }
    deinit { permit.invalidate() }

    var memberID: UUID { identity.member }
    func isAuthorized(by history: TrustedMembershipHistory) -> Bool {
        history.vault == binding.vaultID && history.current.membership.role(of: identity) == .owner
    }
    public var currentDeviceID: UUID { get throws { try permit.check(); return identity.device } }
    public var enrolledDevices: [DevicePublicKey] { get throws { try permit.check(); return history.current.membership.devices } }


    /// Public-key control validation continues while keys are locked, but stops
    /// when account or membership authority is explicitly retired.
    func validateMembershipAuthority(digest: String) throws {
        try authorityValid.withLock { valid in
            guard valid else { throw CloudSyncAdapterError.operationInterrupted }
            guard currentDigest == digest, history.current.membership.role(of: identity) == .owner else {
                throw CloudSyncAdapterError.untrustedRecord
            }
        }
    }

    /// Binds every untrusted transport field to signed ciphertext, including the
    /// account/database/owner namespace that is intentionally absent on the wire.
    public func validate(_ version: EncryptedItemVersion, direction: CloudRecordDirection) throws {
        try authorityValid.withLock { valid in
            guard valid else { throw MopError.vaultUntrusted }
            switch direction {
            case .receiving:
                try validateCurrentState(version)
            case .cached:
                if version.healthItemID != nil { _ = try healthEnvelope(version) }
                else if version.scope.itemID == Self.metadataRecordID { _ = try metadata(version) }
                else { _ = try envelope(version) }
            case .sending:
                try permit.withWritePermission {
                    try validateCurrentState(version)
                    let role = history.current.membership.role(of: identity)
                    guard role == .owner || role == .editor else { throw MopError.cloudPermission }
                }
            }
        }
    }

    private func validateCurrentState(_ version: EncryptedItemVersion) throws {
        try validateScope(version)
        if version.healthItemID != nil {
            let value = try healthEnvelope(version)
            guard value.header.membership == currentDigest else { throw ItemVaultSessionFailure.staleMembershipState }
        } else if version.scope.itemID == Self.metadataRecordID {
            let value = try metadata(version)
            guard value.header.membership == currentDigest else { throw ItemVaultSessionFailure.staleMembershipState }
        } else {
            let value = try envelope(version)
            guard value.header.membership == currentDigest else { throw ItemVaultSessionFailure.staleMembershipState }
        }
    }

    public func initialDownloadExpectedCount() async throws -> Int? {
        try permit.check()
        let count = try await repository.initialDownloadExpectedCount(scope: VaultScope(account: binding.account, vaultID: binding.vaultID, database: binding.database, zoneOwner: binding.zoneOwner))
        try permit.check()
        return count
    }

    private func displayCacheContext() throws -> Data {
        // Root/device/scope binding survives ordinary unlock and additive members;
        // current membership authorization is still checked by session creation.
        try setupEncode(["2ndpass-local-display-1", binding.account, binding.database,
            binding.zoneOwner, binding.vaultID.uuidString, identity.fingerprint,
            try history.orderedStates[0].digest()])
    }
    private func displayCacheEnvelope() async throws -> Data {
        try permit.check()
        let context = try displayCacheContext()
        let stored = try await repository.displayCatalogKey(scope: nameIndexScope)
        if let stored {
            do {
                try permit.withDisplayKey(envelope: stored, context: context) { _ in () }
                return stored
            } catch {
                try permit.check()
                if Authentication.requiresRenewal(error) || error as? MopError == .authentication { throw error }
                // This derived cache is disposable; authenticated source items
                // remain necessary to rebuild after damage or device-key changes.
            }
        }
        let candidate = try permit.createDisplayKey(context: context)
        let selected = try await repository.reserveDisplayCatalogKey(scope: nameIndexScope,
            candidate: candidate, replacing: stored, authorization: permit)
        try permit.withDisplayKey(envelope: selected, context: context) { _ in () }
        return selected
    }

    /// Bulk symmetric decryption only; no per-item hardware operations or network.
    /// Exact source versions are reconciled before these rows enter the UI.
    func cachedDisplayRows(expectedVersions: [UUID: UUID]) async throws -> [ItemVaultDisplayEntry] {
        try permit.check()
        guard let envelope = try await repository.displayCatalogKey(scope: nameIndexScope) else { return [] }
        let context = try displayCacheContext()
        do { try permit.withDisplayKey(envelope: envelope, context: context) { _ in () } }
        catch {
            try permit.check()
            if Authentication.requiresRenewal(error) || error as? MopError == .authentication { throw error }
            // Creating a replacement key belongs to idle cache preparation, not unlock.
            return []
        }
        let rows = try await repository.displayCatalogRows(scope: nameIndexScope)
        return try await background { [self] in
            var result: [ItemVaultDisplayEntry] = []
            for row in rows where expectedVersions[row.itemID] == row.versionID {
                try Task.checkCancellation(); try permit.check()
                let value: ItemVaultDisplayEntry? = try permit.withDisplayKey(envelope: envelope, context: context) { key in
                    guard key.id == row.keyID else { return nil }
                    // A corrupt row costs one item rebuild, never a whole vault.
                    guard var bytes = try? key.open(row.ciphertext, item: row.itemID, version: row.versionID) else { return nil }
                    defer { SecretBytes.wipe(&bytes) }
                    guard let value = try? JSONDecoder().decode(ItemVaultDisplayEntry.self, from: bytes),
                          value.entry.itemID == row.itemID, value.entry.versionID == row.versionID,
                          value.item.fields.filter({ $0.type.concealed }).allSatisfy({ $0.value == nil }) else { return nil }
                    return value
                }
                if let value { result.append(value) }
            }
            let current = try await revisionIndex()
            try permit.check()
            return result.filter { current[$0.entry.itemID] == $0.entry.versionID }
        }
    }

    func cacheDisplayRows(_ rows: [ItemVaultDisplayEntry]) async throws {
        guard !rows.isEmpty else { return }
        let envelope = try await displayCacheEnvelope(), context = try displayCacheContext()
        let encrypted = try await background { [self] in
            try rows.map { row in
                try Task.checkCancellation()
                guard row.item.fields.filter({ $0.type.concealed }).allSatisfy({ $0.value == nil }) else { throw MopError.invalidVault }
                var bytes = try setupEncode(row)
                defer { SecretBytes.wipe(&bytes) }
                return try permit.withDisplayKey(envelope: envelope, context: context) { key in
                    EncryptedDisplayCatalogRow(itemID: row.entry.itemID, versionID: row.entry.versionID, keyID: key.id,
                        ciphertext: try key.seal(bytes, item: row.entry.itemID, version: row.entry.versionID))
                }
            }
        }
        try await repository.saveDisplayCatalogRows(scope: nameIndexScope, rows: encrypted,
            keyEnvelope: envelope, authorization: permit)
    }

    public func revisionIndex() async throws -> [UUID: UUID] {
        try permit.check()
        let index = try await repository.itemRevisionIndex(account: binding.account, vaultID: binding.vaultID,
            database: binding.database, zoneOwner: binding.zoneOwner)
        try permit.check()
        return index
    }

    public func catalog() async throws -> [ItemVaultCatalogEntry] {
        try permit.check()
        let versions = try await repository.items(account: binding.account, vaultID: binding.vaultID,
            database: binding.database, zoneOwner: binding.zoneOwner)
        return try await background { [self] in
            var result: [ItemVaultCatalogEntry] = []
            for version in versions where version.scope.itemID != Self.metadataRecordID && version.healthItemID == nil {
                try Task.checkCancellation()
                if let contentSession { result.append(try await contentSession.catalog(itemID: version.scope.itemID)) }
                else { result.append(try catalogEntry(version)) }
            }
            try permit.check()
            return result
        }
    }

    public func catalog(itemID: UUID) async throws -> ItemVaultCatalogEntry {
        if let contentSession { return try await contentSession.catalog(itemID: itemID) }
        try permit.check()
        guard itemID != Self.metadataRecordID else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        guard let version = try await repository.item(binding.item(itemID)) else { throw MopError.notFound }
        return try await background { [self] in try catalogEntry(version) }
    }

    /// Read only the chosen item's metadata and visible fields; no revision-index
    /// scan, display-cache hydration, or background catalog preparation.
    public func displayItem(itemID: UUID) async throws -> ItemVaultDisplayEntry {
        if let contentSession { return try await contentSession.displayItem(itemID: itemID) }
        try permit.check()
        guard itemID != Self.metadataRecordID else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        guard let version = try await repository.item(binding.item(itemID)) else { throw MopError.notFound }
        return try await background(priority: .userInitiated) { [self] in
            try permit.check()
            let value = try envelope(version)
            let state = try readableState(value.header.membership)
            let projection = try permit.withDevice { device in
                try value.displayCatalog(device: device, membership: state.membership, membershipStateDigest: value.header.membership)
            }
            return ItemVaultDisplayEntry(entry: ItemVaultCatalogEntry(itemID: itemID, versionID: version.versionID,
                catalog: projection.catalog), item: projection.item)
        }
    }

    private struct NameIndexContext: Encodable {
        let binding: ItemVaultBinding
        let membership: String
    }
    private var nameIndexScope: VaultScope {
        VaultScope(account: binding.account, vaultID: binding.vaultID, database: binding.database, zoneOwner: binding.zoneOwner)
    }
    private func nameIndexContext() throws -> Data {
        try setupEncode(NameIndexContext(binding: binding, membership: currentDigest))
    }

    /// Resolve names without decrypting visible values or every item on a fresh
    /// process. The disposable cache is trusted only after device authentication;
    /// changed and removed items are reconciled against the full local inventory.
    public func catalog(named name: String) async throws -> ItemVaultCatalogEntry {
        for _ in 0..<3 {
            try permit.check()
            let versions = try await revisionIndex()
            var index: LocalNameIndex?
            if let bytes = try await repository.localNameIndex(scope: nameIndexScope) {
                index = try? await background { [self] in
                    try permit.withDevice { try LocalNameIndex.open(bytes, context: nameIndexContext(), device: $0) }
                }
                try permit.check()
            }
            let itemVersions = versions.filter { $0.key != Self.metadataRecordID }
            let prior = index?.entries ?? [:]
            var entries = prior.filter { itemVersions[$0.key] == $0.value.version }
            for (id, version) in itemVersions where entries[id] == nil {
                let entry = try await catalog(itemID: id)
                guard entry.versionID == version else { continue }
                entries[id] = LocalNameIndex.Entry(version: version, name: entry.catalog.item.name,
                    deleted: entry.catalog.item.deletion != nil)
            }
            guard entries.count == itemVersions.count, try await revisionIndex() == versions else { continue }
            if index == nil || prior.count != entries.count || prior.contains(where: { entries[$0.key]?.version != $0.value.version }) {
                do { try await persistNameIndex(LocalNameIndex(entries: entries), versions: versions) }
                catch ItemRepositoryError.staleLocalVersion { continue }
                catch {
                    // This is disposable acceleration, not the item transaction.
                    // An unavailable or oversized cache must not hide valid data.
                    try permit.check()
                    try Task.checkCancellation()
                }
            }
            let matches = entries.filter { $0.value.name == name && !$0.value.deleted }
            guard matches.count == 1, let match = matches.first else {
                // Duplicate/not-found decisions require a complete current index.
                guard try await revisionIndex() == versions else { continue }
                if matches.isEmpty { throw MopError.notFound }
                throw MopError.duplicate
            }
            let target = try await catalog(itemID: match.key)
            guard target.versionID == match.value.version, target.catalog.item.name == name,
                  target.catalog.item.deletion == nil, try await revisionIndex() == versions else { continue }
            return target
        }
        throw ItemRepositoryError.staleLocalVersion
    }

    /// Called only with metadata already authenticated by this session's catalog
    /// projection. A partial projection must never seed a complete lookup index.
    func seedNameIndex(_ entries: [ItemVaultCatalogEntry], versions: [UUID: UUID]) async throws {
        let expected = versions.filter { $0.key != Self.metadataRecordID }
        guard Dictionary(uniqueKeysWithValues: entries.map { ($0.itemID, $0.versionID) }) == expected else {
            throw ItemRepositoryError.staleLocalVersion
        }
        let index = LocalNameIndex(entries: Dictionary(uniqueKeysWithValues: entries.map {
            ($0.itemID, LocalNameIndex.Entry(version: $0.versionID, name: $0.catalog.item.name, deleted: $0.catalog.item.deletion != nil))
        }))
        try await persistNameIndex(index, versions: versions)
    }
    private func persistNameIndex(_ index: LocalNameIndex, versions: [UUID: UUID]) async throws {
        let bytes = try await background { [self] in
            try permit.withDevice { try index.sealed(context: nameIndexContext(), device: $0) }
        }
        try await repository.saveLocalNameIndex(scope: nameIndexScope, bytes: bytes, expectedVersions: versions, authorization: permit)
        try permit.check()
    }

    private func readableState(_ digest: String) throws -> MembershipEnvelope {
        let state = try history.state(forDigest: digest)
        guard state.membership.role(of: identity) != nil else {
            try history.verifyAccountPath(from: digest)
            throw ItemVaultSessionFailure.pendingAdmission
        }
        return state
    }

    private func catalogEntry(_ version: EncryptedItemVersion) throws -> ItemVaultCatalogEntry {
        try permit.check()
        let value = try envelope(version)
        let state = try readableState(value.header.membership)
        return try permit.withDevice { device in
            try ItemVaultCatalogEntry(itemID: version.scope.itemID, versionID: version.versionID,
                catalog: value.catalog(device: device, membership: state.membership, membershipStateDigest: value.header.membership))
        }
    }

    /// A bounded projection for progressive UI loading. The caller supplies a
    /// revision-index snapshot; this is never evidence of a complete vault.
    /// Fetching one row at a time avoids retaining a batch of large attachments.
    public func displayCatalogBatch(expectedVersions: [UUID: UUID]) async throws -> [ItemVaultDisplayEntry] {
        let batch = try await admissionAwareDisplayCatalogBatch(expectedVersions: expectedVersions)
        guard batch.waiting.isEmpty else { throw ItemVaultSessionFailure.pendingAdmission }
        return batch.rows
    }

    public func admissionAwareDisplayCatalogBatch(expectedVersions: [UUID: UUID]) async throws -> ItemVaultDisplayBatch {
        guard expectedVersions.count <= 64, expectedVersions[Self.metadataRecordID] == nil else {
            throw ItemVaultSessionFailure.invalidBinding
        }
        try permit.check()
        return try await background(priority: .utility) { [self] in
            var result: [ItemVaultDisplayEntry] = []
            var waiting: [UUID: UUID] = [:]
            for id in expectedVersions.keys.sorted(by: { $0.uuidString < $1.uuidString }) {
                try Task.checkCancellation()
                try permit.check()
                guard let version = try await repository.item(binding.item(id)),
                      version.versionID == expectedVersions[id] else { throw ItemRepositoryError.staleLocalVersion }
                if let contentSession {
                    do {
                        let row = try await contentSession.displayItem(itemID: id)
                        guard row.entry.versionID == version.versionID else { throw ItemRepositoryError.staleLocalVersion }
                        result.append(row)
                    } catch CloudSyncAdapterError.membershipUnavailable { waiting[id] = version.versionID }
                    await Task.yield()
                    continue
                }
                let value = try envelope(version)
                let state = try history.state(forDigest: value.header.membership)
                if state.membership.role(of: identity) == nil {
                    try history.verifyAccountPath(from: value.header.membership)
                    waiting[id] = version.versionID
                    continue
                }
                let projection = try permit.withDevice { device in
                    try value.displayCatalog(device: device, membership: state.membership,
                        membershipStateDigest: value.header.membership)
                }
                result.append(ItemVaultDisplayEntry(entry: ItemVaultCatalogEntry(itemID: id,
                    versionID: version.versionID, catalog: projection.catalog), item: projection.item))
                // A selected-item reveal can take the device gate before the
                // next background item. Keys are not retained across this yield.
                await Task.yield()
            }
            let current = try await revisionIndex()
            guard expectedVersions.allSatisfy({ current[$0.key] == $0.value }) else {
                throw ItemRepositoryError.staleLocalVersion
            }
            try permit.check()
            return ItemVaultDisplayBatch(rows: result, waiting: waiting)
        }
    }

    public func reveal(itemID: UUID, recordID: String) async throws -> SecretBytes {
        try await revealValue(itemID: itemID, recordID: recordID, expectedVersion: nil)
    }

    public func reveal(itemID: UUID, recordID: String, expectedVersion: UUID) async throws -> SecretBytes {
        try await revealValue(itemID: itemID, recordID: recordID, expectedVersion: expectedVersion)
    }

    private func revealValue(itemID: UUID, recordID: String, expectedVersion: UUID?) async throws -> SecretBytes {
        try permit.check()
        guard itemID != Self.metadataRecordID else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        guard let stored = try await repository.item(binding.item(itemID)) else { throw MopError.notFound }
        if let expectedVersion, stored.versionID != expectedVersion { throw ItemRepositoryError.staleLocalVersion }
        if let contentSession {
            guard UUID(uuidString: recordID)?.uuidString == recordID else { throw MopError.notFound }
            return try await contentSession.open(item: itemID, component: recordID, expected: stored.versionID)
        }
        return try await background(priority: .userInitiated) { [self] in
            try permit.check()
            let value = try envelope(stored)
            let state = try readableState(value.header.membership)
            return try permit.withDevice { device in
                try value.read(record: recordID, device: device, membership: state.membership, membershipStateDigest: value.header.membership)
            }
        }
    }

    /// Explicitly keeps expensive signature checking and hardware operations off
    /// the caller's executor, while forwarding cancellation to the worker.
    private func background<T: Sendable>(priority: TaskPriority? = nil, _ body: @escaping @Sendable () async throws -> T) async throws -> T {
        try Task.checkCancellation()
        let task = Task.detached(priority: priority ?? Task.currentPriority) {
            try Task.checkCancellation()
            let result = try await body()
            try Task.checkCancellation()
            return result
        }
        return try await withTaskCancellationHandler(operation: { try await task.value }, onCancel: { task.cancel() })
    }

    private static func editingDeviceName() async -> String {
        #if os(iOS)
        return await MainActor.run { UIDevice.current.name }
        #else
        // Host.localizedName can perform blocking network name resolution.
        // Save attribution needs only the locally configured computer name.
        return SCDynamicStoreCopyComputerName(nil, nil) as String? ?? "Mac"
        #endif
    }

    public func save(_ item: PortableVaultArchive, expectedBase: UUID?) async throws -> PendingItemMutation {
        if let contentSession {
            return try await contentSession.save(item, expectedBase: expectedBase, editOrigin: ItemEditOrigin(deviceID: identity.device, deviceName: Self.editingDeviceName(), updatedAt: Date()))
        }
        try permit.check()
        try item.validate()
        guard item.items.count == 1, let itemName = item.items.first?.name,
              let itemID = item.itemIDs[itemName].flatMap(UUID.init(uuidString:)),
              itemID != Self.metadataRecordID else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        let previous = try await repository.item(binding.item(itemID))
        let deviceName = await Self.editingDeviceName()
        let version = try permit.withDevice { device in
            let generation = try nextGeneration(previous, expectedBase: expectedBase)
            let envelope = try ItemEnvelope.seal(item, vault: binding.vaultID, generation: generation, base: expectedBase,
                membership: history.current.membership, membershipStateDigest: currentDigest, signer: device,
                editOrigin: ItemEditOrigin(deviceID: device.identity.device, deviceName: deviceName, updatedAt: Date()))
            guard envelope.header.item != Self.metadataRecordID else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
            return try EncryptedItemVersion(scope: binding.item(envelope.header.item), versionID: envelope.header.version,
                baseVersionID: expectedBase, ciphertext: envelope.encoded(), generation: generation)
        }
        return try await repository.commitLocalMutation(version, authorization: permit)
    }

    /// Applies an explicit metadata/record graph patch without decrypting any
    /// unchanged field, retained history value, or attachment.
    public func edit(itemID: UUID, expectedBase: UUID, catalog: ItemEnvelopeCatalog,
                     changedRecords: [String: SecretBytes] = [:], removedRecords: Set<String> = []) async throws -> PendingItemMutation {
        if let contentSession {
            var catalog = catalog
            catalog.editOrigin = await ItemEditOrigin(deviceID: identity.device, deviceName: Self.editingDeviceName(), updatedAt: Date())
            return try await contentSession.edit(itemID: itemID, expectedBase: expectedBase, catalog: catalog, changedRecords: changedRecords, removedRecords: removedRecords)
        }
        let timing = ItemSaveTiming()
        defer { timing.mark("session edit finished") }
        try permit.check()
        timing.mark("edit permission checked")
        guard itemID != Self.metadataRecordID else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        let stored = try await repository.item(binding.item(itemID))
        timing.mark("stored version loaded")
        let deviceName = await Self.editingDeviceName()
        timing.mark("device name loaded")
        let version = try permit.withDevice { device in
            guard let stored, stored.versionID == expectedBase else { throw ItemRepositoryError.staleLocalVersion }
            let current = try envelope(stored)
            var catalog = catalog
            catalog.editOrigin = ItemEditOrigin(deviceID: device.identity.device, deviceName: deviceName, updatedAt: Date())
            let changed = try current.edit(catalog: catalog, changedRecords: changedRecords, removedRecords: removedRecords,
                membership: history.current.membership, membershipStateDigest: currentDigest, signer: device)
            return try EncryptedItemVersion(scope: stored.scope, versionID: changed.header.version,
                baseVersionID: expectedBase, ciphertext: changed.encoded(), generation: changed.header.generation)
        }
        timing.mark("envelope encrypted and signed")
        return try await repository.commitLocalMutation(version, authorization: permit)
    }

    public func replaceField(itemID: UUID, expectedBase: UUID, path: String, value: SecretBytes,
                             at date: Date = Date()) async throws -> PendingItemMutation {
        if let contentSession {
            let entry = try await contentSession.catalog(itemID: itemID)
            guard entry.versionID == expectedBase else { throw ItemRepositoryError.staleLocalVersion }
            let patch = try entry.catalog.replacingField(path, value: value, itemID: itemID, at: date)
            return try await edit(itemID: itemID, expectedBase: expectedBase, catalog: patch.catalog, changedRecords: patch.changedRecords, removedRecords: patch.removedRecords)
        }
        try permit.check()
        guard itemID != Self.metadataRecordID else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        let stored = try await repository.item(binding.item(itemID))
        let deviceName = await Self.editingDeviceName()
        let version = try permit.withDevice { device in
            guard let stored, stored.versionID == expectedBase else { throw ItemRepositoryError.staleLocalVersion }
            let current = try envelope(stored)
            guard current.header.membership == currentDigest else { throw ItemEnvelopeFailure.rekeyRequired }
            let catalog = try current.catalog(device: device, membership: history.current.membership, membershipStateDigest: currentDigest)
            let patch = try catalog.replacingField(path, value: value, itemID: itemID, at: date)
            var editedCatalog = patch.catalog
            editedCatalog.editOrigin = ItemEditOrigin(deviceID: device.identity.device, deviceName: deviceName, updatedAt: date)
            let changed = try current.edit(catalog: editedCatalog, changedRecords: patch.changedRecords, removedRecords: patch.removedRecords,
                membership: history.current.membership, membershipStateDigest: currentDigest, signer: device)
            return try EncryptedItemVersion(scope: stored.scope, versionID: changed.header.version,
                baseVersionID: expectedBase, ciphertext: changed.encoded(), generation: changed.header.generation)
        }
        return try await repository.commitLocalMutation(version, authorization: permit)
    }

    /// An explicit full rewrite for an authenticated membership transition. This
    /// intentionally decrypts retained contents; ordinary edit() never does.
    public func rekey(itemID: UUID, expectedBase: UUID, name: String) async throws -> PendingItemMutation {
        try permit.check()
        guard itemID != Self.metadataRecordID else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        let stored = try await repository.item(binding.item(itemID))
        let version = try permit.withDevice { device in
            guard let stored, stored.versionID == expectedBase else { throw ItemRepositoryError.staleLocalVersion }
            let current = try envelope(stored)
            let previous = try history.state(forDigest: current.header.membership)
            let changed = try current.rekey(name: name, previousMembership: previous.membership,
                previousMembershipStateDigest: current.header.membership,
                membership: history.current.membership, membershipStateDigest: currentDigest, signer: device)
            return try EncryptedItemVersion(scope: stored.scope, versionID: changed.header.version,
                baseVersionID: expectedBase, ciphertext: changed.encoded(), generation: changed.header.generation)
        }
        return try await repository.commitLocalMutation(version, authorization: permit)
    }

    public func conflictPreviews() async throws -> [ItemVaultConflictPreview] {
        try Task.checkCancellation()
        try permit.check()
        let conflicts = try await (contentSession == nil ? repository.conflicts(account: binding.account) : repository.contentConflicts(account: binding.account))
        var result: [ItemVaultConflictPreview] = []
        for conflict in conflicts where binding.contains(conflict.local.scope) && (contentSession != nil || conflict.local.scope.itemID != Self.metadataRecordID) && conflict.local.healthItemID == nil {
            try Task.checkCancellation()
            result.append(try await conflictPreview(conflict))
        }
        return result
    }

    /// Re-encryption changes ciphertext and version IDs, not retained contents.
    /// Compare all records, history, metadata and edit attribution before treating
    /// a conflict as a duplicate; matching visible fields alone is insufficient.
    public func isDuplicateConflict(_ expected: EncryptedItemConflict) async throws -> Bool {
        if let contentSession { return try await contentSession.isDuplicateConflict(expected) }
        try validateConflictScope(expected)
        let live = try await repository.reviewedConflict(expected)
        return try await background(priority: .utility) { [self] in
            try Task.checkCancellation()
            return try permit.withDevice { device in
                try Task.checkCancellation()
                guard live == expected else { throw ItemRepositoryError.staleConflict }
                let local = try envelope(expected.local), remote = try envelope(expected.remote)
                let left = try history.state(forDigest: local.header.membership)
                let right = try history.state(forDigest: remote.header.membership)
                let a = try local.catalog(device: device, membership: left.membership, membershipStateDigest: local.header.membership)
                let b = try remote.catalog(device: device, membership: right.membership, membershipStateDigest: remote.header.membership)
                guard a == b else { return false }
                return try local.portableArchive(name: "conflict", device: device, membership: left.membership,
                    membershipStateDigest: local.header.membership) == remote.portableArchive(name: "conflict", device: device,
                    membership: right.membership, membershipStateDigest: remote.header.membership)
            }
        }
    }

    /// Field choices include absence on either side, allowing explicit deletion.
    /// Remote records get fresh IDs and are re-encrypted with the local item key.
    public func combinedConflict(_ expected: EncryptedItemConflict, metadata: ItemVaultConflictSide,
                                 fields: [String: ItemVaultConflictSide]) async throws -> ItemEnvelopePatch {
        let preview = try await conflictPreview(expected)
        let paths = Set(preview.local.item.fields.map(\.path)).union(preview.remote.item.fields.map(\.path))
        guard Set(fields.keys) == paths else { throw MopError.invalidVault }
        var catalog = metadata == .local ? preview.local : preview.remote
        catalog.item.fields = []; catalog.references = [:]; catalog.histories = []; catalog.projectedValuePaths = []
        var changed: [String: SecretBytes] = [:]
        let ordered = preview.local.item.fields.map(\.path) + preview.remote.item.fields.map(\.path).filter { path in
            !preview.local.item.fields.contains { $0.path == path }
        }
        for path in ordered {
            let side = fields[path]!
            let source = side == .local ? preview.local : preview.remote
            guard let field = source.item.fields.first(where: { $0.path == path }) else { continue }
            catalog.item.fields.append(field)
            let sourceReference = SecretReference.encode(source.item.name) + "/" + path
            guard let record = source.references[sourceReference] else { throw MopError.invalidVault }
            func copied(_ id: String) async throws -> String {
                if side == .local { return id }
                let fresh = UUID().uuidString
                changed[fresh] = try await revealConflict(expected, side: .remote, recordID: id)
                return fresh
            }
            catalog.references[SecretReference.encode(catalog.item.name) + "/" + path] = try await copied(record)
            if var history = source.histories.first(where: { $0.path == path }) {
                for index in history.entries.indices {
                    let entry = history.entries[index]
                    history.entries[index] = SecretHistoryEntry(id: try await copied(entry.id), replacedAt: entry.replacedAt)
                }
                catalog.histories.append(history)
            }
            if source.projectedValuePaths.contains(path) { catalog.projectedValuePaths.append(path) }
        }
        let old = Set(preview.local.references.values).union(preview.local.histories.flatMap { $0.entries.map(\.id) })
        let retained = Set(catalog.references.values).union(catalog.histories.flatMap { $0.entries.map(\.id) })
        try catalog.validate(itemID: expected.local.scope.itemID, recordIDs: retained)
        return ItemEnvelopePatch(catalog: catalog, changedRecords: changed, removedRecords: old.subtracting(retained))
    }

    public func conflictPreview(_ expected: EncryptedItemConflict) async throws -> ItemVaultConflictPreview {
        if let contentSession { return try await contentSession.conflictPreview(expected) }
        try permit.check()
        try validateConflictScope(expected)
        let live = try await repository.reviewedConflict(expected)
        let deviceName = await Self.editingDeviceName()
        return try await background(priority: .utility) { [self] in
            try Task.checkCancellation()
            return try permit.withDevice { device in
                try Task.checkCancellation()
                guard live == expected else { throw ItemRepositoryError.staleConflict }
                let local = try envelope(expected.local), remote = try envelope(expected.remote)
                let localState = try history.state(forDigest: local.header.membership)
                let remoteState = try history.state(forDigest: remote.header.membership)
                return try ItemVaultConflictPreview(conflict: expected,
                    local: local.catalog(device: device, membership: localState.membership, membershipStateDigest: local.header.membership),
                    remote: remote.catalog(device: device, membership: remoteState.membership, membershipStateDigest: remote.header.membership),
                    localAuthorName: local.header.author == device.identity.fingerprint ? deviceName : nil,
                    remoteAuthorName: remote.header.author == device.identity.fingerprint ? deviceName : nil)
            }
        }
    }

    /// Decrypts only the specifically selected record after rechecking that the
    /// reviewed conflict has not changed. Preview never reveals field values.
    public func revealConflict(_ expected: EncryptedItemConflict, side: ItemVaultConflictSide,
                               recordID: String) async throws -> SecretBytes {
        if let contentSession { return try await contentSession.revealConflict(expected, side: side, recordID: recordID) }
        try permit.check()
        try validateConflictScope(expected)
        let live = try await repository.reviewedConflict(expected)
        return try permit.withDevice { device in
            guard live == expected else { throw ItemRepositoryError.staleConflict }
            let selected: EncryptedItemVersion
            switch side { case .local: selected = expected.local; case .remote: selected = expected.remote }
            let value = try envelope(selected)
            let state = try history.state(forDigest: value.header.membership)
            _ = try value.catalog(device: device, membership: state.membership, membershipStateDigest: value.header.membership)
            return try value.read(record: recordID, device: device, membership: state.membership, membershipStateDigest: value.header.membership)
        }
    }

    private func validateConflictScope(_ expected: EncryptedItemConflict) throws {
        guard expected.local.scope == expected.remote.scope,
              expected.local.scope.itemID != Self.metadataRecordID else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        try validateScope(expected.local)
        try validateScope(expected.remote)
    }

    /// All production conflict choices run through the process that owns the
    /// CKSyncEngine lease, so older queued uploads are quiesced before the CAS.
    public func healthChecks() async throws -> [CachedPasswordCheck] {
        try permit.check()
        let versions = try await repository.localHealthItems(scope: nameIndexScope)
        return try await background(priority: .utility) { [self] in
            var checks: [CachedPasswordCheck] = []
            for version in versions {
                try Task.checkCancellation()
                try permit.check()
                // Invalid disposable evidence is recomputed; authorization is rechecked below.
                if let values = try? permit.withHealth(version, { device in
                    let verified = try verifiedHealthEnvelope(version)
                    _ = try readableState(verified.envelope.header.membership)
                    return try verified.open(device: device)
                }) { checks += values }
            }
            try permit.check()
            return checks.sorted { $0.record < $1.record }
        }
    }

    public func healthConflicts() async throws -> [EncryptedItemConflict] {
        try permit.check()
        return try await repository.conflicts(account: binding.account).filter {
            binding.contains($0.local.scope) && $0.local.healthItemID != nil
        }
    }

    public func saveHealthChecks(_ checks: [CachedPasswordCheck], itemID: UUID, expectedItemVersion: UUID) async throws -> EncryptedItemVersion? {
        try permit.check()
        guard let parent = try await repository.item(binding.item(itemID)), parent.versionID == expectedItemVersion else {
            throw ItemRepositoryError.staleLocalVersion
        }
        let scope = binding.item(ItemHealthEnvelope.recordID(for: itemID))
        var previous = try await repository.localHealthItem(scope)
        if let invalid = previous, (try? healthEnvelope(invalid)) == nil {
            try await repository.discardLocalHealth(scope, expectedVersion: invalid.versionID, authorization: permit)
            previous = nil
        }
        let contentCatalog = try await contentSession?.catalog(itemID: itemID)
        if let contentCatalog, contentCatalog.versionID != expectedItemVersion { throw ItemRepositoryError.staleLocalVersion }
        let version: EncryptedItemVersion? = try permit.withDevice { device in
            let catalog: ItemEnvelopeCatalog
            if let contentCatalog { catalog = contentCatalog.catalog }
            else {
                let item = try envelope(parent)
                let state = try readableState(item.header.membership)
                catalog = try item.catalog(device: device, membership: state.membership, membershipStateDigest: item.header.membership)
            }
            guard Set(checks.map(\.record)).isSubset(of: Set(catalog.references.values)) else { throw MopError.invalidVault }
            var ordered = checks.sorted { $0.record < $1.record }
            if let previous {
                let old = try healthEnvelope(previous)
                let oldState = try readableState(old.header.membership)
                let existing = try old.open(device: device, membership: oldState.membership, membershipStateDigest: old.header.membership)
                // Re-read and merge at the commit boundary as well: another
                // publisher can have added evidence since the service snapshot.
                let live = Set(catalog.item.fields.filter {
                    !catalog.item.isArchived && catalog.item.deletion == nil &&
                    ($0.type == .password || ($0.path == catalog.item.autoFill?.password && [.concealed, .text, .username, .email].contains($0.type)))
                }.compactMap { catalog.references[SecretReference.encode(catalog.item.name) + "/" + $0.path] })
                var byRecord = Dictionary(uniqueKeysWithValues: existing.filter { live.contains($0.record) }.map { ($0.record, $0) })
                for check in ordered {
                    byRecord[check.record] = byRecord[check.record].map { check.retainingNewerResults(from: $0) } ?? check
                }
                ordered = byRecord.values.sorted { $0.record < $1.record }
                if existing == ordered { return nil }
            } else if ordered.isEmpty { return nil }
            let sealed = try ItemHealthEnvelope.seal(ordered, vault: binding.vaultID, item: itemID,
                generation: nextGeneration(previous, expectedBase: previous?.versionID), base: previous?.versionID,
                membership: history.current.membership, membershipStateDigest: currentDigest, signer: device)
            return try EncryptedItemVersion(scope: scope, versionID: sealed.header.version, baseVersionID: sealed.header.base,
                ciphertext: sealed.encoded(), generation: sealed.header.generation, healthItemID: itemID)
        }
        guard let version else { return nil }
        try await repository.saveLocalHealth(version, expectedParent: expectedItemVersion, authorization: permit)
        return version
    }

    private func healthEnvelope(_ version: EncryptedItemVersion) throws -> ItemHealthEnvelope {
        try verifiedHealthEnvelope(version).envelope
    }

    private func verifiedHealthEnvelope(_ version: EncryptedItemVersion) throws -> ItemHealthEnvelope.Verified {
        try validateScope(version)
        guard let parent = version.healthItemID, parent != Self.metadataRecordID,
              version.scope.itemID == ItemHealthEnvelope.recordID(for: parent) else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        let probe = try JSONDecoder().decode(ItemHealthEnvelope.self, from: version.ciphertext)
        let state = try history.state(forDigest: probe.header.membership)
        let verified = try ItemHealthEnvelope.decodeVerified(version.ciphertext, vault: binding.vaultID, item: parent,
            membership: state.membership, membershipStateDigest: probe.header.membership)
        let value = verified.envelope
        guard value.header.version == version.versionID, value.header.base == version.baseVersionID,
              value.header.generation == version.generation else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        return verified
    }

    private func rewrapHealth(_ stored: EncryptedItemVersion, membership: Membership, digest: String,
                              device: any DeviceOperations) throws -> EncryptedItemVersion {
        let previous = try healthEnvelope(stored)
        let state = try history.state(forDigest: previous.header.membership)
        let checks = try previous.open(device: device, membership: state.membership, membershipStateDigest: previous.header.membership)
        let next = try ItemHealthEnvelope.seal(checks, vault: binding.vaultID, item: previous.header.item,
            generation: nextGeneration(stored, expectedBase: stored.versionID), base: stored.versionID,
            membership: membership, membershipStateDigest: digest, signer: device)
        return try EncryptedItemVersion(scope: stored.scope, versionID: next.header.version, baseVersionID: stored.versionID,
            ciphertext: next.encoded(), generation: next.header.generation, healthItemID: stored.healthItemID)
    }

    public func vaultMetadata() async throws -> (versionID: UUID, value: VaultEnvelopeMetadata) {
        if let contentSession { return try await contentSession.vaultMetadata() }
        try permit.check()
        guard let stored = try await repository.item(binding.item(Self.metadataRecordID)) else {
            throw ItemVaultSessionFailure.missingVaultMetadata
        }
        return try permit.withDevice { device in
            let envelope = try metadata(stored)
            let state = try history.state(forDigest: envelope.header.membership)
            return (stored.versionID, try envelope.open(device: device, membership: state.membership,
                membershipStateDigest: envelope.header.membership))
        }
    }

    public func saveMetadata(_ settings: VaultEnvelopeMetadata, expectedBase: UUID?) async throws -> PendingItemMutation {
        if let contentSession { return try await contentSession.saveMetadata(settings, expectedBase: expectedBase) }
        try permit.check()
        let previous = try await repository.item(binding.item(Self.metadataRecordID))
        let version = try permit.withDevice { device in
            guard history.current.membership.role(of: device.identity) == .owner else { throw MopError.cloudPermission }
            let generation = try nextGeneration(previous, expectedBase: expectedBase)
            let envelope = try VaultMetadataEnvelope.seal(settings, vault: binding.vaultID, generation: generation, base: expectedBase,
                membership: history.current.membership, membershipStateDigest: currentDigest, signer: device)
            return try EncryptedItemVersion(scope: binding.item(Self.metadataRecordID), versionID: envelope.header.version,
                baseVersionID: expectedBase, ciphertext: envelope.encoded(), generation: generation)
        }
        return try await repository.commitLocalMutation(version, authorization: permit)
    }

    /// Exports the local working snapshot, including durable pending edits. It does
    /// not prove that initial cloud inventory fetching has completed. Production
    /// backup UI must establish that separately before claiming completeness.
    /// Missing settings/attachments and unresolved conflicts fail the operation.
    public func exportPortableLocalSnapshot() async throws -> PortableVaultArchive {
        if let contentSession { return try await contentSession.exportPortableLocalSnapshot() }
        try permit.check()
        let versions = try await repository.itemsForPortableExport(account: binding.account, vaultID: binding.vaultID,
            database: binding.database, zoneOwner: binding.zoneOwner)
        return try permit.withDevice { device in
            guard let metadataVersion = versions.first(where: { $0.scope.itemID == Self.metadataRecordID }) else {
                throw ItemVaultSessionFailure.missingVaultMetadata
            }
            let sealedSettings = try metadata(metadataVersion)
            let settingsState = try history.state(forDigest: sealedSettings.header.membership)
            let settings = try sealedSettings.open(device: device, membership: settingsState.membership,
                membershipStateDigest: sealedSettings.header.membership)
            var result = PortableVaultArchive(name: settings.name, items: [], itemIDs: [:], references: [:],
                records: [:], security: settings.security, exclusions: settings.exclusions)
            for version in versions where version.scope.itemID != Self.metadataRecordID && version.healthItemID == nil {
                let value = try envelope(version)
                let state = try readableState(value.header.membership)
                let item = try value.portableArchive(name: settings.name, device: device,
                    membership: state.membership, membershipStateDigest: value.header.membership)
                guard Set(result.itemIDs.keys).isDisjoint(with: item.itemIDs.keys),
                      Set(result.records.keys).isDisjoint(with: item.records.keys) else { throw PortableArchiveFailure.invalid }
                result.items.append(contentsOf: item.items)
                result.itemIDs.merge(item.itemIDs) { _, new in new }
                result.references.merge(item.references) { _, new in new }
                result.records.merge(item.records) { _, new in new }
                if let histories = item.security?.histories, !histories.isEmpty {
                    if result.security == nil { result.security = VaultSecurityMetadata() }
                    result.security?.histories.append(contentsOf: histories)
                }
            }
            try result.validate()
            return result
        }
    }

    private func validateScope(_ version: EncryptedItemVersion) throws {
        guard binding.contains(version.scope) else { throw ItemVaultSessionFailure.invalidBinding }
        guard version.ciphertext.count <= PortableArchive.maximumSize else { throw PortableArchiveFailure.tooLarge }
        guard !version.isTombstone else { throw ItemVaultSessionFailure.unsupportedTombstone }
    }
    private func nextGeneration(_ previous: EncryptedItemVersion?, expectedBase: UUID?) throws -> UInt64 {
        guard previous?.versionID == expectedBase else { throw ItemRepositoryError.staleLocalVersion }
        guard let previous else { return 1 }
        let generation = try previous.healthItemID != nil ? healthEnvelope(previous).header.generation : (previous.scope.itemID == Self.metadataRecordID
            ? metadata(previous).header.generation : envelope(previous).header.generation)
        guard generation < UInt64(Int64.max) else { throw MopError.invalidVault }
        return generation + 1
    }
    private func envelope(_ version: EncryptedItemVersion) throws -> ItemEnvelope {
        try validateScope(version)
        guard version.healthItemID == nil, version.scope.itemID != Self.metadataRecordID else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        let probe = try JSONDecoder().decode(ItemEnvelope.self, from: version.ciphertext)
        let state = try history.state(forDigest: probe.header.membership)
        let value = try ItemEnvelope.decode(version.ciphertext, vault: binding.vaultID, item: version.scope.itemID,
            membership: state.membership, membershipStateDigest: probe.header.membership)
        guard value.header.version == version.versionID, value.header.base == version.baseVersionID,
              value.header.generation == version.generation else {
            throw ItemVaultSessionFailure.invalidEnvelopeBinding
        }
        return value
    }
    private func metadata(_ version: EncryptedItemVersion) throws -> VaultMetadataEnvelope {
        try validateScope(version)
        guard version.healthItemID == nil, version.scope.itemID == Self.metadataRecordID else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        let probe = try JSONDecoder().decode(VaultMetadataEnvelope.self, from: version.ciphertext)
        let state = try history.state(forDigest: probe.header.membership)
        let value = try VaultMetadataEnvelope.decode(version.ciphertext, vault: binding.vaultID,
            membership: state.membership, membershipStateDigest: probe.header.membership)
        guard let author = state.membership.devices.first(where: { $0.fingerprint == value.header.author }),
              state.membership.role(of: author) == .owner else { throw MopError.cloudPermission }
        guard value.header.version == version.versionID, value.header.base == version.baseVersionID,
              value.header.generation == version.generation else {
            throw ItemVaultSessionFailure.invalidEnvelopeBinding
        }
        return value
    }
}

/// A synchronous permit spans the repository transaction and its durable save.
/// Invalidation waits for an already executing transaction, then prevents all
/// queued transactions. No mutex or device handle is held across an await.
final class ItemVaultPermit: RepositoryWritePermit, @unchecked Sendable {
    // The provider is exclusively transferred here and never escapes a locked
    // synchronous closure. Its protocol deliberately does not promise Sendable.
    private struct State: @unchecked Sendable {
        var device: (any DeviceOperations)?
        var displayKey: (envelope: Data, key: LocalDisplayCatalogKey)?
        var health: [UUID: (version: UUID, checks: [CachedPasswordCheck])] = [:]
        var healthProjection: (versions: [UUID: UUID], checks: [CachedPasswordCheck])?
    }
    private let state: Mutex<State>
    init(device: any DeviceOperations) { state = Mutex(State(device: device)) }
    deinit { invalidate() }
    var isValid: Bool { state.withLock { $0.device != nil } }
    func invalidate() {
        state.withLock { value in value.displayKey = nil; value.health.removeAll(); value.healthProjection = nil; value.device?.close(); value.device = nil }
    }
    func check() throws { try withWritePermission {} }
    func withWritePermission<T>(_ body: () throws -> T) throws -> T {
        try state.withLock { value in
            guard value.device != nil else { throw MopError.authentication }
            return try body()
        }
    }
    func cachedHealthProjection(_ versions: [UUID: UUID]) throws -> [CachedPasswordCheck]? {
        try state.withLock { value in
            guard value.device != nil else { throw MopError.authentication }
            return value.healthProjection.flatMap { $0.versions == versions ? $0.checks : nil }
        }
    }
    func cacheHealthProjection(_ versions: [UUID: UUID], checks: [CachedPasswordCheck]) throws {
        try state.withLock { value in
            guard value.device != nil else { throw MopError.authentication }
            value.healthProjection = (versions, checks)
        }
    }
    func withHealth(_ version: EncryptedItemVersion, _ read: (any DeviceOperations) throws -> [CachedPasswordCheck]) throws -> [CachedPasswordCheck] {
        try state.withLock { value in
            guard let device = value.device else { throw MopError.authentication }
            if let cached = value.health[version.scope.itemID], cached.version == version.versionID { return cached.checks }
            let checks = try read(device)
            value.health[version.scope.itemID] = (version.versionID, checks)
            return checks
        }
    }
    func createDisplayKey(context: Data) throws -> Data {
        try state.withLock { value in
            guard let device = value.device else { throw MopError.authentication }
            let created = try LocalDisplayCatalogKey.create(context: context, device: device)
            value.displayKey = (created.envelope, created.key)
            return created.envelope
        }
    }
    func withDisplayKey<T>(envelope: Data, context: Data, _ body: (LocalDisplayCatalogKey) throws -> T) throws -> T {
        try state.withLock { value in
            guard let device = value.device else { throw MopError.authentication }
            if value.displayKey?.envelope != envelope {
                value.displayKey = (envelope, try LocalDisplayCatalogKey.open(envelope, context: context, device: device))
            }
            guard let cached = value.displayKey else { throw MopError.authentication }
            return try body(cached.key)
        }
    }
    func withDevice<T>(_ body: (any DeviceOperations) throws -> T) throws -> T {
        try state.withLock { value in
            guard let device = value.device else { throw MopError.authentication }
            return try body(device)
        }
    }
}

/// Synchronous authority retirement gate. NSLock's non-sending closure allows
/// nesting the repository's generic transaction without transferring its result.
private final class ItemVaultAuthority: @unchecked Sendable {
    private let lock = NSLock()
    private var valid = true
    func withLock<T>(_ body: (inout Bool) throws -> T) rethrows -> T {
        lock.lock(); defer { lock.unlock() }
        return try body(&valid)
    }
}

public enum ItemConflictChoice: Sendable {
    case local, remote
    case combine(metadata: ItemVaultConflictSide, fields: [String: ItemVaultConflictSide])
}
