import CryptoKit
import Foundation
import Synchronization
import MopCore
import MopSync
import MopVaultNext

public struct ItemVaultSetupScope: Codable, Equatable, Sendable {
    public let container: String
    public let environment: String
    public let binding: ItemVaultBinding
    public init(container: String, environment: String, binding: ItemVaultBinding) {
        self.container = container; self.environment = environment; self.binding = binding
    }
    var repositoryScope: VaultScope {
        VaultScope(account: binding.account, vaultID: binding.vaultID, database: binding.database, zoneOwner: binding.zoneOwner)
    }
}

/// A create-only, locally trusted authority anchor. Contains no item plaintext or archive key; the vault name is retained metadata.
public struct ItemVaultSetupRecord: Codable, Equatable, Sendable {
    public let scope: ItemVaultSetupScope
    public let sourceDigest: String
    public let name: String
    public let genesis: Data
    public let pinnedDigest: String
    public init(scope: ItemVaultSetupScope, sourceDigest: String, name: String, genesis: Data, pinnedDigest: String) {
        self.scope = scope; self.sourceDigest = sourceDigest; self.name = name
        self.genesis = genesis; self.pinnedDigest = pinnedDigest
    }
    public var setupID: String { get throws { try setupHash(setupEncode(self)) } }
}

/// Implementations must atomically create or return the existing value. Never overwrite a pin.
public protocol ItemVaultTrustStore: Sendable {
    func load(scope: ItemVaultSetupScope) throws -> ItemVaultSetupRecord?
    func reserve(_ candidate: ItemVaultSetupRecord) throws -> ItemVaultSetupRecord
}

public enum ItemVaultBootstrapFailure: Error, Equatable, Sendable {
    case invalidScope, sourceMismatch, missingSetup, incompleteSetup, concurrentOperation, invalidTrust
    /// Setup is durably complete; authenticate again to open it. Never retry as a new import.
    case committedButLocked(VaultInitializationReceipt)
}

/// Local-only setup. Transfer exclusive device ownership here. Encryption runs off
/// the caller's actor; lock can interrupt between items. The immutable Keychain pin
/// precedes one atomic database transaction, so an interrupted setup resumes using
/// the same authority. A committed retry never rewrites subsequent user edits.
public final class ItemVaultBootstrap: @unchecked Sendable {
    private let repository: EncryptedItemRepository
    private let trustStore: any ItemVaultTrustStore
    private let scope: ItemVaultSetupScope
    private let permit: ItemVaultPermit
    private let running = Mutex(false)
    private let completed = Mutex<ItemVaultSession?>(nil)

    public init(repository: EncryptedItemRepository, trustStore: any ItemVaultTrustStore,
                scope: ItemVaultSetupScope, device: any DeviceOperations) throws {
        guard !scope.container.isEmpty, ["Development", "Production"].contains(scope.environment),
              !scope.binding.account.isEmpty, scope.binding.database == "private",
              scope.binding.zoneOwner == "__defaultOwner__" else { throw ItemVaultBootstrapFailure.invalidScope }
        self.repository = repository; self.trustStore = trustStore; self.scope = scope
        permit = ItemVaultPermit(device: device)
    }
    public func lock() { permit.invalidate() }

    public func restore(archiveData: Data, recoveryKey: SecretBytes, name: String) async throws -> ItemVaultSession {
        try begin(); defer { end() }
        let task = Task.detached { [self] in
            try permit.check(); try Task.checkCancellation()
            var archive = try PortableArchive.open(archiveData, recoveryKey: recoveryKey)
            archive.name = name
            if var security = archive.security {
                security.passwordChecks = nil
                for a in security.accounts.indices {
                    for r in security.accounts[a].registrations.indices { security.accounts[a].registrations[r].external = true }
                }
                archive.security = security
            }
            return try await prepare(archive, sourceDigest: setupHash(archiveData))
        }
        return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
    }
    public func create(name: String) async throws -> ItemVaultSession {
        try begin(); defer { end() }
        let task = Task.detached { [self] in
            let archive = PortableVaultArchive(name: name, items: [], itemIDs: [:], references: [:], records: [:])
            return try await prepare(archive, sourceDigest: setupHash(Data("2ndpass-empty-item-vault-1".utf8)))
        }
        return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
    }
    /// Opens a completed local setup from its independent pin; never creates authority.
    public func open() async throws -> ItemVaultSession {
        try begin(); defer { end() }
        guard let record = try trustStore.load(scope: scope) else { throw ItemVaultBootstrapFailure.missingSetup }
        let history = try authenticate(record)
        guard let receipt = try await repository.vaultInitialization(scope.repositoryScope) else { throw ItemVaultBootstrapFailure.incompleteSetup }
        try validate(receipt, record: record)
        return try completedSession(receipt: receipt, history: history)
    }
    /// Call only after native account validation and retrieval from this same
    /// account's private CloudKit database. This channel supplies the initial
    /// bootstrap authority; an existing local pin is never replaced.
    public func acceptFromAuthenticatedPrivateCloudKit(approval: DeviceEnrollmentApproval,
            request: DeviceEnrollmentRequest, metadata: EncryptedItemVersion,
            metadataSystemFields: Data? = nil, successors: [MembershipEnvelope] = []) async throws -> ItemVaultSession {
        try begin(); defer { end() }
        guard let membershipStore = trustStore as? any ItemVaultMembershipTrustStore else { throw ItemVaultBootstrapFailure.invalidTrust }
        let expectedScope = try permit.withDevice { device in
            guard device.identity == request.identity else { throw ItemVaultBootstrapFailure.invalidTrust }
            return EnrollmentScope(container: scope.container, environment: scope.environment,
                account: scope.binding.account, vault: scope.binding.vaultID, member: device.identity.member)
        }
        var history = try approval.acceptFromAuthenticatedPrivateCloudKit(request: request, scope: expectedScope)
        for successor in successors {
            try ItemVaultMembershipAuthority.validateAddition(previous: history.current, next: successor)
            try history.append(successor)
        }
        let digest = try history.current.digest()
        guard metadata.scope == scope.binding.item(ItemVaultSession.metadataRecordID), !metadata.isTombstone else {
            throw ItemVaultBootstrapFailure.invalidTrust
        }
        let envelope = try VaultMetadataEnvelope.decode(metadata.ciphertext, vault: scope.binding.vaultID,
            membership: history.current.membership, membershipStateDigest: digest)
        guard envelope.header.version == metadata.versionID, envelope.header.base == metadata.baseVersionID,
              envelope.header.generation == metadata.generation else { throw ItemVaultBootstrapFailure.invalidTrust }
        let name = try permit.withDevice { device in
            try envelope.open(device: device, membership: history.current.membership, membershipStateDigest: digest).name
        }
        guard let genesis = history.orderedStates.first else { throw ItemVaultBootstrapFailure.invalidTrust }
        let existingReceipt = try await repository.vaultInitialization(scope.repositoryScope)
        let restoringMissingStore = approval.isReconnect && existingReceipt == nil
        let sourceDigest = try setupHash(approval.encoded())
        let record = try permit.withWritePermission { () throws -> ItemVaultSetupRecord in
            let record: ItemVaultSetupRecord
            if let existing = try trustStore.load(scope: scope) {
                guard existing.scope == scope, (existing.sourceDigest == sourceDigest || restoringMissingStore),
                      existing.genesis == (try genesis.encoded()), existing.pinnedDigest == (try genesis.digest()) else {
                    throw ItemVaultBootstrapFailure.invalidTrust
                }
                record = existing
            } else {
                record = try trustStore.reserve(ItemVaultSetupRecord(scope: scope, sourceDigest: sourceDigest, name: name,
                    genesis: genesis.encoded(), pinnedDigest: genesis.digest()))
                guard record.scope == scope, record.sourceDigest == sourceDigest,
                      record.genesis == (try genesis.encoded()), record.pinnedDigest == (try genesis.digest()) else {
                    throw ItemVaultBootstrapFailure.invalidTrust
                }
            }
            try membershipStore.reserveMembership(scope: scope, successors: history.orderedStates.dropFirst().map { try $0.encoded() })
            return record
        }
        let receipt = try await repository.initializeEnrolledVault(scope: scope.repositoryScope, metadata: metadata,
            metadataSystemFields: metadataSystemFields, expectedItemCount: approval.expectedItemCount, membershipState: record.genesis,
            currentControl: history.current.encoded(), setupID: record.setupID, authorization: permit)
        return try completedSession(receipt: receipt, history: history)
    }

    private func begin() throws {
        try permit.check()
        try running.withLock { value in
            guard !value else { throw ItemVaultBootstrapFailure.concurrentOperation }; value = true
        }
    }
    private func end() { running.withLock { $0 = false } }

    private func authenticate(_ record: ItemVaultSetupRecord) throws -> TrustedMembershipHistory {
        guard record.scope == scope else { throw ItemVaultBootstrapFailure.invalidTrust }
        try VaultName.validate(record.name)
        let genesis = try MembershipEnvelope.decode(record.genesis)
        let history = try ItemVaultMembershipAuthority.history(record: record, trustStore: trustStore)
        try permit.withDevice { device in
            guard genesis.membership.accounts.count == 1,
                  genesis.membership.accounts[0].role == .owner,
                  genesis.membership.accounts[0].id == device.identity.member,
                  history.current.membership.role(of: device.identity) == .owner,
                  genesis.membership.offlineRecovery == nil else {
                throw ItemVaultBootstrapFailure.invalidTrust
            }
        }
        return history
    }
    private func validate(_ receipt: VaultInitializationReceipt, record: ItemVaultSetupRecord) throws {
        guard receipt.scope == scope.repositoryScope, receipt.setupID == (try record.setupID),
              receipt.membershipState == record.genesis else { throw ItemVaultBootstrapFailure.invalidTrust }
    }
    private func prepare(_ archive: PortableVaultArchive, sourceDigest: String) async throws -> ItemVaultSession {
        try Task.checkCancellation(); try permit.check(); try archive.validate()
        guard !archive.itemIDs.values.contains(where: { UUID(uuidString: $0) == ItemVaultSession.metadataRecordID }) else { throw PortableArchiveFailure.invalid }
        let record: ItemVaultSetupRecord
        if let existing = try trustStore.load(scope: scope) { record = existing }
        else {
            record = try permit.withDevice { device in
                let membership = try Membership(accounts: [AccountMember(id: device.identity.member, role: .owner, devices: [device.identity])])
                let genesis = try MembershipEnvelope.genesis(vault: scope.binding.vaultID, membership: membership, owner: device)
                return try trustStore.reserve(ItemVaultSetupRecord(scope: scope, sourceDigest: sourceDigest, name: archive.name,
                    genesis: genesis.encoded(), pinnedDigest: genesis.digest()))
            }
        }
        guard record.sourceDigest == sourceDigest, record.name == archive.name else { throw ItemVaultBootstrapFailure.sourceMismatch }
        let history = try authenticate(record)
        let committed: VaultInitializationReceipt
        if let receipt = try await repository.vaultInitialization(scope.repositoryScope) {
            try validate(receipt, record: record)
            committed = receipt
        } else {
            let versions = try encrypt(archive, history: history)
            do {
                committed = try await repository.initializeVault(scope: scope.repositoryScope, versions: versions,
                    membershipState: record.genesis, setupID: record.setupID, authorization: permit)
            } catch {
                // A competing process can commit this same pinned logical import
                // using different random ciphertext. Authenticate its operation identity.
                guard let receipt = try await repository.vaultInitialization(scope.repositoryScope) else { throw error }
                try validate(receipt, record: record)
                committed = receipt
            }
        }
        return try completedSession(receipt: committed, history: history)
    }
    private func completedSession(receipt: VaultInitializationReceipt, history: TrustedMembershipHistory) throws -> ItemVaultSession {
        do {
            return try completed.withLock { session in
                try permit.check()
                if let session { return session }
                let value = try ItemVaultSession(repository: repository, binding: scope.binding, history: history, permit: permit)
                session = value
                return value
            }
        } catch {
            if !permit.isValid { throw ItemVaultBootstrapFailure.committedButLocked(receipt) }
            throw error
        }
    }
    private func encrypt(_ document: PortableVaultArchive, history: TrustedMembershipHistory) throws -> [EncryptedItemVersion] {
        let membership = history.current.membership, digest = try history.current.digest()
        var records: [String: [String: PortableArchiveRecord]] = [:]
        for (id, record) in document.records { records[record.itemID, default: [:]][id] = record }
        var references: [String: [String: String]] = [:]
        for (path, id) in document.references {
            guard let record = document.records[id] else { throw PortableArchiveFailure.invalid }
            references[record.itemID, default: [:]][path] = id
        }
        let histories = Dictionary(grouping: document.security?.histories ?? [], by: \.itemID)
        var versions: [EncryptedItemVersion] = []
        for item in document.items {
            try Task.checkCancellation()
            guard let id = document.itemIDs[item.name], let uuid = UUID(uuidString: id) else { throw PortableArchiveFailure.invalid }
            var security = VaultSecurityMetadata(); security.histories = histories[id] ?? []
            let projection = PortableVaultArchive(name: document.name, items: [item], itemIDs: [item.name: id],
                references: references[id] ?? [:], records: records[id] ?? [:], security: security)
            let sealed = try permit.withDevice { try ItemEnvelope.seal(projection, vault: scope.binding.vaultID, generation: 1,
                membership: membership, membershipStateDigest: digest, signer: $0) }
            versions.append(EncryptedItemVersion(scope: scope.binding.item(uuid), versionID: sealed.header.version,
                baseVersionID: nil, ciphertext: try sealed.encoded(), generation: 1))
        }
        var security = document.security; security?.histories = []
        let metadata = try permit.withDevice { try VaultMetadataEnvelope.seal(VaultEnvelopeMetadata(name: document.name,
            security: security, exclusions: document.exclusions), vault: scope.binding.vaultID, generation: 1,
            membership: membership, membershipStateDigest: digest, signer: $0) }
        versions.append(EncryptedItemVersion(scope: scope.binding.item(ItemVaultSession.metadataRecordID), versionID: metadata.header.version,
            baseVersionID: nil, ciphertext: try metadata.encoded(), generation: 1))
        try Task.checkCancellation()
        return versions
    }
}

func setupEncode<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try encoder.encode(value)
}
func setupHash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
