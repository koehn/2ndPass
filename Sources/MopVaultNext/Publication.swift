import Foundation
import CloudKit
import MopCore

/// Includes the owner and database scope: a shared-zone UUID alone is not an
/// address. Account is the local authenticated account, not the vault owner.
public struct VaultAddress: Codable, Equatable, Sendable {
    public enum Namespace: String, Codable, Sendable { case user, probe }
    public let namespace: Namespace
    public var zoneName: String { (namespace == .user ? "mop-v6-" : "mop-v6-probe-") + vault.uuidString }
    static func discoveredVault(in zoneName: String) -> UUID? {
        guard zoneName.hasPrefix("mop-v6-") else { return nil }
        return UUID(uuidString: String(zoneName.dropFirst(7)))
    }
    public enum Database: String, Codable, Sendable { case `private`, shared }
    public let container: String
    public let environment: String
    public let account: String
    public let database: Database
    public let owner: String
    public let vault: UUID
    public init(container: String, environment: String, account: String, database: Database, owner: String, vault: UUID, namespace: Namespace = .user) throws {
        guard !container.isEmpty, ["Development", "Production"].contains(environment), !account.isEmpty, !owner.isEmpty,
              database != .shared || owner != CKCurrentUserDefaultName else { throw MopError.cloudInvalidRequest }
        guard namespace != .probe || environment == "Development" else { throw MopError.cloudInvalidRequest }
        self.namespace = namespace
        self.container = container; self.environment = environment; self.account = account
        self.database = database; self.owner = owner; self.vault = vault
    }
    public var binding: String { Codec.digest(try! Codec.encode(self)) }
}

public struct RevisionHead: Sendable {
    public let digest: String
    public let version: Data
    public init(digest: String, version: Data) { self.digest = digest; self.version = version }
}

/// Implementations must check the current authenticated account, use immutable
/// exact-byte blob uploads, and compare actual server versions for head saves.
/// A missing head is not permission to create/recreate a zone during refresh.
/// Publishing an unchanged digest MUST advance the server version (fencing an
/// outstanding old-version request). The native private-database probe verifies
/// this for CKModifyRecordsOperation; adapters must preserve that behavior.
public protocol RevisionTransport: Sendable {
    func head(at address: VaultAddress) async throws -> RevisionHead
    func revision(_ digest: String, at address: VaultAddress) async throws -> Data
    func upload(_ bytes: Data, digest: String, at address: VaultAddress) async throws
    func publish(_ digest: String, expectedVersion: Data, at address: VaultAddress) async throws
}

public protocol VaultTransport: RevisionTransport {
    func enrollment(at address: VaultAddress) async throws -> EnrollmentInbox
    func saveEnrollment(_ mailbox: EnrollmentMailbox, version: Data?, at address: VaultAddress) async throws
    func discover() async throws -> [VaultAddress]
    func account() async throws -> String
    func validateOfflineAccount() async throws
    func initialize(_ genesis: VerifiedVault, at address: VaultAddress) async throws
    func share(with account: String, role: MemberRole, at address: VaultAddress) async throws -> URL
    func reconcileShare(_ membership: Membership, at address: VaultAddress) async throws
    func acceptShare(_ url: URL, vault: UUID, expectedOwner: String) async throws -> VaultAddress
    func delete(at address: VaultAddress) async throws
}

public struct PendingPublication: Codable, Sendable {
    public let operation: UUID
    public let parent: String
    public let candidate: String
}
public struct VerifiedState: Codable, Sendable {
    public let address: VaultAddress
    public let snapshot: Data
    public let verifiedDigest: String
    public let verifiedAt: Date
    public let pending: PendingPublication?
}

/// Synchronous atomic private local-state replacement. FileVerifiedStateStore
/// supplies local persistence and a lease; production routing must retain it.
/// Never implement it with a synchronized store or a downloaded-state cache.
public protocol VerifiedStateStore: Sendable {
    func load(binding: String) throws -> VerifiedState?
    func save(_ state: VerifiedState, binding: String) throws
}

public enum PublicationOutcome: String, Sendable { case committed, abandoned, pending, noPending }

/// Single-vault coordinator: model-tested independently of the CloudKit adapter.
/// Reentrant actor calls fail while an operation is suspended, rather than
/// publishing two proposals from the same locally verified state.
public actor PublicationCoordinator {
    public let address: VaultAddress
    private let transport: any RevisionTransport
    private let storage: any VerifiedStateStore
    private var state: VerifiedState
    private var current: VerifiedVault
    private var busy = false

    /// The checkpoint must already be independently verified or locally created
    /// and confirmed committed. This initializer is not a first-upload API.
    public init(address: VaultAddress, checkpoint: VerifiedVault, transport: any RevisionTransport, storage: any VerifiedStateStore) throws {
        guard checkpoint.id == address.vault else { throw MopError.vaultUntrusted }
        self.address = address; self.transport = transport; self.storage = storage
        if let saved = try storage.load(binding: address.binding) {
            guard saved.address == address else { throw MopError.vaultUntrusted }
            let verified = try VerifiedVault(checkpoint: saved.snapshot, independentlyVerifiedDigest: saved.verifiedDigest)
            guard verified.id == address.vault, verified.generation >= checkpoint.generation,
                  verified.generation != checkpoint.generation || verified.digest == checkpoint.digest else { throw MopError.vaultUntrusted }
            current = verified; state = saved
        } else {
            current = checkpoint
            state = VerifiedState(address: address, snapshot: checkpoint.bytes, verifiedDigest: checkpoint.digest, verifiedAt: Date(), pending: nil)
            try storage.save(state, binding: address.binding)
        }
    }
    /// Cached reads are explicitly stale. They cannot observe remote revocation.
    public func offlineSnapshot() -> (VerifiedVault, Date) { (current, state.verifiedAt) }
    private func enter() throws {
        guard !busy else { throw MopError.vaultConflict }; busy = true
    }
    private func save(_ verified: VerifiedVault, pending: PendingPublication?, at date: Date = Date()) throws {
        let next = VerifiedState(address: address, snapshot: verified.bytes, verifiedDigest: verified.digest, verifiedAt: date, pending: pending)
        try storage.save(next, binding: address.binding)
        state = next; current = verified
    }
    @discardableResult public func refresh(reconcileUnchangedPending: Bool = false) async throws -> PublicationOutcome {
        try enter(); defer { busy = false }
        let head = try await transport.head(at: address)
        guard Codec.hash(head.digest) else { throw MopError.invalidVault }
        var digest = head.digest
        var chain: [Data] = []
        var seen = Set<String>(), size = 0
        while digest != current.digest {
            guard seen.insert(digest).inserted, chain.count < 1024, size < 64 * 1024 * 1024 else { throw MopError.vaultUntrusted }
            let bytes = try await transport.revision(digest, at: address)
            guard Codec.digest(bytes) == digest else { throw MopError.invalidVault }
            size += bytes.count
            guard size <= 64 * 1024 * 1024 else { throw MopError.vaultUntrusted }
            let document = try Revision.decode(bytes)
            guard document.header.vault == address.vault, document.header.generation > current.generation,
                  let parent = document.header.parent else { throw MopError.vaultUntrusted }
            chain.append(bytes); digest = parent
        }
        var verified = current
        for bytes in chain.reversed() { verified = try verified.applying(bytes) }
        let outcome: PublicationOutcome
        if let pending = state.pending {
            if seen.contains(pending.candidate) || verified.digest == pending.candidate { outcome = .committed }
            else if verified.digest == pending.parent {
                // The timed-out request could still be in flight. An unchanged
                // head cannot establish failure or justify repeating the write.
                if reconcileUnchangedPending {
                    do {
                        // This is a version barrier, not a replay of the secret
                        // mutation. Either it wins, or a competing head save does.
                        try await transport.publish(verified.digest, expectedVersion: head.version, at: address)
                        try save(verified, pending: nil)
                        return .abandoned
                    } catch MopError.vaultConflict {
                        return .pending // Fetch/validate the winner on next refresh.
                    } catch { throw MopError.cloudUncertain }
                }
                try save(verified, pending: pending)
                return .pending
            } else { outcome = .abandoned }
        } else { outcome = .noPending }
        try save(verified, pending: nil)
        return outcome
    }
    public func publish(_ proposal: VerifiedVault, offline: Bool = false) async throws {
        guard !offline else { throw MopError.offlineWrite }
        try enter(); defer { busy = false }
        guard state.pending == nil else { throw MopError.cloudUncertain }
        _ = try current.applying(proposal.bytes)
        let head = try await transport.head(at: address)
        guard head.digest == current.digest else { throw MopError.vaultConflict }
        let journal = PendingPublication(operation: UUID(), parent: current.digest, candidate: proposal.digest)
        try save(current, pending: journal, at: state.verifiedAt)
        do { try await transport.upload(proposal.bytes, digest: proposal.digest, at: address) }
        catch {
            // No head call was submitted; unreachable immutable data is harmless.
            try save(current, pending: nil, at: state.verifiedAt)
            throw error
        }
        do { try await transport.publish(proposal.digest, expectedVersion: head.version, at: address) }
        catch MopError.vaultConflict {
            try save(current, pending: nil, at: state.verifiedAt)
            throw MopError.vaultConflict
        } catch {
            // Submitted mutations may have committed despite cancellation/timeout.
            // Leave the journal; refresh walks ancestry and never repeats mutation.
            throw MopError.cloudUncertain
        }
        // If persisting confirmation fails, disk still holds the pending journal.
        do { try save(proposal, pending: nil) }
        catch { throw MopError.cloudUncertain }
    }
}
