import Foundation
import CryptoKit
import MopCore
import MopSync
import MopVaultNext

/// Account-scoped public verification. Discovery and self-signed requests are
/// retained as hints/work; neither can reserve or replace a local trust pin.
public struct GrantBackedCoordinationInbox: Sendable {
    public let repository: EncryptedItemRepository
    public let container: String
    public let environment: String
    public let account: String
    public let member: UUID
    public init(repository: EncryptedItemRepository, container: String, environment: String, account: String, member: UUID) {
        self.repository = repository; self.container = container; self.environment = environment; self.account = account; self.member = member
    }
    public func scope(vault: UUID) -> EnrollmentScope {
        EnrollmentScope(container: container, environment: environment, account: account, vault: vault, member: member)
    }
    public func deletionBinding(vault: UUID, genesis: String) -> VaultDeletionNotice.Binding {
        .init(container: container, environment: environment, account: account, vault: vault,
              database: "private", zone: SyncStoreLayout.contentZone(vault: vault), owner: "__defaultOwner__", genesis: genesis)
    }
    /// Retiring work is not granting access. Require a valid historical author,
    /// signature, scope and recipient before treating removal as obsolescence.
    func obsoleteGrantRequest(_ record: PreparedCoordinationRecord, history: TrustedMembershipHistory?) throws -> Bool {
        guard record.kind == .grantRequest else { return false }
        guard record.account == account, record.zoneOwner == "__defaultOwner__" else { throw MopError.vaultUntrusted }
        let value = try CoordinationEnvelope.decode(record.bytes, scope: scope(vault: record.vault))
        guard value.kind == .grantRequest, value.identity == record.identity,
              let membership = value.membership else { throw MopError.vaultUntrusted }
        let request = try JSONDecoder().decode(ContentGrantRequest.self, from: value.payload)
        guard request.recipient == value.author.fingerprint else { throw MopError.vaultUntrusted }
        guard let history else { throw CloudSyncAdapterError.membershipUnavailable }
        guard history.vault == record.vault else { throw MopError.vaultUntrusted }
        guard let state = try? history.state(forDigest: membership) else { throw CloudSyncAdapterError.membershipUnavailable }
        guard state.membership.accounts.count == 1, state.membership.accounts[0].id == member,
              state.membership.devices.contains(value.author) else { throw MopError.vaultUntrusted }
        try history.verifyAccountPath(from: membership, allowingDeviceRemoval: true)
        return !history.current.membership.devices.contains(value.author)
    }

    /// Re-evaluate only retained grant-request work, never generic quarantines.
    /// A missing history or failed verification leaves the original failure intact.
    func retireObsoleteFailure(_ operation: SyncOperation, history: TrustedMembershipHistory?,
                               permit: any RepositoryWritePermit) async throws -> Bool {
        guard operation.account == account, operation.database == "private",
              operation.zoneOwner == "__defaultOwner__", operation.kind == .enrollment,
              operation.state == .needsAttention, operation.failure == .invalidAuthority,
              let record = try? JSONDecoder().decode(PreparedCoordinationRecord.self, from: operation.payload),
              record.vault == operation.vaultID,
              (try? obsoleteGrantRequest(record, history: history)) == true else { return false }
        try await repository.retireObsoleteCoordination(operation, permit: permit)
        AccessSyncTrace.event("persisted obsolete grant request retired", operation: operation.id, record: record.recordName)
        return true
    }

    func retireQuarantinedRequest(_ candidate: QuarantinedSyncRecord, history: TrustedMembershipHistory?,
                                  permit: any RepositoryWritePermit) async throws -> Bool {
        guard let bytes = candidate.payload,
              let envelope = try? JSONDecoder().decode(CoordinationEnvelope.self, from: bytes),
              envelope.kind == .grantRequest,
              let record = try? PreparedCoordinationRecord(account: account, vault: envelope.scope.vault,
                  kind: .grantRequest, identity: envelope.identity, bytes: bytes),
              (try? obsoleteGrantRequest(record, history: history)) == true else { return false }
        guard candidate.operations?.isEmpty == false else { return false }
        try await repository.retireQuarantinedGrant(candidate, record: record, permit: permit)
        AccessSyncTrace.event("quarantined obsolete grant request retired", record: record.recordName)
        return true
    }

    public func verify(_ record: PreparedCoordinationRecord, history: TrustedMembershipHistory?) throws -> CoordinationEnvelope {
        guard record.account == account, record.zoneOwner == "__defaultOwner__" else { throw MopError.vaultUntrusted }
        let value = try CoordinationEnvelope.decode(record.bytes, scope: scope(vault: record.vault))
        guard value.identity == record.identity, value.kind.rawValue == record.kind.rawValue else { throw MopError.vaultUntrusted }
        if value.kind == .enrollmentRequest { return value }
        if value.kind == .enrollmentApproval {
            let approval = try DeviceEnrollmentApproval.decode(value.payload)
            guard approval.request.id == value.identity, approval.request.scope == value.scope,
                  approval.author == value.author else { throw MopError.vaultUntrusted }
            let approved = try approval.verifiedHistory()
            if let history {
                let common = min(history.count, approved.count)
                guard Array(history.orderedStates.prefix(common)) == Array(approved.orderedStates.prefix(common)) else { throw MopError.vaultUntrusted }
                // A newer local checkpoint may have revoked the approving device.
                if history.count > approved.count { try value.verifyAuthority(history: history) }
            }
            try value.verifyAuthority(history: approved)
        } else if value.kind == .deletion {
            guard let history else { throw CloudSyncAdapterError.membershipUnavailable }
            let notice = try VaultDeletionNotice.decode(value.payload)
            let certified = try notice.verifiedHistory(binding: deletionBinding(vault: record.vault, genesis: history.orderedStates[0].digest()), trusted: history)
            guard value.identity == record.vault, value.author.fingerprint == notice.author,
                  value.membership == notice.membership else { throw MopError.vaultUntrusted }
            try value.verifyAuthority(history: certified)
        } else if let history {
            // Coordination and membership arrive from different zones. A valid
            // signature may refer to a committed membership we have not fetched
            // yet; absence from the local pin is not a failed signature.
            if let membership = value.membership, (try? history.state(forDigest: membership)) == nil {
                throw CloudSyncAdapterError.membershipUnavailable
            }
            try value.verifyAuthority(history: history)
        }
        else if value.kind != .discovery { throw CloudSyncAdapterError.membershipUnavailable }
        switch value.kind {
        case .discovery:
            guard value.identity == record.vault, value.payload == Data(record.vault.uuidString.utf8) else { throw MopError.vaultUntrusted }
        case .enrollmentAcknowledgment:
            let acknowledgment = try JSONDecoder().decode(EnrollmentAcknowledgment.self, from: value.payload)
            guard acknowledgment.request == value.identity, acknowledgment.approvalDigest.count == 64,
                  acknowledgment.approvalDigest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw MopError.vaultUntrusted }
        case .grantRequest:
            let request = try JSONDecoder().decode(ContentGrantRequest.self, from: value.payload)
            guard request.recipient == value.author.fingerprint else { throw MopError.vaultUntrusted }
        default: break
        }
        return value
    }

    /// Exact public deletion readback before grant routing. Verification precedes
    /// the atomic marker/work save; no content or cloud data is deleted here.
    func acceptDeletionBeforeRouting(_ incoming: IncomingRecord, history: TrustedMembershipHistory,
                                       permit: any RepositoryWritePermit) async throws {
        let address = try PreparedCoordinationRecord.address(recordType: incoming.recordType, zone: incoming.zoneName, record: incoming.recordName)
        guard incoming.account == account, incoming.database == "private", incoming.zoneOwner == "__defaultOwner__",
              address.kind == .deletion, address.vault == history.vault, address.identity == history.vault,
              incoming.vaultID == history.vault else { throw MopError.vaultUntrusted }
        let record = try PreparedCoordinationRecord(account: account, vault: history.vault,
            kind: .deletion, identity: history.vault, bytes: incoming.bytes)
        _ = try verify(record, history: history)
        let scope = VaultScope(account: account, vaultID: history.vault)
        if try await repository.deletion(scope) != nil { return }
        let digest = Array(SHA256.hash(data: Data(("apply-coordination:" + record.operationID.uuidString).utf8)).prefix(16))
        let id = UUID(uuid: (digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]))
        let work = SyncOperation(id: id, account: account, vaultID: record.vault, kind: .deletion, payload: try setupEncode(record))
        _ = try await repository.saveDeletion(scope: scope, notice: record.bytes, phase: .prepared, cleanup: work, authorization: permit)
    }

    public func handle(_ operation: SyncOperation, history: TrustedMembershipHistory?,
                       permit: any RepositoryWritePermit) async -> SyncOperationOutcome {
        guard operation.account == account, operation.database == "private", operation.kind == .applyIncoming,
              let id = String(data: operation.payload, encoding: .utf8) else { return .attention(.invalidAuthority) }
        do {
            guard let incoming = try await repository.incomingRecord(id: id, account: account, database: "private") else { return .completed }
            do {
                let address = try PreparedCoordinationRecord.address(recordType: incoming.recordType, zone: incoming.zoneName, record: incoming.recordName)
                guard incoming.vaultID == address.vault else { throw MopError.vaultUntrusted }
                let record = try PreparedCoordinationRecord(account: account, zoneOwner: incoming.zoneOwner, vault: address.vault,
                    kind: address.kind, identity: address.identity, bytes: incoming.bytes)
                do {
                    if try obsoleteGrantRequest(record, history: history) {
                        try await repository.completeIncoming(incoming, failure: nil, permit: permit)
                        return .completed
                    }
                    _ = try verify(record, history: history)
                }
                catch CloudSyncAdapterError.membershipUnavailable {
                    let envelope = try CoordinationEnvelope.decode(record.bytes, scope: scope(vault: record.vault))
                    if let membership = envelope.membership {
                        let dependencies: Set<SyncDependency> = [.init(.membership, identifier: record.vault.uuidString + ":" + membership)]
                        try await repository.deferContentIncoming(incoming, dependencies: dependencies, permit: permit)
                        return .waiting(dependencies)
                    }
                    throw CloudSyncAdapterError.membershipUnavailable
                }
                catch { throw MopError.vaultUntrusted }
                if [.enrollmentRequest, .enrollmentApproval, .enrollmentAcknowledgment].contains(record.kind),
                   try await repository.enrollmentReceipt(account: account, vault: record.vault, request: record.identity) != nil {
                    try await repository.completeIncoming(incoming, failure: nil, permit: permit)
                    return .completed
                }
                let work: [SyncOperation]
                switch record.kind {
                case .discovery:
                    if try await repository.deletion(VaultScope(account: account, vaultID: record.vault)) != nil {
                        try await repository.completeIncoming(incoming, failure: nil, permit: permit)
                        return .completed
                    }
                    try await repository.retainContentDiscovery(account: account, addresses: [VaultCloudAddress(vaultID: record.vault,
                        zoneName: SyncStoreLayout.contentZone(vault: record.vault), ownerName: record.zoneOwner)], authorization: permit)
                    work = []
                default:
                    let digest = Array(SHA256.hash(data: Data(("apply-coordination:" + record.operationID.uuidString).utf8)).prefix(16))
                    let id = UUID(uuid: (digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]))
                    work = [SyncOperation(id: id, account: account, vaultID: record.vault, kind: record.kind == .deletion ? .deletion : .enrollment,
                        payload: try setupEncode(record))]
                }
                var equivalent: PreparedCoordinationRecord?
                if record.kind == .enrollmentApproval,
                   let prepared = try await repository.preparedCoordination(account: account, vault: record.vault, kind: record.kind, identity: record.identity), prepared != record {
                    let local = try DeviceEnrollmentApproval.decode(verify(prepared, history: history).payload)
                    let remote = try DeviceEnrollmentApproval.decode(verify(record, history: history).payload)
                    let left = try local.verifiedHistory(), right = try remote.verifiedHistory()
                    let common = min(left.count, right.count)
                    if local.request == remote.request, Array(left.orderedStates.prefix(common)) == Array(right.orderedStates.prefix(common)) { equivalent = prepared }
                }
                if record.kind == .deletion,
                   let prepared = try await repository.preparedCoordination(account: account, vault: record.vault, kind: record.kind, identity: record.identity), prepared != record {
                    let local = try VaultDeletionNotice.decode(verify(prepared, history: history).payload)
                    let remote = try VaultDeletionNotice.decode(verify(record, history: history).payload)
                    let common = min(local.chain.count, remote.chain.count)
                    if local.binding == remote.binding, Array(local.chain.prefix(common)) == Array(remote.chain.prefix(common)) { equivalent = prepared }
                }
                try await repository.receiveCoordination(record, from: incoming, work: work, equivalentPending: equivalent, permit: permit)
                return .completed
            } catch CloudSyncAdapterError.membershipUnavailable {
                return .retry(.dependency)
            } catch ContentStoreError.identityCollision {
                try await repository.quarantineIncoming(incoming, permit: permit)
                return .attention(.invalidAuthority)
            } catch let error as MopError where error == .vaultUntrusted || error == .cloudPermission || error == .invalidVault {
                try await repository.quarantineIncoming(incoming, permit: permit)
                return .attention(.invalidAuthority)
            } catch is DecodingError {
                try await repository.quarantineIncoming(incoming, permit: permit)
                return .attention(.invalidAuthority)
            }
        } catch CloudSyncAdapterError.operationInterrupted { return .retry(.authorization) }
        catch SyncJournalError.staleOperation { return .retry(.dependency) }
        catch { return .retry(.storagePressure) }
    }
}
