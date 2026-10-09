@preconcurrency import CloudKit
import Foundation
import Synchronization
import MopCore
import MopAuth
import MopSync
import MopVaultNext

public enum ItemRecoveryFailure: Error, LocalizedError {
    public static func message(for error: any Error) -> String {
        if Authentication.requiresRenewal(error) {
            return "Your device needs to authenticate again. Your recovery progress is saved. Choose Resume Recovery Setup and unlock when prompted."
        }
        switch error as? CloudSyncAdapterError {
        case .engineAlreadyOwned: return "Another app or extension is synchronizing your vaults. Wait for it to finish, then resume recovery setup."
        case .operationInterrupted: return "Synchronization was interrupted while preparing recovery. Resume recovery setup to continue."
        case .leaseUnavailable: return "Recovery could not access the local synchronization lock. Restart the app and resume recovery setup."
        default: return (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }
    case codeRequired, pending, configurationBusy, recoveryInProgress
    public var errorDescription: String? {
        switch self {
        case .codeRequired: "Enter your saved recovery code again to continue."
        case .pending: "Recovery is waiting for encrypted records or keys. Keep this app open and retry; an existing device may need to reconnect."
        case .configurationBusy: "A recovery-key change is incomplete. Resume it before creating a vault or starting another change."
        case .recoveryInProgress: "Complete recovery before opening your vaults."
        }
    }
}

/// The backend serializes operations. lock() synchronously destroys the sole
/// recovery provider; the authorization callback guards all durable boundaries.
final class ItemRecoveryCoordinator: @unchecked Sendable {
    let account: any ItemRecoveryAccount
    let repository: EncryptedItemRepository
    let transport: any ItemRecoveryTransport
    let trust: any ItemVaultMembershipTrustStore
    let store: ItemRecoveryStateStore
    private let progressState = Mutex<(String?, Double?)>((nil, nil))
    var operationProgress: String? { progressState.withLock { $0.0 } }
    var operationFraction: Double? { progressState.withLock { $0.1 } }
    private func report(_ message: String, completed: Int? = nil, total: Int? = nil) {
        let fraction = completed.flatMap { done in total.flatMap { $0 > 0 ? Double(done) / Double($0) : nil } }
        progressState.withLock { $0 = (message, fraction) }
    }
    private let key = Mutex<OfflineRecoveryKey?>(nil)
    convenience init(account: NativeItemCloudAccount, repository: EncryptedItemRepository) throws {
        try self.init(account: account, repository: repository, transport: NativeItemRecoveryTransport(account: account), trust: KeychainItemVaultTrustStore())
    }
    init(account: any ItemRecoveryAccount, repository: EncryptedItemRepository,
         transport: any ItemRecoveryTransport, trust: any ItemVaultMembershipTrustStore) {
        self.account = account; self.repository = repository; self.transport = transport; self.trust = trust
        store = ItemRecoveryStateStore(directory: account.directory, account: account.accountNamespace)
    }
    func lock() { key.withLock { $0?.close(); $0 = nil } }
    deinit { lock() }
    private func recoveryKey() throws -> OfflineRecoveryKey {
        guard let value = key.withLock({ $0 }) else { throw ItemRecoveryFailure.codeRequired }; return value
    }
    typealias DeviceLoader = @Sendable (UUID, Bool) async throws -> any DeviceOperations
    typealias Check = @Sendable () throws -> Void

    func execute(_ action: VaultManagement, device: DeviceLoader, check: Check) async throws -> VaultResult {
        try check()
        defer { progressState.withLock { $0 = (nil, nil) } }
        // Generation is local and does not need the cloud or its synchronization lease.
        if case .recoveryGenerate = action {} else {
            report("Checking your iCloud account…")
            try await transport.check()
        }
        var result = VaultResult(); result.recoveryScope = account.recoveryScope
        switch action {
        case .recoveryGenerate:
            let fresh = try OfflineRecoveryKey(scope: account.recoveryScope); defer { fresh.close() }
            result.recoveryCode = try fresh.code(); result.recoveryFile = try fresh.export(); result.recoveryFingerprint = fresh.identity.fingerprint
        case .recoveryEligibility:
            result.recoveryNeeded = true
            if let progress = try store.load(), progress.blocksRegularAccess {
                result.message = "Recovery is incomplete. Enter your code if requested and continue. Keep this app open."
                if progress.phase != .preview {
                    do {
                        for id in progress.vaults where !progress.completed.contains(id) { try await complete(id, device: device, check: check) }
                        result.message = "Recovery completed. Existing devices retain access."
                    } catch {
                        try check()
                        if Authentication.requiresRenewal(error) { throw error }
                        result.message = error.localizedDescription
                        if var interrupted = try store.load() { interrupted.issue = result.message; try store.save(interrupted) }
                    }
                }
                let latest = try store.load() ?? progress
                result.vaults = latest.vaults.map { VaultDescriptor(id: $0.uuidString, name: nil, format: "mop-items-v2", enrolled: latest.completed.contains($0)) }
            }
        case .recoveryStatus:
            var (configuration, _) = try await transport.configuration()
            report("Verifying recovery coverage across all vaults…")
            configuration.vaults = try await coverage(device: device, check: check, expected: configuration.incomplete ? configuration.target : configuration.active)
            result.recoveryConfiguration = configuration
        case .recoveryActivate(let copy, let fingerprint):
            let imported = try OfflineRecoveryKey(document: copy, scope: account.recoveryScope); defer { imported.close() }
            guard fingerprint.isEmpty || fingerprint == imported.identity.fingerprint else { throw MopError.invalidRecovery }
            result.recoveryConfiguration = try await rotate(to: imported.identity, resume: false, device: device, check: check)
        case .recoveryRevoke:
            result.recoveryConfiguration = try await rotate(to: nil, resume: false, device: device, check: check)
        case .recoveryResume:
            result.recoveryConfiguration = try await rotate(to: nil, resume: true, device: device, check: check)
        case .recoveryOpen(let copy):
            let imported = try OfflineRecoveryKey(document: copy, scope: account.recoveryScope)
            key.withLock { $0?.close(); $0 = imported }
            let discovered = try await transport.discover()
            var statuses: [RecoveryVaultStatus] = []
            for vault in discovered {
                guard let id = UUID(uuidString: vault.id) else { continue }
                do {
                    let (history, _) = try await transport.history(id)
                    guard history.current.membership.offlineRecovery == imported.identity else { throw MopError.invalidRecovery }
                    let records = try await transport.records(id)
                    guard let metadata = records.first(where: { $0.0.scope.itemID == ItemVaultSession.metadataRecordID })?.0 else { throw ItemRecoveryFailure.pending }
                    try ItemEnvelopeTransition.verifyReadable(metadata, history: history, device: imported)
                    let envelope = try JSONDecoder().decode(VaultMetadataEnvelope.self, from: metadata.ciphertext)
                    let previous = try history.state(forDigest: envelope.header.membership)
                    let name = try envelope.open(device: imported, membership: previous.membership, membershipStateDigest: envelope.header.membership).name
                    result.vaults.append(VaultDescriptor(id: id.uuidString, name: name, format: "mop-items-v2", enrolled: false))
                    statuses.append(.init(id: id, fingerprint: imported.identity.fingerprint, complete: false))
                } catch {
                    statuses.append(.init(id: id, fingerprint: nil, complete: false, issue: error.localizedDescription))
                }
                try check()
            }
            guard !result.vaults.isEmpty else { lock(); throw MopError.invalidRecovery }
            if try store.load()?.blocksRegularAccess != true {
                try check(); try store.save(ItemRecoveryState(account: account.accountNamespace, vaults: result.vaults.compactMap { UUID(uuidString: $0.id) }))
            }
            result.recoveryVaults = statuses; result.recoveryReadOnly = true
            result.message = "Read-only recovery is open. Keep this app open while enrolling this device."
        case .recoveryCatalog(let id), .recoveryRead(let id, _):
            let recovery = try recoveryKey(), (history, _) = try await transport.history(id)
            guard history.current.membership.offlineRecovery == recovery.identity else { throw MopError.invalidRecovery }
            let records = try await transport.records(id)
            var items: [VaultItem] = []
            for (record, _) in records where record.scope.itemID != ItemVaultSession.metadataRecordID && record.healthItemID == nil {
                let digest = try ItemEnvelopeTransition.membershipDigest(record), previous = try history.state(forDigest: digest)
                let envelope = try ItemEnvelope.decode(record.ciphertext, vault: id, item: record.scope.itemID,
                    membership: previous.membership, membershipStateDigest: digest)
                let catalog = try envelope.catalog(device: recovery, membership: previous.membership, membershipStateDigest: digest)
                items.append(catalog.item)
                if case .recoveryRead(_, let path) = action,
                   let recordID = catalog.references[path] {
                    let value = try envelope.read(record: recordID, device: recovery, membership: previous.membership, membershipStateDigest: digest)
                    if catalog.item.fields.contains(where: { $0.type == .attachment && SecretReference.encode(catalog.item.name) + "/" + $0.path == path }) {
                        result.recoveredAttachment = try Attachment.decode(String(decoding: value, as: UTF8.self))
                    } else { result.value = value }
                }
            }
            result.catalog = ItemCatalog(vault: id.uuidString, revision: try history.current.digest(), items: items)
            if case .recoveryRead = action, result.value == nil && result.recoveredAttachment == nil { throw MopError.notFound }
        case .recoveryCompleteAll(let ids):
            guard !ids.isEmpty, Set(ids).count == ids.count, var progress = try store.load() else { throw MopError.invalidRecovery }
            if progress.phase == .preview || progress.phase == .complete {
                progress.vaults = ids; progress.completed = []; progress.phase = .enrolling
                try check(); try store.save(progress)
            } else { guard Set(progress.vaults) == Set(ids) else { throw ItemRecoveryFailure.recoveryInProgress } }
            for id in ids where !progress.completed.contains(id) { try await complete(id, device: device, check: check) }
            result.recoveryVaults = ids.map { .init(id: $0, fingerprint: nil, complete: true) }
            result.message = "All selected vaults recovered. Existing devices retain access."
        case .recoveryComplete(let id):
            try await complete(id, device: device, check: check)
            result.recoveryVaults = [.init(id: id, fingerprint: nil, complete: true)]
            result.message = "Recovery completed. Existing devices and your recovery key retain access."
        default: throw ItemVaultServiceFailure.unavailable
        }
        if let progress = try store.load() { result.recoveryInProgress = progress.blocksRegularAccess && progress.phase != .preview }
        try check(); return result
    }

    private func coverage(device: DeviceLoader, check: Check, expected: DevicePublicKey?) async throws -> [RecoveryVaultStatus] {
        var statuses: [RecoveryVaultStatus] = []
        for descriptor in try await transport.discover() {
            guard let id = UUID(uuidString: descriptor.id) else { continue }
            do {
                let (history, _) = try await transport.history(id)
                let records = try await transport.records(id)
                let owner = try await device(id, false); defer { owner.close() }
                guard history.current.membership.offlineRecovery == expected,
                      records.contains(where: { $0.0.scope.itemID == ItemVaultSession.metadataRecordID }) else { throw ItemRecoveryFailure.pending }
                for (record, _) in records {
                    guard try ItemEnvelopeTransition.membershipDigest(record) == history.current.digest() else { throw ItemRecoveryFailure.pending }
                    try ItemEnvelopeTransition.verifyReadable(record, history: history, device: owner)
                }
                statuses.append(.init(id: id, fingerprint: expected?.fingerprint, complete: true))
            } catch {
                if Authentication.requiresRenewal(error) { throw error }
                statuses.append(.init(id: id, fingerprint: expected?.fingerprint, complete: false, issue: error.localizedDescription))
            }
            try check()
        }
        return statuses
    }

    private struct StagedRecord: Codable { let value: EncryptedItemVersion; let expected: Data }
    private func discardStaging(_ operation: UUID) {
        // Only after acknowledged writes and verified completion; never on error.
        try? FileManager.default.removeItem(at: account.directory.appendingPathComponent("RecoveryStaging").appendingPathComponent(operation.uuidString))
    }
    private func stagedURL(_ record: EncryptedItemVersion, operation: UUID, digest: String) throws -> URL {
        let location = account.directory.appendingPathComponent("RecoveryStaging").appendingPathComponent(operation.uuidString)
            .appendingPathComponent(record.scope.vaultID.uuidString)
        _ = try LocalDirectory(directory: location)
        return location.appendingPathComponent(record.scope.itemID.uuidString + "-" + record.versionID.uuidString + "-" + digest + ".json")
    }
    private func prepared(_ record: EncryptedItemVersion, fields: Data, history: TrustedMembershipHistory,
                          operation: UUID, decryptor: any DeviceOperations, signer: any DeviceOperations) throws -> EncryptedItemVersion {
        let url = try stagedURL(record, operation: operation, digest: history.current.digest())
        if FileManager.default.fileExists(atPath: url.path) {
            let saved = try JSONDecoder().decode(StagedRecord.self, from: LocalFile.read(url, privateFile: true, limit: EncryptedItemRepository.maximumCiphertextBytes * 2))
            guard saved.value.scope == record.scope, saved.value.baseVersionID == record.versionID,
                  try ItemEnvelopeTransition.membershipDigest(saved.value) == history.current.digest() else { throw MopError.invalidRecovery }
            try ItemEnvelopeTransition.verifyReadable(saved.value, history: history, device: signer)
            return saved.value
        }
        let next = try ItemEnvelopeTransition.rewrite(record, history: history, decryptor: decryptor, signer: signer)
        try LocalFile.write(JSONEncoder().encode(StagedRecord(value: next, expected: fields)), to: url, replace: false)
        return next
    }
    /// Stage all known encrypted successors before publishing the authority head.
    private func prepareTransition(_ history: TrustedMembershipHistory, operation: UUID,
                                   decryptor: any DeviceOperations, signer: any DeviceOperations, check: Check) async throws {
        report("Downloading vault records to prepare recovery protection…")
        let records = try await transport.records(history.vault)
        for (index, entry) in records.enumerated() {
            let (record, fields) = entry
            report("Preparing encrypted record \(index + 1) of \(records.count)…", completed: index, total: records.count)
            try check()
            _ = try prepared(record, fields: fields, history: history, operation: operation, decryptor: decryptor, signer: signer)
        }
    }
    private func adoptAcknowledged(_ value: EncryptedItemVersion, fields: Data) async throws {
        do { try await repository.applyRemote(value, serverSystemFields: fields) }
        catch ItemRepositoryError.pendingLocalChanges { return }
        catch ItemRepositoryError.unresolvedConflict { return }
        catch ItemRepositoryError.remoteVersionConflict { return }
    }

    /// Each pass includes a full server inventory. Conflicts retry from freshly
    /// fetched authenticated data; repeated changes remain pending, never complete.
    private func rewrite(_ id: UUID, operation: UUID, decryptor: any DeviceOperations,
                         signer: any DeviceOperations, check: Check, adoptLocally: Bool = false) async throws -> (TrustedMembershipHistory, [(EncryptedItemVersion, Data)]) {
        for pass in 0..<8 {
            try check()
            let (history, _) = try await transport.history(id)
            report("Downloading vault records (pass \(pass + 1))…")
            let records = try await transport.records(id)
            guard records.contains(where: { $0.0.scope.itemID == ItemVaultSession.metadataRecordID }) else { throw ItemRecoveryFailure.pending }
            var changed = false
            for (index, entry) in records.enumerated() {
                let (record, fields) = entry
                report("Verifying and updating record \(index + 1) of \(records.count)…", completed: index, total: records.count)
                try check()
                let digest = try ItemEnvelopeTransition.membershipDigest(record)
                if digest == (try history.current.digest()) {
                    try ItemEnvelopeTransition.verifyReadable(record, history: history, device: signer)
                    if adoptLocally { try await adoptAcknowledged(record, fields: fields) }
                    continue
                }
                let reader: any DeviceOperations
                if (try? ItemEnvelopeTransition.verifyReadable(record, history: history, device: signer)) != nil { reader = signer }
                else { reader = decryptor }
                let next = try prepared(record, fields: fields, history: history, operation: operation, decryptor: reader, signer: signer)
                try check()
                do {
                    let acknowledgedFields = try await transport.save(next, expected: fields)
                    try check()
                    if adoptLocally { try await adoptAcknowledged(next, fields: acknowledgedFields) }
                }
                catch {
                    // Preserve the journal and re-read: the write may have committed.
                    try await transport.check()
                    guard Self.isRecordConflict(error) else { throw error }
                }
                changed = true
            }
            let (after, _) = try await transport.history(id)
            if !changed, try after.current.digest() == history.current.digest() { return (history, records) }
        }
        throw ItemRecoveryFailure.pending
    }

    static func isRecordConflict(_ error: any Error) -> Bool {
        if error as? MopError == .vaultConflict { return true }
        guard let cloud = error as? CKError else { return false }
        if cloud.code == .serverRecordChanged { return true }
        guard cloud.code == .partialFailure, let failures = cloud.partialErrorsByItemID, !failures.isEmpty else { return false }
        return failures.values.allSatisfy { isRecordConflict($0) }
    }

    private func rotate(to target: DevicePublicKey?, resume: Bool, device: DeviceLoader, check: Check) async throws -> RecoveryConfiguration {
        var (configuration, record) = try await transport.configuration()
        if !resume {
            if configuration.incomplete {
                // Retrying verification of the same saved code resumes its committed operation.
                guard configuration.target == target else { throw ItemRecoveryFailure.configurationBusy }
            } else {
                configuration.operation = UUID(); configuration.target = target
                try check(); try await transport.saveConfiguration(configuration, expected: record)
            }
        }
        (configuration, record) = try await transport.configuration()
        guard let operation = configuration.operation else { return configuration }
        let desired = configuration.target
        report("Finding your iCloud vaults…")
        let vaults = try await transport.discover()
        for (index, descriptor) in vaults.enumerated() {
            report("Updating recovery protection for vault \(index + 1) of \(vaults.count)…")
            guard let id = UUID(uuidString: descriptor.id) else { continue }
            let owner = try await device(id, false); defer { owner.close() }
            let (history, head) = try await transport.history(id)
            guard history.current.membership.role(of: owner.identity) == .owner else { throw MopError.cloudPermission }
            if history.current.membership.offlineRecovery != desired {
                let before = history.current.membership
                let membership = try Membership(accounts: before.accounts, offlineRecovery: desired, removedDevices: before.removedDevices)
                let successor = try MembershipEnvelope.successor(of: history.current, membership: membership, owner: owner)
                var targetHistory = history; try targetHistory.append(successor)
                try await prepareTransition(targetHistory, operation: operation, decryptor: owner, signer: owner, check: check)
                try check(); try await transport.publish(successor, expected: head)
            }
            _ = try await rewrite(id, operation: operation, decryptor: owner, signer: owner, check: check, adoptLocally: true)
            configuration.vaults.removeAll { $0.id == id }
            configuration.vaults.append(.init(id: id, fingerprint: desired?.fingerprint, complete: true))
            try check(); try await transport.saveConfiguration(configuration, expected: record)
            (configuration, record) = try await transport.configuration()
            guard configuration.operation == operation, configuration.target == desired else { throw ItemRecoveryFailure.configurationBusy }
        }
        report("Verifying recovery coverage across all vaults…")
        configuration.vaults = try await coverage(device: device, check: check, expected: desired)
        guard configuration.vaults.allSatisfy(\.complete) else { throw ItemRecoveryFailure.pending }
        configuration.active = desired; configuration.target = nil; configuration.operation = nil
        try check(); try await transport.saveConfiguration(configuration, expected: record)
        discardStaging(operation)
        return configuration
    }

    private func complete(_ id: UUID, device: DeviceLoader, check: Check) async throws {
        guard var progress = try store.load() else { throw ItemRecoveryFailure.codeRequired }
        if progress.phase == .preview || progress.phase == .complete {
            progress.vaults = [id]; progress.completed = []; progress.phase = .enrolling
            try check(); try store.save(progress)
        }
        guard progress.vaults.contains(id) else { throw ItemRecoveryFailure.recoveryInProgress }
        let joining = try await device(id, true); defer { joining.close() }
        var (history, head) = try await transport.history(id)
        let approval: DeviceEnrollmentApproval
        if let bytes = progress.approvals[id.uuidString] {
            approval = try DeviceEnrollmentApproval.decode(bytes)
            guard approval.request.identity == joining.identity else { throw MopError.invalidRecovery }
        } else {
            let recovery = try recoveryKey()
            guard history.current.membership.offlineRecovery == recovery.identity else { throw MopError.invalidRecovery }
            let scope = EnrollmentScope(container: account.containerIdentifier, environment: account.environment,
                account: account.accountNamespace, vault: id, member: account.memberID)
            let request = try DeviceEnrollmentRequest.create(scope: scope, device: joining)
            if history.current.membership.devices.contains(joining.identity) {
                approval = try DeviceEnrollmentApproval.reconnect(request: request, history: history, owner: joining)
            } else { approval = try DeviceEnrollmentApproval.create(request: request, history: history, owner: recovery) }
            progress.approvals[id.uuidString] = try approval.encoded()
            try check(); try store.save(progress)
        }
        if !history.current.membership.devices.contains(joining.identity) {
            guard history.current == approval.history.last else { throw MopError.vaultConflict }
            var targetHistory = history; try targetHistory.append(approval.successor)
            try await prepareTransition(targetHistory, operation: progress.operation, decryptor: recoveryKey(), signer: joining, check: check)
            try check(); try await transport.publish(approval.successor, expected: head)
            (history, head) = try await transport.history(id)
        }
        progress.phase = .repairing; try check(); try store.save(progress)
        let decryptor: any DeviceOperations = key.withLock { $0 } ?? joining
        if key.withLock({ $0 }) == nil {
            for (record, _) in try await transport.records(id) {
                if (try? ItemEnvelopeTransition.verifyReadable(record, history: history, device: joining)) == nil {
                    // A prepared successor can be replayed without retaining the recovery secret.
                    let url = try stagedURL(record, operation: progress.operation, digest: history.current.digest())
                    guard FileManager.default.fileExists(atPath: url.path) else { throw ItemRecoveryFailure.codeRequired }
                }
            }
        }
        let (verified, records) = try await rewrite(id, operation: progress.operation, decryptor: decryptor, signer: joining, check: check)
        progress.phase = .verifying; try check(); try store.save(progress)
        guard let metadata = records.first(where: { $0.0.scope.itemID == ItemVaultSession.metadataRecordID }) else { throw ItemRecoveryFailure.pending }
        let scope = try account.setupScope(vaultID: id)
        let bootstrap = try ItemVaultBootstrap(repository: repository, trustStore: trust, scope: scope, device: joining)
        let session: ItemVaultSession
        if let existing = try trust.load(scope: scope), try await repository.vaultInitialization(scope.repositoryScope) != nil {
            guard existing.pinnedDigest == (try verified.orderedStates[0].digest()) else { throw MopError.vaultUntrusted }
            try trust.reserveMembership(scope: scope, successors: verified.orderedStates.dropFirst().map { try $0.encoded() })
            session = try await bootstrap.open()
        } else {
            let later = verified.orderedStates.filter { $0.header.generation > approval.successor.header.generation }
            session = try await bootstrap.acceptFromAuthenticatedPrivateCloudKit(approval: approval, request: approval.request,
                metadata: metadata.0, metadataSystemFields: metadata.1, successors: later)
        }
        defer { session.lock() }
        for (value, fields) in records {
            try check(); try ItemEnvelopeTransition.verifyReadable(value, history: verified, device: joining)
            try await repository.applyRemote(value, serverSystemFields: fields)
        }
        if !progress.completed.contains(id) { progress.completed.append(id) }
        progress.phase = Set(progress.completed) == Set(progress.vaults) ? .complete : .enrolling
        try check(); try store.save(progress)
        if progress.phase == .complete { discardStaging(progress.operation) }
    }
}
