import Foundation
import MopCore
import MopSync
import MopVaultNext

public protocol ItemVaultInventoryStore: ItemVaultTrustStore {
    func records(container: String, environment: String, account: String) throws -> [ItemVaultSetupRecord]
}

/// Public-key verification rooted exclusively in this device's independent pin.
/// No device private key is required to receive ciphertext for an unopened vault.
struct ItemVaultPinnedAuthority: Sendable {
    let record: ItemVaultSetupRecord
    let history: TrustedMembershipHistory
    init(record: ItemVaultSetupRecord, memberID: UUID, successors: [Data] = []) throws {
        let genesis = try MembershipEnvelope.decode(record.genesis)
        history = try ItemVaultMembershipAuthority.history(record: record, successors: successors)
        guard genesis.membership.accounts.count == 1, genesis.membership.accounts[0].id == memberID,
              genesis.membership.accounts[0].role == .owner, genesis.membership.devices.count == 1,
              genesis.membership.offlineRecovery == nil else { throw ItemVaultBootstrapFailure.invalidTrust }
        self.record = record
    }
    func verify(_ version: EncryptedItemVersion) throws {
        let binding = record.scope.binding
        guard version.scope == binding.item(version.scope.itemID), !version.isTombstone,
              version.ciphertext.count <= PortableArchive.maximumSize else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        struct Probe: Decodable { struct Header: Decodable { let membership: String }; let header: Header }
        let digest = try JSONDecoder().decode(Probe.self, from: version.ciphertext).header.membership
        let state: MembershipEnvelope
        do { state = try history.state(forDigest: digest) }
        catch { throw CloudSyncAdapterError.membershipUnavailable }
        // Every accepted edge is additive-only: earlier authors remain authorized.
        // Signed per-item generations still reject replay of an older value.
        let membership = state.membership
        if version.scope.itemID == ItemVaultSession.metadataRecordID {
            let value = try VaultMetadataEnvelope.decode(version.ciphertext, vault: binding.vaultID,
                membership: membership, membershipStateDigest: digest)
            guard value.header.version == version.versionID, value.header.base == version.baseVersionID,
                  value.header.generation == version.generation,
                  let author = membership.devices.first(where: { $0.fingerprint == value.header.author }),
                  membership.role(of: author) == .owner else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        } else {
            let value = try ItemEnvelope.decode(version.ciphertext, vault: binding.vaultID, item: version.scope.itemID,
                membership: membership, membershipStateDigest: digest)
            guard value.header.version == version.versionID, value.header.base == version.baseVersionID,
                  value.header.generation == version.generation else { throw ItemVaultSessionFailure.invalidEnvelopeBinding }
        }
    }
}
