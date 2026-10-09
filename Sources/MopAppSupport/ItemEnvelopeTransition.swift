import Foundation
import MopCore
import MopSync
import MopVaultNext

/// Shared by recovery, enrollment repair, and returning-device catch-up.
/// The decryptor may be a recovery key; only an enrolled device signs content.
public enum ItemEnvelopeTransition {
    public static func membershipDigest(_ record: EncryptedItemVersion) throws -> String {
        struct Probe: Decodable { struct Header: Decodable { let membership: String }; let header: Header }
        return try JSONDecoder().decode(Probe.self, from: record.ciphertext).header.membership
    }
    public static func verify(_ record: EncryptedItemVersion, history: TrustedMembershipHistory) throws {
        let digest = try membershipDigest(record), state = try history.state(forDigest: digest)
        guard record.scope.vaultID == history.vault, !record.isTombstone else { throw MopError.invalidVault }
        if let item = record.healthItemID {
            let value = try ItemHealthEnvelope.decode(record.ciphertext, vault: history.vault, item: item,
                membership: state.membership, membershipStateDigest: digest)
            guard ItemHealthEnvelope.recordID(for: item) == record.scope.itemID, value.header.version == record.versionID,
                  value.header.base == record.baseVersionID, value.header.generation == record.generation else { throw MopError.invalidVault }
        } else if record.scope.itemID == ItemVaultSession.metadataRecordID {
            let value = try VaultMetadataEnvelope.decode(record.ciphertext, vault: history.vault,
                membership: state.membership, membershipStateDigest: digest)
            guard value.header.version == record.versionID, value.header.base == record.baseVersionID,
                  value.header.generation == record.generation else { throw MopError.invalidVault }
        } else {
            let value = try ItemEnvelope.decode(record.ciphertext, vault: history.vault, item: record.scope.itemID,
                membership: state.membership, membershipStateDigest: digest)
            guard value.header.version == record.versionID, value.header.base == record.baseVersionID,
                  value.header.generation == record.generation else { throw MopError.invalidVault }
        }
    }
    public static func verifyReadable(_ record: EncryptedItemVersion, history: TrustedMembershipHistory,
                                      device: any DeviceOperations) throws {
        try verify(record, history: history)
        let digest = try membershipDigest(record), state = try history.state(forDigest: digest)
        guard record.scope.vaultID == history.vault, !record.isTombstone else { throw MopError.invalidVault }
        if let item = record.healthItemID {
            let value = try JSONDecoder().decode(ItemHealthEnvelope.self, from: record.ciphertext)
            guard value.header.version == record.versionID, ItemHealthEnvelope.recordID(for: item) == record.scope.itemID,
                  value.header.item == item, value.header.vault == history.vault else { throw MopError.invalidVault }
            _ = try value.open(device: device, membership: state.membership, membershipStateDigest: digest)
        } else if record.scope.itemID == ItemVaultSession.metadataRecordID {
            let value = try JSONDecoder().decode(VaultMetadataEnvelope.self, from: record.ciphertext)
            guard value.header.version == record.versionID, value.header.vault == history.vault else { throw MopError.invalidVault }
            _ = try value.open(device: device, membership: state.membership, membershipStateDigest: digest)
        } else {
            let value = try ItemEnvelope.decode(record.ciphertext, vault: history.vault, item: record.scope.itemID,
                membership: state.membership, membershipStateDigest: digest)
            guard value.header.version == record.versionID else { throw MopError.invalidVault }
            _ = try value.portableArchive(name: "verification", device: device, membership: state.membership, membershipStateDigest: digest)
        }
    }
    public static func rewrite(_ record: EncryptedItemVersion, history: TrustedMembershipHistory,
                               decryptor: any DeviceOperations, signer: any DeviceOperations) throws -> EncryptedItemVersion {
        try verify(record, history: history)
        guard history.current.membership.role(of: signer.identity) == .owner,
              record.generation < UInt64(Int64.max) else { throw MopError.cloudPermission }
        let digest = try membershipDigest(record), previous = try history.state(forDigest: digest)
        try history.verifyAccountPath(from: digest)
        let target = history.current, targetDigest = try target.digest()
        guard digest != targetDigest else { return record }
        let bytes: Data, version: UUID
        if record.healthItemID != nil {
            let old = try JSONDecoder().decode(ItemHealthEnvelope.self, from: record.ciphertext)
            let value = try old.open(device: decryptor, membership: previous.membership, membershipStateDigest: digest)
            let next = try ItemHealthEnvelope.seal(value, vault: history.vault, item: old.header.item,
                generation: record.generation + 1, base: record.versionID, membership: target.membership,
                membershipStateDigest: targetDigest, signer: signer)
            bytes = try next.encoded(); version = next.header.version
        } else if record.scope.itemID == ItemVaultSession.metadataRecordID {
            let old = try JSONDecoder().decode(VaultMetadataEnvelope.self, from: record.ciphertext)
            let value = try old.open(device: decryptor, membership: previous.membership, membershipStateDigest: digest)
            let next = try VaultMetadataEnvelope.seal(value, vault: history.vault, generation: record.generation + 1,
                base: record.versionID, membership: target.membership, membershipStateDigest: targetDigest, signer: signer)
            bytes = try next.encoded(); version = next.header.version
        } else {
            let old = try ItemEnvelope.decode(record.ciphertext, vault: history.vault, item: record.scope.itemID,
                membership: previous.membership, membershipStateDigest: digest)
            let next: ItemEnvelope
            if (try? history.verifyAdditivePath(from: digest)) != nil {
                next = try old.repairingMembership(history: history, decryptor: decryptor, signer: signer)
            } else {
                let archive = try old.portableArchive(name: "vault", device: decryptor, membership: previous.membership, membershipStateDigest: digest)
                next = try ItemEnvelope.seal(archive, vault: history.vault, generation: record.generation + 1,
                    base: record.versionID, membership: target.membership, membershipStateDigest: targetDigest, signer: signer,
                    editOrigin: old.catalog(device: decryptor, membership: previous.membership, membershipStateDigest: digest).editOrigin)
            }
            bytes = try next.encoded(); version = next.header.version
        }
        return EncryptedItemVersion(scope: record.scope, versionID: version, baseVersionID: record.versionID,
            ciphertext: bytes, generation: record.generation + 1, healthItemID: record.healthItemID)
    }
}
