import CryptoKit
import Foundation
import MopCore

/// Pure cryptographic operations. Publication, account binding, journal recovery,
/// and online requirements are the service's responsibility. No private or
/// symmetric key is retained by this engine between operations.
public enum VaultEngine {
    public static func create(name: String, owner: any DeviceOperations, recovery: DevicePublicKey? = nil, id: UUID = UUID()) throws -> VerifiedVault {
        let membership = try Membership(accounts: [AccountMember(id: owner.identity.member, role: .owner, devices: [owner.identity])], recovery: recovery)
        let header = Revision.Header(format: "mop-vault-v6", vault: id, name: name, generation: 1, parent: nil,
                                     epoch: 1, membership: membership, operation: .create, acceptedInvitations: [])
        let revision = try Revision.seal(header: header, references: [:], records: [:], signer: owner)
        try revision.verifyGenesis()
        return try VerifiedVault(revision: revision, bytes: revision.encoded())
    }
    public static func references(in vault: VerifiedVault, device: any DeviceOperations) throws -> [String] {
        try authorizeRead(vault, device)
        return try vault.revision.references(device: device).keys.sorted()
    }
    private static func authorizeRead(_ vault: VerifiedVault, _ device: any DeviceOperations) throws {
        guard vault.membership.role(of: device.identity) != nil || vault.membership.recovery == device.identity else { throw MopError.notVaultMember }
    }
    public static func read(_ reference: String, in vault: VerifiedVault, device: any DeviceOperations) throws -> SecretBytes {
        try authorizeRead(vault, device)
        let references = try vault.revision.references(device: device)
        guard let id = references[reference], let record = vault.revision.records[id] else { throw MopError.notFound }
        var bytes = try record.open(vault: vault.id, epoch: vault.revision.header.epoch, object: id, device: device,
                                    authenticating: Codec.encode(ObjectContext(vault: vault.id, object: id)))
        defer { SecretBytes.wipe(&bytes) }
        return SecretBytes(copying: bytes)
    }
    static func header(_ vault: VerifiedVault, operation: RevisionOperation, membership: Membership? = nil,
                               invitations: [UUID]? = nil) throws -> Revision.Header {
        let old = vault.revision.header
        guard old.generation < UInt64.max, membership == nil || old.epoch < UInt64.max else { throw MopError.invalidVault }
        return Revision.Header(format: "mop-vault-v6", vault: vault.id, name: vault.name,
            generation: old.generation + 1, parent: vault.digest,
            epoch: membership == nil ? old.epoch : old.epoch + 1,
            membership: membership ?? vault.membership, operation: operation,
            acceptedInvitations: (invitations ?? old.acceptedInvitations).sorted { $0.uuidString < $1.uuidString })
    }
    public static func write(_ reference: String, value: SecretBytes?, in vault: VerifiedVault, device: any DeviceOperations) throws -> VerifiedVault {
        guard !reference.isEmpty, reference.utf8.count <= 4096 else { throw MopError.invalidReference }
        let role = vault.membership.role(of: device.identity)
        guard role == .owner || role == .editor else { throw MopError.cloudPermission }
        var references = try vault.revision.references(device: device)
        var records = vault.revision.records
        if let old = references.removeValue(forKey: reference) { records.removeValue(forKey: old) }
        else if value == nil { throw MopError.notFound }
        if let value {
            let id = UUID().uuidString
            var bytes = Data(value)
            defer { SecretBytes.wipe(&bytes) }
            records[id] = try SealedObject.seal(bytes, vault: vault.id, epoch: vault.revision.header.epoch, object: id,
                membership: vault.membership, authenticating: Codec.encode(ObjectContext(vault: vault.id, object: id)))
            references[reference] = id
        }
        var items = try vault.revision.payload(device: device).items
        if let parsed = try? SecretReference(vault: vault.name, relativePath: reference),
           let item = items.firstIndex(where: { $0.name == parsed.item }) {
            let path = [parsed.section, parsed.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
            if let field = items[item].fields.firstIndex(where: { $0.path == path }) {
                if let value {
                    items[item].fields[field].value = items[item].fields[field].type.concealed ? nil : String(decoding: value, as: UTF8.self)
                    items[item].fields[field].passwordQuality = items[item].fields[field].type == .password ? PasswordEstimator.estimate(String(decoding: value, as: UTF8.self), userInputs: [parsed.item]) : nil
                } else { items[item].fields.remove(at: field) }
            }
            if items[item].fields.isEmpty { items.remove(at: item) }
        }
        let revision = try Revision.seal(header: header(vault, operation: .content), references: references, records: records, items: items, signer: device)
        return try vault.applying(revision.encoded())
    }
    public static func invite(member: UUID, role: MemberRole, to vault: VerifiedVault, owner: any DeviceOperations,
                              now: Date = Date(), expires: Date) throws -> Invitation {
        guard vault.membership.role(of: owner.identity) == .owner, expires > now,
              expires.timeIntervalSince(now) <= 7 * 24 * 60 * 60,
              role != .owner || member == vault.membership.owner else { throw MopError.cloudPermission }
        if let existing = vault.membership.accounts.first(where: { $0.id == member }), existing.role != role { throw MopError.cloudPermission }
        return try Invitation(vault: vault.id, checkpoint: vault.digest, member: member, role: role, expires: expires, issuer: owner)
    }
    public static func approve(_ acceptance: Acceptance, expectedDeviceFingerprint: String, in vault: VerifiedVault,
                               owner: any DeviceOperations, now: Date = Date()) throws -> VerifiedVault {
        guard vault.membership.role(of: owner.identity) == .owner else { throw MopError.cloudPermission }
        try acceptance.validate(now: now)
        let invitation = acceptance.invitation
        guard invitation.vault == vault.id, invitation.checkpoint == vault.digest,
              vault.membership.role(of: invitation.issuer) == .owner,
              acceptance.device.fingerprint == expectedDeviceFingerprint,
              !vault.revision.header.acceptedInvitations.contains(invitation.nonce),
              !(vault.membership.removedDevices ?? []).contains(acceptance.device.device),
              !vault.membership.devices.contains(where: { $0.device == acceptance.device.device && $0 != acceptance.device }),
              invitation.role != .owner || invitation.member == vault.membership.owner else { throw MopError.vaultUntrusted }
        var accounts = vault.membership.accounts
        if let index = accounts.firstIndex(where: { $0.id == invitation.member }) {
            let old = accounts[index]
            guard old.role == invitation.role else { throw MopError.cloudPermission }
            accounts[index] = AccountMember(id: old.id, role: old.role, devices: old.devices.contains(acceptance.device) ? old.devices : old.devices + [acceptance.device])
        } else { accounts.append(AccountMember(id: invitation.member, role: invitation.role, devices: [acceptance.device])) }
        let membership = try Membership(accounts: accounts, recovery: vault.membership.recovery, removedDevices: vault.membership.removedDevices)
        return try change(membership, in: vault, signer: owner, operation: .membership,
                          invitations: vault.revision.header.acceptedInvitations + [invitation.nonce])
    }
    public static func remove(device id: UUID, from vault: VerifiedVault, owner: any DeviceOperations) throws -> VerifiedVault {
        guard vault.membership.role(of: owner.identity) == .owner,
              vault.membership.devices.contains(where: { $0.device == id }) else { throw MopError.cloudPermission }
        let accounts = vault.membership.accounts.compactMap { account -> AccountMember? in
            let remaining = account.devices.filter { $0.device != id }
            return remaining.isEmpty ? nil : AccountMember(id: account.id, role: account.role, devices: remaining)
        }
        return try change(Membership(accounts: accounts, recovery: vault.membership.recovery, removedDevices: Array(Set((vault.membership.removedDevices ?? []) + [id])).sorted { $0.uuidString < $1.uuidString }), in: vault, signer: owner, operation: .membership)
    }
    public static func remove(member id: UUID, from vault: VerifiedVault, owner: any DeviceOperations) throws -> VerifiedVault {
        guard vault.membership.role(of: owner.identity) == .owner, id != vault.membership.owner,
              vault.membership.accounts.contains(where: { $0.id == id }) else { throw MopError.cloudPermission }
        return try change(Membership(accounts: vault.membership.accounts.filter { $0.id != id }, recovery: vault.membership.recovery, removedDevices: Array(Set((vault.membership.removedDevices ?? []) + vault.membership.devices.filter { $0.member == id }.map(\.device))).sorted { $0.uuidString < $1.uuidString }),
                          in: vault, signer: owner, operation: .membership)
    }
    public static func setRole(_ role: MemberRole, member: UUID, in vault: VerifiedVault, owner: any DeviceOperations) throws -> VerifiedVault {
        guard vault.membership.role(of: owner.identity) == .owner, member != vault.membership.owner,
              role != .owner, vault.membership.accounts.contains(where: { $0.id == member }) else { throw MopError.cloudPermission }
        let accounts = vault.membership.accounts.map { account in
            AccountMember(id: account.id, role: account.id == member ? role : account.role, devices: account.devices)
        }
        return try change(Membership(accounts: accounts, recovery: vault.membership.recovery, removedDevices: vault.membership.removedDevices), in: vault, signer: owner, operation: .membership)
    }
    public static func replaceRecovery(with recovery: DevicePublicKey, in vault: VerifiedVault, owner: any DeviceOperations) throws -> VerifiedVault {
        guard recovery.encryption != vault.membership.recovery?.encryption, recovery.signing != vault.membership.recovery?.signing else { throw MopError.invalidRecovery }
        guard vault.membership.role(of: owner.identity) == .owner else { throw MopError.cloudPermission }
        return try change(Membership(accounts: vault.membership.accounts, recovery: recovery, removedDevices: vault.membership.removedDevices), in: vault, signer: owner, operation: .membership)
    }
    public static func recover(_ vault: VerifiedVault, using recovery: any DeviceOperations, owner: DevicePublicKey,
                               replacementRecovery: DevicePublicKey) throws -> VerifiedVault {
        guard recovery.identity == vault.membership.recovery, replacementRecovery.encryption != recovery.identity.encryption, replacementRecovery.signing != recovery.identity.signing else { throw MopError.invalidRecovery }
        // In-place recovery retains the transport owner account. Lost-account
        // recovery must create a separate new vault/zone with a new trust root.
        guard owner.member == vault.membership.owner else { throw MopError.cloudPermission }
        return try change(Membership(accounts: [AccountMember(id: owner.member, role: .owner, devices: [owner])], recovery: replacementRecovery, removedDevices: Array(Set((vault.membership.removedDevices ?? []) + vault.membership.devices.filter { $0 != owner }.map(\.device))).sorted { $0.uuidString < $1.uuidString }),
                          in: vault, signer: recovery, operation: .recovery)
    }
    /// Recreates contents in another account without modifying/deleting the source.
    public static func recoverCopy(_ vault: VerifiedVault, using recovery: any DeviceOperations, name: String,
                                   owner: any DeviceOperations, replacementRecovery: DevicePublicKey) throws -> VerifiedVault {
        guard recovery.identity == vault.membership.recovery, replacementRecovery.encryption != recovery.identity.encryption, replacementRecovery.signing != recovery.identity.signing else { throw MopError.invalidRecovery }
        let membership = try Membership(accounts: [AccountMember(id: owner.identity.member, role: .owner, devices: [owner.identity])], recovery: replacementRecovery)
        let destination = UUID()
        var references: [String: String] = [:], records: [String: SealedObject] = [:]
        for (reference, sourceID) in try vault.revision.references(device: recovery) {
            guard let source = vault.revision.records[sourceID] else { throw MopError.invalidVault }
            let id = UUID().uuidString
            var plaintext = try source.open(vault: vault.id, epoch: vault.revision.header.epoch, object: sourceID,
                device: recovery, authenticating: Codec.encode(ObjectContext(vault: vault.id, object: sourceID)))
            defer { SecretBytes.wipe(&plaintext) }
            records[id] = try SealedObject.seal(plaintext, vault: destination, epoch: 1, object: id,
                membership: membership, authenticating: Codec.encode(ObjectContext(vault: destination, object: id)))
            references[reference] = id
        }
        // One new genesis, one plaintext at a time, and no intermediate snapshots.
        let header = Revision.Header(format: "mop-vault-v6", vault: destination, name: name, generation: 1,
                                     parent: nil, epoch: 1, membership: membership, operation: .create, acceptedInvitations: [])
        let root = try Revision.seal(header: header, references: references, records: records, items: vault.revision.payload(device: recovery).items, signer: owner)
        try root.verifyGenesis()
        return try VerifiedVault(revision: root, bytes: root.encoded())
    }
    private static func change(_ membership: Membership, in vault: VerifiedVault, signer: any DeviceOperations,
                               operation: RevisionOperation, invitations: [UUID]? = nil) throws -> VerifiedVault {
        let header = try header(vault, operation: operation, membership: membership, invitations: invitations)
        let previous = try vault.revision.references(device: signer)
        let removed = Set(vault.membership.recipients.map(\.fingerprint)).subtracting(membership.recipients.map(\.fingerprint))
        let rotate = !removed.isEmpty || operation == .recovery
        var references: [String: String] = [:], records: [String: SealedObject] = [:]
        for (reference, oldID) in previous {
            guard let old = vault.revision.records[oldID] else { throw MopError.invalidVault }
            if rotate {
                // One plaintext and key at a time; no bulk-decrypted vault buffer.
                let id = UUID().uuidString
                var bytes = try old.open(vault: vault.id, epoch: vault.revision.header.epoch, object: oldID, device: signer,
                                         authenticating: Codec.encode(ObjectContext(vault: vault.id, object: oldID)))
                defer { SecretBytes.wipe(&bytes) }
                records[id] = try SealedObject.seal(bytes, vault: vault.id, epoch: header.epoch, object: id,
                    membership: membership, authenticating: Codec.encode(ObjectContext(vault: vault.id, object: id)))
                references[reference] = id
            } else {
                let key = try old.key(vault: vault.id, epoch: vault.revision.header.epoch, object: oldID, device: signer)
                records[oldID] = try SealedObject(ciphertext: old.ciphertext,
                    envelopes: SealedObject.envelopes(key: key, vault: vault.id, epoch: header.epoch, object: oldID, membership: membership))
                references[reference] = oldID
            }
        }
        let revision = try Revision.seal(header: header, references: references, records: records, items: vault.revision.payload(device: signer).items, signer: signer)
        return try vault.applying(revision.encoded())
    }
}
