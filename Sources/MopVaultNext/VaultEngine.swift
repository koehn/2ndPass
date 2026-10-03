import CryptoKit
import Foundation
import MopCore

/// Pure cryptographic operations. Publication, account binding, journal recovery,
/// and online requirements are the service's responsibility. No private or
/// symmetric key is retained by this engine between operations.
public enum VaultEngine {
    public static func create(name: String, owner: any DeviceOperations, recovery: DevicePublicKey? = nil, id: UUID = UUID()) throws -> VerifiedVault {
        try CloudVaultBoundary.validateName(name)
        let membership = try Membership(accounts: [AccountMember(id: owner.identity.member, role: .owner, devices: [owner.identity])], offlineRecovery: recovery)
        let header = Revision.Header(requiredFeatures: ["credential-redundancy-1", "secret-history-1"], format: "mop-vault-v7", vault: id, name: name, generation: 1, parent: nil,
                                     epoch: 1, membership: membership, operation: .create, acceptedInvitations: [])
        let revision = try Revision.seal(header: header, references: [:], records: [:], security: VaultSecurityMetadata(), signer: owner)
        try revision.verifyGenesis()
        return try VerifiedVault(revision: revision, bytes: revision.encoded())
    }
    public static func references(in vault: VerifiedVault, device: any DeviceOperations) throws -> [String] {
        try authorizeRead(vault, device)
        return try vault.revision.references(device: device).keys.sorted()
    }
    private static func authorizeRead(_ vault: VerifiedVault, _ device: any DeviceOperations) throws {
        guard vault.membership.role(of: device.identity) != nil || vault.membership.offlineRecovery == device.identity else { throw MopError.notVaultMember }
    }
    public static func read(_ reference: String, in vault: VerifiedVault, device: any DeviceOperations) throws -> SecretBytes {
        try authorizeRead(vault, device)
        let references = try vault.revision.references(device: device)
        guard let id = references[reference], vault.revision.records[id] != nil else { throw MopError.notFound }
        var bytes = try openRecord(id, in: vault, device: device)
        defer { SecretBytes.wipe(&bytes) }
        return SecretBytes(copying: bytes)
    }
    static func header(_ vault: VerifiedVault, operation: RevisionOperation, membership: Membership? = nil,
                               invitations: [UUID]? = nil) throws -> Revision.Header {
        let old = vault.revision.header
        guard old.generation < UInt64.max, membership == nil || old.epoch < UInt64.max else { throw MopError.invalidVault }
        return Revision.Header(requiredFeatures: old.requiredFeatures, format: "mop-vault-v7", vault: vault.id, name: vault.name,
            generation: old.generation + 1, parent: vault.digest,
            epoch: membership == nil ? old.epoch : old.epoch + 1,
            membership: membership ?? vault.membership, operation: operation,
            acceptedInvitations: (invitations ?? old.acceptedInvitations).sorted { $0.uuidString < $1.uuidString })
    }
    public static func write(_ reference: String, value: SecretBytes?, in vault: VerifiedVault, device: any DeviceOperations, at date: Date = Date()) throws -> VerifiedVault {
        guard !reference.isEmpty, reference.utf8.count <= 4096 else { throw MopError.invalidReference }
        let role = vault.membership.role(of: device.identity)
        guard role == .owner || role == .editor else { throw MopError.cloudPermission }
        var payload = try vault.revision.payload(device: device)
        var references = payload.references
        var keys = vault.revision.itemKeys
        let name = try SecretReference(vault: vault.name, relativePath: reference).item
        let itemID = try references.first { try SecretReference(vault: vault.name, relativePath: $0.key).item == name }.flatMap { vault.revision.records[$0.value]?.itemID } ?? UUID().uuidString
        var records = vault.revision.records
        let existingKey = try value == nil ? nil : keys[itemID]?.unwrap(vault: vault.id, item: itemID, device: device)
        if let old = references.removeValue(forKey: reference) {
            let ref = try SecretReference(vault: vault.name, relativePath: reference)
            let path = [ref.section, ref.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
            let type = payload.items.first { $0.name == name }?.fields.first { $0.path == path }?.type ?? .concealed
            if let value, [.password, .concealed].contains(type) {
                try retainPrevious(old, replacement: Data(value), itemID: itemID, path: path, payload: &payload, records: &records, vault: vault, device: device, at: date, key: existingKey)
            }
            if !(payload.security?.histories.contains { $0.entries.contains { $0.id == old } } ?? false) { records.removeValue(forKey: old) }
        }
        else if value == nil { throw MopError.notFound }
        if let value {
            let id = UUID().uuidString
            var bytes = Data(value)
            defer { SecretBytes.wipe(&bytes) }
            let key: SymmetricKey
            if let existingKey { key = existingKey }
            else {
                key = SymmetricKey(size: .bits256)
                keys[itemID] = try ItemKey.wrap(key, vault: vault.id, item: itemID, generation: 1, recipients: vault.membership.recipients)
            }
            records[id] = try SealedObject.field(bytes, key: key, vault: vault.id, item: itemID, generation: keys[itemID]!.generation, id: id)
            references[reference] = id
        }
        var items = try catalog(payload, in: vault, device: device).items + payload.items.filter { $0.deletion != nil }
        if !items.contains(where: { $0.name == name }), value != nil {
            var item = VaultItem(name: name, fields: [])
            item.metadata = ItemMetadata(createdAt: date, addedAt: date, updatedAt: date)
            items.append(item)
        }
        if let parsed = try? SecretReference(vault: vault.name, relativePath: reference),
           let item = items.firstIndex(where: { $0.name == parsed.item }) {
            let path = [parsed.section, parsed.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
            if items[item].metadata == nil { items[item].metadata = ItemMetadata() }
            items[item].metadata?.updatedAt = date
            if !items[item].fields.contains(where: { $0.path == path }), value != nil {
                items[item].fields.append(ItemField(path: path))
            }
            if let field = items[item].fields.firstIndex(where: { $0.path == path }) {
                if let value {
                    if items[item].fields[field].type == .attachment { _ = try Attachment.decode(String(decoding: value, as: UTF8.self)) }
                    if items[item].fields[field].type.isCompound { _ = try CompoundField(String(decoding: value, as: UTF8.self)) }
                    items[item].fields[field].value = items[item].fields[field].type.concealed ? nil : String(decoding: value, as: UTF8.self)
                    items[item].fields[field].passwordQuality = items[item].fields[field].type == .password ? PasswordEstimator.estimate(String(decoding: value, as: UTF8.self), userInputs: [parsed.item]) : nil
                } else { items[item].fields.remove(at: field) }
            }
            if items[item].fields.isEmpty { items.remove(at: item) }
        }
        let revision = try Revision.seal(header: header(vault, operation: .content), references: references, records: records, itemKeys: keys, items: items, security: payload.security, signer: device)
        return try vault.applying(revision)
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
        let membership = try Membership(accounts: accounts, offlineRecovery: vault.membership.offlineRecovery, removedDevices: vault.membership.removedDevices)
        return try change(membership, in: vault, signer: owner, operation: .membership,
                          invitations: vault.revision.header.acceptedInvitations + [invitation.nonce])
    }
    public static func remove(device id: UUID, from vault: VerifiedVault, owner: any DeviceOperations,
                              progress: ((Int, Int) throws -> Void)? = nil) throws -> VerifiedVault {
        guard vault.membership.role(of: owner.identity) == .owner,
              vault.membership.devices.contains(where: { $0.device == id }) else { throw MopError.cloudPermission }
        let accounts = vault.membership.accounts.compactMap { account -> AccountMember? in
            let remaining = account.devices.filter { $0.device != id }
            return remaining.isEmpty ? nil : AccountMember(id: account.id, role: account.role, devices: remaining)
        }
        return try change(Membership(accounts: accounts, offlineRecovery: vault.membership.offlineRecovery, removedDevices: Array(Set((vault.membership.removedDevices ?? []) + [id])).sorted { $0.uuidString < $1.uuidString }), in: vault, signer: owner, operation: .membership, progress: progress)
    }
    public static func remove(member id: UUID, from vault: VerifiedVault, owner: any DeviceOperations) throws -> VerifiedVault {
        guard vault.membership.role(of: owner.identity) == .owner, id != vault.membership.owner,
              vault.membership.accounts.contains(where: { $0.id == id }) else { throw MopError.cloudPermission }
        return try change(Membership(accounts: vault.membership.accounts.filter { $0.id != id }, offlineRecovery: vault.membership.offlineRecovery, removedDevices: Array(Set((vault.membership.removedDevices ?? []) + vault.membership.devices.filter { $0.member == id }.map(\.device))).sorted { $0.uuidString < $1.uuidString }),
                          in: vault, signer: owner, operation: .membership)
    }
    public static func setRole(_ role: MemberRole, member: UUID, in vault: VerifiedVault, owner: any DeviceOperations) throws -> VerifiedVault {
        guard vault.membership.role(of: owner.identity) == .owner, member != vault.membership.owner,
              role != .owner, vault.membership.accounts.contains(where: { $0.id == member }) else { throw MopError.cloudPermission }
        let accounts = vault.membership.accounts.map { account in
            AccountMember(id: account.id, role: account.id == member ? role : account.role, devices: account.devices)
        }
        return try change(Membership(accounts: accounts, offlineRecovery: vault.membership.offlineRecovery, removedDevices: vault.membership.removedDevices), in: vault, signer: owner, operation: .membership)
    }
    public static func setOfflineRecovery(_ recovery: DevicePublicKey?, in vault: VerifiedVault, owner: any DeviceOperations) throws -> VerifiedVault {
        guard vault.membership.role(of: owner.identity) == .owner else { throw MopError.cloudPermission }
        if let old = vault.membership.offlineRecovery, let recovery, old != recovery {
            guard old.encryption != recovery.encryption, old.signing != recovery.signing else { throw MopError.invalidRecovery }
        }
        return try change(Membership(accounts: vault.membership.accounts, offlineRecovery: recovery, removedDevices: vault.membership.removedDevices), in: vault, signer: owner, operation: .membership)
    }
    public static func recover(_ vault: VerifiedVault, using recovery: any DeviceOperations, owner: DevicePublicKey) throws -> VerifiedVault {
        guard recovery.identity == vault.membership.offlineRecovery, owner.member == vault.membership.owner else { throw MopError.invalidRecovery }
        let accounts = vault.membership.accounts.map { account in
            guard account.id == owner.member else { return account }
            return AccountMember(id: account.id, role: account.role,
                devices: account.devices.contains(owner) ? account.devices : account.devices + [owner])
        }
        return try change(Membership(accounts: accounts, offlineRecovery: recovery.identity,
            removedDevices: vault.membership.removedDevices), in: vault, signer: recovery, operation: .recovery)
    }
    private static func change(_ membership: Membership, in vault: VerifiedVault, signer: any DeviceOperations,
                               operation: RevisionOperation, invitations: [UUID]? = nil,
                               progress: ((Int, Int) throws -> Void)? = nil) throws -> VerifiedVault {
        let header = try header(vault, operation: operation, membership: membership, invitations: invitations)
        var payload = try vault.revision.payload(device: signer)
        let removedDeviceIDs = Set(vault.membership.devices.map { $0.device.uuidString }).subtracting(membership.devices.map { $0.device.uuidString })
        if payload.security != nil {
            for a in payload.security!.accounts.indices {
                for r in payload.security!.accounts[a].registrations.indices where removedDeviceIDs.contains(payload.security!.accounts[a].registrations[r].deviceID) {
                    payload.security!.accounts[a].registrations[r].state = .removed
                }
            }
        }
        let removed = Set(vault.membership.recipients.map(\.fingerprint)).subtracting(membership.recipients.map(\.fingerprint))
        let added = membership.recipients.filter { recipient in !vault.membership.recipients.contains { $0.fingerprint == recipient.fingerprint } }
        let rotate = !removed.isEmpty || operation == .recovery
        var references = payload.references, records = vault.revision.records, keys = vault.revision.itemKeys
        let paths = Dictionary(uniqueKeysWithValues: payload.references.map { ($0.value, $0.key) })
        let grouped = Dictionary(grouping: records.keys, by: { records[$0]!.itemID! })
        try progress?(0, keys.count)
        var completed = 0
        for (item, old) in vault.revision.itemKeys {
            try Task.checkCancellation()
            if rotate {
                guard old.generation < UInt64.max else { throw MopError.invalidVault }
                let source = try old.unwrap(vault: vault.id, item: item, device: signer)
                let key = SymmetricKey(size: .bits256), generation = old.generation + 1
                keys[item] = try ItemKey.wrap(key, vault: vault.id, item: item, generation: generation, recipients: membership.recipients)
                for oldID in grouped[item] ?? [] {
                    let record = records.removeValue(forKey: oldID)!
                    var bytes = try record.open(using: source, authenticating: Codec.encode(FieldContext(vault: vault.id, item: item, generation: old.generation, field: oldID)))
                    defer { SecretBytes.wipe(&bytes) }
                    let id = UUID().uuidString
                    records[id] = try SealedObject.field(bytes, key: key, vault: vault.id, item: item, generation: generation, id: id)
                    if let path = paths[oldID] { references[path] = id }
                    else if let h = payload.security?.histories.firstIndex(where: { $0.entries.contains { $0.id == oldID } }),
                            let e = payload.security?.histories[h].entries.firstIndex(where: { $0.id == oldID }) {
                        payload.security?.histories[h].entries[e].id = id
                    } else { throw MopError.invalidVault }
                }
            } else if !added.isEmpty {
                let key = try old.unwrap(vault: vault.id, item: item, device: signer)
                let additions = try ItemKey.wrap(key, vault: vault.id, item: item, generation: old.generation, recipients: added)
                keys[item]!.envelopes.merge(additions.envelopes) { _, new in new }
            }
            completed += 1
            try progress?(completed, keys.count)
        }
        let revision = try Revision.seal(header: header, references: references, records: records, itemKeys: keys, items: payload.items, security: payload.security, signer: signer)
        return try vault.applying(revision)
    }

    static func openRecord(_ id: String, in vault: VerifiedVault, device: any DeviceOperations) throws -> Data {
        guard let record = vault.revision.records[id], let item = record.itemID, let wrapped = vault.revision.itemKeys[item] else { throw MopError.invalidVault }
        let key = try wrapped.unwrap(vault: vault.id, item: item, device: device)
        return try record.open(using: key, authenticating: Codec.encode(FieldContext(vault: vault.id, item: item, generation: wrapped.generation, field: id)))
    }
}
