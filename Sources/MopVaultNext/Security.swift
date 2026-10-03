import Foundation
import CryptoKit
import MopCore

public extension VaultEngine {
    static func savePasswordChecks(_ checks: [CachedPasswordCheck], revision: String, in vault: VerifiedVault, device: any DeviceOperations) throws -> VerifiedVault? {
        guard vault.supportsSecurity else { throw MopError.legacyVault }
        guard revision == vault.digest else { throw MopError.vaultConflict }
        let role = vault.membership.role(of: device.identity)
        guard role == .owner || role == .editor else { throw MopError.cloudPermission }
        var payload = try vault.revision.payload(device: device)
        if payload.security?.passwordChecks == checks { return nil }
        payload.security?.passwordChecks = checks
        return try saveSecurity(payload, records: vault.revision.records, revision: revision, in: vault, device: device)
    }
    static func securityMetadata(in vault: VerifiedVault, device: any DeviceOperations) throws -> VaultSecurityMetadata {
        try vault.revision.payload(device: device).security ?? VaultSecurityMetadata()
    }
    static func upgradeSecurity(revision: String, in vault: VerifiedVault, device: any DeviceOperations) throws -> VerifiedVault {
        guard vault.membership.role(of: device.identity) == .owner else { throw MopError.cloudPermission }
        guard revision == vault.digest else { throw MopError.vaultConflict }
        var payload = try vault.revision.payload(device: device)
        payload.security = payload.security ?? VaultSecurityMetadata()
        var next = try header(vault, operation: .content)
        next.requiredFeatures = Set((next.requiredFeatures ?? []) + ["secret-history-1", "credential-redundancy-1"]).sorted()
        return try vault.applying(Revision.seal(header: next, references: payload.references, records: vault.revision.records,
            itemKeys: vault.revision.itemKeys, items: payload.items, security: payload.security, signer: device))
    }
    static func readHistory(_ entry: String, revision: String, in vault: VerifiedVault, device: any DeviceOperations) throws -> SecretBytes {
        guard revision == vault.digest else { throw MopError.vaultConflict }
        let payload = try vault.revision.payload(device: device)
        guard payload.security?.histories.contains(where: { $0.entries.contains { $0.id == entry } }) == true else { throw MopError.notFound }
        var bytes = try openRecord(entry, in: vault, device: device)
        defer { SecretBytes.wipe(&bytes) }
        return SecretBytes(copying: bytes)
    }
    static func restoreHistory(_ entry: String, revision: String, in vault: VerifiedVault, device: any DeviceOperations, at date: Date = Date()) throws -> VerifiedVault {
        let payload = try vault.revision.payload(device: device)
        guard let history = payload.security?.histories.first(where: { $0.entries.contains { $0.id == entry } }),
              let name = payload.itemIDs.first(where: { $0.value == history.itemID })?.key,
              payload.items.first(where: { $0.name == name })?.deletion == nil else { throw MopError.notFound }
        let value = try readHistory(entry, revision: revision, in: vault, device: device)
        return try write(SecretReference.encode(name) + "/" + history.path, value: value, in: vault, device: device, at: date)
    }
    static func clearHistory(_ field: UUID, revision: String, in vault: VerifiedVault, device: any DeviceOperations) throws -> VerifiedVault {
        var payload = try vault.revision.payload(device: device)
        guard let index = payload.security?.histories.firstIndex(where: { $0.id == field }) else { throw MopError.notFound }
        var records = vault.revision.records
        for entry in payload.security!.histories[index].entries { records.removeValue(forKey: entry.id) }
        payload.security!.histories[index].entries = []
        return try saveSecurity(payload, records: records, revision: revision, in: vault, device: device)
    }
    static func invalidateMissingLocalCredentials(_ ids: Set<UUID>, revision: String, in vault: VerifiedVault, device: any DeviceOperations) throws -> VerifiedVault? {
        var payload = try vault.revision.payload(device: device)
        guard payload.security != nil else { return nil }
        var changed = false
        for a in payload.security!.accounts.indices {
            for r in payload.security!.accounts[a].registrations.indices {
                let registration = payload.security!.accounts[a].registrations[r]
                if registration.deviceID == device.identity.device.uuidString, let id = registration.localIdentityID,
                   !registration.external, !ids.contains(id), registration.state != .removed {
                    payload.security!.accounts[a].registrations[r].state = .removed; changed = true
                }
            }
        }
        guard changed else { return nil }
        return try saveSecurity(payload, records: vault.revision.records, revision: revision, in: vault, device: device)
    }
    static func saveCredentialAccount(_ account: CredentialAccount, revision: String, in vault: VerifiedVault, device: any DeviceOperations, at date: Date = Date()) throws -> VerifiedVault {
        guard vault.supportsSecurity else { throw MopError.legacyVault }
        var payload = try vault.revision.payload(device: device)
        var account = account
        let previous = payload.security?.accounts.first { $0.id == account.id }
        for index in account.registrations.indices {
            let registration = account.registrations[index]
            let old = previous?.registrations.first { $0.id == registration.id }
            let accountChanged = previous.map { $0.service != account.service || $0.account != account.account || $0.relyingParty != account.relyingParty || $0.userHandle != account.userHandle } ?? false
            let reconfirmed = registration.confirmedAt != old?.confirmedAt
            if accountChanged && registration.state == .confirmed && !reconfirmed {
                account.registrations[index].state = .generated
                account.registrations[index].confirmedAt = nil
                account.registrations[index].confirmedBy = nil
            } else if registration.state == .confirmed && (reconfirmed || old?.protocolName != registration.protocolName || old?.state != .confirmed || old?.publicIdentifier != registration.publicIdentifier || old?.deviceID != registration.deviceID) {
                account.registrations[index].confirmedAt = date
                account.registrations[index].confirmedBy = device.identity.member.uuidString
            } else if registration.state == .confirmed {
                account.registrations[index].confirmedAt = old?.confirmedAt
                account.registrations[index].confirmedBy = old?.confirmedBy
            } else {
                account.registrations[index].confirmedAt = nil
                account.registrations[index].confirmedBy = nil
            }
        }
        try account.validate()
        payload.security = payload.security ?? VaultSecurityMetadata()
        payload.security!.accounts.removeAll { $0.id == account.id }
        payload.security!.accounts.append(account)
        return try saveSecurity(payload, records: vault.revision.records, revision: revision, in: vault, device: device)
    }
    private static func saveSecurity(_ payload: CatalogPayload, records: [String: SealedObject], revision: String, in vault: VerifiedVault, device: any DeviceOperations) throws -> VerifiedVault {
        guard revision == vault.digest else { throw MopError.vaultConflict }
        let role = vault.membership.role(of: device.identity)
        guard role == .owner || role == .editor else { throw MopError.cloudPermission }
        return try vault.applying(Revision.seal(header: header(vault, operation: .content), references: payload.references,
            records: records, itemKeys: vault.revision.itemKeys, items: payload.items, security: payload.security, signer: device))
    }
}
extension VaultEngine {
    static func retainPrevious(_ record: String, replacement: Data, itemID: String, path: String,
                               payload: inout CatalogPayload, records: inout [String: SealedObject],
                               vault: VerifiedVault, device: any DeviceOperations, at date: Date, key: SymmetricKey? = nil, fieldID: UUID? = nil) throws {
        guard vault.supportsSecurity else { return }
        var previous: Data
        if let key, let object = vault.revision.records[record], let generation = vault.revision.itemKeys[itemID]?.generation {
            previous = try object.open(using: key, authenticating: Codec.encode(FieldContext(vault: vault.id, item: itemID, generation: generation, field: record)))
        } else { previous = try openRecord(record, in: vault, device: device) }
        defer { SecretBytes.wipe(&previous) }
        guard previous != replacement else { return }
        payload.security = payload.security ?? VaultSecurityMetadata()
        let stableID = fieldID ?? payload.items.first(where: { payload.itemIDs[$0.name] == itemID })?.fields.first(where: { $0.path == path })?.historyID
        func matches(_ history: SecretFieldHistory) -> Bool {
            history.itemID == itemID && (stableID.map { history.id == $0 } ?? (history.path == path))
        }
        if !payload.security!.histories.contains(where: matches) {
            var history = SecretFieldHistory(itemID: itemID, path: path)
            history.id = stableID ?? history.id
            payload.security!.histories.append(history)
        }
        let index = payload.security!.histories.firstIndex(where: matches)!
        payload.security!.histories[index].entries.insert(SecretHistoryEntry(id: record, replacedAt: date), at: 0)
        while payload.security!.histories[index].entries.count > 20 {
            let removed = payload.security!.histories[index].entries.removeLast()
            records.removeValue(forKey: removed.id)
        }
    }
}
