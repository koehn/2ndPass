import Foundation
import CryptoKit
import Security
import MopCore
import MopCredentials
import MopLocalIdentity

public struct CloudCredentialRecord: Sendable, Identifiable {
    public let vault: String
    public let item: VaultItem
    public var id: String { vault + ":" + (item.storageID ?? item.name) }
    public var credential: KeyCredential { item.credential! }
    public init(vault: String, item: VaultItem) throws {
        guard item.credential != nil else { throw CredentialFailure.invalid }
        try CloudKey.validate(item: item); self.vault = vault
        var publicItem = item
        for i in publicItem.fields.indices where publicItem.fields[i].type.concealed { publicItem.fields[i].value = nil }
        self.item = publicItem
    }
    public var sshBlob: Data {
        if credential.algorithm == .p256 { return (try? SSHPublicKey.wireBlob(x963: credential.publicKey)) ?? Data() }
        return credential.publicKey
    }
    public var fingerprint: String { CloudKey.fingerprint(sshBlob) }
    public var publicKeyText: String {
        let name = credential.algorithm == .p256 ? "ecdsa-sha2-nistp256" : credential.algorithm == .rsa ? "ssh-rsa" : "ssh-ed25519"
        return name + " " + sshBlob.base64EncodedString() + " " + item.name
    }
}
/// All reads and writes use the existing authenticated vault boundary and membership checks.
public struct CloudCredentialService: Sendable {
    public struct PasskeyDiscovery: Sendable {
        public var vaults: [VaultDescriptor] = []
        public var records: [CloudCredentialRecord] = []
        public var unavailableVaults = 0
    }
    public let vaultService: any VaultService
    public init(_ service: any VaultService) { vaultService = service }
    /// Resolve public suggestion metadata only after the user selects an account.
    /// The live catalog, rather than the suggestion index, authorizes credential use.
    public func resolvePasskey(_ suggestion: AutoFillIdentity, relyingParty: String, allowed: [Data]) async throws -> CloudCredentialRecord {
        guard suggestion.matchesPasskey(relyingParty: relyingParty, allowed: allowed),
              let vault = AutoFillEntry.vaultID(suggestion.recordIdentifier) else { throw MopError.notFound }
        let rows = try await records(vault: vault)
        try Task.checkCancellation()
        guard let row = rows.first(where: { AutoFillIdentity(passkey: $0.item, vaultID: vault) == suggestion }) else { throw MopError.notFound }
        return row
    }
    public func discoverPasskeys(relyingParty: String, allowed: [Data], registration: Bool) async throws -> PasskeyDiscovery {
        let generation = vaultService.sessionGeneration
        let discovery = try await vaultService.execute(.discover, vault: nil, offline: false)
        var result = PasskeyDiscovery()
        for vault in discovery.vaults where vault.enrolled && vault.supported {
            try Task.checkCancellation()
            guard generation == vaultService.sessionGeneration else { throw MopError.authentication }
            do {
                let catalog = try await vaultService.execute(.catalog, vault: vault.id, offline: false).requireCatalog()
                if !registration || catalog.canEdit == true { result.vaults.append(vault) }
                for item in catalog.items where item.deletion == nil && !item.isArchived {
                    guard let credential = item.credential, credential.purposes == [.passkey],
                          credential.relyingParty == relyingParty, let id = credential.credentialID,
                          allowed.isEmpty || allowed.contains(id) else { continue }
                    result.records.append(try CloudCredentialRecord(vault: vault.id, item: item))
                }
            } catch {
                try Task.checkCancellation()
                guard generation == vaultService.sessionGeneration else { throw MopError.authentication }
                // A stale or inaccessible vault must not hide other accessible credentials.
                result.unavailableVaults += 1
            }
        }
        try Task.checkCancellation()
        guard generation == vaultService.sessionGeneration else { throw MopError.authentication }
        return result
    }
    /// Normalize legacy SSH text fields as part of the original revision-bound save.
    public func prepareSSHSave(_ edit: ItemEdit, vault: String, purpose: CredentialPurpose = .ssh,
                               passphrase: SecretBytes? = nil) async throws -> ItemEdit {
        guard edit.item.type == .sshKey, edit.item.credential == nil else { return edit }
        guard !LocalVault.isLocal(vault) else { throw CredentialFailure.localImport }
        try CloudVaultBoundary.requireCloud(vault)
        guard purpose == .ssh || purpose == .gitSigning else { throw CredentialFailure.invalid }
        let generation = vaultService.sessionGeneration
        let catalog = try await vaultService.execute(.catalog, vault: vault, offline: false).requireCatalog()
        guard catalog.canEdit == true else { throw MopError.cloudPermission }
        guard catalog.revision == edit.revision else { throw MopError.vaultConflict }
        let original = edit.originalName ?? edit.item.name
        func value(_ path: String) async throws -> SecretBytes? {
            guard let field = edit.item.fields.first(where: { $0.path == path }) else { return nil }
            if let value = field.value { return SecretBytes(utf8: value) }
            guard !edit.create else { return nil }
            let reference = try SecretReference(vault: catalog.vault, relativePath: SecretReference.encode(original) + "/" + path)
            return try await vaultService.execute(.read(reference), vault: vault, offline: false).value
        }
        guard let bytes = try await value("privateKey"), !bytes.isEmpty else { throw CredentialFailure.invalid }
        let password: SecretBytes?
        if let passphrase { password = passphrase } else { password = try await value("passphrase") }
        let key = try await Task.detached { try OpenSSHImport.read(bytes, passphrase: password) }.value
        try Task.checkCancellation()
        guard generation == vaultService.sessionGeneration, vaultService.isAuthenticated else { throw MopError.authentication }
        let normalized = try key.item(name: edit.item.name, purposes: [purpose])
        var result = edit
        result.item.credential = normalized.credential
        result.item.fields = normalized.fields + edit.item.fields.filter {
            !["privateKey", "publicKey", "passphrase", "fingerprint", KeyCredential.privateField].contains($0.path)
        }
        return result
    }
    public func records(vault: String, offline: Bool = false) async throws -> [CloudCredentialRecord] {
        try CloudVaultBoundary.requireCloud(vault)
        let generation = vaultService.sessionGeneration
        let catalog = try await vaultService.execute(.catalog, vault: vault, offline: offline).requireCatalog()
        guard generation == vaultService.sessionGeneration else { throw MopError.authentication }
        return try catalog.items.filter { $0.credential != nil && !$0.isArchived && $0.deletion == nil }.map { try CloudCredentialRecord(vault: vault, item: $0) }
    }
    public func createSSH(vault: String, name: String, algorithm: CredentialAlgorithm = .ed25519, purposes: [CredentialPurpose]) async throws -> CloudCredentialRecord {
        try CloudVaultBoundary.requireCloud(vault)
        guard !purposes.contains(.passkey) else { throw CredentialFailure.invalid }
        let key = try CloudKey.generate(algorithm)
        return try await save(try key.item(name: name, purposes: purposes), vault: vault)
    }
    public func importSSH(vault: String, name: String, bytes: SecretBytes, passphrase: SecretBytes? = nil, purposes: [CredentialPurpose], converting: Bool = false) async throws -> CloudCredentialRecord {
        guard !LocalVault.isLocal(vault) else { throw CredentialFailure.localImport }
        guard !purposes.contains(.passkey) else { throw CredentialFailure.invalid }
        let key = try OpenSSHImport.read(bytes, passphrase: passphrase)
        return try await save(try key.item(name: name, purposes: purposes), vault: vault, converting: converting)
    }
    private func save(_ item: VaultItem, vault: String, converting: Bool = false) async throws -> CloudCredentialRecord {
        let generation = vaultService.sessionGeneration
        var item = item
        try CloudVaultBoundary.requireCloud(vault)
        _ = try LocalIdentity.validateName(item.name)
        let catalog = try await vaultService.execute(.catalog, vault: vault, offline: false).requireCatalog()
        guard catalog.canEdit == true else { throw MopError.cloudPermission }
        if converting {
            guard let old = catalog.items.first(where: { $0.name == item.name }), old.type == .sshKey, old.credential == nil else { throw CredentialFailure.invalid }
            item.metadata = old.metadata
            item.fields += old.fields.filter { !["privateKey", "publicKey", "passphrase", "fingerprint", KeyCredential.privateField].contains($0.path) }
        }
        let result = try await vaultService.execute(.save(ItemEdit(revision: catalog.revision, item: item, create: !converting)), vault: vault, offline: false)
        guard generation == vaultService.sessionGeneration, !result.usingCache, vaultService.isAuthenticated else { throw MopError.authentication }
        try Task.checkCancellation()
        let saved = result.catalog?.items.first { $0.name == item.name } ?? item
        return try CloudCredentialRecord(vault: vault, item: saved)
    }
    public func key(_ record: CloudCredentialRecord, offline: Bool = false) async throws -> CloudKey {
        let generation = vaultService.sessionGeneration
        let current = try await records(vault: record.vault, offline: offline)
        guard let row = current.first(where: { $0.id == record.id }), row.credential == record.credential else { throw MopError.notFound }
        let catalog = try await vaultService.execute(.catalog, vault: record.vault, offline: offline).requireCatalog()
        let ref = try SecretReference(vault: catalog.vault, relativePath: SecretReference.encode(row.item.name) + "/" + KeyCredential.privateField)
        guard let secret = try await vaultService.execute(.read(ref), vault: record.vault, offline: offline).value,
              var bytes = secret.withFoundationData({ Data(base64Encoded: $0) }) else { throw CredentialFailure.invalid }
        defer { SecretBytes.wipe(&bytes) }
        let key = try CloudKey(algorithm: row.credential.algorithm, privateBytes: SecretBytes(copying: bytes))
        guard key.publicKey == row.credential.publicKey, generation == vaultService.sessionGeneration, vaultService.isAuthenticated else { throw CredentialFailure.invalid }
        try Task.checkCancellation()
        return key
    }
    public func registerPasskey(vault: String, relyingParty: String, userName: String, userHandle: Data, clientDataHash: Data, algorithms: [Int]) async throws -> CloudCredentialRecord {
        guard clientDataHash.count == 32, algorithms.contains(-7) else { throw CredentialFailure.unsupportedAlgorithm }
        let key = try CloudKey.generate(.p256)
        var credentialID = Data(count: 32)
        guard credentialID.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else { throw CredentialFailure.invalid }
        var item = try key.item(name: String((userName + "@" + relyingParty).prefix(45)) + "-" + UUID().uuidString.prefix(8), purposes: [.ssh])
        item.type = .passkey
        item.credential = KeyCredential(algorithm: .p256, publicKey: key.publicKey, purposes: [.passkey], relyingParty: relyingParty, userName: userName, userHandle: userHandle, credentialID: credentialID)
        try CloudKey.validate(item: item)
        return try await save(item, vault: vault)
    }
    public func assertPasskey(_ record: CloudCredentialRecord, relyingParty: String, allowed: [Data], clientDataHash: Data) async throws -> (authenticatorData: Data, signature: Data) {
        guard record.credential.purposes == [.passkey], record.credential.relyingParty == relyingParty,
              let id = record.credential.credentialID, allowed.isEmpty || allowed.contains(id), clientDataHash.count == 32 else { throw CredentialFailure.invalid }
        let generation = vaultService.sessionGeneration
        let key = try await key(record)
        let data = Self.authenticatorData(relyingParty: relyingParty)
        let signature = try key.signPasskey(data + clientDataHash)
        try Task.checkCancellation()
        guard generation == vaultService.sessionGeneration, vaultService.isAuthenticated else { throw MopError.authentication }
        return (data, signature)
    }
    public static func authenticatorData(relyingParty: String) -> Data { Data(SHA256.hash(data: Data(relyingParty.utf8))) + Data([0x1d, 0, 0, 0, 0]) }
    public static func attestation(_ record: CloudCredentialRecord) throws -> Data {
        let c = record.credential
        guard let rp = c.relyingParty, let user = c.userName, let handle = c.userHandle, let id = c.credentialID else { throw CredentialFailure.invalid }
        let metadata = try PasskeyMetadata(relyingParty: rp, userName: user, userHandle: handle, credentialID: id)
        return try LocalWebAuthn.attestation(metadata: metadata, publicKey: c.publicKey, backedUp: true)
    }
}
