import Foundation
import LocalAuthentication
import MopCore
import MopKeychain

/// Projects device-local Secure Enclave identities into a read-only item catalog.
///
/// Private keys are never represented. Each item carries only the public key (the
/// OpenSSH line for signing identities, or the x963 point for key-agreement
/// identities) plus the protocol/algorithm, so the UI can never display or copy a
/// non-exportable private key. The identity's keychain UUID is carried in
/// `storageID` so detail/sign/delete can resolve the exact Secure Enclave key.
public enum LocalIdentityCatalog {
    /// The catalog revision marker for the fixed device-local vault.
    public static let revision = "device-local"

    public static func build(identities: [LocalIdentity]) -> ItemCatalog {
        let items = identities.map { identity -> VaultItem in
            var fields: [ItemField] = [ItemField(path: "publicKey", type: .text, value: publicKeyText(for: identity))]
            if identity.algorithm.supportsSigning {
                fields.append(ItemField(path: "comment", type: .text, value: identity.sshComment))
            }
            fields.append(ItemField(path: "notes", type: .notes, value: "\(identity.protocolType.rawValue) · \(identity.algorithm.rawValue)"))
            var item = VaultItem(name: identity.name, type: .sshKey, fields: fields)
            item.storageID = identity.id.uuidString
            return item
        }
        var catalog = ItemCatalog(vault: LocalVault.name, revision: revision, items: items)
        catalog.canEdit = false
        return catalog
    }

    /// Human-readable public key. OpenSSH line for signing keys, x963 hex otherwise.
    public static func publicKeyText(for identity: LocalIdentity) -> String {
        if identity.algorithm.supportsSigning {
            if let line = try? SSHPublicKey.openSSH(x963: identity.publicKey, comment: identity.sshComment) {
                return line
            }
        }
        return identity.publicKey.map { String(format: "%02x", $0) }.joined()
    }
}

/// Operations the fixed device-local vault can be asked to perform.
public enum LocalVaultOperation: Sendable, CaseIterable {
    case list, create, deleteItem, publicKey, sign
    case renameVault, renameItem, export, share, deleteVault
}

/// Pure policy for the device-local vault. Kept store-free so it can be unit-tested
/// without a Secure Enclave. The vault is always present, never created/deleted, and
/// non-exportable; individual identities are create- and delete-only (no rename).
public enum LocalVaultPolicy {
    public static func isAllowed(_ operation: LocalVaultOperation) -> Bool {
        switch operation {
        case .list, .create, .deleteItem, .publicKey, .sign:
            true
        case .renameVault, .renameItem, .export, .share, .deleteVault:
            false
        }
    }

    /// A concise reason an operation is rejected, or nil when it is allowed.
    public static func disallowedReason(_ operation: LocalVaultOperation) -> String? {
        guard !isAllowed(operation) else { return nil }
        return switch operation {
        case .renameVault:
            "The device-local vault is fixed and cannot be renamed."
        case .renameItem:
            "Device-local identities cannot be renamed."
        case .export:
            "The device-local vault is non-exportable; its keys never leave the Secure Enclave."
        case .share:
            "The device-local vault cannot be shared to other people or devices."
        case .deleteVault:
            "The device-local vault is part of this device and cannot be deleted."
        default:
            "This operation is not supported for the device-local vault."
        }
    }
}

/// The local operations used by the UI, independently of cloud authentication.
@MainActor
public protocol LocalVaultServing {
    func list() throws -> [LocalIdentity]
    func create(name: String, protocolType: LocalIdentityProtocol, context: LAContext) throws -> LocalIdentity
    func delete(id: UUID) throws
}

/// Device-local vault operations backed by the Secure Enclave.
///
/// This is deliberately a separate service, not a cloud `VaultService`: the local
/// vault has no account, no sync, and no revision history. It wraps
/// `LocalIdentityStore` and enforces `LocalVaultPolicy` so no caller can route a
/// forbidden operation (rename/export/share/delete-vault) through the local vault.
@MainActor
public final class LocalVaultService: LocalVaultServing {
    private let store: LocalIdentityStore

    public init() throws {
        store = try LocalIdentityStore.open()
    }

    public init(store: LocalIdentityStore) {
        self.store = store
    }

    // MARK: - Allowed operations

    /// A read-only projection of the current identities for display.
    public func catalog() throws -> ItemCatalog {
        LocalIdentityCatalog.build(identities: try store.list())
    }

    /// The current identities. Listing needs no authentication; public keys are not secret.
    public func list() throws -> [LocalIdentity] {
        try store.list()
    }

    public func publicKey(id: UUID) throws -> Data { try store.publicKey(id: id) }

    public func create(name: String, protocolType: LocalIdentityProtocol, context: LAContext) throws -> LocalIdentity {
        guard LocalVaultPolicy.isAllowed(.create) else { throw MopError.localOperationForbidden }
        return try store.create(name: name, protocolType: protocolType, context: context)
    }

    public func delete(id: UUID) throws {
        guard LocalVaultPolicy.isAllowed(.deleteItem) else { throw MopError.localOperationForbidden }
        try store.delete(id: id)
    }

    public func sign(id: UUID, data: Data, context: LAContext) throws -> Data {
        guard LocalVaultPolicy.isAllowed(.sign) else { throw MopError.localOperationForbidden }
        return try store.sign(id: id, data: data, context: context)
    }

    // MARK: - Forbidden operations

    public func renameVault(_ newName: String) throws {
        throw MopError.localOperationForbidden
    }

    public func renameItem(id: UUID, newName: String) throws {
        throw MopError.localOperationForbidden
    }

    public func export(to url: URL) throws {
        throw MopError.localOperationForbidden
    }

    public func share(_ to: String) throws {
        throw MopError.localOperationForbidden
    }

    public func deleteVault() throws {
        throw MopError.localOperationForbidden
    }
}