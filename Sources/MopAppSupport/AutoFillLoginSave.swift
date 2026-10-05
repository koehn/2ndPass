import Foundation
import AuthenticationServices
import MopCore

/// A transient draft from the picker or the system's save-password ceremony.
/// Never persisted outside the encrypted vault or placed in the suggestion index.
public struct AutoFillLoginDraft: Sendable {
    public var name: String
    public var username: String
    public var password: String
    public var website: String
    public init(name: String, username: String, password: String, website: String) {
        self.name = name; self.username = username; self.password = password; self.website = website
    }
    public var canSave: Bool {
        !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !password.isEmpty && AutoFillEntry.website(website) != nil
    }
    public var canSaveAndFill: Bool { canSave && !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    /// A new login is durably saved before any credential is returned for filling.
    /// Discovery/generation never authorize this operation; authenticate freshly.
    public func saveAndPrepareFill(vault: String, service: any VaultService) async throws -> (credential: ASPasswordCredential, catalog: ItemCatalog) {
        guard canSaveAndFill else { throw AutoFillLoginSaveError.invalidDraft }
        service.lock()
        defer { service.lock() }
        let catalog = try await save(vault: vault, service: service)
        try Task.checkCancellation()
        return (ASPasswordCredential(user: username, password: password), catalog)
    }
    public func save(vault: String, service: any VaultService) async throws -> ItemCatalog {
        guard UUID(uuidString: vault) != nil, canSave else { throw AutoFillLoginSaveError.invalidDraft }
        let generation = service.sessionGeneration
        let catalog = try await service.execute(.catalog, vault: vault, offline: false).requireCatalog()
        guard catalog.canEdit == true else { throw AutoFillLoginSaveError.readOnly }
        try Task.checkCancellation()
        guard generation == service.sessionGeneration else { throw MopError.authentication }
        let item = VaultItem(name: name.trimmingCharacters(in: .whitespacesAndNewlines), type: .login, fields: [
            ItemField(path: "username", type: .username, value: username),
            ItemField(path: "password", type: .password, value: password),
            ItemField(path: "website", type: .website, value: website)
        ])
        // Create-only: a conflicting name must never overwrite an existing login.
        let result = try await service.execute(.save(ItemEdit(revision: catalog.revision, item: item, create: true)), vault: vault, offline: false)
        try Task.checkCancellation()
        guard generation == service.sessionGeneration, service.isAuthenticated, !result.usingCache else { throw MopError.authentication }
        return try result.requireCatalog()
    }
}

public enum AutoFillLoginSaveError: LocalizedError {
    case invalidDraft, readOnly
    public var errorDescription: String? {
        switch self {
        case .invalidDraft: "Enter a name and password, and choose a cloud vault for this login."
        case .readOnly: "You no longer have permission to save in this vault. Choose another vault."
        }
    }
}
