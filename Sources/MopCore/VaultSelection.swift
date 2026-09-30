import Foundation

/// The single, built-in, device-local vault. Its name is a fixed constant, not
/// user input, so it can never be renamed. It is never published to CloudKit,
/// shared, exported, backed up, or recoverable.
public enum LocalVault {
    /// Exact, stable vault name.
    public static let name = "local"
    /// Stable identifier. Chosen so it can never equal a cloud vault UUID.
    public static let id = "local-vault"

    public static func isLocal(_ selection: String) -> Bool {
        selection == name || selection == id
    }

    /// The device-local vault has no rename operation. Any attempt is a hard error
    /// rather than a no-op, so a caller can never silently rename it.
    public static func rename(to name: String) throws {
        throw MopError.localOperationForbidden
    }
}


/// Only cloud UUIDs cross the synchronized-vault boundary.
public struct CloudVaultID: Hashable, Codable, Sendable {
    public let value: UUID
    public init(_ value: UUID) { self.value = value }
    public init(_ string: String) throws {
        guard let value = UUID(uuidString: string) else { throw MopError.invalidVault }
        self.value = value
    }
    public var description: String { value.uuidString }
}

public enum VaultSelection: Hashable, Sendable {
    case cloud(CloudVaultID)
    case local
    public var id: String {
        switch self { case .cloud(let id): id.description; case .local: LocalVault.id }
    }
}

public enum CloudVaultBoundary {
    public static func requireCloud(_ selection: String?) throws {
        if let selection, LocalVault.isLocal(selection) { throw MopError.localOperationForbidden }
    }
    public static func validateName(_ name: String) throws {
        try VaultName.validate(name)
        guard name != LocalVault.name else { throw MopError.localOperationForbidden }
    }
}
