import Foundation

public enum VaultName {
    public static func validate(_ name: String) throws {
        let parts = name.utf8.split(separator: 45, omittingEmptySubsequences: false)
        guard !name.isEmpty, name.utf8.count <= 63,
              parts.allSatisfy({ !$0.isEmpty && $0.allSatisfy { (97...122).contains($0) || (48...57).contains($0) } })
        else { throw MopError.invalidVaultName }
    }
}

/// Discovery metadata is not trust evidence. Verify the header when unlocking.
public struct VaultDescriptor: Codable, Identifiable, Equatable, Sendable {
    public let id: String
    public let name: String?
    public let format: String
    public let enrolled: Bool
    public var supported: Bool { format == "mop-vault-v5" }
    public init(id: String, name: String?, format: String, enrolled: Bool) {
        self.id = id; self.name = name; self.format = format; self.enrolled = enrolled
    }
}
