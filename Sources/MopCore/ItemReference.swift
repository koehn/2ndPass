import Foundation

/// A vault item reference, distinct from a reference to one of its secret fields.
/// Routing does not imply a storage backend or a particular kind of key.
public struct ItemReference: Hashable, Sendable, CustomStringConvertible {
    public let vault: String
    public let name: String

    public init(_ reference: String) throws {
        guard reference.hasPrefix("sp://"),
              reference.dropFirst(5).split(separator: "/", omittingEmptySubsequences: false).count == 2 else {
            throw MopError.invalidReference
        }
        let parts = reference.dropFirst(5).split(separator: "/", omittingEmptySubsequences: false)
        try self.init(vault: SecretReference.decode(String(parts[0])), name: SecretReference.decode(String(parts[1])))
    }

    public init(vault: String, name: String) throws {
        let normalizedVault = UUID(uuidString: vault)?.uuidString.lowercased() ?? vault
        let validated = try SecretReference(vault: normalizedVault, item: name, field: "item")
        self.vault = validated.vault
        self.name = validated.item
    }

    public var description: String {
        "sp://" + SecretReference.encode(vault) + "/" + SecretReference.encode(name)
    }
}
