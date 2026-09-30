import Foundation
import MopCore

/// Common presentation, without inserting local into a cloud descriptor/catalog.
public enum VaultPresentation: Identifiable, Sendable {
    case cloud(VaultDescriptor)
    case local
    public var id: String { switch self { case .cloud(let row): row.id; case .local: LocalVault.id } }
    public var name: String? { switch self { case .cloud(let row): row.name; case .local: LocalVault.name } }
    public var selection: VaultSelection? {
        switch self { case .local: .local; case .cloud(let row): (try? CloudVaultID(row.id)).map(VaultSelection.cloud) }
    }
}
