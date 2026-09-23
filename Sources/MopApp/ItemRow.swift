import Foundation
import MopCore

struct ItemRow: Identifiable {
    struct ID: Hashable { let vault: String; let name: String }
    let id: ID
    let vaultName: String
    let item: VaultItem
}
