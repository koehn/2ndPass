import Foundation
import MopCore

struct ItemRow: Identifiable {
    struct ID: Hashable { let vault: String; let name: String }
    let id: ID
    let vaultName: String
    let item: VaultItem
    var subtitle: String? {
        item.fields.first { [.username, .email, .website].contains($0.type) && !($0.value ?? "").isEmpty }?.value
    }
}

extension ItemType {
    var symbol: String {
        switch self {
        case .login: "person.crop.square"
        case .password: "key"
        case .apiCredential: "terminal"
        case .secureNote: "note.text"
        case .database: "externaldrive"
        case .custom: "square.grid.2x2"
        }
    }
}

struct ItemSearchResult: Identifiable {
    let row: ItemRow
    let field: ItemField?
    var id: ItemRow.ID { row.id }
    var detail: String {
        guard let field else { return row.vaultName }
        let label = (field.path.removingPercentEncoding ?? field.path).replacingOccurrences(of: "/", with: " / ")
        return label + (field.value.map { ": " + $0 } ?? "")
    }
}
