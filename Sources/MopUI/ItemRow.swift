import Foundation
import MopCore

struct ItemRow: Identifiable {
    struct ID: Hashable { let vault: String; let name: String }
    let id: ID
    let vaultName: String
    let item: VaultItem
    var searchDetail: String? = nil
    var recentDate: Date? = nil
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
        case .sshKey: "terminal"
        case .paymentCard: "creditcard"
        case .identity: "person.text.rectangle"
        case .document: "doc"
        case .custom: "square.grid.2x2"
        }
    }
}

struct ItemSearchResult: Identifiable {
    var row: ItemRow
    let field: ItemField?
    var tag: String? = nil
    var id: ItemRow.ID { row.id }
    var detail: String {
        guard let field else { return tag.map { "Tag: " + $0 } ?? row.vaultName }
        let label = (field.path.removingPercentEncoding ?? field.path).replacingOccurrences(of: "/", with: " / ")
        return label + (field.value.map { ": " + $0 } ?? "")
    }
}
