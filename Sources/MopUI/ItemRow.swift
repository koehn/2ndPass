import Foundation
import MopCore
import MopLocalIdentity

struct ItemRow: Identifiable, Sendable {
    struct ID: Hashable, Sendable { let vault: String; let name: String }
    let id: ID
    let vaultName: String
    let item: VaultItem
    var searchDetail: String? = nil
    var recentDate: Date? = nil
    var localIdentity: LocalIdentity? = nil
    static func local(_ identity: LocalIdentity) -> ItemRow {
        let presentation = CredentialPresentation(identity: identity)
        var fields = [ItemField(path: "name", type: .text, value: identity.name)]
        if let website = presentation.website { fields.append(ItemField(path: "website", type: .website, value: website)) }
        if let account = presentation.account { fields.insert(ItemField(path: "username", type: .username, value: account), at: 0) }
        let type: ItemType = identity.protocolType == .webauthn ? .passkey : [.ssh, .gitSigning].contains(identity.protocolType) ? .sshKey : .identity
        let item = VaultItem(name: presentation.title, type: type, fields: fields)
        return ItemRow(id: .init(vault: LocalVault.id, name: identity.id.uuidString), vaultName: LocalVault.name, item: item, localIdentity: identity)
    }
    var subtitle: String? {
        if let credential = item.credential, credential.purposes == [.passkey] {
            return credential.userName
        }
        return item.fields.first { [.username, .email, .website].contains($0.type) && !($0.value ?? "").isEmpty }?.value
    }
}

extension VaultItem {
    /// Registration names are unique storage references, not user-facing titles.
    /// Preserve names explicitly changed by the user.
    var displayTitle: String {
        guard let credential, credential.purposes == [.passkey],
              let website = credential.relyingParty, let account = credential.userName else { return name }
        let prefix = String((account + "@" + website).prefix(45)) + "-"
        guard name.hasPrefix(prefix) else { return name }
        let suffix = name.dropFirst(prefix.count)
        guard suffix.count == 8, suffix.allSatisfy(\.isHexDigit) else { return name }
        return website
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
        case .passkey: "person.badge.key"
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
