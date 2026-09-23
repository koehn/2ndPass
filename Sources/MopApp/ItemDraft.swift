import Foundation
import MopCore

/// A revision-bound draft. Nil values preserve concealed records without reading
/// them; an explicit empty string replaces a value with an empty value.
struct ItemDraft: Identifiable {
    struct Field: Identifiable {
        let id: String
        let dragID = UUID()
        let existing: Bool
        let isTemplate: Bool
        var path: String
        var type: FieldType
        let storedPasswordQuality: PasswordQuality?
        var loadedPassword: String?
        var value: String?
        init(_ field: ItemField, existing: Bool = true) {
            id = existing ? "existing:" + field.path : "new:" + UUID().uuidString
            isTemplate = field.isTemplate == true
            self.existing = existing; path = field.path; type = field.type; value = field.value
            storedPasswordQuality = existing ? field.passwordQuality : nil
            loadedPassword = existing && field.type == .password ? field.value : nil
        }
        /// Only changed or new input is sent to the live estimator.
        var passwordToEstimate: String? {
            guard type == .password else { return nil }
            return existing && value == loadedPassword ? nil : value
        }
        var encodedPath: String {
            existing ? path : path.split(separator: "/", omittingEmptySubsequences: false).map { SecretReference.encode(String($0)) }.joined(separator: "/")
        }
        var field: ItemField {
            ItemField(path: encodedPath, type: type,
                      value: existing && loadedPassword != nil && value == loadedPassword ? nil : value,
                      isTemplate: isTemplate ? true : nil)
        }
    }
    enum Mode: Equatable { case item, value(String) }
    let id = UUID()
    var vault: String
    let isNew: Bool
    let revision: String
    let originalName: String
    var name: String
    var type: ItemType
    var fields: [Field]
    var mode: Mode

    init(vault: String, revision: String, item: VaultItem, mode: Mode = .item, isNew: Bool = false) {
        self.isNew = isNew
        self.vault = vault; self.revision = revision; originalName = item.name; name = item.name; type = item.type
        fields = item.fields.map { field in
            var field = field
            if item.isTemplateField(field) { field.isTemplate = true }
            return Field(field, existing: !isNew)
        }; self.mode = mode
        if case .value(let path) = mode, let index = fields.firstIndex(where: { $0.path == path }), fields[index].type != .password {
            fields[index].value = fields[index].value ?? ""
        }
    }
    var item: VaultItem { VaultItem(name: name.precomposedStringWithCanonicalMapping, type: type, fields: fields.map(\.field)) }
    func valid(vaultName: String) -> Bool {
        !fields.isEmpty && Set(fields.map(\.encodedPath)).count == fields.count && fields.allSatisfy {
            guard let ref = try? SecretReference(vault: vaultName, relativePath: SecretReference.encode(item.name) + "/" + $0.encodedPath) else { return false }
            return ref.item == item.name
        }
    }
    mutating func move(_ id: String, to target: String) {
        guard mode == .item, let source = fields.firstIndex(where: { $0.id == id }),
              let destination = fields.firstIndex(where: { $0.id == target }), source != destination else { return }
        let field = fields.remove(at: source); fields.insert(field, at: destination)
    }
}
