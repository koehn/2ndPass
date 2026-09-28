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
        var label: String?
        var path: String
        var type: FieldType
        let storedPasswordQuality: PasswordQuality?
        var loadedPassword: String?
        var loadedCompound: String?
        var value: String?
        init(_ field: ItemField, existing: Bool = true) {
            id = existing ? "existing:" + field.path : "new:" + UUID().uuidString
            isTemplate = field.isTemplate == true
            label = field.label
            self.existing = existing; path = field.path; type = field.type
            value = existing && field.type == .otp ? nil : field.value
            storedPasswordQuality = existing ? field.passwordQuality : nil
            loadedCompound = existing && field.type.isCompound ? field.value : nil
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
        var effectiveType: FieldType {
            if type == .concealed, let value,
               value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix("otpauth:") { return .otp }
            return type
        }
        var validationError: String? {
            if effectiveType.isCompound {
                guard let value else { return existing ? nil : CompoundFieldFailure.invalid.errorDescription }
                return (try? CompoundField(value)) == nil ? CompoundFieldFailure.invalid.errorDescription : nil
            }
            if effectiveType == .attachment {
                guard let value else { return existing ? nil : "Choose a file to attach." }
                do { _ = try Attachment.decode(value); return nil }
                catch { return (error as? AttachmentFailure)?.errorDescription ?? "Invalid attachment." }
            }
            guard effectiveType == .otp else { return nil }
            guard let value else { return existing ? nil : MopError.invalidOTP.errorDescription }
            return (try? TimeBasedOTP(value)) == nil ? MopError.invalidOTP.errorDescription : nil
        }
        var field: ItemField {
            var result = ItemField(path: encodedPath, type: effectiveType,
                      value: existing && ((loadedPassword != nil && value == loadedPassword) || (loadedCompound != nil && value == loadedCompound)) ? nil : value,
                      isTemplate: isTemplate ? true : nil)
            result.label = label
            return result
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
    var tagsText: String {
        didSet {
            if metadata == nil { metadata = ItemMetadata() }
            metadata?.tags = Array(Set(tagsText.split(separator: ",").map {
                $0.trimmingCharacters(in: .whitespacesAndNewlines)
            }.filter { !$0.isEmpty })).sorted()
        }
    }
    var metadata: ItemMetadata?
    var autoFill: AutoFillMapping
    var mode: Mode
    private let initialVault: String
    private let initialItem: VaultItem

    /// Compare the save projection, not transient IDs or decrypted password loads.
    var isModified: Bool { vault != initialVault || item != initialItem }

    init(vault: String, revision: String, item: VaultItem, mode: Mode = .item, isNew: Bool = false) {
        tagsText = item.metadata?.tags.joined(separator: ", ") ?? ""
        metadata = item.metadata
        autoFill = item.autoFill ?? AutoFillMapping()
        initialVault = vault
        self.isNew = isNew
        self.vault = vault; self.revision = revision; originalName = item.name; name = item.name; type = item.type
        fields = item.fields.map { field in
            var field = field
            if item.isTemplateField(field) { field.isTemplate = true }
            return Field(field, existing: !isNew)
        }; self.mode = mode
        if case .value(let path) = mode, let index = fields.firstIndex(where: { $0.path == path }), fields[index].type != .password && fields[index].type != .otp && fields[index].type != .attachment && !fields[index].type.isCompound {
            fields[index].value = fields[index].value ?? ""
        }
        var baseline = VaultItem(name: name.precomposedStringWithCanonicalMapping, type: type, fields: fields.map(\.field))
        baseline.metadata = metadata
        baseline.autoFill = autoFill.isAutomatic ? nil : autoFill
        initialItem = baseline
    }
    var item: VaultItem {
        var result = VaultItem(name: name.precomposedStringWithCanonicalMapping, type: type, fields: fields.map(\.field))
        result.metadata = metadata
        result.autoFill = autoFill.isAutomatic ? nil : autoFill
        return result
    }
    func valid(vaultName: String) -> Bool {
        autoFill.validationError(in: fields.map(\.field)) == nil && !fields.isEmpty && fields.allSatisfy { $0.validationError == nil } && Set(fields.map(\.encodedPath)).count == fields.count && fields.allSatisfy {
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
