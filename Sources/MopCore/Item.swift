import Foundation

public enum FieldType: String, Codable, CaseIterable, Sendable {
    case text, username, website, email, password, otp, concealed, notes, recoveryCodes, privateKey, cardNumber, expirationMonthYear, date, phone, attachment, bankAccount, address
    public var concealed: Bool { [.password, .otp, .concealed, .recoveryCodes, .privateKey, .cardNumber, .attachment, .bankAccount, .address].contains(self) }
    public var isCompound: Bool { self == .bankAccount || self == .address }
    public var label: String {
        switch self {
        case .otp: "OTP"
        case .privateKey: "Private key"
        case .recoveryCodes: "Recovery codes"
        case .cardNumber: "Card number"
        case .bankAccount: "Bank account"
        case .expirationMonthYear: "Month/year"
        default: rawValue.capitalized
        }
    }
}

public enum ItemType: String, Codable, CaseIterable, Sendable {
    case login, password, apiCredential, secureNote, database, sshKey, passkey, paymentCard, identity, document, custom
    public var label: String {
        switch self {
        case .apiCredential: "API credential"
        case .secureNote: "Secure note"
        case .sshKey: "SSH key"
        case .passkey: "Passkey"
        case .paymentCard: "Payment card"
        default: rawValue.capitalized
        }
    }
    /// Custom remains decodable for existing items, but has no creation template.
    public static var templateTypes: [ItemType] { allCases.filter { $0 != .custom && $0 != .passkey } }
    public var template: [ItemField] {
        let fields: [(String, FieldType)]
        switch self {
        case .login: fields = [("username", .username), ("password", .password), ("website", .website)]
        case .password: fields = [("password", .password)]
        case .apiCredential: fields = [("token", .concealed), ("endpoint", .website)]
        case .secureNote: fields = [("note", .concealed)]
        case .database: fields = [("server", .text), ("username", .username), ("password", .password), ("database", .text)]
        case .sshKey: fields = [("privateKey", .privateKey)]
        case .paymentCard: fields = [("cardholder", .text), ("number", .cardNumber), ("brand", .text), ("expiration", .expirationMonthYear), ("securityCode", .concealed), ("pin", .concealed)]
        case .identity: fields = [("firstName", .text), ("middleName", .text), ("lastName", .text), ("company", .text), ("birthDate", .date), ("email", .email), ("phone", .phone), ("address1", .text), ("address2", .text), ("city", .text), ("state", .text), ("postalCode", .text), ("country", .text), ("username", .username), ("governmentID", .concealed)]
        case .document: fields = [("attachment", .attachment)]
        case .custom, .passkey: return []
        }
        return (fields + (self == .secureNote ? [] : [("notes", .notes)])).map { ItemField(path: $0.0, type: $0.1, value: "", isTemplate: true) }
    }
}

/// Values are present only for visible fields when listing. In edits, nil keeps the existing value.
public struct ItemField: Codable, Equatable, Sendable {
    public var path: String
    public var type: FieldType
    public var value: String?
    public var passwordQuality: PasswordQuality?
    public var isTemplate: Bool?
    public var label: String?
    public init(path: String, type: FieldType = .concealed, value: String? = nil, isTemplate: Bool? = nil) {
        self.path = path; self.type = type; self.value = value; self.isTemplate = isTemplate
    }
}

/// Stored only inside the encrypted catalog. Nil means automatic field selection.
public struct AutoFillMapping: Codable, Equatable, Sendable {
    public var username: String?
    public var password: String?
    public var oneTimeCode: String?
    public init(username: String? = nil, password: String? = nil, oneTimeCode: String? = nil) {
        self.username = username; self.password = password; self.oneTimeCode = oneTimeCode
    }
    public var isAutomatic: Bool { username == nil && password == nil && oneTimeCode == nil }
    public func validationError(in fields: [ItemField]) -> String? {
        for (path, types, label) in [(username, [FieldType.username, .email, .text], "username"),
                                    (password, [.password, .concealed], "password"),
                                    (oneTimeCode, [.otp], "verification code")] {
            if let path, !fields.contains(where: { $0.path == path && types.contains($0.type) }) {
                return "Choose an existing \(label) field for AutoFill, or choose Automatic."
            }
        }
        return nil
    }
}

public struct VaultItem: Codable, Equatable, Sendable {
    public var name: String
    public var type: ItemType
    public var fields: [ItemField]
    public var deletion: ItemDeletion?
    public var autoFill: AutoFillMapping?
    public var metadata: ItemMetadata?
    public var credential: KeyCredential?
    /// Verified catalog projection, never serialized or accepted from an edit/import.
    public var storageID: String? = nil
    private enum CodingKeys: String, CodingKey { case name, type, fields, deletion, autoFill, metadata, credential }
    public var isArchived: Bool { metadata?.archived == true }
    public var isFavorite: Bool { metadata?.favorite == true }
    public var requiresExtendedModel: Bool {
        credential != nil || metadata != nil || [.sshKey, .paymentCard, .identity, .document].contains(type) || fields.contains {
            $0.label != nil || [.recoveryCodes, .privateKey, .cardNumber, .expirationMonthYear, .date, .phone, .attachment, .bankAccount, .address].contains($0.type)
        }
    }
    public func isTemplateField(_ field: ItemField) -> Bool {
        field.isTemplate == true || type.template.contains { $0.path == field.path }
    }
    public init(name: String, type: ItemType = .custom, fields: [ItemField]) {
        self.name = name; self.type = type; self.fields = fields
    }
}

public struct ItemCatalog: Codable, Sendable {
    public var vault: String
    public var revision: String
    public var items: [VaultItem]
    public var canEdit: Bool?
    public var usageScope: String? = nil
    public init(vault: String, revision: String, items: [VaultItem]) { self.vault = vault; self.revision = revision; self.items = items }
}

public struct ItemEdit: Codable, Sendable {
    public var revision: String
    public var item: VaultItem
    public var create: Bool
    public var originalName: String?
    public init(revision: String, item: VaultItem, create: Bool, originalName: String? = nil) {
        self.revision = revision; self.item = item; self.create = create; self.originalName = originalName
    }
}

public struct ImportSourceIdentity: Codable, Equatable, Sendable {
    public var provider: String
    public var container: String
    public var item: String
    public init(provider: String, container: String, item: String) {
        self.provider = provider; self.container = container; self.item = item
    }
}
public struct ItemMetadata: Codable, Equatable, Sendable {
    public var createdAt: Date?
    public var addedAt: Date?
    public var updatedAt: Date?
    public var tags: [String]
    public var favorite: Bool
    public var archived: Bool
    public var source: ImportSourceIdentity?
    public init(tags: [String] = [], favorite: Bool = false, archived: Bool = false, source: ImportSourceIdentity? = nil, createdAt: Date? = nil, addedAt: Date? = nil, updatedAt: Date? = nil) {
        self.tags = tags; self.favorite = favorite; self.archived = archived; self.source = source
        self.createdAt = createdAt; self.addedAt = addedAt; self.updatedAt = updatedAt
    }
}
