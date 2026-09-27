import Foundation

public enum CompoundFieldFailure: Error, LocalizedError, Sendable {
    case invalid
    public var errorDescription: String? { "Bank account and address fields must contain a JSON object with named components." }
}

/// A JSON object matching source compound fields. Unknown keys and nested values
/// survive edits to known components; identifiers remain strings, including zeros.
public struct CompoundField: Equatable, Sendable {
    public let encodedValue: String
    public init(_ value: String) throws {
        guard let object = try? JSONSerialization.jsonObject(with: Data(value.utf8)) as? [String: Any],
              let bytes = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) else { throw CompoundFieldFailure.invalid }
        encodedValue = String(decoding: bytes, as: UTF8.self)
    }
    private var object: [String: Any] {
        (try? JSONSerialization.jsonObject(with: Data(encodedValue.utf8)) as? [String: Any]) ?? [:]
    }
    public var keys: [String] { object.keys.sorted() }
    public func text(for key: String) -> String? { object[key] as? String }
    public func contains(_ key: String) -> Bool { object[key] != nil }
    public func valueDescription(for key: String) -> String {
        guard let value = object[key] else { return "" }
        if let text = value as? String { return text }
        guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed, .sortedKeys, .withoutEscapingSlashes]) else { return "" }
        return String(decoding: data, as: UTF8.self)
    }
    public func replacing(_ key: String, with text: String) throws -> Self {
        var fields = object; fields[key] = text
        let bytes = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
        return try Self(String(decoding: bytes, as: UTF8.self))
    }
    public static func components(for type: FieldType) -> [(key: String, label: String)] {
        switch type {
        case .bankAccount:
            [("bankName", "Bank"), ("owner", "Account holder"), ("accountType", "Account type"),
             ("accountNo", "Account number"), ("routingNo", "Routing number"), ("iban", "IBAN"),
             ("swift", "SWIFT / BIC"), ("telephonePin", "Telephone PIN"), ("branchPhone", "Branch phone")]
        case .address:
            [("street", "Street"), ("street2", "Address line 2"), ("street3", "Address line 3"),
             ("city", "City"), ("state", "State / province"), ("zip", "Postal code"), ("country", "Country")]
        default: []
        }
    }
    public func displayText(for type: FieldType) -> String {
        let components = Self.components(for: type)
        let known = Set(components.map(\.key))
        return (components + keys.filter { !known.contains($0) }.map { (key: $0, label: $0) })
            .filter { contains($0.key) && !valueDescription(for: $0.key).isEmpty }
            .map { $0.label + ": " + valueDescription(for: $0.key) }.joined(separator: "\n")
    }
}
