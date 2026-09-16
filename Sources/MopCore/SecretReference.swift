import Foundation

public struct SecretReference: Hashable, Sendable, Comparable, CustomStringConvertible {
    public let vault: String
    public let item: String
    public let section: String?
    public let field: String

    public init(_ token: String) throws {
        guard token.hasPrefix("mop://") else { throw MopError.invalidReference }
        let parts = token.dropFirst(6).split(separator: "/", omittingEmptySubsequences: false)
        guard [3, 4].contains(parts.count) else { throw MopError.invalidReference }
        let decoded = try parts.map { try Self.decode(String($0)) }
        vault = decoded[0]
        item = decoded[1]
        section = decoded.count == 4 ? decoded[2] : nil
        field = decoded.last!
    }

    public init(vault: String, item: String, section: String? = nil, field: String) throws {
        guard ([vault, item, field] + (section.map { [$0] } ?? [])).allSatisfy({ !$0.isEmpty && !$0.contains("\0") }) else {
            throw MopError.invalidReference
        }
        self.vault = vault.precomposedStringWithCanonicalMapping
        self.item = item.precomposedStringWithCanonicalMapping
        self.section = section?.precomposedStringWithCanonicalMapping
        self.field = field.precomposedStringWithCanonicalMapping
    }

    private static func unreserved(_ byte: UInt8) -> Bool {
        (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte)
            || [45, 46, 95, 126].contains(byte)
    }

    private static func decode(_ value: String) throws -> String {
        let bytes = Array(value.utf8)
        var offset = 0
        while offset < bytes.count {
            if bytes[offset] == 37 {
                guard offset + 2 < bytes.count,
                      bytes[(offset + 1)...(offset + 2)].allSatisfy({
                          (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0)
                      }) else { throw MopError.invalidReference }
                offset += 3
            } else {
                guard unreserved(bytes[offset]) else { throw MopError.invalidReference }
                offset += 1
            }
        }
        guard let result = value.removingPercentEncoding, !result.isEmpty, !result.contains("\0") else {
            throw MopError.invalidReference
        }
        return result.precomposedStringWithCanonicalMapping
    }

    public static func encode(_ value: String) -> String {
        value.utf8.map { unreserved($0) ? String(UnicodeScalar($0)) : String(format: "%%%02X", $0) }.joined()
    }

    public var description: String {
        "mop://" + ([vault, item] + (section.map { [$0] } ?? []) + [field]).map(Self.encode).joined(separator: "/")
    }

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.description < rhs.description }
}
