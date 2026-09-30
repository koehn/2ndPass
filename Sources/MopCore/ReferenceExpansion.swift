import Foundation

/// Expansion happens on encoded reference text, before decoding. Substituted
/// values are encoded as literal component text and are never interpreted again.
public enum ReferenceExpansion {
    public static func resolve(_ token: String, variables: [String: String]) throws -> SecretReference {
        try resolve(token) { variables[$0] }
    }

    static func resolve(_ token: String, value: (String) -> String?) throws -> SecretReference {
        guard let prefix = SecretReference.prefixes.first(where: { token.hasPrefix($0) }) else { throw MopError.invalidReference }
        var output = "sp://"
        let text = String(token.dropFirst(prefix.count))
        var cursor = text.startIndex
        while cursor < text.endIndex {
            guard text[cursor] == "$" else {
                output.append(text[cursor]); cursor = text.index(after: cursor); continue
            }
            cursor = text.index(after: cursor)
            guard cursor < text.endIndex else { throw MopError.invalidReference }
            let name: String
            if text[cursor] == "{" {
                let start = text.index(after: cursor)
                guard let end = text[start...].firstIndex(of: "}") else { throw MopError.invalidReference }
                name = String(text[start..<end])
                cursor = text.index(after: end)
            } else {
                let start = cursor
                while cursor < text.endIndex,
                      text[cursor].asciiValue.map({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 95 }) == true {
                    cursor = text.index(after: cursor)
                }
                name = String(text[start..<cursor])
            }
            guard DotEnv.validKey(name), let value = value(name), !value.contains("\0") else { throw MopError.invalidReference }
            output += SecretReference.encode(value)
        }
        return try SecretReference(output)
    }
}
