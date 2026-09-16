import Foundation

/// A literal, line-oriented subset of dotenv. Never executes or expands input.
public enum DotEnv {
    public static func parse(_ text: String) throws -> [String: String] {
        var values: [String: String] = [:]
        for (index, raw) in text.components(separatedBy: "\n").enumerated() {
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") { continue }
            guard let equals = line.firstIndex(of: "=") else {
                throw MopError.invalidEnvironment(line: index + 1)
            }
            let key = line[..<equals].trimmingCharacters(in: .whitespaces)
            guard validKey(key) else { throw MopError.invalidEnvironment(line: index + 1) }
            let value = line[line.index(after: equals)...].trimmingCharacters(in: .whitespaces)
            guard !value.contains("\0") else { throw MopError.invalidEnvironment(line: index + 1) }
            if let quote = value.first, quote == "\"" || quote == "'" {
                let body = value.dropFirst()
                guard let close = body.firstIndex(of: quote) else {
                    throw MopError.invalidEnvironment(line: index + 1)
                }
                let trailing = body[body.index(after: close)...].trimmingCharacters(in: .whitespaces)
                guard trailing.isEmpty || trailing.hasPrefix("#") else {
                    throw MopError.invalidEnvironment(line: index + 1)
                }
                values[key] = String(body[..<close])
            } else {
                // Inline comments start only after whitespace. '#' within a value is literal.
                let chars = Array(value)
                let comment = chars.indices.first { chars[$0] == "#" && ($0 == 0 || chars[$0 - 1].isWhitespace) }
                values[key] = String(chars[..<(comment ?? chars.count)]).trimmingCharacters(in: .whitespaces)
            }
        }
        return values
    }

    public static func validKey(_ key: String) -> Bool {
        let bytes = Array(key.utf8)
        func initial(_ b: UInt8) -> Bool { (65...90).contains(b) || (97...122).contains(b) || b == 95 }
        return bytes.first.map(initial) == true && bytes.dropFirst().allSatisfy { initial($0) || (48...57).contains($0) }
    }
}
