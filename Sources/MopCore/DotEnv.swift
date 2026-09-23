import Foundation

/// A literal, line-oriented subset of dotenv. Never executes or expands input.
public enum DotEnv {
    public static func parse(_ text: SecretBytes) throws -> [String: SecretBytes] {
        _ = try text.validatedUTF8()
        var values: [String: SecretBytes] = [:]
        for (index, raw) in text.split(separator: 10, omittingEmptySubsequences: false).enumerated() {
            let line = SecretParsing.trim(raw)
            if line.isEmpty || line.first == 35 { continue }
            guard let equals = line.firstIndex(of: 61) else { throw MopError.invalidEnvironment(line: index + 1) }
            let key = String(decoding: SecretParsing.trim(line[..<equals], newlines: false), as: UTF8.self)
            guard validKey(key) else { throw MopError.invalidEnvironment(line: index + 1) }
            let value = SecretParsing.trim(line[(equals + 1)...], newlines: false)
            guard !value.contains(0) else { throw MopError.invalidEnvironment(line: index + 1) }
            if let quote = value.first, quote == 34 || quote == 39 {
                let body = value.dropFirst()
                guard let close = body.firstIndex(of: quote) else { throw MopError.invalidEnvironment(line: index + 1) }
                let trailing = SecretParsing.trim(body[(close + 1)...], newlines: false)
                guard trailing.isEmpty || trailing.first == 35 else { throw MopError.invalidEnvironment(line: index + 1) }
                values[key] = SecretBytes(copying: body[..<close])
            } else {
                let comment = value.indices.first { position in
                    value[position] == 35 && (position == value.startIndex ||
                        SecretParsing.commentWhitespace.contains { value[..<position].suffix($0.count).elementsEqual($0) })
                }
                values[key] = SecretBytes(copying: SecretParsing.trim(value[..<(comment ?? value.endIndex)], newlines: false))
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
