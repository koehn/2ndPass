import Foundation

// Byte offsets keep literal plaintext out of String/Substring and their CoW storage.
enum SecretParsing {
    private static let whitespaceScalars = (Array(9...13) + [0x20, 0x85, 0xA0, 0x1680] +
        Array(0x2000...0x200B) + [0x2028, 0x2029, 0x202F, 0x205F, 0x3000]).compactMap(Unicode.Scalar.init)
    static let whitespace = whitespaceScalars.filter { CharacterSet.whitespacesAndNewlines.contains($0) }
        .map { Array(String($0).utf8) }
    private static let horizontalWhitespace = whitespaceScalars.filter { CharacterSet.whitespaces.contains($0) }
        .map { Array(String($0).utf8) }
    static let commentWhitespace = whitespaceScalars.filter { $0.properties.isWhitespace }
        .map { Array(String($0).utf8) }
    static func trim(_ bytes: Slice<SecretBytes>, newlines: Bool = true) -> Slice<SecretBytes> {
        let spaces = newlines ? whitespace : horizontalWhitespace
        var result = bytes
        while let match = spaces.first(where: { result.starts(with: $0) }) { result = result.dropFirst(match.count) }
        while let match = spaces.first(where: { result.suffix($0.count).elementsEqual($0) }) { result = result.dropLast(match.count) }
        return result
    }
    static func references(in environment: [String: SecretBytes]) throws -> [String: SecretReference] {
        guard environment.allSatisfy({ !$0.key.isEmpty && !$0.key.contains("=") && !$0.key.contains("\0") && !$0.value.contains(0) }) else {
            throw MopError.invalidProcess
        }
        var references: [String: SecretReference] = [:]
        for key in environment.keys.sorted() {
            if let value = environment[key], value.starts(with: "mop://".utf8) {
                references[key] = try ReferenceExpansion.resolve(String(decoding: value, as: UTF8.self)) { name in
                    environment[name].map { String(decoding: $0, as: UTF8.self) }
                }
            }
        }
        return references
    }
    static func placeholders(_ template: SecretBytes, variables: [String: String]) throws -> [(Range<Int>, SecretReference)] {
        var result: [(Range<Int>, SecretReference)] = []
        var cursor = 0
        while cursor + 1 < template.count {
            guard template[cursor] == 123, template[cursor + 1] == 123 else { cursor += 1; continue }
            let opening = cursor
            cursor += 2
            let start = cursor
            var closing: Int?
            while cursor + 1 < template.count {
                if template[cursor] == 36 && template[cursor + 1] == 123 {
                    cursor += 2
                    while cursor < template.count && template[cursor] != 125 { cursor += 1 }
                    if cursor == template.count { break }
                    cursor += 1
                } else if template[cursor] == 125 && template[cursor + 1] == 125 {
                    closing = cursor; break
                } else { cursor += 1 }
            }
            guard let closing else {
                if trim(template[start...]).starts(with: "mop://".utf8) { throw MopError.invalidTemplate }
                break
            }
            let token = trim(template[start..<closing])
            if token.starts(with: "mop://".utf8) {
                result.append((opening..<(closing + 2), try ReferenceExpansion.resolve(String(decoding: token, as: UTF8.self), variables: variables)))
            }
            cursor = closing + 2
        }
        return result
    }
    static func render(_ template: SecretBytes, placeholders: [(Range<Int>, SecretReference)], values: [SecretReference: SecretBytes]) -> SecretBytes {
        let output = SecretBuilder()
        var cursor = 0
        for (range, reference) in placeholders {
            output.append(template[cursor..<range.lowerBound]); output.append(values[reference]!)
            cursor = range.upperBound
        }
        output.append(template[cursor...])
        return output.finish()
    }
}
