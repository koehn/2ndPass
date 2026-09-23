import Security

public struct PasswordOptions: Codable, Equatable, Sendable {
    public var length = 24
    public var lowercase = true
    public var uppercase = true
    public var numbers = true
    public var symbols = true
    public var readable = false
    public var pronounceable = false
    public init() {}
}

public enum PasswordGenerator {
    public enum Failure: Error { case invalidOptions, randomUnavailable }

    public static func generate(_ options: PasswordOptions) throws -> String {
        try generate(options) {
            var byte: UInt8 = 0
            guard SecRandomCopyBytes(kSecRandomDefault, 1, &byte) == errSecSuccess else {
                throw Failure.randomUnavailable
            }
            return byte
        }
    }

    // Rejection sampling avoids modulo bias; failures never fall back to a PRNG.
    static func generate(_ o: PasswordOptions, byte: () throws -> UInt8) throws -> String {
        guard (8...128).contains(o.length) else { throw Failure.invalidOptions }
        let ambiguous = Set("Il1O0o|")
        func alphabet(_ text: String) -> [Character] {
            Array(text).filter { !o.readable || !ambiguous.contains($0) }
        }
        func pick(_ count: Int) throws -> Int {
            let limit = 256 - 256 % count
            while true {
                let value = Int(try byte())
                if value < limit { return value % count }
            }
        }
        func sample(_ chars: [Character]) throws -> Character { chars[try pick(chars.count)] }
        var groups: [[Character]] = []
        if o.lowercase { groups.append(alphabet("abcdefghijklmnopqrstuvwxyz")) }
        if o.uppercase { groups.append(alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ")) }
        if o.numbers { groups.append(alphabet("0123456789")) }
        if o.symbols { groups.append(alphabet("!@#$%^&*()-_=+[]{};:,.?")) }
        guard !groups.isEmpty else { throw Failure.invalidOptions }
        var result: [Character] = []
        if o.pronounceable {
            guard o.lowercase || o.uppercase else { throw Failure.invalidOptions }
            let suffix = (o.numbers ? 1 : 0) + (o.symbols ? 1 : 0)
            for index in 0..<(o.length - suffix) {
                let letters = index.isMultiple(of: 2) ? "bcdfghjkmnprstvz" : "aeiou"
                let upper = o.uppercase && (!o.lowercase || index == 0)
                result.append(try sample(alphabet(upper ? letters.uppercased() : letters)))
            }
            if o.numbers { result.append(try sample(alphabet("0123456789"))) }
            if o.symbols { result.append(try sample(alphabet("!@#$%^&*()-_=+[]{};:,.?"))) }
        } else {
            for group in groups { result.append(try sample(group)) }
            let all = groups.flatMap { $0 }
            while result.count < o.length { result.append(try sample(all)) }
            for index in stride(from: result.count - 1, through: 1, by: -1) {
                result.swapAt(index, try pick(index + 1))
            }
        }
        return String(result)
    }
}
