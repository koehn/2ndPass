import Foundation
import CryptoKit

/// RFC 6238 TOTP and the otpauth provisioning format. Never includes input in errors.
public struct TimeBasedOTP {
    private let key: SymmetricKey
    private let algorithm: String
    public let digits: Int
    public let period: Int

    public init(_ input: String) throws {
        let input = input.trimmingCharacters(in: .whitespacesAndNewlines)
        var secret = input, algorithm = "SHA1", digits = 6, period = 30
        if input.lowercased().hasPrefix("otpauth:") {
            guard let url = URLComponents(string: input), url.scheme?.lowercased() == "otpauth",
                  url.host?.lowercased() == "totp", !url.path.dropFirst().isEmpty,
                  url.user == nil, url.password == nil, url.port == nil, url.fragment == nil else { throw MopError.invalidOTP }
            var values: [String: String] = [:]
            for query in url.queryItems ?? [] {
                guard values[query.name] == nil, let value = query.value else { throw MopError.invalidOTP }
                values[query.name] = value
            }
            guard let supplied = values["secret"] else { throw MopError.invalidOTP }
            secret = supplied
            algorithm = (values["algorithm"] ?? "SHA1").uppercased()
            if let value = values["digits"] { guard let number = Int(value) else { throw MopError.invalidOTP }; digits = number }
            if let value = values["period"] { guard let number = Int(value) else { throw MopError.invalidOTP }; period = number }
        }
        guard ["SHA1", "SHA256", "SHA512"].contains(algorithm), [6, 8].contains(digits),
              period > 0, period <= 86400 else { throw MopError.invalidOTP }
        let normalized = Array(secret.uppercased().filter { !$0.isWhitespace }.utf8)
        let payload = normalized.prefix { $0 != 61 }
        let padding = normalized.count - payload.count
        let remainder = payload.count % 8
        guard !payload.isEmpty, [0, 2, 4, 5, 7].contains(remainder),
              padding == 0 || (normalized.suffix(padding).allSatisfy { $0 == 61 } && normalized.count % 8 == 0 && padding == (8 - remainder) % 8) else { throw MopError.invalidOTP }
        var bytes = Data(), buffer: UInt32 = 0, bits = 0
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        for character in payload {
            let value: UInt32
            switch character {
            case 65...90: value = UInt32(character - 65)
            case 50...55: value = UInt32(character - 50 + 26)
            default: throw MopError.invalidOTP
            }
            buffer = (buffer << 5) | value; bits += 5
            if bits >= 8 { bits -= 8; bytes.append(UInt8((buffer >> bits) & 255)) }
            buffer &= (1 << bits) - 1
        }
        guard !bytes.isEmpty, buffer == 0 else { throw MopError.invalidOTP }
        key = SymmetricKey(data: bytes); self.algorithm = algorithm; self.digits = digits; self.period = period
    }

    public func expires(at date: Date = Date()) -> Date {
        Date(timeIntervalSince1970: (floor(date.timeIntervalSince1970 / Double(period)) + 1) * Double(period))
    }

    public func code(at date: Date = Date()) throws -> String {
        let steps = floor(date.timeIntervalSince1970 / Double(period))
        guard steps.isFinite, steps >= 0, steps < Double(UInt64.max) else { throw MopError.invalidOTP }
        var counter = UInt64(steps).bigEndian
        let data = withUnsafeBytes(of: &counter) { Data($0) }
        let hash: [UInt8]
        switch algorithm {
        case "SHA256": hash = Array(HMAC<SHA256>.authenticationCode(for: data, using: key))
        case "SHA512": hash = Array(HMAC<SHA512>.authenticationCode(for: data, using: key))
        default: hash = Array(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: key))
        }
        let offset = Int(hash[hash.count - 1] & 15)
        let binary = hash[offset..<offset + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } & 0x7fffffff
        let modulus: UInt32 = digits == 8 ? 100_000_000 : 1_000_000
        return String(format: "%0*u", digits, binary % modulus)
    }
}
