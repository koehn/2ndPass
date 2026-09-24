import Foundation
import Testing
@testable import MopCore

struct TimeBasedOTPTests {
    // RFC 6238 Appendix B, including leading zeroes and dates beyond 2038.
    @Test func standardVectors() throws {
        let times: [TimeInterval] = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]
        let vectors: [(String, String, [String])] = [
            ("SHA1", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"]),
            ("SHA256", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA", ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"]),
            ("SHA512", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA", ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"]),
        ]
        for (algorithm, secret, expected) in vectors {
            let otp = try TimeBasedOTP("otpauth://totp/Test?secret=\(secret)&algorithm=\(algorithm)&digits=8")
            for (time, code) in zip(times, expected) { #expect(try otp.code(at: Date(timeIntervalSince1970: time)) == code) }
        }
    }
    @Test func rawSecretURLEquivalenceAndRollover() throws {
        let raw = try TimeBasedOTP("jbsw y3dp ehpk 3pxp")
        let url = try TimeBasedOTP("otpauth://totp/Mop:test@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Mop&algorithm=SHA1&digits=6&period=30")
        for time: TimeInterval in [0, 29, 30, 59, 60] {
            #expect(try raw.code(at: Date(timeIntervalSince1970: time)) == url.code(at: Date(timeIntervalSince1970: time)))
        }
        #expect(try raw.code(at: Date(timeIntervalSince1970: 29)) != raw.code(at: Date(timeIntervalSince1970: 30)))
        let slow = try TimeBasedOTP("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=60")
        #expect(try slow.code(at: Date(timeIntervalSince1970: 59)) == raw.code(at: Date(timeIntervalSince1970: 29)))
    }
    @Test func expirationTracksConfiguredPeriodAndRollover() throws {
        let otp = try TimeBasedOTP("otpauth://totp/Test?secret=MY&period=60")
        for time: TimeInterval in [0, 54, 55, 59, 59.9] {
            #expect(otp.expires(at: Date(timeIntervalSince1970: time)).timeIntervalSince1970 == 60)
        }
        #expect(otp.expires(at: Date(timeIntervalSince1970: 60)).timeIntervalSince1970 == 120)
    }
    @Test func invalidInputsAreRejected() {
        for input in ["", "123456", "A", "ABC", "MZ", "MY=", "MY======X", "https://example.com",
                      "otpauth://hotp/Test?secret=MY", "otpauth://totp/Test", "otpauth://totp/Test?secret=MY&secret=MY",
                      "otpauth://totp/Test?secret=MY&algorithm=MD5", "otpauth://totp/Test?secret=MY&digits=7",
                      "otpauth://totp/Test?secret=MY&period=0", "otpauth://totp/Test?secret=MY&period=-1",
                      "otpauth://totp/Test?secret=MY&period=abc"] {
            #expect(throws: MopError.invalidOTP) { try TimeBasedOTP(input) }
        }
    }
    @Test func base32PaddingAndInvalidTime() throws {
        let padded = try TimeBasedOTP("MY======"), unpadded = try TimeBasedOTP("MY")
        let time = Date(timeIntervalSince1970: 59)
        #expect(try padded.code(at: time) == unpadded.code(at: time))
        #expect(throws: MopError.invalidOTP) { try padded.code(at: Date(timeIntervalSince1970: -1)) }
    }
}
