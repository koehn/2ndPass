import Testing
@testable import MopAppSupport

struct PasswordGeneratorTests {
    @Test func compositionAndReadableModes() throws {
        for mask in 1..<16 {
            for readable in [false, true] {
                var options = PasswordOptions()
                options.length = 128
                options.lowercase = mask & 1 != 0
                options.uppercase = mask & 2 != 0
                options.numbers = mask & 4 != 0
                options.symbols = mask & 8 != 0
                options.readable = readable
                let value = try PasswordGenerator.generate(options)
                #expect(value.count == 128)
                #expect(value.contains(where: \.isLowercase) == options.lowercase)
                #expect(value.contains(where: \.isUppercase) == options.uppercase)
                #expect(value.contains(where: \.isNumber) == options.numbers)
                #expect(value.contains { !$0.isLetter && !$0.isNumber } == options.symbols)
                if readable { #expect(!value.contains { "Il1O0o|".contains($0) }) }
            }
        }
    }
    @Test func pronounceableAndInvalidOptions() throws {
        var options = PasswordOptions()
        options.pronounceable = true
        options.readable = true
        let value = Array(try PasswordGenerator.generate(options))
        #expect(value.count == options.length)
        #expect(value[0].isUppercase)
        #expect(value[22].isNumber)
        for index in 0..<22 {
            #expect((index.isMultiple(of: 2) ? "bcdfghjkmnprstvz" : "aeiu").contains(value[index].lowercased()))
        }
        options.lowercase = false
        let uppercase = try PasswordGenerator.generate(options)
        #expect(!uppercase.contains { "Il1O0o|".contains($0) })
        #expect(!uppercase.contains { $0.isLowercase })
        options.lowercase = false; options.uppercase = false
        #expect(throws: PasswordGenerator.Failure.self) { try PasswordGenerator.generate(options) }
        options.pronounceable = false; options.numbers = false; options.symbols = false
        #expect(throws: PasswordGenerator.Failure.self) { try PasswordGenerator.generate(options) }
        options.length = 0
        #expect(throws: PasswordGenerator.Failure.self) { try PasswordGenerator.generate(options) }
    }
    @Test func randomFailureAndRejection() throws {
        #expect(throws: PasswordGenerator.Failure.self) {
            try PasswordGenerator.generate(PasswordOptions()) { throw PasswordGenerator.Failure.randomUnavailable }
        }
        var options = PasswordOptions()
        options.lowercase = false; options.uppercase = false; options.symbols = false
        options.length = 8
        var calls = 0
        let value = try PasswordGenerator.generate(options) {
            calls += 1
            return calls == 1 ? 255 : 0
        }
        #expect(value == "00000000")
        #expect(calls == 16) // Rejected 255, eight samples, seven shuffle draws.
    }
}
