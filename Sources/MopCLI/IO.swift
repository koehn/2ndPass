import Darwin
import Foundation
import MopCore

enum IO {
    static func input(file: String? = nil) throws -> String {
        let data: Data
        do {
            if let file { data = try Data(contentsOf: URL(fileURLWithPath: file)) }
            else { data = try FileHandle.standardInput.readToEnd() ?? Data() }
        } catch { throw MopError.inputOutput }
        guard let text = String(data: data, encoding: .utf8) else { throw MopError.invalidUTF8 }
        return text
    }

    static func secret() throws -> String {
        if isatty(STDIN_FILENO) == 0 { return try input() }
        // readpassphrase restores terminal settings on cancellation/signals. The
        // extra byte detects truncation; larger or multiline input uses stdin.
        var buffer = [CChar](repeating: 0, count: 65_538)
        defer { _ = buffer.withUnsafeMutableBytes { memset_s($0.baseAddress!, $0.count, 0, $0.count) } }
        guard readpassphrase("Secret: ", &buffer, buffer.count, RPP_ECHO_OFF | RPP_REQUIRE_TTY) != nil else {
            throw MopError.inputOutput
        }
        let count = buffer.firstIndex(of: 0) ?? buffer.count
        guard count < buffer.count - 1 else { throw MopError.inputOutput }
        let data = Data(buffer.prefix(count).map { UInt8(bitPattern: $0) })
        guard let secret = String(data: data, encoding: .utf8) else { throw MopError.invalidUTF8 }
        return secret
    }

    static func output(_ string: String) throws {
        do { try FileHandle.standardOutput.write(contentsOf: Data(string.utf8)) }
        catch { throw MopError.inputOutput }
    }

    static func diagnostic(_ string: String) {
        try? FileHandle.standardError.write(contentsOf: Data(string.utf8))
    }
}
