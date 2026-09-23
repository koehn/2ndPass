import Darwin
import MopCore

/// C environment entries retain owned, NUL-terminated storage through the syscall.
/// No concatenated secret Strings or strdup allocations are created.
struct EnvironmentBlock {
    private let entries: [SecretBytes]
    init(_ environment: [String: SecretBytes]) throws {
        entries = try environment.keys.sorted().map { name in
            let value = environment[name]!
            guard !name.isEmpty, !name.contains("="), !name.contains("\0"), !value.contains(0) else { throw MopError.invalidProcess }
            let entry = SecretBuilder()
            entry.append(name.utf8); entry.append(61); entry.append(value); entry.append(0)
            return entry.finish()
        }
    }
    func withPointers<R>(_ body: (UnsafePointer<UnsafeMutablePointer<CChar>?>) throws -> R) rethrows -> R {
        // SecretBytes allocations cannot move; keep all owners alive for the syscall.
        let pointers: [UnsafeMutablePointer<CChar>?] = entries.map { entry in
            entry.withUnsafeBytes { UnsafeMutablePointer(mutating: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
        } + [nil]
        return try withExtendedLifetime(entries) { try pointers.withUnsafeBufferPointer { try body($0.baseAddress!) } }
    }
}
