import Darwin
import Foundation
import MopCore

enum IO {
    static func input(file: String? = nil) throws -> SecretBytes {
        let descriptor: Int32
        if let file {
            descriptor = Darwin.open(file, O_RDONLY | O_CLOEXEC)
            guard descriptor >= 0 else { throw MopError.inputOutput }
        } else { descriptor = STDIN_FILENO }
        defer { if file != nil { Darwin.close(descriptor) } }
        return try SecretBytes.read(descriptor: descriptor).validatedUTF8()
    }

    static func requireDeletionConfirmation(_ target: VaultDescriptor, yes: Bool) throws {
        diagnostic("Delete vault \(target.name ?? "(unnamed or legacy)") [\(target.id)]?\nAll cloud contents and history will be deleted. This Mac's vault cache will be removed. Backups and other Macs' caches remain.\n")
        guard !yes else { return }
        guard isatty(STDIN_FILENO) != 0 else { throw MopError.confirmationRequired }
        let expected = target.name ?? target.id
        diagnostic("Type \(expected) to delete: ")
        guard readLine() == expected else { throw MopError.operationCancelled }
    }

    static func secret() throws -> SecretBytes {
        if isatty(STDIN_FILENO) == 0 { return try input() }
        let count = 65_538
        let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: count)
        buffer.initialize(repeating: 0, count: count)
        defer {
            _ = memset_s(buffer, count, 0, count)
            buffer.deallocate()
        }
        guard readpassphrase("Secret: ", buffer, count, RPP_ECHO_OFF | RPP_REQUIRE_TTY) != nil else { throw MopError.inputOutput }
        let length = strnlen(buffer, count)
        guard length < count - 1 else { throw MopError.inputOutput }
        return try SecretBytes(copying: UnsafeRawBufferPointer(start: buffer, count: length)).validatedUTF8()
    }

    static func output(_ value: SecretBytes) throws { try value.write(descriptor: STDOUT_FILENO) }

    static func output(_ string: String) throws {
        do { try FileHandle.standardOutput.write(contentsOf: Data(string.utf8)) }
        catch { throw MopError.inputOutput }
    }

    static func diagnostic(_ string: String) {
        try? FileHandle.standardError.write(contentsOf: Data(string.utf8))
    }
}
