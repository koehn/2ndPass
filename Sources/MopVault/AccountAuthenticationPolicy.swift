import Foundation
import Darwin
import LocalAuthentication
import MopAuth
import MopCore

/// Local application policy, not an ACL on the synchronized private keys.
public enum AccountAuthenticationPolicy {
    public static func strict(state: URL, requested: Bool = false) throws -> Bool {
        let file = state.appendingPathComponent("account-authentication.json")
        guard FileManager.default.fileExists(atPath: file.path) else { return requested }
        return try JSONDecoder().decode(Bool.self, from: SafeFile.read(file, privateFile: true, limit: 1024)) || requested
    }
    public static func save(state: URL, strict: Bool) throws {
        try SafeFile.privateDirectory(state)
        let fd = Darwin.open(state.appendingPathComponent("account-authentication.lock").path,
                             O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw MopError.filePermissions }
        defer { Darwin.close(fd) }
        var status = stat()
        guard fstat(fd, &status) == 0, status.st_uid == getuid(),
              status.st_mode & S_IFMT == S_IFREG, status.st_mode & 0o077 == 0 else { throw MopError.filePermissions }
        try PrivateACL.validate(fd)
        guard flock(fd, LOCK_EX) == 0 else { throw MopError.inputOutput }
        defer { flock(fd, LOCK_UN) }
        let file = state.appendingPathComponent("account-authentication.json")
        // Never let another setup operation weaken an existing strict policy.
        let effective = try self.strict(state: state, requested: strict)
        try SafeFile.write(JSONEncoder().encode(effective), to: file, replace: FileManager.default.fileExists(atPath: file.path))
    }
    public static func authorize(state: URL, strict requested: Bool = false,
                                 reason: String = "access secrets for this mop command",
                                 contextCreated: (LAContext) throws -> Void = { _ in }) throws -> LAContext {
        let effective = try strict(state: state, requested: requested)
        let context = try Authentication.authorize(strictBiometrics: effective, reason: reason, contextCreated: contextCreated)
        do { try save(state: state, strict: effective) }
        catch { context.invalidate(); throw error }
        return context
    }
}
