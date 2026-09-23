import Testing
import MopCore
@testable import MopCLI

@Suite struct ValidationTests {
    @Test func wrappedLegacyOptionRetainsSafeDiagnostic() throws {
        do {
            _ = try Mop.parseAsRoot(["read", "mop://personal/mycloud/sshd", "--vault-file", "/sensitive-path"])
            Issue.record("Legacy file configuration was accepted")
        } catch {
            #expect(Mop.knownValidationError(error) == .fileMigration)
            #expect(Mop.knownValidationError(error)?.errorDescription?.contains("Unset MOP_VAULT_FILE") == true)
            #expect(Mop.knownValidationError(error)?.errorDescription?.contains("sensitive-path") == false)
        }
    }

    @Test func unexpectedArgumentsRemainRedacted() throws {
        do {
            _ = try Mop.parseAsRoot(["completion", "bash", "unintended-secret-argument"])
            Issue.record("Unexpected argument was accepted")
        } catch {
            #expect(Mop.knownValidationError(error) == nil)
        }
    }
}
