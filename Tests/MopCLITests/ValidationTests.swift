import Testing
import MopCore
@testable import MopCLI

@Suite struct ValidationTests {
    @Test func packagingIdentityCommandRemainsAvailable() throws {
        let command = try Mop.parseAsRoot(["device", "identity"])
        #expect(command is Device.Identity)
    }

    @Test func removedFileOptionIsAnUnknownArgument() throws {
        do {
            _ = try Mop.parseAsRoot(["read", "mop://personal/mycloud/sshd", "--vault-file", "/sensitive-path"])
            Issue.record("Legacy file configuration was accepted")
        } catch {
            #expect(Mop.knownValidationError(error) == nil)
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
