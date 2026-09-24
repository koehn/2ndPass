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

@Test(arguments: [
    ["device", "request"], ["device", "requests"], ["device", "list"],
    ["device", "add", "request", "--fingerprint", String(repeating: "a", count: 64)],
    ["device", "remove", String(repeating: "a", count: 64)],
    ["vault", "init", "personal", "--recovery-file", "/tmp/unused", "--device-name", "old-device"],
    ["vault", "recover", "--recovery-file", "/tmp/unused", "--name", "old-device"]
]) func removedDeviceCommandsAndOptionsAreRejected(arguments: [String]) {
    #expect(throws: (any Error).self) { try Mop.parseAsRoot(arguments) }
}
