import Foundation
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
    ["device", "requests"], ["device", "list"],
    ["device", "add", "request", "--fingerprint", String(repeating: "a", count: 64)],
    ["device", "remove", String(repeating: "a", count: 64)],
    ["vault", "init", "personal", "--recovery-file", "/tmp/unused", "--device-name", "old-device"],
    ["vault", "recover", "--recovery-file", "/tmp/unused", "--name", "old-device"]
]) func removedDeviceCommandsAndOptionsAreRejected(arguments: [String]) {
    #expect(throws: (any Error).self) { try Mop.parseAsRoot(arguments) }
}

@Test(arguments: [
    ["vault", "init", "personal", "--recovery-file", "/tmp/unused", "--strict-biometrics"],
    ["vault", "import", "--file", "/tmp/unused", "--strict-biometrics"],
    ["vault", "recover", "--recovery-file", "/tmp/unused", "--strict-biometrics"]
]) func removedStrictBiometricsOptionIsRejected(arguments: [String]) {
    #expect(throws: (any Error).self) { try Mop.parseAsRoot(arguments) }
}

@Test func deviceRequestsAndSharingCommandsAreAvailable() throws {
    #expect(try Mop.parseAsRoot(["device", "request", "--recovery"]) is Device.Request)
    #expect(try Mop.parseAsRoot(["vault", "members"]) is Vault.Members)
    #expect(try Mop.parseAsRoot(["vault", "remove-device", UUID().uuidString]) is Vault.RemoveDevice)
}

@Test func creationNeedsNoRecoveryAndRejectsHalfSpecifiedRecovery() throws {
    let plain = try Mop.parseAsRoot(["vault", "init", "personal"])
    #expect(plain is Vault.Initialize)
    #expect(throws: (any Error).self) { try Mop.parseAsRoot(["vault", "init", "personal", "--recovery-request", "/tmp/unused"]) }
    #expect(throws: (any Error).self) { try Mop.parseAsRoot(["vault", "init", "personal", "--fingerprint", String(repeating: "a", count: 64)]) }
}

@Test func cloudEnrollmentCommandsRequireExplicitApprovalArguments() throws {
    #expect(try Mop.parseAsRoot(["vault", "enrollment", "request", "--vault", UUID().uuidString]) is Vault.Enrollment)
    #expect(try Mop.parseAsRoot(["vault", "enrollment", "approve", "--request-id", UUID().uuidString, "--code", "ABCD"]) is Vault.Enrollment)
    #expect(throws: (any Error).self) { try Mop.parseAsRoot(["vault", "enrollment", "approve", "--request-id", UUID().uuidString]) }
    #expect(throws: (any Error).self) { try Mop.parseAsRoot(["vault", "enrollment", "confirm"]) }
}
