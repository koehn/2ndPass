import Foundation
import Testing
import MopCore
@testable import MopCLI

@Suite struct ValidationTests {
    @Test func agentReportsPurposeMismatchInsteadOfMissingSecret() throws {
        try SSHAgent.validatePurpose(.ssh, requested: .ssh, reference: "sp://local/login")
        try SSHAgent.validatePurpose(.gitSigning, requested: .gitSigning, reference: "sp://local/git-key")
        do {
            try SSHAgent.validatePurpose(.gitSigning, requested: .ssh, reference: "sp://local/git-key")
            Issue.record("Git signing identity accepted for SSH authentication")
        } catch {
            let message = String(describing: error)
            #expect(message.contains("sp://local/git-key"))
            #expect(message.contains("--purpose git-signing"))
            #expect(message.contains("cannot authenticate SSH"))
        }
        #expect(throws: (any Error).self) {
            try SSHAgent.validatePurpose(.x509, requested: .ssh, reference: "sp://local/certificate")
        }
    }

    @Test func identityReferencesAreVaultQualifiedAndRoundTripEscapedNames() throws {
        let vaultID = UUID().uuidString
        let uuidReference = try ItemReference("sp://" + vaultID + "/deploy")
        #expect(try IdentitySelection(uuidReference.description, vault: vaultID).reference == uuidReference)
        let reference = try ItemReference(vault: "work", name: "SSH / deploy #1")
        #expect(reference.description == "sp://work/SSH%20%2F%20deploy%20%231")
        #expect(try ItemReference(reference.description) == reference)
        #expect(try IdentitySelection(reference.description, vault: nil).reference == reference)
        #expect(try IdentitySelection("SSH / deploy #1", vault: "work").reference == reference)
        #expect(throws: (any Error).self) { try IdentitySelection(reference.description, vault: "local") }
        #expect(throws: (any Error).self) { try IdentitySelection("deploy", vault: nil) }
        #expect(throws: (any Error).self) { try ItemReference("sp://local/deploy/private-key") }
        #expect(throws: (any Error).self) { try ItemReference("sp://local/bad%ZZ") }
        #expect(throws: (any Error).self) { try IdentitySelection.requireSupportedBackend("work") }
        try IdentitySelection.requireSupportedBackend("local")
    }

    @Test func identityCommandsAcceptReferencesAndAgentVaultSelectors() throws {
        #expect(try Mop.parseAsRoot(["item", "public-key", "sp://local/deploy"]) is Item.PublicKey)
        #expect(try Mop.parseAsRoot(["item", "delete", "sp://work/deploy"]) is Item.DeleteIdentity)
        #expect(try Mop.parseAsRoot(["ssh-agent", "--vault", "work", "--identity", "deploy"]) is SSHAgent)
        #expect(try Mop.parseAsRoot(["ssh-agent", "--identity", "sp://local/deploy"]) is SSHAgent)
    }

    @Test func packagingIdentityCommandRemainsAvailable() throws {
        let command = try Mop.parseAsRoot(["device", "identity"])
        #expect(command is Device.Identity)
    }

    @Test func removedFileOptionIsAnUnknownArgument() throws {
        do {
            _ = try Mop.parseAsRoot(["read", "sp://personal/mycloud/sshd", "--vault-file", "/sensitive-path"])
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
    #expect(try Mop.parseAsRoot(["device", "request"]) is Device.Request)
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

@Test func importCLIRequiresExplicitVaultAndSupportsFormats() throws {
    #expect(throws: (any Error).self) { try Mop.parseAsRoot(["item", "import", "export.csv"]) }
    #expect(try Mop.parseAsRoot(["item", "import", "export.csv", "--vault", "personal", "--dry-run", "--format", "apple-csv", "--json"]) is Item.Import)
    #expect(try Mop.parseAsRoot(["item", "import", "export.1pux", "--vault", "personal", "--yes"]) is Item.Import)
    #expect(throws: (any Error).self) { try Mop.parseAsRoot(["item", "import", "export.csv", "--vault", "personal", "--offline"]) }
}

@Test func localCommandsAreAvailable() throws {
    #expect(try Mop.parseAsRoot(["list", "--vault", "local"]) is List)
    #expect(try Mop.parseAsRoot(["item", "create", "--vault", "local", "--type", "ssh", "--name", "deploy", "--acknowledge-device-loss"]) is Item.Create)
    #expect(try Mop.parseAsRoot(["item", "public-key", "--vault", "local", "deploy"]) is Item.PublicKey)
    #expect(try Mop.parseAsRoot(["item", "delete", "--vault", "local", "deploy"]) is Item.DeleteIdentity)
    #expect(throws: (any Error).self) { try Mop.parseAsRoot(["local", "sign", "deploy"]) }
}

@Test func localCreateRejectsInvalidProtocolAndName() {
    #expect(throws: (any Error).self) { try Mop.parseAsRoot(["local", "create", "deploy", "--protocol", "not-a-protocol"]) }
    #expect(throws: (any Error).self) { try Mop.parseAsRoot(["local", "create", "bad\nname"]) }
}

@Test func sshAgentCommandIsAvailable() throws {
    #expect(try Mop.parseAsRoot(["ssh-agent"]) is SSHAgent)
    #expect(try Mop.parseAsRoot(["ssh-agent", "--", "ssh", "user@example.com"]) is SSHAgent)
}
