import Foundation
import Testing
@testable import MopAppSupport

struct CLIClientTests {
    private func fixture(_ body: String) throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-ui-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("mop")
        try Data(("#!/bin/sh\n" + body).utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        return url
    }
    @Test func visibleSelectionOverridesLegacyEnvironment() {
        let result = CLIClient.environment(["MOP_CLOUD_VAULT": "hidden", "MOP_VAULT_FILE": "/old/vault", "MOP_STATE_DIRECTORY": "/state", "PATH": "/bin"])
        #expect(result == ["MOP_STATE_DIRECTORY": "/state", "PATH": "/bin"])
    }
    @Test func earlyChildExitDoesNotTerminateWriter() async throws {
        let executable = try fixture("exit 3\n")
        defer { try? FileManager.default.removeItem(at: executable.deletingLastPathComponent()) }
        do {
            _ = try await CLIClient(executable: executable).run([], input: String(repeating: "x", count: 1_000_000))
            Issue.record("Expected rejection")
        } catch { #expect(error.localizedDescription.contains("Authentication")) }
    }
    @Test func explicitSelectionAndOfflineArguments() {
        #expect(CLIClient.arguments(["list", "--json"], vault: "uuid", offline: true) == ["list", "--json", "--cloud-vault", "uuid", "--offline"])
        #expect(CLIClient.arguments(["vault", "list"], vault: nil, offline: false) == ["vault", "list"])
    }
    @Test func valueUsesStdinPreservesBytesAndDoesNotUseShell() async throws {
        let executable = try fixture("printf '%s\\n' \"$@\" >&2\ncat\n")
        defer { try? FileManager.default.removeItem(at: executable.deletingLastPathComponent()) }
        let secret = "first line\n$(do-not-execute) ' \"\nlast line\n"
        let result = try await CLIClient(executable: executable).run(["write", "mop://personal/item/token"], input: secret)
        #expect(result.text == secret)
        #expect(!result.diagnostic.contains(secret))
        #expect(result.diagnostic == "write\nmop://personal/item/token\n")
    }
    @Test func drainsBothPipesWhileWritingLargeInput() async throws {
        let executable = try fixture("head -c 262144 /dev/zero >&2\ncat\n")
        defer { try? FileManager.default.removeItem(at: executable.deletingLastPathComponent()) }
        let input = String(repeating: "secret", count: 100_000)
        let result = try await CLIClient(executable: executable).run([], input: input)
        #expect(result.text == input)
        #expect(result.diagnostic.utf8.count == 262_144)
    }
    @Test func failureDoesNotExposeChildOutput() async throws {
        let executable = try fixture("echo SECRET >&2\necho SECRET\nexit 22\n")
        defer { try? FileManager.default.removeItem(at: executable.deletingLastPathComponent()) }
        do {
            _ = try await CLIClient(executable: executable).run([])
            Issue.record("Expected failure")
        } catch {
            #expect(error.localizedDescription.contains("uncertain"))
            #expect(!error.localizedDescription.contains("SECRET"))
        }
    }
    @Test func parsesOnlyValidOfflineTimestamp() throws {
        let result = CLIResult(output: Data("[]".utf8), diagnostic: "mop: offline cache from 2026-09-22T09:41:00Z; remote revocation cannot be checked.\n")
        #expect(result.offlineDate == "2026-09-22T09:41:00Z")
        #expect(try result.decode([String].self) == [])
        #expect(CLIResult(output: Data(), diagnostic: "mop: offline cache from untrusted text").offlineDate == nil)
    }
    @Test func malformedJSONFailsClosed() {
        #expect(throws: (any Error).self) { try CLIResult(output: Data("invalid".utf8), diagnostic: "").decode([String].self) }
    }
}
