import Darwin
import Foundation
import Testing
import MopCore
@testable import MopCLI

// The runner temporarily installs process-wide signal handlers.
@Suite(.serialized) struct ExecutionTests {
    private func execute(_ command: [String], secrets: [SecretBytes] = [], input: Data = Data(), environment: [String: SecretBytes] = ["PATH": "/usr/bin:/bin"]) throws -> (Int32, Data, Data) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-process-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let inURL = root.appendingPathComponent("input")
        let outURL = root.appendingPathComponent("output")
        let errURL = root.appendingPathComponent("error")
        try input.write(to: inURL)
        let infd = open(inURL.path, O_RDONLY | O_CLOEXEC)
        let outfd = open(outURL.path, O_WRONLY | O_CREAT | O_CLOEXEC, 0o600)
        let errfd = open(errURL.path, O_WRONLY | O_CREAT | O_CLOEXEC, 0o600)
        defer { [infd, outfd, errfd].forEach { _ = close($0) } }
        let status = try MaskedExecute.execute(command, environment: environment, secrets: secrets,
                                                input: infd, output: outfd, errorOutput: errfd)
        return (status, try Data(contentsOf: outURL), try Data(contentsOf: errURL))
    }

    @Test func maskedStreamsAndStdin() throws {
        let (status, out, err) = try execute(["/bin/sh", "-c", "cat; printf 'secret-two' >&2; exit 42"],
                                           secrets: ["secret-one", "secret-two"], input: Data("secret-one\n".utf8))
        #expect(status >> 8 == 42)
        #expect(out == Data("[concealed by 2ndpass]\n".utf8))
        #expect(err == Data("[concealed by 2ndpass]".utf8))
    }

    @Test func largeConcurrentStreamsAndBinaryData() throws {
        let script = "import os,threading; data=b'abc-secret-xyz\\xff\\x00'*20000; t=threading.Thread(target=lambda: os.write(2,data)); t.start(); os.write(1,data); t.join()"
        let (status, out, err) = try execute(["/usr/bin/python3", "-c", script], secrets: ["secret"])
        let expected = Data(Array(repeating: Array("abc-[concealed by 2ndpass]-xyz".utf8) + [0xff, 0], count: 20000).flatMap { $0 })
        #expect(status == 0)
        #expect(out == expected)
        #expect(err == expected)
    }

    @Test func statusLookupAndNoImplicitShell() throws {
        let (status, _, _) = try execute(["/bin/sh", "-c", "kill -TERM $$"])
        #expect(status & 0x7f == SIGTERM)
        let (success, out, _) = try execute(["printf", "%s", "literal"])
        #expect(success == 0)
        #expect(out == Data("literal".utf8))
        #expect(throws: MopError.executableNotFound) { try execute(["mop-no-such-executable"]) }
        #expect(throws: MopError.launch) { try execute(["/etc/hosts"]) }
    }

    @Test func ownedEnvironmentPreservesExactBytesAndRejectsNUL() throws {
        let value: SecretBytes = "é-e\u{301}-🔒\nquotes'\"=end"
        let environment: [String: SecretBytes] = ["PATH": "/usr/bin:/bin", "TOKEN": value, "EMPTY": ""]
        let (status, out, _) = try execute(["/bin/sh", "-c", "printf '%s' \"$TOKEN\""], environment: environment)
        #expect(status == 0)
        #expect(out.elementsEqual(value))
        let (_, masked, _) = try execute(["/bin/sh", "-c", "printf '%s' \"$TOKEN\""], secrets: [value], environment: environment)
        #expect(masked == Data("[concealed by 2ndpass]".utf8))
        #expect(throws: MopError.invalidProcess) { try EnvironmentBlock(["TOKEN": "a\0b"]) }
        #expect(throws: MopError.invalidProcess) { try EnvironmentBlock(["BAD=NAME": "value"]) }
    }

    @Test func brokenOutputPipeTerminatesAndReapsChild() throws {
        var pipeFD = [Int32](repeating: -1, count: 2)
        #expect(pipe(&pipeFD) == 0)
        close(pipeFD[0])
        defer { close(pipeFD[1]) }
        let null = open("/dev/null", O_RDWR | O_CLOEXEC)
        defer { close(null) }
        #expect(throws: MopError.inputOutput) {
            try MaskedExecute.execute(["/bin/sh", "-c", "trap '' TERM; while :; do printf secret; done"],
                                      environment: [:], secrets: ["secret"], input: null, output: pipeFD[1], errorOutput: null)
        }
    }
}
