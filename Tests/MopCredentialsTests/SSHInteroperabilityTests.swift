import XCTest
import Foundation
import Synchronization
import MopCore
import MopLocalIdentity
@testable import MopCredentials

private struct CloudGitBackend: SSHAgentBackend {
    let key: CloudKey
    func identities() throws -> [SSHAgentIdentity] { [.init(blob: key.sshBlob, comment: "cloud-test")] }
    func sign(blob: Data, data: Data) throws -> Data { throw CredentialFailure.invalid }
    func signature(blob: Data, data: Data, flags: UInt32) throws -> Data {
        guard blob == key.sshBlob else { throw CredentialFailure.invalid }
        try SSHSigningPolicy.validate(data: data, key: blob, purpose: .gitSigning)
        return try key.sign(data, flags: flags)
    }
}
final class SSHInteroperabilityTests: XCTestCase {
    func testGitCommitsAndTagsWithAllCloudAlgorithms() throws {
        let root = URL(fileURLWithPath: "/tmp/mop-git-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        func run(_ exe: String, _ args: [String], _ directory: URL, _ env: [String: String] = [:]) throws -> String {
            let process = Process(), pipe = Pipe(); process.executableURL = URL(fileURLWithPath: exe); process.arguments = args; process.currentDirectoryURL = directory
            process.environment = ProcessInfo.processInfo.environment.merging(env) { _, value in value }; process.standardOutput = pipe; process.standardError = pipe
            try process.run(); let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self); process.waitUntilExit()
            guard process.terminationStatus == 0 else { XCTFail("\(args): \(output)"); throw CredentialFailure.invalid }; return output
        }
        _ = try run("/usr/bin/ssh-keygen", ["-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", root.appendingPathComponent("rsa").path], root)
        let rsa = try OpenSSHImport.read(SecretBytes(copying: Data(contentsOf: root.appendingPathComponent("rsa"))))
        XCTAssertThrowsError(try rsa.sign(Data([1]), flags: 0))
        XCTAssertFalse(try rsa.sign(Data([1]), flags: 2).isEmpty)
        XCTAssertFalse(try rsa.sign(Data([1]), flags: 6).isEmpty)
        for key in [try CloudKey.generate(.ed25519), try CloudKey.generate(.p256), rsa] {
            let directory = root.appendingPathComponent(key.algorithm.rawValue + "-repo")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let agent = SSHAgent(backend: CloudGitBackend(key: key)), socket = directory.appendingPathComponent("agent").path
            let ready = DispatchSemaphore(value: 0), done = DispatchGroup(), error = Mutex<String?>(nil)
            done.enter()
            DispatchQueue.global().async {
                defer { done.leave() }
                do { try agent.serve(socketPath: socket, onReady: { ready.signal() }) }
                catch let failure { error.withLock { $0 = String(describing: failure) }; ready.signal() }
            }
            defer { agent.stop(); done.wait() }
            guard ready.wait(timeout: .now() + 5) == .success, error.withLock({ $0 }) == nil else { throw CredentialFailure.invalid }
            let type = key.algorithm == .ed25519 ? "ssh-ed25519" : key.algorithm == .p256 ? "ecdsa-sha2-nistp256" : "ssh-rsa"
            let line = type + " " + key.sshBlob.base64EncodedString()
            let allowed = directory.appendingPathComponent("allowed")
            try Data(("test@example.com " + line + "\n").utf8).write(to: allowed)
            let env = ["SSH_AUTH_SOCK": socket, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"]
            _ = try run("/usr/bin/ssh-add", ["-L"], directory, env)
            _ = try run("/usr/bin/git", ["init", "-q"], directory, env)
            for (name, value) in [("user.name", "Test"), ("user.email", "test@example.com"), ("gpg.format", "ssh"), ("user.signingkey", "key::" + line), ("gpg.ssh.allowedSignersFile", allowed.path)] {
                _ = try run("/usr/bin/git", ["config", name, value], directory, env)
            }
            _ = try run("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-S", "-m", "test"], directory, env)
            _ = try run("/usr/bin/git", ["verify-commit", "HEAD"], directory, env)
            _ = try run("/usr/bin/git", ["tag", "-s", "test", "-m", "test"], directory, env)
            _ = try run("/usr/bin/git", ["verify-tag", "test"], directory, env)
            agent.stop(); done.wait()
        }
    }
}
