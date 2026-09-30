import CryptoKit
import Foundation
import Synchronization
import Testing
import MopCore
@testable import MopLocalIdentity

private func command(_ executable: String, _ arguments: [String], directory: URL, environment: [String: String] = [:]) throws -> String {
    let process = Process(), pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
    process.currentDirectoryURL = directory
    process.environment = ProcessInfo.processInfo.environment.merging(environment) { _, new in new }
    process.standardOutput = pipe; process.standardError = pipe
    try process.run()
    let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    process.waitUntilExit()
    try #require(process.terminationStatus == 0, "\(arguments): \(output)")
    return output
}

private struct GitBackend: SSHAgentBackend {
    // Software fixture only: validates wire interoperability, never hardware claims.
    let key = P256.Signing.PrivateKey()
    func identities() throws -> [SSHAgentIdentity] { [SSHAgentIdentity(blob: try SSHPublicKey.wireBlob(x963: key.publicKey.x963Representation), comment: "git-test")] }
    func sign(blob: Data, data: Data) throws -> Data {
        guard try blob == identities()[0].blob else { throw MopError.notFound }
        try SSHSigningPolicy.validate(data: data, key: blob, purpose: .gitSigning)
        return try key.signature(for: data).derRepresentation
    }
}

@Test func realGitSignsAndVerifiesCommitAndTagThroughPurposeRestrictedAgent() throws {
    let directory = URL(fileURLWithPath: "/tmp/git-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let backend = GitBackend(), agent = SSHAgent(backend: backend)
    let socket = directory.appendingPathComponent("agent").path
    let ready = DispatchSemaphore(value: 0), done = DispatchGroup(), failure = Mutex<String?>(nil)
    done.enter()
    DispatchQueue.global().async {
        defer { done.leave() }
        do { try agent.serve(socketPath: socket, onReady: { ready.signal() }) }
        catch { failure.withLock { $0 = String(describing: error) }; ready.signal() }
    }
    defer { agent.stop(); done.wait() }
    try #require(ready.wait(timeout: .now() + 5) == .success)
    try #require(failure.withLock { $0 } == nil)
    let line = try SSHPublicKey.openSSH(x963: backend.key.publicKey.x963Representation, comment: "git-test")
    try Data(("test@example.com " + line + "\n").utf8).write(to: directory.appendingPathComponent("allowed"))
    let env = ["SSH_AUTH_SOCK": socket, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"]
    func git(_ args: [String]) throws -> String { try command("/usr/bin/git", args, directory: directory, environment: env) }
    _ = try git(["init", "-q"])
    for (key, value) in [("user.email", "test@example.com"), ("user.name", "Test"), ("gpg.format", "ssh"), ("user.signingKey", "key::" + line), ("gpg.ssh.allowedSignersFile", directory.appendingPathComponent("allowed").path)] {
        _ = try git(["config", key, value])
    }
    _ = try git(["-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-S", "-m", "test"])
    _ = try git(["verify-commit", "HEAD"])
    _ = try git(["tag", "-s", "test-tag", "-m", "test tag"])
    _ = try git(["verify-tag", "test-tag"])
}

@Test func opensslVerifiesCSRWithAllSANForms() throws {
    let directory = URL(fileURLWithPath: "/tmp/csr-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let key = P256.Signing.PrivateKey() // DER interoperability fixture, not enclave evidence
    let info = try LocalCSR.requestInfo(publicKey: key.publicKey.x963Representation, subject: CertificateSubject(commonName: "Client", organization: "Example", organizationalUnit: "Engineering", country: "US"), names: [.dns("client.example.com"), .email("client@example.com"), .uri("urn:example:client"), .ip("127.0.0.1"), .ip("::1")])
    let pem = try LocalCSR.pem(requestInfo: info, signature: key.signature(for: info).derRepresentation)
    let path = directory.appendingPathComponent("request.pem")
    try Data(pem.utf8).write(to: path)
    let text = try command("/usr/bin/openssl", ["req", "-in", path.path, "-verify", "-text", "-noout"], directory: directory)
    #expect(text.contains("client.example.com"))
    #expect(text.contains("client@example.com"))
    #expect(text.contains("urn:example:client"))
    #expect(text.contains("127.0.0.1"))
}

@Test func sshPurposeRejectsGitAndArbitraryPayloads() throws {
    let blob = try SSHPublicKey.wireBlob(x963: P256.Signing.PrivateKey().publicKey.x963Representation)
    var data = Data()
    SSHAgentFraming.appendString(&data, Data(repeating: 1, count: 32)); data.append(50)
    for value in ["alice", "ssh-connection", "publickey"] { SSHAgentFraming.appendString(&data, Data(value.utf8)) }
    data.append(1); SSHAgentFraming.appendString(&data, Data(SSHPublicKey.algorithm.utf8)); SSHAgentFraming.appendString(&data, blob)
    try SSHSigningPolicy.validate(data: data, key: blob, purpose: .ssh)
    #expect(throws: (any Error).self) { try SSHSigningPolicy.validate(data: data, key: blob, purpose: .gitSigning) }
    #expect(throws: (any Error).self) { try SSHSigningPolicy.validate(data: data + Data([0]), key: blob, purpose: .ssh) }
}

@Test func sshPurposeAcceptsHostboundAuthenticationAndRejectsMalformedRequests() throws {
    let key = P256.Signing.PrivateKey() // Protocol fixture only, not hardware evidence.
    let blob = try SSHPublicKey.wireBlob(x963: key.publicKey.x963Representation)
    let hostBlob = try SSHPublicKey.wireBlob(x963: P256.Signing.PrivateKey().publicKey.x963Representation)
    var prefix = Data()
    SSHAgentFraming.appendString(&prefix, Data(repeating: 1, count: 32)); prefix.append(50)
    for value in ["alice", "ssh-connection", "publickey-hostbound-v00@openssh.com"] {
        SSHAgentFraming.appendString(&prefix, Data(value.utf8))
    }
    prefix.append(1)
    SSHAgentFraming.appendString(&prefix, Data(SSHPublicKey.algorithm.utf8))
    SSHAgentFraming.appendString(&prefix, blob)
    var data = prefix
    SSHAgentFraming.appendString(&data, hostBlob)
    try SSHSigningPolicy.validate(data: data, key: blob, purpose: .ssh)
    #expect(throws: (any Error).self) { try SSHSigningPolicy.validate(data: data, key: blob, purpose: .gitSigning) }
    #expect(throws: (any Error).self) { try SSHSigningPolicy.validate(data: data, key: hostBlob, purpose: .ssh) }
    var emptyHost = prefix
    SSHAgentFraming.appendString(&emptyHost, Data())
    for invalid in [prefix, emptyHost, Data(data.dropLast()), data + Data([0])] {
        #expect(throws: (any Error).self) { try SSHSigningPolicy.validate(data: invalid, key: blob, purpose: .ssh) }
    }

    struct Backend: SSHAgentBackend {
        let key: P256.Signing.PrivateKey
        func identities() throws -> [SSHAgentIdentity] {
            [SSHAgentIdentity(blob: try SSHPublicKey.wireBlob(x963: key.publicKey.x963Representation), comment: "test")]
        }
        func sign(blob: Data, data: Data) throws -> Data {
            try SSHSigningPolicy.validate(data: data, key: identities()[0].blob, purpose: .ssh)
            return try key.signature(for: data).derRepresentation
        }
    }
    var request = Data()
    SSHAgentFraming.appendString(&request, blob)
    SSHAgentFraming.appendString(&request, data)
    SSHAgentFraming.appendUInt32(&request, 0)
    let response = try SSHAgentFraming.handle(command: SSHAgentCommand.signRequest, payload: request, backend: Backend(key: key))
    #expect(response.first == SSHAgentCommand.signResponse)
    var offset = 1
    let signatureBlob = try SSHAgentFraming.parseString(response, &offset)
    #expect(offset == response.count)
    offset = 0
    #expect(try SSHAgentFraming.parseString(signatureBlob, &offset) == Data(SSHPublicKey.algorithm.utf8))
    let scalars = try SSHAgentFraming.parseString(signatureBlob, &offset)
    #expect(offset == signatureBlob.count)
    offset = 0
    var rawSignature = Data()
    for _ in 0..<2 {
        let scalar = try SSHAgentFraming.parseString(scalars, &offset).drop(while: { $0 == 0 })
        try #require(scalar.count <= 32)
        rawSignature.append(Data(repeating: 0, count: 32 - scalar.count))
        rawSignature.append(contentsOf: scalar)
    }
    #expect(offset == scalars.count)
    #expect(try key.publicKey.isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: rawSignature), for: data))
}

@Test func certificateMetadataMatchesKeyAndAcceptsRenewalButRejectsMismatch() throws {
    let directory = URL(fileURLWithPath: "/tmp/cert-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    // Disposable software fixture. Production code never exports enclave private keys.
    let key = P256.Signing.PrivateKey(), privateFile = directory.appendingPathComponent("fixture.pem")
    try Data(key.pemRepresentation.utf8).write(to: privateFile)
    let certificateFile = directory.appendingPathComponent("certificate.pem")
    for serial in ["1", "2"] {
        _ = try command("/usr/bin/openssl", ["req", "-new", "-x509", "-key", privateFile.path, "-subj", "/CN=Client", "-days", "1", "-set_serial", serial, "-out", certificateFile.path], directory: directory)
        let cert = try LocalIdentityStore.parseCertificates(Data(contentsOf: certificateFile))[0]
        let der = Data(try cert.serializeAsPEM().derBytes)
        let identity = try LocalIdentity(name: "certificate", algorithm: .p256Signing, protocolType: .x509, publicKey: key.publicKey.x963Representation, metadata: .certificate(chain: [der]))
        #expect(try identity.certificateInfo.first?.subject.contains("Client") == true)
        #expect(try identity.certificateInfo.first?.trustValidated == false)
        #expect(throws: MopError.invalidLocalIdentity) {
            try LocalIdentity(name: "wrong-key", algorithm: .p256Signing, protocolType: .x509, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation, metadata: .certificate(chain: [der]))
        }
    }
}
