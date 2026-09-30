#if os(macOS)
import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Testing
import MopCore
@testable import MopLocalIdentity

private final class SessionFixture {
    let key = P256.Signing.PrivateKey() // Software protocol fixture, not enclave evidence.
    var rows: [LocalIdentity] = []
    var authorizations: [LocalAuthorization] = []
    var prompts: [String] = []
    var cancel = false
    var afterApproval: () -> Void = {}
    var afterSign: () -> Void = {}

    init() throws {
        rows = try ["first", "second"].map {
            try LocalIdentity(name: $0, algorithm: .p256Signing, protocolType: .ssh, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        }
    }
    func session(wrapped: Bool = false) throws -> SSHAgentSession {
        try SSHAgentSession(purpose: .ssh, ids: Set(rows.map(\.id)), wrapped: wrapped, approvalLifetime: 300,
            list: { self.rows }, sign: { id, data, auth in
                try auth.begin(id: id, purpose: .ssh, operation: .sign)
                self.afterSign()
                return try self.key.signature(for: data).derRepresentation
            }, authorize: { reason, identity, lifetime, created in
                self.prompts.append(reason)
                let context = LAContext()
                try created(context)
                if self.cancel { throw MopError.authentication }
                let auth = LocalAuthorization(context: context, ids: [identity.id], purposes: [.ssh], operations: [.sign], expires: Date().addingTimeInterval(lifetime))
                self.authorizations.append(auth)
                self.afterApproval()
                return auth
            }, watchDevice: false)
    }
}

private func withPeer(_ body: (Int32) throws -> Void) throws {
    var pair: [Int32] = [-1, -1]
    try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
    defer { pair.forEach { _ = close($0) } }
    try body(pair[0])
}

private func authenticationPayload(_ blob: Data) -> Data {
    var data = Data()
    SSHAgentFraming.appendString(&data, Data(repeating: 1, count: 32)); data.append(50)
    for text in ["alice", "ssh-connection", "publickey"] { SSHAgentFraming.appendString(&data, Data(text.utf8)) }
    data.append(1)
    SSHAgentFraming.appendString(&data, Data(SSHPublicKey.algorithm.utf8))
    SSHAgentFraming.appendString(&data, blob)
    return data
}

@Test func invalidApprovalLifetimeFailsBeforeAuthentication() {
    for lifetime in [0.0, -1.0, 43201.0, Double.infinity, Double.nan] {
        #expect(throws: (any Error).self) {
            try LocalAuthorization.authorize(reason: "test", ids: [], purposes: [.ssh], operations: [.sign], lifetime: lifetime, contextCreated: { _ in
                Issue.record("Invalid lifetime reached authentication")
            })
        }
    }
}

@Test func requestAuthorizationIsLazyKeyScopedAndRevocable() throws {
    let fixture = try SessionFixture(), session = try fixture.session()
    defer { session.stop() }
    #expect(fixture.prompts.isEmpty)
    try withPeer { fd in
        let backend = try session.backend(socket: fd)
        let keys = try backend.identities()
        #expect(keys.count == 2)
        #expect(fixture.prompts.isEmpty)
        #expect(throws: (any Error).self) { try backend.sign(blob: keys[0].blob, data: Data("arbitrary".utf8)) }
        #expect(fixture.prompts.isEmpty)
        _ = try backend.sign(blob: keys[0].blob, data: authenticationPayload(keys[0].blob))
        _ = try backend.sign(blob: keys[0].blob, data: authenticationPayload(keys[0].blob))
        #expect(fixture.prompts.count == 1)
        #expect(fixture.prompts[0].contains("300 seconds"))
        _ = try backend.sign(blob: keys[1].blob, data: authenticationPayload(keys[1].blob))
        #expect(fixture.prompts.count == 2)
        fixture.authorizations[0].revoke()
        _ = try backend.sign(blob: keys[0].blob, data: authenticationPayload(keys[0].blob))
        #expect(fixture.prompts.count == 3)
        session.stop()
        #expect(fixture.authorizations.allSatisfy { !$0.isActive })
        #expect(throws: (any Error).self) { try backend.identities() }
    }
}

@Test func cancelledAndLateAuthorizationsFailClosed() throws {
    let fixture = try SessionFixture(), session = try fixture.session()
    defer { session.stop() }
    try withPeer { fd in
        let backend = try session.backend(socket: fd), key = try backend.identities()[0]
        fixture.cancel = true
        #expect(throws: (any Error).self) { try backend.sign(blob: key.blob, data: authenticationPayload(key.blob)) }
        fixture.cancel = false
        fixture.afterApproval = { session.stop() }
        #expect(throws: (any Error).self) { try backend.sign(blob: key.blob, data: authenticationPayload(key.blob)) }
        #expect(fixture.prompts.count == 2)
        #expect(fixture.authorizations.allSatisfy { !$0.isActive })
    }
}

@Test func deletionAndLateSignaturesFailClosed() throws {
    for delete in [true, false] {
        let fixture = try SessionFixture(), session = try fixture.session()
        defer { session.stop() }
        try withPeer { fd in
            let backend = try session.backend(socket: fd), key = try backend.identities()[0]
            if delete { fixture.rows.removeAll() }
            else { fixture.afterSign = { session.stop() } }
            #expect(throws: (any Error).self) { try backend.sign(blob: key.blob, data: authenticationPayload(key.blob)) }
            #expect(!session.isActive)
        }
    }
}

@Test func wrappedSessionRequiresRootAndRejectsUnrelatedProcesses() throws {
    let fixture = try SessionFixture(), session = try fixture.session(wrapped: true)
    defer { session.stop() }
    try withPeer { fd in
        #expect(throws: (any Error).self) { try session.backend(socket: fd) }
        try session.setCommand(getpid())
        #expect(try session.backend(socket: fd).identities().count == 2)
    }
    let child = Process()
    child.executableURL = URL(fileURLWithPath: "/bin/sleep"); child.arguments = ["30"]
    try child.run()
    defer { child.terminate(); child.waitUntilExit() }
    let unrelated = try fixture.session(wrapped: true)
    defer { unrelated.stop() }
    try unrelated.setCommand(child.processIdentifier)
    try withPeer { fd in
        #expect(throws: (any Error).self) { try unrelated.backend(socket: fd) }
    }
    #expect(fixture.prompts.isEmpty)
}

@Test func peerRejectsReusedProcessInstanceAndInvalidSocket() throws {
    let actual = try SSHAgentProcess.read(getpid())
    let reused = SSHAgentProcess(pid: actual.pid, parent: actual.parent, seconds: actual.seconds + 1, microseconds: actual.microseconds)
    #expect(!actual.sameInstance(as: reused))
    #expect(throws: (any Error).self) { try SSHAgentPeer(socket: -1) }
    try withPeer { fd in
        let peer = try SSHAgentPeer(socket: fd)
        #expect(throws: (any Error).self) { try peer.validate(root: reused) }
    }
}
#endif

#if os(macOS)
@Test func realWrappedAgentAllowsDescendantButRejectsSiblingWithoutPrompting() throws {
    let fixture = try SessionFixture(), session = try fixture.session(wrapped: true)
    defer { session.stop() }
    let root = URL(fileURLWithPath: "/tmp/sp-scope-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let socket = root.appendingPathComponent("agent").path
    let agent = SSHAgent(connectionBackend: { try session.backend(socket: $0) }, onStop: { session.stop() })
    let ready = DispatchSemaphore(value: 0), done = DispatchGroup()
    done.enter()
    DispatchQueue.global().async {
        defer { done.leave() }
        do { try agent.serve(socketPath: socket, onReady: { ready.signal() }) }
        catch { ready.signal() }
    }
    defer { agent.stop(); done.wait() }
    try #require(ready.wait(timeout: .now() + 5) == .success)

    let child = Process(), input = Pipe(), output = Pipe()
    child.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
    child.arguments = ["-c", "import sys,subprocess; sys.stdin.readline(); sys.exit(subprocess.call(['/usr/bin/ssh-add','-L']))"]
    child.environment = ["SSH_AUTH_SOCK": socket, "PATH": "/usr/bin:/bin"]
    child.standardInput = input; child.standardOutput = output; child.standardError = output
    try child.run()
    defer { if child.isRunning { child.terminate(); child.waitUntilExit() } }
    try session.setCommand(child.processIdentifier)
    let sibling = Process()
    sibling.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-add"); sibling.arguments = ["-L"]
    sibling.environment = child.environment
    sibling.standardOutput = FileHandle.nullDevice; sibling.standardError = FileHandle.nullDevice
    try sibling.run(); sibling.waitUntilExit()
    #expect(sibling.terminationStatus != 0)
    try input.fileHandleForWriting.write(contentsOf: Data("go\n".utf8))
    try input.fileHandleForWriting.close()
    let listed = output.fileHandleForReading.readDataToEndOfFile()
    child.waitUntilExit()
    #expect(child.terminationStatus == 0)
    #expect(String(decoding: listed, as: UTF8.self).contains("ecdsa-sha2-nistp256"))
    #expect(fixture.prompts.isEmpty)
}
#endif

#if os(macOS)
@Test func standaloneApprovalsAreNotSharedBetweenRealClientProcesses() throws {
    let fixture = try SessionFixture(), session = try fixture.session()
    defer { session.stop() }
    let root = URL(fileURLWithPath: "/tmp/sp-clients-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let socket = root.appendingPathComponent("agent").path
    let agent = SSHAgent(connectionBackend: { try session.backend(socket: $0) }, onStop: { session.stop() })
    let ready = DispatchSemaphore(value: 0), done = DispatchGroup()
    done.enter()
    DispatchQueue.global().async {
        defer { done.leave() }
        do { try agent.serve(socketPath: socket, onReady: { ready.signal() }) }
        catch { ready.signal() }
    }
    defer { agent.stop(); done.wait() }
    try #require(ready.wait(timeout: .now() + 5) == .success)
    let blob = try SSHPublicKey.wireBlob(x963: fixture.rows[0].publicKey)
    var request = Data([SSHAgentCommand.signRequest])
    SSHAgentFraming.appendString(&request, blob)
    SSHAgentFraming.appendString(&request, authenticationPayload(blob))
    SSHAgentFraming.appendUInt32(&request, 0)
    let frame = SSHAgentFraming.frame(request).base64EncodedString()
    for _ in 0..<2 {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        child.arguments = ["-c", """
        import base64,socket,struct,sys
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(sys.argv[1])
        stream=s.makefile('rb')
        for _ in range(2):
            s.sendall(base64.b64decode(sys.argv[2]))
            length=struct.unpack('>I',stream.read(4))[0]
            response=stream.read(length)
            assert response[0]==14, response
        """, socket, frame]
        try child.run(); child.waitUntilExit()
        #expect(child.terminationStatus == 0)
    }
    // Two requests per process reused its approval; the next process prompted again.
    #expect(fixture.prompts.count == 2)
    #expect(fixture.authorizations.count == 2)
}
#endif
