import CryptoKit
import Darwin
import Foundation
import Testing
import MopCore
@testable import MopLocalIdentity

private struct FakeBackend: SSHAgentBackend {
    var keys: [SSHAgentIdentity]
    var signature: Data
    func identities() throws -> [SSHAgentIdentity] { keys }
    func sign(blob: Data, data: Data) throws -> Data {
        guard keys.contains(where: { $0.blob == blob }) else { throw MopError.notFound }
        return signature
    }
}

@Test func messageNumbersMatchRFC9987() {
    // Client requests
    #expect(SSHAgentCommand.requestIdentities == 11)
    #expect(SSHAgentCommand.signRequest == 13)
    #expect(SSHAgentCommand.addIdentity == 17)
    #expect(SSHAgentCommand.removeIdentity == 18)
    #expect(SSHAgentCommand.removeAllIdentities == 19)
    #expect(SSHAgentCommand.lock == 22)
    #expect(SSHAgentCommand.unlock == 23)
    #expect(SSHAgentCommand.agentExtension == 27)
    // Agent responses
    #expect(SSHAgentCommand.failure == 5)
    #expect(SSHAgentCommand.success == 6)
    #expect(SSHAgentCommand.identitiesAnswer == 12)
    #expect(SSHAgentCommand.signResponse == 14)
}

@Test func framePrependsLengthPrefix() throws {
    let message = SSHAgentFraming.simple(SSHAgentCommand.success)
    let framed = SSHAgentFraming.frame(message)
    #expect(framed.count == message.count + 4)
    var offset = 0
    #expect(try SSHAgentFraming.parseUInt32(framed, &offset) == UInt32(message.count))
    #expect(Array(framed.dropFirst(4)) == Array(message))
}

@Test func identitiesResponseRoundTrip() throws {
    let a = SSHAgentIdentity(blob: Data([1, 2, 3]), comment: "one")
    let b = SSHAgentIdentity(blob: Data([4, 5, 6]), comment: "two")
    let response = SSHAgentFraming.identitiesResponse([a, b])
    #expect(response.first == SSHAgentCommand.identitiesAnswer)
    var offset = 1
    #expect(try SSHAgentFraming.parseUInt32(response, &offset) == 2)
    #expect(try SSHAgentFraming.parseString(response, &offset) == a.blob)
    #expect(try SSHAgentFraming.parseString(response, &offset) == Data("one".utf8))
    #expect(try SSHAgentFraming.parseString(response, &offset) == b.blob)
    #expect(try SSHAgentFraming.parseString(response, &offset) == Data("two".utf8))
}

@Test func emptyIdentitiesResponse() throws {
    let response = SSHAgentFraming.identitiesResponse([])
    #expect(response.count == 5) // command + uint32(0)
    #expect(Array(response[1...]) == [0, 0, 0, 0])
}

@Test func signRequestDispatch() throws {
    let backend = FakeBackend(keys: [SSHAgentIdentity(blob: Data([9, 9, 9]), comment: "k")],
                              signature: try P256.Signing.PrivateKey().signature(for: Data("message".utf8)).derRepresentation)
    var payload = Data()
    SSHAgentFraming.appendString(&payload, Data([9, 9, 9]))    // key blob
    SSHAgentFraming.appendString(&payload, Data("message".utf8)) // data
    SSHAgentFraming.appendUInt32(&payload, 0)                  // flags
    let response = try SSHAgentFraming.handle(command: SSHAgentCommand.signRequest, payload: payload, backend: backend)
    #expect(response.first == SSHAgentCommand.signResponse)
    var offset = 1
    // The response carries only the signature, no key blob (RFC 9987 §5.6).
    #expect(try SSHAgentFraming.parseString(response, &offset) == SSHAgentFraming.sshSignature(der: backend.signature))
    #expect(offset == response.count)
}

@Test func signRequestRejectsUnknownBlob() {
    let backend = FakeBackend(keys: [SSHAgentIdentity(blob: Data([9, 9, 9]), comment: "k")],
                              signature: Data([0x30, 0x06]))
    var payload = Data()
    SSHAgentFraming.appendString(&payload, Data([1, 1, 1]))
    SSHAgentFraming.appendString(&payload, Data("m".utf8))
    SSHAgentFraming.appendUInt32(&payload, 0)
    #expect(throws: MopError.notFound) {
        try SSHAgentFraming.handle(command: SSHAgentCommand.signRequest, payload: payload, backend: backend)
    }
}

@Test func controlCommands() throws {
    let backend = FakeBackend(keys: [], signature: Data())
    #expect(try SSHAgentFraming.handle(command: SSHAgentCommand.lock, payload: Data(), backend: backend).first == SSHAgentCommand.failure)
    #expect(try SSHAgentFraming.handle(command: SSHAgentCommand.unlock, payload: Data(), backend: backend).first == SSHAgentCommand.failure)
    #expect(try SSHAgentFraming.handle(command: SSHAgentCommand.removeAllIdentities, payload: Data(), backend: backend).first == SSHAgentCommand.failure)
    #expect(try SSHAgentFraming.handle(command: SSHAgentCommand.addIdentity, payload: Data(), backend: backend).first == SSHAgentCommand.failure)
    #expect(try SSHAgentFraming.handle(command: SSHAgentCommand.addIdConstrained, payload: Data(), backend: backend).first == SSHAgentCommand.failure)
    #expect(try SSHAgentFraming.handle(command: SSHAgentCommand.removeIdentity, payload: Data(), backend: backend).first == SSHAgentCommand.failure)
}

@Test func unknownCommandReturnsFailureNotNil() throws {
    let backend = FakeBackend(keys: [], signature: Data())
    let response = try SSHAgentFraming.handle(command: 0x7f, payload: Data(), backend: backend)
    #expect(response.first == SSHAgentCommand.failure)
}

@Test func sessionBindExtensionIsUnsupported() throws {
    let backend = FakeBackend(keys: [], signature: Data())
    var payload = Data()
    SSHAgentFraming.appendString(&payload, Data("session-bind@openssh.com".utf8))
    SSHAgentFraming.appendString(&payload, Data([0xAA])) // hostkey
    SSHAgentFraming.appendString(&payload, Data([0xBB])) // session id
    SSHAgentFraming.appendString(&payload, Data([0xCC])) // signature
    payload.append(0) // is_forwarding = false
    let response = try SSHAgentFraming.handle(command: SSHAgentCommand.agentExtension, payload: payload, backend: backend)
    #expect(response.first == SSHAgentCommand.failure)
}

@Test func unsupportedExtensionReturnsFailure() throws {
    let backend = FakeBackend(keys: [], signature: Data())
    var payload = Data()
    SSHAgentFraming.appendString(&payload, Data("nonsense@openssh.com".utf8))
    let response = try SSHAgentFraming.handle(command: SSHAgentCommand.agentExtension, payload: payload, backend: backend)
    #expect(response.first == SSHAgentCommand.failure)
}
@Test func slicedAndUnalignedProtocolFields() throws {
    let bytes = Data([99, 0, 0, 0, 3, 1, 2, 3])
    var offset = 0
    #expect(try SSHAgentFraming.parseString(bytes.dropFirst(), &offset) == Data([1, 2, 3]))
    #expect(offset == 7)
}

@Test func socketKeepsServingAfterUnsupportedAndMalformedRequests() throws {
    var sockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    let client = sockets[0]
    let server = sockets[1]
    var timeout = timeval(tv_sec: 3, tv_usec: 0)
    _ = setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    let agent = SSHAgent(backend: FakeBackend(keys: [], signature: Data()))
    let done = DispatchGroup()
    done.enter()
    DispatchQueue.global().async {
        agent.handleConnection(server)
        done.leave()
    }
    defer { close(client); #expect(done.wait(timeout: .now() + 5) == .success) }
    let io = SSHAgentIO(fd: client)
    var extensionPayload = Data()
    SSHAgentFraming.appendString(&extensionPayload, Data("session-bind@openssh.com".utf8))
    let messages = [
        SSHAgentFraming.withCommand(SSHAgentCommand.agentExtension, extensionPayload),
        Data([SSHAgentCommand.signRequest, 0, 0]),
        Data([SSHAgentCommand.requestIdentities]),
    ]
    for (message, expected) in zip(messages, [Data([5]), Data([5]), Data([12, 0, 0, 0, 0])]) {
        // Split the length and payload across writes, as a stream transport may do.
        for byte in SSHAgentFraming.frame(message) { #expect(io.writeAll(Data([byte]))) }
        let length = try #require(io.readUInt32())
        #expect(io.readExact(Int(length)) == expected)
    }
}

private struct SoftwareSigningBackend: SSHAgentBackend {
    let key = P256.Signing.PrivateKey()
    func identities() throws -> [SSHAgentIdentity] {
        [SSHAgentIdentity(blob: try SSHPublicKey.wireBlob(x963: key.publicKey.x963Representation), comment: "interop")]
    }
    func sign(blob: Data, data: Data) throws -> Data {
        guard blob == (try identities()[0].blob) else { throw MopError.notFound }
        return try key.signature(for: data).derRepresentation
    }
}

@Test func openSSHListsKeysAndVerifiesAgentSignatures() throws {
    let backend = SoftwareSigningBackend()
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let publicKey = try SSHPublicKey.openSSH(x963: backend.key.publicKey.x963Representation, comment: "interop")
    let publicKeyFile = directory.appendingPathComponent("key.pub")
    try Data((publicKey + "\n").utf8).write(to: publicKeyFile)
    for arguments in [["-L"], ["-T", publicKeyFile.path]] {
        let agent = SSHAgent(backend: backend)
        // A short path fits Darwin's sockaddr_un even with a long TMPDIR.
        let path = "/tmp/mop-\(UUID().uuidString).sock"
        let done = DispatchGroup()
        done.enter()
        DispatchQueue.global().async {
            defer { done.leave() }
            do {
                try agent.serve(socketPath: path)
            } catch { Issue.record("Agent startup failed: \(error)") }
        }
        defer { agent.stop() }
        for _ in 0..<200 where !FileManager.default.fileExists(atPath: path) { usleep(5_000) }
        try #require(FileManager.default.fileExists(atPath: path))
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-add")
        process.arguments = arguments
        var environment = ProcessInfo.processInfo.environment
        environment["SSH_AUTH_SOCK"] = path
        process.environment = environment
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        process.waitUntilExit()
        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        #expect(process.terminationStatus == 0, "ssh-add \(arguments): \(text)")
        if arguments == ["-L"] { #expect(text.trimmingCharacters(in: .whitespacesAndNewlines) == publicKey) }
        agent.stop()
        #expect(done.wait(timeout: .now() + 5) == .success)
    }
}

@Test func sshSignatureEncodesPositiveMinimalMPInts() throws {
    // r needs a sign-protecting zero; s needs its leading zero bytes removed.
    let raw = Data([0x80] + Array(repeating: UInt8(0), count: 31)
                   + Array(repeating: UInt8(0), count: 31) + [1])
    let der = try P256.Signing.ECDSASignature(rawRepresentation: raw).derRepresentation
    let encoded = try SSHAgentFraming.sshSignature(der: der)
    var offset = 0
    #expect(try SSHAgentFraming.parseString(encoded, &offset) == Data("ecdsa-sha2-nistp256".utf8))
    let integers = try SSHAgentFraming.parseString(encoded, &offset)
    #expect(offset == encoded.count)
    var integerOffset = 0
    #expect(try SSHAgentFraming.parseString(integers, &integerOffset) == Data([0]) + raw.prefix(32))
    #expect(try SSHAgentFraming.parseString(integers, &integerOffset) == Data([1]))
    #expect(integerOffset == integers.count)
}

@Test func agentServesConcurrentClientsAndStopsIdleAndPartialReads() throws {
    let agent = SSHAgent(backend: FakeBackend(keys: [], signature: Data()))
    let path = "/tmp/mop-\(UUID().uuidString).sock"
    let done = DispatchGroup()
    done.enter()
    DispatchQueue.global().async {
        defer { done.leave() }
        do { try agent.serve(socketPath: path) }
        catch { Issue.record("Agent failed: \(error)") }
    }
    var clients: [Int32] = []
    defer {
        agent.stop()
        clients.forEach { close($0) }
        #expect(done.wait(timeout: .now() + 3) == .success)
    }
    for _ in 0..<200 where !FileManager.default.fileExists(atPath: path) { usleep(5_000) }
    try #require(FileManager.default.fileExists(atPath: path))
    for _ in 0..<3 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        try #require(fd >= 0)
        clients.append(fd)
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8CString)
        memcpy(&address.sun_path, pathBytes, pathBytes.count)
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        try #require(connected == 0)
        let io = SSHAgentIO(fd: fd)
        #expect(io.writeAll(Data([0, 0, 0, 1, 11])))
        #expect(io.readUInt32() == 5)
        #expect(io.readExact(5) == Data([12, 0, 0, 0, 0]))
        // Leave all clients connected. Subsequent clients must still be served.
    }
    // One worker waits for a length, one for a partial length, one for a body.
    #expect(SSHAgentIO(fd: clients[1]).writeAll(Data([0, 0])))
    #expect(SSHAgentIO(fd: clients[2]).writeAll(Data([0, 0, 0, 10, 13])))
    agent.stop()
    agent.stop() // idempotent
    #expect(done.wait(timeout: .now() + 3) == .success)
    #expect(!FileManager.default.fileExists(atPath: path))
    for client in clients { #expect(SSHAgentIO(fd: client).readExact(1) == nil) }
}

@Test func agentStoppedBeforeStartupDoesNotStartServing() {
    let agent = SSHAgent(backend: FakeBackend(keys: [], signature: Data()))
    let path = "/tmp/mop-\(UUID().uuidString).sock"
    agent.stop()
    #expect(throws: MopError.inputOutput) { try agent.serve(socketPath: path) }
    #expect(!FileManager.default.fileExists(atPath: path))
}
