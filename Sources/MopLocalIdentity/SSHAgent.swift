import CryptoKit
import Foundation
import Darwin
import MopCore

/// The SSH agent protocol message type numbers (RFC 9987, §8.1).
public enum SSHAgentCommand {
    // Client requests
    public static let requestIdentities: UInt8 = 11
    public static let signRequest: UInt8 = 13
    public static let addIdentity: UInt8 = 17
    public static let removeIdentity: UInt8 = 18
    public static let removeAllIdentities: UInt8 = 19
    public static let addSmartcardKey: UInt8 = 20
    public static let removeSmartcardKey: UInt8 = 21
    public static let lock: UInt8 = 22
    public static let unlock: UInt8 = 23
    public static let addIdConstrained: UInt8 = 25
    public static let addSmartcardKeyConstrained: UInt8 = 26
    public static let agentExtension: UInt8 = 27
    // Agent responses
    public static let failure: UInt8 = 5
    public static let success: UInt8 = 6
    public static let identitiesAnswer: UInt8 = 12
    public static let signResponse: UInt8 = 14
    public static let extensionFailure: UInt8 = 28
    public static let extensionResponse: UInt8 = 29
}

/// A public key the agent offers to a client. The blob is the full OpenSSH wire
/// blob (see `SSHPublicKey.wireBlob`); the comment is the identity name.
public struct SSHAgentIdentity: Equatable, Sendable {
    public let blob: Data
    public let comment: String
}

/// The source of keys the agent serves. Production wraps the Secure Enclave store;
/// tests use a deterministic in-memory backend.
public protocol SSHAgentBackend {
    func identities() throws -> [SSHAgentIdentity]
    /// Return a DER-encoded ECDSA signature over `data` using the key `blob`.
    func sign(blob: Data, data: Data) throws -> Data
}

/// Pure SSH agent-protocol framing and dispatch (RFC 9987). No I/O: the socket
/// layer reads/writes bytes and hands the parsed message here.
public enum SSHAgentFraming {
    static func withCommand(_ command: UInt8, _ payload: Data) -> Data {
        var data = Data([command])
        data.append(payload)
        return data
    }

    /// Wrap a message (type + contents) in its `uint32 length` prefix (RFC 9987 §5).
    static func frame(_ message: Data) -> Data {
        var framed = Data()
        appendUInt32(&framed, UInt32(message.count))
        framed.append(message)
        return framed
    }

    static func appendUInt32(_ data: inout Data, _ value: UInt32) {
        var bigEndian = value.bigEndian
        data.append(Data(bytes: &bigEndian, count: MemoryLayout<UInt32>.size))
    }

    static func appendString(_ data: inout Data, _ bytes: Data) {
        appendUInt32(&data, UInt32(bytes.count))
        data.append(bytes)
    }

    static func parseUInt32(_ data: Data, _ offset: inout Int) throws -> UInt32 {
        guard offset >= 0, offset <= data.count, data.count - offset >= 4 else { throw MopError.invalidLocalIdentity }
        let start = data.startIndex + offset
        let value = data[start..<(start + 4)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        offset += 4
        return value
    }

    static func parseString(_ data: Data, _ offset: inout Int) throws -> Data {
        let length = try parseUInt32(data, &offset)
        guard length <= 1024 * 1024, offset + Int(length) <= data.count else { throw MopError.invalidLocalIdentity }
        let bytes = Data(data[(data.startIndex + offset)..<(data.startIndex + offset + Int(length))])
        offset += Int(length)
        return bytes
    }

    public static func identitiesResponse(_ identities: [SSHAgentIdentity]) -> Data {
        var payload = Data()
        appendUInt32(&payload, UInt32(identities.count))
        for identity in identities {
            appendString(&payload, identity.blob)
            appendString(&payload, Data(identity.comment.utf8))
        }
        return withCommand(SSHAgentCommand.identitiesAnswer, payload)
    }

    /// SSH_AGENT_SIGN_RESPONSE carries only the signature (RFC 9987 §5.6).
    public static func signResponse(signature: Data) -> Data {
        var payload = Data()
        appendString(&payload, signature)
        return withCommand(SSHAgentCommand.signResponse, payload)
    }

    public static func simple(_ command: UInt8) -> Data {
        withCommand(command, Data())
    }

    /// Dispatch one fully-read message (type + contents). Always returns a response
    /// (never nil): unknown or unsupported types yield SSH_AGENT_FAILURE so the
    /// connection stays open, as RFC 9987 §5.1 requires.
    public static func handle(command: UInt8, payload: Data, backend: SSHAgentBackend) throws -> Data {
        switch command {
        case SSHAgentCommand.requestIdentities:
            guard payload.isEmpty else { throw MopError.invalidLocalIdentity }
            return identitiesResponse(try backend.identities())
        case SSHAgentCommand.signRequest:
            var offset = 0
            let blob = try parseString(payload, &offset)
            let data = try parseString(payload, &offset)
            guard try parseUInt32(payload, &offset) == 0, offset == payload.count else { throw MopError.invalidLocalIdentity }
            let signature = try backend.sign(blob: blob, data: data)
            return signResponse(signature: try sshSignature(der: signature))
        case SSHAgentCommand.agentExtension:
            return handleExtension(payload: payload)
        case SSHAgentCommand.lock, SSHAgentCommand.unlock, SSHAgentCommand.removeAllIdentities:
            // These operations are unsupported; do not claim keys were locked or removed.
            return simple(SSHAgentCommand.failure)
        case SSHAgentCommand.addIdentity, SSHAgentCommand.addIdConstrained,
             SSHAgentCommand.removeIdentity, SSHAgentCommand.addSmartcardKey,
             SSHAgentCommand.addSmartcardKeyConstrained, SSHAgentCommand.removeSmartcardKey:
            // This agent only serves existing hardware keys; it never imports or
            // deletes identities.
            return simple(SSHAgentCommand.failure)
        default:
            return simple(SSHAgentCommand.failure)
        }
    }

    /// RFC 5656: algorithm name followed by a string containing two positive mpints.
    static func sshSignature(der: Data) throws -> Data {
        let raw = try P256.Signing.ECDSASignature(derRepresentation: der).rawRepresentation
        var integers = Data()
        for component in [raw.prefix(32), raw.suffix(32)] {
            var integer = Data(component.drop(while: { $0 == 0 }))
            if let first = integer.first, first & 0x80 != 0 { integer.insert(0, at: 0) }
            appendString(&integers, integer)
        }
        var signature = Data()
        appendString(&signature, Data(SSHPublicKey.algorithm.utf8))
        appendString(&signature, integers)
        return signature
    }

    /// Handle an SSH_AGENTC_EXTENSION request (RFC 9987 §5.8; PROTOCOL.agent).
    static func handleExtension(payload: Data) -> Data {
        var offset = 0
        guard let name = try? parseString(payload, &offset),
              let typeName = String(data: name, encoding: .utf8) else {
            return simple(SSHAgentCommand.failure)
        }
        switch typeName {
        case "query":
            var response = Data()
            appendString(&response, name)
            return withCommand(SSHAgentCommand.extensionResponse, response)
        default:
            // In particular, session-bind is unsupported: success would promise
            // signature verification and per-connection binding state we do not implement.
            return simple(SSHAgentCommand.failure)
        }
    }
}

/// Minimal blocking reader/writer over a connected socket file descriptor.
final class SSHAgentIO {
    private let fd: Int32
    init(fd: Int32) { self.fd = fd }

    func readExact(_ count: Int) -> Data? {
        guard count >= 0 else { return nil }
        var data = Data(capacity: count)
        var chunk = [UInt8](repeating: 0, count: max(count, 1))
        while data.count < count {
            let remaining = count - data.count
            let n = chunk.withUnsafeMutableBytes { read(fd, $0.baseAddress, remaining) }
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { return nil }
            data.append(contentsOf: chunk[0..<n])
        }
        return data
    }

    func readUInt32() -> UInt32? {
        guard let bytes = readExact(4) else { return nil }
        return bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }

    @discardableResult
    func writeAll(_ data: Data) -> Bool {
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Bool in
            guard let base = raw.baseAddress else { return raw.isEmpty }
            var offset = 0
            while offset < raw.count {
                let n = write(fd, base.advanced(by: offset), raw.count - offset)
                if n < 0 && errno == EINTR { continue }
                if n <= 0 { return false }
                offset += n
            }
            return true
        }
    }
}

/// A minimal SSH agent. It serves the public keys of one `LocalIdentityStore` over
/// a Unix socket and performs ECDSA signatures in the Secure Enclave. It never
/// imports, exports, or deletes keys and never writes private material.
public final class SSHAgent: @unchecked Sendable {
    private let connectionBackend: (Int32) throws -> any SSHAgentBackend
    private let onStop: () -> Void
    private let lock = NSLock()
    private let backendLock = NSLock()
    private var started = false
    private var stopped = false
    private var clients = Set<Int32>()

    public init(backend: SSHAgentBackend) {
        self.connectionBackend = { _ in backend }
        self.onStop = {}
    }

    public init(connectionBackend: @escaping (Int32) throws -> any SSHAgentBackend, onStop: @escaping () -> Void) {
        self.connectionBackend = connectionBackend
        self.onStop = onStop
    }

    /// Serve independent client connections until stopped. An instance is single-use.
    /// The accept loop owns the listener; each worker owns its accepted descriptor.
    public func serve(socketPath: String, whileActive: @escaping () -> Bool = { true }, onReady: () -> Void = {}) throws {
        let canStart = lock.withLock {
            guard !started, !stopped else { return false }
            started = true
            return true
        }
        guard canStart else { throw MopError.inputOutput }
        let fd = try Self.bindAndListen(socketPath)
        let workers = DispatchGroup()
        defer {
            stop()
            close(fd)
            workers.wait()
            try? FileManager.default.removeItem(atPath: socketPath)
        }
        // Nonblocking accept plus a bounded poll avoids closing/reusing the listening
        // descriptor while another thread is still inside accept on that descriptor.
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw MopError.inputOutput }
        onReady()
        while !isStopped && whileActive() {
            var event = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = poll(&event, 1, 100)
            if ready < 0 {
                if errno == EINTR { continue }
                throw MopError.inputOutput
            }
            if isStopped { break }
            if ready == 0 { continue }
            guard event.revents & Int16(POLLIN) != 0 else { throw MopError.inputOutput }
            let client = accept(fd, nil, nil)
            if client < 0 {
                if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
                throw MopError.inputOutput
            }
            // Darwin may inherit the listener's nonblocking flag. Workers use
            // blocking stream I/O and are interrupted by shutdown during stop().
            let clientFlags = fcntl(client, F_GETFL)
            guard clientFlags >= 0, fcntl(client, F_SETFL, clientFlags & ~O_NONBLOCK) == 0 else {
                close(client)
                throw MopError.inputOutput
            }
            let registered = lock.withLock {
                guard !stopped, clients.count < 32 else { return false }
                clients.insert(client)
                return true
            }
            guard registered else { close(client); continue }
            workers.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                defer { workers.leave() }
                self.handleConnection(client)
            }
        }
    }

    /// Wake all connected readers/writers. The listener checks cancellation at
    /// most 100ms later, and serve waits for every worker before returning.
    public func stop() {
        onStop()
        lock.withLock {
            stopped = true
            // Keep the lock through shutdown so a worker cannot close an fd and
            // let the OS reuse it between taking the snapshot and the syscall.
            for client in clients { _ = shutdown(client, SHUT_RDWR) }
        }
    }

    private var isStopped: Bool { lock.withLock { stopped } }

    private func finishConnection(_ fd: Int32) {
        lock.withLock {
            clients.remove(fd)
            close(fd)
        }
    }

    func handleConnection(_ fd: Int32) {
        var noSigPipe: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        defer { finishConnection(fd) }
        guard let backend = try? connectionBackend(fd) else { return }
        let io = SSHAgentIO(fd: fd)
        while true {
            guard let length = io.readUInt32(), length >= 1, length <= 1024 * 1024 else { break }
            guard let message = io.readExact(Int(length)) else { break }
            let command = message[message.startIndex]
            let payload = message.dropFirst()
            // Socket reads are independent, but the backend and its LAContext
            // remain serialized and never need to promise concurrent access.
            let response = backendLock.withLock {
                guard !isStopped else { return SSHAgentFraming.simple(SSHAgentCommand.failure) }
                return (try? SSHAgentFraming.handle(command: command, payload: payload, backend: backend))
                    ?? SSHAgentFraming.simple(SSHAgentCommand.failure)
            }
            guard !isStopped, io.writeAll(SSHAgentFraming.frame(response)) else { break }
        }
    }

    private static func bindAndListen(_ path: String) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw MopError.inputOutput }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8CString)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard pathBytes.count <= capacity, !path.utf8.contains(0) else { close(fd); throw MopError.inputOutput }
        memcpy(&address.sun_path, pathBytes, pathBytes.count)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0 else { close(fd); throw MopError.inputOutput }
        guard chmod(path, 0o600) == 0, listen(fd, 16) == 0 else {
            unlink(path)
            close(fd)
            throw MopError.inputOutput
        }
        return fd
    }
}