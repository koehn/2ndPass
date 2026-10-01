import XCTest
import CryptoKit
import MopCore
@testable import MopCredentials
final class CredentialTests: XCTestCase {
    func testOpenSSHImports() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        for type in ["ed25519", "ecdsa", "rsa"] {
            for password in ["", "test passphrase"] {
                let file = directory.appendingPathComponent(UUID().uuidString)
                let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
                process.arguments = ["-q", "-t", type, "-b", type == "rsa" ? "2048" : "256", "-N", password, "-f", file.path]
                try process.run(); process.waitUntilExit(); XCTAssertEqual(process.terminationStatus, 0)
                let bytes = SecretBytes(copying: try Data(contentsOf: file))
                let key = try OpenSSHImport.read(bytes, passphrase: SecretBytes(utf8: password))
                XCTAssertFalse(try key.sign(Data("test".utf8), flags: type == "rsa" ? 4 : 0).isEmpty)
                let pub = try String(contentsOf: URL(fileURLWithPath: file.path + ".pub"), encoding: .utf8).split(separator: " ")[1]
                XCTAssertEqual(key.sshBlob.base64EncodedString(), String(pub))
                if !password.isEmpty { XCTAssertThrowsError(try OpenSSHImport.read(bytes, passphrase: "wrong")) }
            }
        }
    }
    func testGeneratedKeysAndMetadata() throws {
        for algorithm in [CredentialAlgorithm.ed25519, .p256] {
            let key = try CloudKey.generate(algorithm)
            let item = try key.item(name: "test", purposes: [.ssh, .gitSigning])
            try CloudKey.validate(item: item)
            XCTAssertFalse(try key.sign(Data("test".utf8)).isEmpty)
            var invalid = item; invalid.credential?.publicKey = Data([0])
            XCTAssertThrowsError(try CloudKey.validate(item: invalid))
        }
    }
}

extension CredentialTests {
    func testImportRejectsMalformedAndUnsupportedEnvelopes() throws {
        for text in ["", "-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----\n!!!!\n-----END OPENSSH PRIVATE KEY-----"] {
            XCTAssertThrowsError(try OpenSSHImport.read(SecretBytes(utf8: text)))
        }
        XCTAssertThrowsError(try OpenSSHImport.read(SecretBytes(copying: Data(repeating: 0, count: 1024 * 1024 + 1))))
        let key = try CloudKey.generate(.ed25519)
        // Build an unencrypted OpenSSH fixture without delegating validation to ssh-keygen.
        var payload = SSHWire.uint32(7) + SSHWire.uint32(7) + SSHWire.text("ssh-ed25519")
        let publicBytes = Data(key.publicKey.suffix(32))
        payload += SSHWire.string(publicBytes) + SSHWire.string(Data(key.privateBytes) + publicBytes) + SSHWire.text("test")
        var padding: UInt8 = 1
        while payload.count % 8 != 0 { payload.append(padding); padding += 1 }
        func envelope(blob: Data, cipher: String = "none") -> SecretBytes {
            let bytes = Data("openssh-key-v1\0".utf8) + SSHWire.text(cipher) + SSHWire.text("none") + SSHWire.string(Data()) + SSHWire.uint32(1) + SSHWire.string(blob) + SSHWire.string(payload)
            return SecretBytes(utf8: "-----BEGIN OPENSSH PRIVATE KEY-----\n" + bytes.base64EncodedString() + "\n-----END OPENSSH PRIVATE KEY-----")
        }
        XCTAssertEqual(try OpenSSHImport.read(envelope(blob: key.sshBlob)).publicKey, key.publicKey)
        var mismatch = key.sshBlob; mismatch[mismatch.count - 1] ^= 1
        XCTAssertThrowsError(try OpenSSHImport.read(envelope(blob: mismatch)))
        XCTAssertThrowsError(try OpenSSHImport.read(envelope(blob: key.sshBlob, cipher: "aes256-cbc")))
        payload[0] ^= 1
        XCTAssertThrowsError(try OpenSSHImport.read(envelope(blob: key.sshBlob)))
    }
}
