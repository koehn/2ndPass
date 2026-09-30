import CryptoKit
import Foundation
import Testing
import MopCore
@testable import MopLocalIdentity

@Test func wireBlobIsOpenSSHEcdsaP256() throws {
    let x963 = P256.Signing.PrivateKey().publicKey.x963Representation
    let blob = try SSHPublicKey.wireBlob(x963: x963)
    var offset = 0
    #expect(try SSHAgentFraming.parseString(blob, &offset) == Data("ecdsa-sha2-nistp256".utf8))
    #expect(try SSHAgentFraming.parseString(blob, &offset) == Data("nistp256".utf8))
    #expect(try SSHAgentFraming.parseString(blob, &offset) == x963)
    #expect(offset == blob.count)
}

@Test func openSSHLineHasTypeBlobAndComment() throws {
    let x963 = P256.Signing.PrivateKey().publicKey.x963Representation
    let line = try SSHPublicKey.openSSH(x963: x963, comment: "deploy")
    let parts = line.split(separator: " ")
    #expect(parts.count == 3)
    #expect(parts[0] == "ecdsa-sha2-nistp256")
    #expect(parts[2] == "deploy")
    let decoded = Data(base64Encoded: String(parts[1]))
    let blob = try SSHPublicKey.wireBlob(x963: x963)
    #expect(decoded == blob)
}

@Test func rejectsNonP256Points() {
    #expect(throws: MopError.invalidLocalIdentity) { try SSHPublicKey.wireBlob(x963: Data([0x02, 1, 2])) }
    #expect(throws: MopError.invalidLocalIdentity) { try SSHPublicKey.wireBlob(x963: Data(count: 64)) }
    #expect(throws: MopError.invalidLocalIdentity) { try SSHPublicKey.wireBlob(x963: Data([0x05] + Array(repeating: 0, count: 64))) }
}
