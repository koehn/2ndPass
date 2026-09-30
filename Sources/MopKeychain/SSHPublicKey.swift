import Foundation
import MopCore

/// OpenSSH wire-format encoding for the `ecdsa-sha2-nistp256` key type built from
/// a P-256 public key's x963 representation. Pure and deterministic.
public enum SSHPublicKey {
    public static let algorithm = "ecdsa-sha2-nistp256"

    /// Encode a P-256 public key (x963, 65 bytes) as the OpenSSH wire blob:
    /// `string "ecdsa-sha2-nistp256" || string "nistp256" || string Q` where Q is the point.
    public static func wireBlob(x963: Data) throws -> Data {
        guard x963.count == 65, x963.first == 0x04 else { throw MopError.invalidLocalIdentity }
        var blob = Data()
        appendSSHString(&blob, algorithm)
        appendSSHString(&blob, "nistp256")
        appendSSHBytes(&blob, x963)
        return blob
    }

    /// A full OpenSSH authorized_keys / agent line: `<type> <base64> <comment>`.
    public static func openSSH(x963: Data, comment: String) throws -> String {
        let blob = try wireBlob(x963: x963)
        return algorithm + " " + blob.base64EncodedString() + " " + comment
    }

    static func appendSSHString(_ data: inout Data, _ string: String) {
        appendSSHBytes(&data, Data(string.utf8))
    }

    static func appendSSHBytes(_ data: inout Data, _ bytes: Data) {
        var length = UInt32(bytes.count).bigEndian
        data.append(Data(bytes: &length, count: MemoryLayout<UInt32>.size))
        data.append(bytes)
    }
}
