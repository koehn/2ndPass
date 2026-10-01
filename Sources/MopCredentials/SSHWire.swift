import Foundation
import MopCore

struct SSHReader {
    let data: Data
    var offset = 0
    var remaining: Int { data.count - offset }
    mutating func uint32() throws -> UInt32 {
        guard remaining >= 4 else { throw CredentialFailure.invalid }
        defer { offset += 4 }
        return data[offset..<offset+4].reduce(0) { ($0 << 8) | UInt32($1) }
    }
    mutating func bytes() throws -> Data {
        let n = Int(try uint32())
        guard n <= remaining, n <= 1024 * 1024 else { throw CredentialFailure.invalid }
        defer { offset += n }
        return data.subdata(in: offset..<offset+n)
    }
    mutating func text() throws -> String {
        guard let s = String(data: try bytes(), encoding: .utf8) else { throw CredentialFailure.invalid }; return s
    }
    mutating func integer() throws -> Data {
        let d = try bytes()
        guard !d.isEmpty, d[0] & 0x80 == 0, d.count == 1 || d[0] != 0 || d[1] & 0x80 != 0 else { throw CredentialFailure.invalid }
        return Data(d.drop(while: { $0 == 0 }))
    }
}
enum SSHWire {
    static func uint32(_ n: Int) -> Data { var n = UInt32(n).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }
    static func string(_ d: Data) -> Data { uint32(d.count) + d }
    static func text(_ s: String) -> Data { string(Data(s.utf8)) }
    static func integer(_ d: Data) -> Data {
        var d = Data(d.drop(while: { $0 == 0 })); if let first = d.first, first & 0x80 != 0 { d.insert(0, at: 0) }; return string(d)
    }
}
