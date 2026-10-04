import Foundation
import MopCore

public enum AccountScope {
    /// A namespace identifier, not an authentication credential or private key.
    public static func member(container: String, environment: String, account: String) -> UUID {
        let hash = Codec.digest(Data(["mop-v7-account", container, environment, account].map { "\($0.utf8.count):\($0)" }.joined().utf8))
        let chars = Array(hash.prefix(32))
        return UUID(uuidString: String(chars[0..<8]) + "-" + String(chars[8..<12]) + "-" + String(chars[12..<16]) + "-" + String(chars[16..<20]) + "-" + String(chars[20..<32]))!
    }
}
