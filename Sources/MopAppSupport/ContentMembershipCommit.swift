import Foundation
import MopCore
import MopVaultNext

/// Exact signed authority publication, persisted before conditional transport.
struct ContentMembershipCommit: Codable, Sendable {
    let history: [MembershipEnvelope]
    let successor: MembershipEnvelope
    func verified() throws -> TrustedMembershipHistory {
        guard let genesis = history.first, history.count < 4096 else { throw MopError.vaultUntrusted }
        var result = try TrustedMembershipHistory(genesis: genesis, vault: genesis.header.vault, pinnedDigest: genesis.digest())
        for state in history.dropFirst() {
            try state.verifyAccountTransition(of: result.current, allowingDeviceRemoval: true)
            try result.append(state)
        }
        try successor.verifyAccountTransition(of: result.current, allowingDeviceRemoval: true)
        try result.append(successor)
        return result
    }
}
