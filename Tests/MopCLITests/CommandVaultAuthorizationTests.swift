import CryptoKit
import Foundation
import Testing
import MopCore
import MopVault
@testable import MopCLI

private final class CommandTestOpener: VaultKeyOpener {
    let publicKey = Data()
    func unwrap(_ recipient: VaultRecipient, vaultID: UUID) throws -> SymmetricKey {
        throw MopError.invalidDevice
    }
}

struct CommandVaultAuthorizationTests {
    @Test func oneLazyAuthorizationAcrossVaultsAndOneInvalidation() throws {
        let device = CommandTestOpener()
        var opens = 0, closes = 0
        let session = CommandVaultAuthorization {
            opens += 1
            return (device, { closes += 1 })
        }
        #expect(opens == 0)
        for _ in 0..<5 { #expect(try session.opener() as? CommandTestOpener === device) }
        #expect(opens == 1 && closes == 0)
        session.close(); session.close()
        #expect(closes == 1)
        #expect(throws: MopError.authentication) { try session.opener() }
        #expect(opens == 1)
    }
    @Test func unusedAndFailedAuthorizationsDoNotCreateAnExtraSession() {
        var opens = 0
        let unused = CommandVaultAuthorization { opens += 1; throw MopError.authentication }
        unused.close()
        #expect(opens == 0)
        let failing = CommandVaultAuthorization { opens += 1; throw MopError.authentication }
        #expect(throws: MopError.authentication) { try failing.opener() }
        failing.close()
        #expect(opens == 1)
    }
}
