import Foundation
import MopCore

extension LocalIdentity {
    public var reference: ItemReference {
        // Names are validated at creation/decoding; the vault name is fixed.
        try! ItemReference(vault: LocalVault.name, name: name)
    }

    public var gitSetup: String {
        let quotedKey = ("key::" + publicKeyText).replacingOccurrences(of: "'", with: "'\\''")
        return """
        git config gpg.format ssh
        git config user.signingKey '\(quotedKey)'
        # Save the public key to an allowed signers file with your email as principal:
        # you@example.com \(publicKeyText)
        git config gpg.ssh.allowedSignersFile /path/to/allowed_signers
        sp ssh-agent --purpose git-signing --identity '\(reference.description)' -- git commit -S
        sp ssh-agent --purpose git-signing --identity '\(reference.description)' -- git tag -s TAG
        """
    }
}
