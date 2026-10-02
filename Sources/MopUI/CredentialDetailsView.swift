import SwiftUI
import MopCore
import MopAppSupport
import MopLocalIdentity

/// Public presentation shared by both storage backends. No private key material
/// or editable hardware-key fields enter this model.
struct CredentialPresentation {
    let title: String
    let website: String?
    let account: String?
    let algorithm: String
    let fingerprint: String?
    let publicKey: String?
    let setup: String?
    var isPasskey: Bool { website != nil }
    var label: String { isPasskey ? "Passkey" : "SSH Key" }
    var symbol: String { isPasskey ? "person.badge.key" : "terminal" }

    init(record: CloudCredentialRecord) {
        title = record.item.displayTitle
        website = record.credential.relyingParty
        account = record.credential.userName
        switch record.credential.algorithm {
        case .p256: algorithm = "P-256"
        case .ed25519: algorithm = "Ed25519"
        case .rsa: algorithm = "RSA"
        }
        let passkey = record.credential.purposes == [.passkey]
        fingerprint = passkey ? nil : record.fingerprint
        publicKey = passkey ? nil : record.publicKeyText
        setup = passkey ? nil : Self.instructions(vault: record.vault, name: record.item.name,
            publicKey: record.publicKeyText, gitSigning: record.credential.purposes.contains(.gitSigning))
    }

    init(identity: LocalIdentity) {
        if case .passkey(let data) = identity.metadata {
            title = data.relyingParty; website = data.relyingParty; account = data.userName
            fingerprint = nil; publicKey = nil; setup = nil
        } else {
            title = identity.name; website = nil; account = nil
            fingerprint = identity.fingerprint; publicKey = identity.publicKeyText
            setup = Self.instructions(vault: LocalVault.name, name: identity.name,
                publicKey: identity.publicKeyText, gitSigning: identity.protocolType == .gitSigning)
        }
        algorithm = "P-256"
    }

    private static func instructions(vault: String, name: String, publicKey: String, gitSigning: Bool) -> String {
        func quote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'" }
        let agent = "sp ssh-agent --vault " + quote(vault) + " --identity " + quote(name)
        let prerequisite = "Install the separate 2ndPass CLI to use these commands.\n\n"
        if gitSigning {
            return prerequisite + "git config gpg.format ssh\ngit config user.signingkey " + quote("key::" + publicKey) + "\n" + agent + " --purpose git-signing -- git commit -S\n\nRegister the public key with your Git provider as a signing key."
        }
        return prerequisite + "Register this public key with the server first.\n\n" + agent + " -- ssh user@host\n\nFor IDEs, start the agent without a command and configure the IDE’s SSH_AUTH_SOCK using the printed socket path. Approvals are scoped to the requesting process."
    }
}

struct CredentialDetailsView: View {
    let credential: CredentialPresentation
    let copy: (String) -> Void
    var body: some View {
        GroupBox(credential.label) {
            VStack(alignment: .leading, spacing: 10) {
                if let website = credential.website { LabeledContent("Website", value: website) }
                if let account = credential.account { LabeledContent("Account", value: account) }
                if let publicKey = credential.publicKey, let fingerprint = credential.fingerprint {
                    LabeledContent("Algorithm", value: credential.algorithm)
                    LabeledContent("Fingerprint", value: fingerprint).textSelection(.enabled)
                    Text(publicKey).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    HStack {
                        Button("Copy Public Key") { copy(publicKey) }
                        ShareLink("Share Public Key", item: publicKey)
                    }
                }
                if let setup = credential.setup {
                    DisclosureGroup("Use with SSH and Git") {
                        Text(setup).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        Button("Copy Setup Instructions") { copy(setup) }
                    }
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct VaultItemRowLabel: View {
    let title: String
    let symbol: String
    var subtitle: String? = nil
    var vaultName: String? = nil
    var recentDate: Date? = nil
    var searchDetail: String? = nil
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: symbol).foregroundStyle(Color.accentColor).frame(width: 22)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).fontWeight(.medium)
                if let recentDate {
                    Text(recentDate, style: .relative).font(.caption).foregroundStyle(.secondary)
                        .help(recentDate.formatted(date: .complete, time: .standard))
                }
                if let subtitle { Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1) }
                if let vaultName { Text(vaultName).font(.caption).foregroundStyle(.secondary) }
                if let searchDetail { Text(searchDetail).font(.caption).foregroundStyle(.secondary).lineLimit(1) }
            }
        }.padding(.vertical, 2)
    }
}
