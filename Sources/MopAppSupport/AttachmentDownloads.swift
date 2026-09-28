import Foundation
import MopCore
import MopKeychain
import MopVaultNext

public enum AttachmentDownloadSettings {
    public static let key = "attachmentDownloadDuringSync"
    public static var defaults: UserDefaults {
        SigningIdentity.appGroupIdentifier.flatMap(UserDefaults.init(suiteName:)) ?? .standard
    }
    public static var duringSync: Bool { defaults.bool(forKey: key) }
}

/// Account/vault-bound cache containing only authenticated ciphertext.
struct AttachmentDownloads {
    let directory: URL
    let address: VaultAddress
    init(state: URL, address: VaultAddress) {
        self.address = address
        let member = AccountScope.member(container: address.container, environment: address.environment, account: address.account)
        directory = state.appendingPathComponent("v7").appendingPathComponent(member.uuidString)
            .appendingPathComponent("attachments").appendingPathComponent(address.binding)
    }
    func cache(_ vault: VerifiedVault) throws {
        guard !vault.loadedAttachments.isEmpty else { return }
        try LocalFile.privateDirectory(directory)
        for (digest, bytes) in vault.loadedAttachments {
            let url = directory.appendingPathComponent(digest)
            if FileManager.default.fileExists(atPath: url.path) { continue }
            do { try LocalFile.write(bytes, to: url) } catch MopError.duplicate { }
        }
    }
    func load(_ vault: VerifiedVault, digests: Set<String>, transport: any RevisionTransport, offline: Bool) async throws -> VerifiedVault {
        var vault = vault
        guard digests.isSubset(of: vault.attachmentDigests) else { throw MopError.invalidVault }
        for digest in digests.sorted() {
            try Task.checkCancellation()
            if vault.loadedAttachments[digest] != nil { continue }
            let url = directory.appendingPathComponent(digest)
            if FileManager.default.fileExists(atPath: url.path) {
                vault = try vault.loadingAttachment(LocalFile.read(url, privateFile: true), digest: digest)
            } else {
                guard !offline else { throw AttachmentFailure.unavailable }
                let bytes = try await transport.attachment(digest, at: address)
                vault = try vault.loadingAttachment(bytes, digest: digest)
                try cache(vault)
            }
        }
        return vault
    }
}
