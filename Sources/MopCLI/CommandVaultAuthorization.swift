import Foundation
import MopAuth
import LocalAuthentication
import MopCloudKit
import MopKeychain
import MopCore
import MopVault

/// One account authorization per command; stores borrow the synchronized identity.
final class CommandAccountAuthorization {
    private var closed = false
    private var identity: AccountIdentity?
    private var context: LAContext?
    private let state: URL
    init(state: URL) { self.state = state }
    func opener(repo: CloudRepository, offline: Bool) async throws -> AccountIdentity {
        guard !closed else { throw MopError.authentication }
        if let identity { return identity }
        context = try Authentication.authorize()
        let opened = try await repo.accountIdentity(keys: SynchronizedIdentityStore(), create: !offline)
        identity = opened
        return opened
    }
    func store(repo: CloudRepository, vault: CloudVault, snapshot: Data, offline: Bool,
               closeWithStore: Bool = false) async throws -> CloudSecretStore {
        _ = try VaultDocument.decode(snapshot)
        let owner = try await opener(repo: repo, offline: offline)
        return try CloudSecretStore(vault: vault, snapshot: snapshot, opener: owner, offline: offline,
                                    onClose: closeWithStore ? { self.close() } : {})
    }
    func close() { closed = true; identity?.close(); identity = nil; context?.invalidate(); context = nil }
    deinit { close() }
}
