import Foundation
import MopAuth
import LocalAuthentication
import MopCloudKit
import MopKeychain
import MopCore
import MopVault

/// Lazily authorizes once for a command; individual vault stores borrow the opener.
final class CommandVaultAuthorization {
    typealias Device = (opener: any VaultKeyOpener, close: () -> Void)
    private let open: () throws -> Device
    private var device: Device?
    private var closed = false

    init(open: @escaping () throws -> Device) { self.open = open }

    func opener() throws -> any VaultKeyOpener {
        guard !closed else { throw MopError.authentication }
        if let device { return device.opener }
        let device = try open()
        self.device = device
        return device.opener
    }

    func close() {
        guard !closed else { return }
        closed = true
        device?.close()
        device = nil
    }
    deinit { close() }
}


/// The CLI keeps the same per-command authentication boundary while borrowing
/// the synchronized account identity for v5 vaults and legacy migration.
final class CommandAccountAuthorization {
    private let devices: CommandVaultAuthorization
    private var identity: AccountIdentity?
    private var context: LAContext?
    private let state: URL
    init(state: URL) {
        self.state = state
        devices = CommandVaultAuthorization {
            let device = try LocalDevice.open(directory: state)
            return (device, { device.close() })
        }
    }
    func store(repo: CloudRepository, vault: CloudVault, snapshot: Data, offline: Bool,
               closeWithStore: Bool = false) async throws -> CloudSecretStore {
        let document = try VaultDocument.decode(snapshot)
        if offline, document.header.membership == nil { throw MopError.conversionRequired }
        let device: (any VaultKeyOpener)? = document.header.membership == nil ? try devices.opener() : nil
        if identity == nil {
            if device == nil {
                let policy = state.appendingPathComponent("account-authentication.json")
                let strict = FileManager.default.fileExists(atPath: policy.path)
                    ? try JSONDecoder().decode(Bool.self, from: SafeFile.read(policy, privateFile: true, limit: 1024)) : false
                context = try Authentication.authorize(strictBiometrics: strict)
            }
            identity = try await repo.accountIdentity(keys: SynchronizedIdentityStore(), create: !offline)
        }
        guard let identity else { throw MopError.identityPending }
        let opener: any VaultKeyOpener = device ?? identity
        let store = try CloudSecretStore(vault: vault, snapshot: snapshot, opener: opener, offline: offline,
                                        onClose: closeWithStore ? { self.close() } : {})
        if !offline, store.membership == nil { try await store.adoptOwner(identity) }
        return store
    }
    func close() { identity?.close(); identity = nil; context?.invalidate(); context = nil; devices.close() }
    deinit { close() }
}
