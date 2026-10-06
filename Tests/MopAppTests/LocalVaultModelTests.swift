@testable import MopLocalIdentity
import CryptoKit
import Foundation
import LocalAuthentication
import Synchronization
import Testing
import MopCore
import MopAppSupport
@testable import MopUI

/// A cloud service that only knows about cloud vaults. The local vault must be
/// injected by the model, never produced or read through this service.
private final class CloudOnlyService: VaultService, Sendable {
    private let operations = Mutex<[VaultOperation]>([])
    var authenticatedAt: TimeInterval? { nil }
    func lock() {}
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult {
        operations.withLock { $0.append(operation) }
        var result = VaultResult()
        if case .discover = operation {
            result.vaults = [VaultDescriptor(id: "cloud", name: "iCloud", format: "mop-vault-v7", enrolled: true)]
        }
        return result
    }
    func recorded() -> [VaultOperation] { operations.withLock { $0 } }
    func contains(where predicate: (VaultOperation) -> Bool) -> Bool { recorded().contains(where: predicate) }
}

@MainActor
private func localModel(localService: (any LocalVaultServing)? = nil,
                        authorizeLocal: @escaping (String, Set<UUID>, Set<LocalIdentityProtocol>, Set<LocalKeyOperation>) async throws -> LocalAuthorization = { _, _, _, _ in throw MopError.authentication }) -> (AppModel, CloudOnlyService) {
    let service = CloudOnlyService()
    let defaults = UserDefaults(suiteName: "mop-local-vault-test-" + UUID().uuidString)!
    let model = AppModel(breachClient: TestBreachClient(), service: service, defaults: defaults, automaticTimer: false,
                         localService: localService, authorizeLocal: authorizeLocal)
    model.vault = ""; model.vaults = []
    return (model, service)
}

@MainActor
private func finish(_ model: AppModel) async throws {
    for _ in 0..<500 {
        if !model.busy && !model.refreshing && !model.loadingVaults { return }
        try await Task.sleep(for: .milliseconds(10))
    }
}

private func localDescriptor() -> VaultDescriptor {
    VaultDescriptor(id: LocalVault.id, name: LocalVault.name, format: "device-local", enrolled: true)
}

@MainActor
private final class FakeLocalService: LocalVaultServing {
    var events: [String] = []
    var deleted: [UUID] = []
    var identities: [LocalIdentity] = []
    func list() throws -> [LocalIdentity] { events.append("list"); return identities }
    func create(name: String, protocolType: LocalIdentityProtocol, authorization: LocalAuthorization) throws -> LocalIdentity {
        throw MopError.enclaveUnavailable
    }
    func delete(id: UUID, authorization: LocalAuthorization) throws { events.append("delete"); deleted.append(id) }
}

@MainActor struct LocalVaultModelTests {
    @Test func localRowsUseNamesAndSelectionResolvesOnlyInLocalVault() throws {
        let (model, cloud) = localModel()
        let key = P256.Signing.PrivateKey().publicKey.x963Representation
        let zebra = try LocalIdentity(name: "Zebra", algorithm: .p256Signing, protocolType: .ssh, publicKey: key)
        let alpha = try LocalIdentity(name: "Alpha", algorithm: .p256Signing, protocolType: .ssh, publicKey: key)
        model.vault = LocalVault.id
        model.localIdentities = [zebra, alpha]
        #expect(model.displayedLocalIdentities.map(\.name) == ["Alpha", "Zebra"])
        model.selectedLocalIdentityID = alpha.id
        #expect(model.selectedLocalIdentity?.id == alpha.id)
        model.search = "zeb"
        #expect(model.displayedLocalIdentities.map(\.id) == [zebra.id])
        model.vault = "cloud"
        #expect(model.selectedLocalIdentity == nil)
        model.vault = LocalVault.id
        model.localIdentities = [zebra]
        #expect(model.selectedLocalIdentityID == nil)
        model.selectedLocalIdentityID = zebra.id
        model.beginLocalCreate()
        #expect(model.selectedLocalIdentityID == nil)
        #expect(model.localCreatePresented)
        #expect(cloud.recorded().isEmpty)
    }

    @Test func vaultListShowsLocalEvenWhenCloudVaultsAreReplaced() {
        let (model, _) = localModel()
        // A cloud refresh replaces `vaults` with cloud-only rows; the sidebar list must keep local.
        model.vaults = [VaultDescriptor(id: "cloud", name: "iCloud", format: "mop-vault-v7", enrolled: true)]
        #expect(!model.vaults.contains { $0.id == LocalVault.id })
        #expect(model.vaultList.contains { $0.id == LocalVault.id })
        #expect(model.vaultList.count == 2)
    }

    @Test func discoverKeepsCloudVaultsPureAndShowsLocalSeparately() async throws {
        let (model, _) = localModel()
        model.discover()
        try await finish(model)
        #expect(!model.vaults.contains { $0.id == LocalVault.id })
        #expect(model.vaultList.contains { $0.id == LocalVault.id })
        #expect(model.cloudVaults.count == 1)
        #expect(model.cloudVaults.allSatisfy { $0.id != LocalVault.id })
        #expect(model.cloudVaultsPresent)
        #expect(!model.isLocalVaultSelected)
    }

    @Test func localSelectionIsTrackedAndShownAlongsideCloud() {
        let (model, _) = localModel()
        model.vaults = [VaultDescriptor(id: "cloud", name: "iCloud", format: "mop-vault-v7", enrolled: true)]
        model.vault = LocalVault.id
        #expect(model.isLocalVaultSelected)
        #expect(model.selectedVaultDescriptor == nil)
        #expect(model.vaultSelection == .local)
        #expect(model.vaultList.contains { $0.id == LocalVault.id })
        #expect(model.cloudVaults.count == 1)
    }

    @Test func switchingFromLocalToCloudUsesCloudCollection() {
        let (model, _) = localModel()
        model.vault = LocalVault.id
        #expect(model.collection == .local)
        model.vault = UUID().uuidString
        #expect(model.collection == .vault(model.vault))
        #expect(!model.isLocalVaultSelected)
    }

    @Test func selectingLocalThroughSidebarLoadsItsListWithoutCloudCalls() async throws {
        let store = FakeLocalService()
        let (model, cloud) = localModel(localService: store)
        model.collection = .all
        model.sidebarSelection = "vault:" + LocalVault.id
        for _ in 0..<100 where model.localLoading { try await Task.sleep(for: .milliseconds(10)) }
        #expect(model.collection == .local)
        #expect(model.sidebarSelection == "vault:" + LocalVault.id)
        #expect(model.localReady)
        #expect(store.events == ["list"])
        #expect(cloud.recorded().isEmpty)
        #expect(model.catalog == nil)
        #expect(model.itemFields.isEmpty)
    }

    @Test func forbiddenOperationsAreRejectedForLocal() {
        let (model, service) = localModel()
        let local = localDescriptor()

        model.renameVault(to: "renamed", target: local)
        #expect(model.error != nil)
        #expect(!service.contains { op in if case .rename = op { true } else { false } })

        model.deleteVault(target: local, confirmation: LocalVault.name)
        #expect(model.error != nil)

        model.chooseExportBackup(target: local)
        #expect(model.error != nil)
        #expect(!service.contains { op in if case .export = op { true } else { false } })
    }
    @Test func cloudCollectionsDoNotKeepShowingLocalIdentities() {
        let (model, _) = localModel()
        for selection in ["all", "favorites", "archive", "recent-added", "recent-changed", "recent-used", "deleted"] {
            model.collection = .local
            model.vault = LocalVault.id
            #expect(model.isLocalVaultSelected)
            model.sidebarSelection = selection
            #expect(model.sidebarSelection == selection)
            #expect(!model.isLocalVaultSelected)
        }
    }

    @Test func localDeletionRequiresSuccessfulAuthorization() async throws {
        let store = FakeLocalService()
        let (model, _) = localModel(localService: store, authorizeLocal: { _, ids, purposes, operations in
            store.events.append("authorize")
            throw MopError.authentication
        })
        let identity = try LocalIdentity(name: "test", algorithm: .p256Signing, protocolType: .ssh, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        model.localIdentities = [identity]
        model.requestLocalDelete(identity.id)
        model.confirmLocalDelete()
        for _ in 0..<100 where model.localDeleteInProgress { try await Task.sleep(for: .milliseconds(10)) }
        #expect(!model.localDeleteInProgress)
        #expect(store.events == ["authorize"])
        #expect(store.deleted.isEmpty)
        #expect(model.localError != nil)
    }

    @Test func localDeletionAuthorizesBeforeMutationAndRefresh() async throws {
        let store = FakeLocalService()
        let (model, _) = localModel(localService: store, authorizeLocal: { _, ids, purposes, operations in
            store.events.append("authorize")
            return LocalAuthorization(context: LAContext(), ids: ids, purposes: purposes, operations: operations)
        })
        let identity = try LocalIdentity(name: "test", algorithm: .p256Signing, protocolType: .ssh, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        let id = identity.id
        model.localIdentities = [identity]
        model.requestLocalDelete(id)
        model.confirmLocalDelete()
        model.confirmLocalDelete() // A second confirmation must not duplicate deletion.
        for _ in 0..<100 where model.localDeleteInProgress { try await Task.sleep(for: .milliseconds(10)) }
        #expect(!model.localDeleteInProgress)
        #expect(store.events == ["authorize", "delete", "list"])
        #expect(store.deleted == [id])
        #expect(model.localError == nil)
    }

}

extension LocalVaultModelTests {
    @Test func localVaultAndItemSurviveRelaunchWithoutCloudAuthentication() async throws {
        let suite = "local-selection-" + UUID().uuidString
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = FakeLocalService()
        let key = P256.Signing.PrivateKey().publicKey.x963Representation
        let identity = try LocalIdentity(name: "Private local name", algorithm: .p256Signing, protocolType: .ssh, publicKey: key)
        store.identities = [identity]
        func makeModel() -> AppModel {
            AppModel(breachClient: TestBreachClient(), service: CloudOnlyService(), defaults: defaults,
                     automaticTimer: false, localService: store)
        }
        let first = makeModel()
        first.chooseVault(LocalVault.id)
        while first.localLoading { await Task.yield() }
        first.selectedLocalIdentityID = identity.id
        #expect(!first.authenticated)
        let bytes = try #require(defaults.data(forKey: "lastSelection.local"))
        #expect(!String(decoding: bytes, as: UTF8.self).contains(identity.name))
        // Relaunch directly, without relying on lock or quit to save selection.
        let next = makeModel()
        next.start()
        while next.localLoading { await Task.yield() }
        try await finish(next)
        #expect(next.collection == .local && next.vault == LocalVault.id)
        #expect(next.selectedLocalIdentity?.id == identity.id)
        next.lock()
        let afterLock = makeModel()
        afterLock.start()
        while afterLock.localLoading { await Task.yield() }
        try await finish(afterLock)
        #expect(afterLock.selectedLocalIdentity?.id == identity.id)
        store.identities = []
        let missing = makeModel()
        missing.start()
        while missing.localLoading { await Task.yield() }
        try await finish(missing)
        #expect(missing.collection == .local && missing.selectedLocalIdentityID == nil)
    }
}
