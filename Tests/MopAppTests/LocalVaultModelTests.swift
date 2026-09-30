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
                        authorizeLocal: @escaping (String) async throws -> LAContext = { _ in throw MopError.authentication }) -> (AppModel, CloudOnlyService) {
    let service = CloudOnlyService()
    let defaults = UserDefaults(suiteName: "mop-local-vault-test-" + UUID().uuidString)!
    let model = AppModel(service: service, defaults: defaults, automaticTimer: false,
                         localService: localService, authorizeLocal: authorizeLocal)
    model.vault = ""; model.vaults = []
    return (model, service)
}

@MainActor
private func finish(_ model: AppModel) async throws {
    for _ in 0..<500 {
        if !model.busy && !model.refreshing && !model.enrollmentWorking && !model.loadingVaults { return }
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
    func list() throws -> [LocalIdentity] { events.append("list"); return [] }
    func create(name: String, protocolType: LocalIdentityProtocol, context: LAContext) throws -> LocalIdentity {
        throw MopError.enclaveUnavailable
    }
    func delete(id: UUID) throws { events.append("delete"); deleted.append(id) }
}

@MainActor struct LocalVaultModelTests {
    @Test func vaultsIncludingLocalGuaranteesTheFixedLocalVault() {
        let (model, _) = localModel()
        let cloud = [VaultDescriptor(id: "cloud", name: "iCloud", format: "mop-vault-v7", enrolled: true)]
        #expect(model.vaultsIncludingLocal(cloud).map(\.id) == ["cloud", LocalVault.id])
        #expect(model.vaultsIncludingLocal([]).map(\.id) == [LocalVault.id])
        #expect(model.vaultsIncludingLocal(model.vaultsIncludingLocal(cloud)).count == 2)
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
        #expect(model.selectedVaultDescriptor?.id == LocalVault.id)
        #expect(model.vaultList.contains { $0.id == LocalVault.id })
        #expect(model.cloudVaults.count == 1)
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
            model.collection = .vault(LocalVault.id)
            model.vault = LocalVault.id
            #expect(model.isLocalVaultSelected)
            model.sidebarSelection = selection
            #expect(model.sidebarSelection == selection)
            #expect(!model.isLocalVaultSelected)
        }
    }

    @Test func localDeletionRequiresSuccessfulAuthorization() async throws {
        let store = FakeLocalService()
        let (model, _) = localModel(localService: store, authorizeLocal: { _ in
            store.events.append("authorize")
            throw MopError.authentication
        })
        model.requestLocalDelete(UUID())
        model.confirmLocalDelete()
        for _ in 0..<100 where model.localDeleteInProgress { try await Task.sleep(for: .milliseconds(10)) }
        #expect(!model.localDeleteInProgress)
        #expect(store.events == ["authorize"])
        #expect(store.deleted.isEmpty)
        #expect(model.localError != nil)
    }

    @Test func localDeletionAuthorizesBeforeMutationAndRefresh() async throws {
        let store = FakeLocalService()
        let (model, _) = localModel(localService: store, authorizeLocal: { _ in
            store.events.append("authorize")
            return LAContext()
        })
        let id = UUID()
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