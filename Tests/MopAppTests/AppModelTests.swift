import Foundation
import CryptoKit
import MopLocalIdentity
import Synchronization
import Testing
import MopCore
@testable import MopAppSupport
@testable import MopSync
import MopVaultNext
@testable import MopUI

struct TestBreachClient: BreachChecking {
    func contains(_ password: Data, force: Bool) async throws -> Bool { throw BreachCheckFailure.unavailable }
    func clear() async {}
}

private final class FakeService: VaultService, Sendable {
    struct State {
        var started: TimeInterval?
        var locks = 0
        var operations: [VaultOperation] = []
        var progress: String?
        var fraction: Double?
        var capabilities = Set(VaultServiceCapability.allCases)
        var observers: [UUID: AsyncStream<Void>.Continuation] = [:]
        var displayResult: VaultResult?
        var syncRequests = 0
        var syncFails = false
        var displayCalls = 0
        var exactReadIDs: [String?] = []
        var conflicts: [ItemVaultConflictPreview] = []
        var conflictCalls = 0
    }
    let state = Mutex(State())
    let handler: @Sendable (VaultOperation, String?, Bool) async throws -> VaultResult
    let cachedHandler: @Sendable (String) async throws -> VaultResult?
    init(_ handler: @escaping @Sendable (VaultOperation, String?, Bool) async throws -> VaultResult = { _, _, _ in VaultResult() }) {
        cachedHandler = { _ in nil }; self.handler = handler
    }
    init(cached: @escaping @Sendable (String) async throws -> VaultResult?,
         _ handler: @escaping @Sendable (VaultOperation, String?, Bool) async throws -> VaultResult) {
        cachedHandler = cached; self.handler = handler
    }
    func displayCatalog(vault: String) async throws -> VaultResult {
        let result = state.withLock { $0.displayCalls += 1; return $0.displayResult }
        if let result { return result }
        return try await execute(.catalog, vault: vault, offline: false)
    }
    func readLocal(_ reference: SecretReference, vault: String?, itemID: String?) async throws -> VaultResult {
        state.withLock { $0.exactReadIDs.append(itemID) }
        return try await readLocal(reference, vault: vault)
    }
    func requestSynchronization() async throws {
        let fail = state.withLock { $0.syncRequests += 1; return $0.syncFails }
        if fail { throw MopError.cloudUnavailable }
    }
    func conflicts(vault: String) async throws -> [ItemVaultConflictPreview] {
        state.withLock { state in
            state.conflictCalls += 1
            return state.conflicts.filter { $0.conflict.local.scope.vaultID.uuidString == vault }
        }
    }
    func cachedCatalog(vault: String) async throws -> VaultResult? { try await cachedHandler(vault) }

    var authenticatedAt: TimeInterval? { state.withLock { $0.started } }
    var capabilities: Set<VaultServiceCapability> { state.withLock { $0.capabilities } }
    func changes() async -> AsyncStream<Void> {
        let id = UUID()
        return AsyncStream { continuation in
            state.withLock { $0.observers[id] = continuation }
            continuation.onTermination = { [weak self] _ in self?.state.withLock { $0.observers[id] = nil } }
        }
    }
    var observerCount: Int { state.withLock { $0.observers.count } }
    func notifyChange() { state.withLock { Array($0.observers.values) }.forEach { $0.yield(()) } }
    var operationProgress: String? { state.withLock { $0.progress } }
    var operationFraction: Double? { state.withLock { $0.fraction } }
    func authenticate(at time: TimeInterval = 0) { state.withLock { $0.started = time } }
    func lock() { state.withLock { $0.started = nil; $0.locks += 1 } }
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult {
        state.withLock { $0.operations.append(operation) }
        return try await handler(operation, vault, offline)
    }
}
private actor Barrier {
    var entered = false
    var continuation: CheckedContinuation<Void, Never>?
    func wait() async { entered = true; await withCheckedContinuation { continuation = $0 } }
    func release() { continuation?.resume(); continuation = nil }
}
@MainActor private final class Clock { var time: TimeInterval = 0 }

@MainActor struct AppModelTests {
    private func model(_ service: FakeService, clock: Clock = Clock(), repairEnabled: Bool = false) -> AppModel {
        let defaults = UserDefaults(suiteName: "mop-session-test-" + UUID().uuidString)!
        defaults.set(repairEnabled, forKey: "icloud-connection-repair-enabled")
        let model = AppModel(breachClient: TestBreachClient(), service: service, defaults: defaults, now: { clock.time }, automaticTimer: false)
        model.vault = UUID().uuidString
        model.vaults = [VaultDescriptor(id: model.vault, name: "personal", format: "mop-items-v2", enrolled: true)]
        return model
    }
    @Test func conflictAppearsWithoutMountingListAndUpdatesWhileEditing() async throws {
        let service = FakeService()
        let app = model(service)
        let vault = try #require(UUID(uuidString: app.vault))
        let scope = ItemScope(account: "test", vaultID: vault, itemID: UUID())
        let local = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([1]))
        let remote = EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([2]))
        let conflict = EncryptedItemConflict(id: UUID(), local: local, remote: remote, serverSystemFields: Data([3]))
        let item = VaultItem(name: "login", fields: [ItemField(path: "password", type: .password)])
        let catalog = ItemEnvelopeCatalog(item: item, references: [:])
        let preview = ItemVaultConflictPreview(conflict: conflict, local: catalog, remote: catalog)
        service.state.withLock { $0.conflicts = [preview] }
        service.authenticate()
        app.catalogs = [app.vault: ItemCatalog(vault: "personal", revision: "same", items: [item])]
        app.authenticated = true
        // No SwiftUI view exists: loading must not depend on a nonempty list.
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while app.conflictPreviews.isEmpty || service.observerCount == 0 {
            guard ContinuousClock.now < deadline else { throw CocoaError(.coderInvalidValue) }
            await Task.yield()
        }
        let row = ItemRow.ID(vault: app.vault, name: "login")
        #expect(app.conflictItems.contains(row))
        app.reviewConflict(row)
        #expect(app.conflictReviewPresented && app.conflictReviewItem == row)
        app.busy = true // Catalog refresh may be deferred; conflict state must not be.
        service.state.withLock { $0.conflicts = [] }
        service.notifyChange()
        while !app.conflictPreviews.isEmpty {
            guard ContinuousClock.now < deadline else { throw CocoaError(.coderInvalidValue) }
            await Task.yield()
        }
        #expect(app.conflictItems.isEmpty)
        service.state.withLock { $0.conflicts = [preview] }
        service.notifyChange()
        while app.conflictPreviews.isEmpty {
            guard ContinuousClock.now < deadline else { throw CocoaError(.coderInvalidValue) }
            await Task.yield()
        }
        app.deactivate()
        #expect(app.conflictPreviews.isEmpty && !app.conflictReviewPresented)
        app.isActive = true
        while app.conflictPreviews.isEmpty {
            guard ContinuousClock.now < deadline else { throw CocoaError(.coderInvalidValue) }
            await Task.yield()
        }
        app.lock(clearClipboard: false)
        #expect(app.conflictItems.isEmpty && !app.conflictReviewPresented)
    }

    @Test func editWithExpiredNativeAuthorizationLocksAndOffersFreshUnlock() async throws {
        let service = FakeService { operation, _, _ in
            if case .read = operation {
                throw NSError(domain: "com.apple.LocalAuthentication", code: -1004)
            }
            return VaultResult()
        }
        let app = model(service)
        let item = VaultItem(name: "login", fields: [ItemField(path: "password", type: .password)])
        try app.applyCatalog(ItemCatalog(vault: "personal", revision: "r", items: [item]))
        service.authenticate(); app.authenticated = true; app.selectedItem = item.name
        app.beginItemEditing(); try await finish(app)
        #expect(!app.authenticated && app.itemDraft == nil)
        #expect(app.error == "Unlock 2ndPass again to continue. Your device requires authentication.")
        #expect(service.state.withLock { $0.locks } > 0)
        #expect(app.canUnlock)
    }

    @Test func cloudWakeIsIndependentOfCatalogRefreshAndReportsFailuresWithoutLocking() async throws {
        let id = UUID().uuidString
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            switch operation {
            case .discover: result.vaults = [.init(id: id, name: "personal", format: "mop-items-v2", enrolled: true)]
            case .catalog: result.catalog = ItemCatalog(vault: "personal", revision: "r", items: [])
            default: break
            }
            return result
        }
        service.authenticate()
        let app = model(service); app.vault = id; app.start(); try await finish(app)
        func settleWake() async throws {
            let deadline = ContinuousClock.now.advanced(by: .seconds(3))
            while app.requestingSynchronization, ContinuousClock.now < deadline { await Task.yield() }
            #expect(!app.requestingSynchronization)
        }
        try await settleWake()
        func requests() -> Int { service.state.withLock { $0.syncRequests } }
        let initial = requests()
        #expect(initial > 0 && app.authenticated)
        app.cloudChanged(); try await finish(app); try await settleWake()
        #expect(requests() == initial) // Local change notifications do not loop.
        service.state.withLock { $0.syncFails = true }
        app.refresh(); try await finish(app); try await settleWake()
        #expect(requests() > initial && app.syncIssue != nil && app.authenticated)
        service.state.withLock { $0.syncFails = false }
        app.deactivate(); app.activate(); try await finish(app); try await settleWake()
        #expect(app.syncIssue == nil && app.authenticated)
        let beforeLock = requests()
        app.lock(); app.requestBackgroundSynchronization(); try await settleWake()
        #expect(requests() == beforeLock)
    }

    @Test func firstLaunchCreatesOnlyForEmptyCloudAndAutomaticallyConnectsExistingVaults() async throws {
        let empty = model(FakeService())
        empty.vault = ""; empty.vaults = []
        empty.discover(); try await finish(empty)
        #expect(empty.sheet == .createVault)
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            if case .discover = operation { result.vaults = [VaultDescriptor(id: "cloud-vault", name: "iCloud vault", format: "mop-items-v2", enrolled: false)] }
            return result
        }
        let fresh = model(service); fresh.vault = ""; fresh.vaults = []
        fresh.discover(autoUnlock: true); try await finish(fresh)
        #expect(fresh.sheet == nil)
        #expect(!fresh.authenticated)
        #expect(service.state.withLock { $0.operations.contains { if case .manage(.automaticEnrollment) = $0 { return true }; return false } })
        #expect(!service.state.withLock { $0.operations.contains { if case .create = $0 { return true }; return false } })
    }
    @Test func delayedVaultConnectionContinuesWithoutAnotherUnlockAndManualLockCancelsIt() async throws {
        let id = UUID().uuidString, second = UUID().uuidString
        let stage = Mutex(0)
        let service = FakeService { operation, vault, _ in
            var result = VaultResult()
            if case .discover = operation {
                let current = stage.withLock { $0 }
                result.vaults = [
                    .init(id: id, name: "personal", format: "mop-items-v2", enrolled: current >= 1),
                    .init(id: second, name: "other", format: "mop-items-v2", enrolled: current >= 2)]
            } else if case .catalog = operation {
                result.catalog = ItemCatalog(vault: vault == id ? "personal" : "other", revision: "ready", items: [])
            }
            return result
        }
        let app = model(service); app.vault = ""; app.vaults = []; app.start()
        try await finish(app)
        #expect(app.isConnectingVaults && !app.authenticated)
        app.retryVaultConnection(); try await finish(app)
        #expect(app.isConnectingVaults && !app.authenticated)
        #expect(service.state.withLock { $0.operations.filter { if case .manage(.automaticEnrollment) = $0 { return true }; return false }.count } >= 2)
        // A cloud hint supplies key access after the initial operation returned.
        service.authenticate(); stage.withLock { $0 = 1 }; service.notifyChange()
        let firstDeadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !app.authenticated, ContinuousClock.now < firstDeadline { await Task.yield() }
        #expect(app.authenticated && app.catalogs[id] != nil)
        #expect(app.isConnectingVaults)
        stage.withLock { $0 = 2 }; service.notifyChange()
        let secondDeadline = ContinuousClock.now.advanced(by: .seconds(3))
        while app.catalogs[second] == nil, ContinuousClock.now < secondDeadline { await Task.yield() }
        #expect(app.authenticated && app.catalogs[id] != nil && app.catalogs[second] != nil)
        #expect(service.state.withLock { $0.locks } == 0)
        app.lock()
        #expect(!app.isConnectingVaults)
        service.notifyChange(); try await finish(app)
        #expect(!app.authenticated)
        stage.withLock { $0 = 0 }
        app.vault = ""; app.vaults = []
        app.discover(autoUnlock: true); try await finish(app)
        #expect(app.isConnectingVaults)
        app.lock()
        stage.withLock { $0 = 2 }
        app.cloudChanged(); try await finish(app)
        #expect(!app.authenticated && !app.isConnectingVaults)
        #expect(app.catalogs.isEmpty)
    }

    @Test func incompleteRemoteDiscoveryNeverOffersFreshVaultCreation() async throws {
        let complete = Mutex(false)
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            if case .discover = operation { result.discoveryComplete = complete.withLock { $0 } }
            return result
        }
        let app = model(service); app.vault = ""; app.vaults = []
        app.discover(); try await finish(app)
        #expect(app.sheet == nil && app.vaults.isEmpty && !app.authenticated)
        #expect(!service.state.withLock { $0.operations.contains { if case .create = $0 { return true }; return false } })
        complete.withLock { $0 = true }
        app.discover(); try await finish(app)
        #expect(app.sheet == .createVault)
    }

    @Test func failedDiscoveryDoesNotOfferAnEmptyAccountSetup() async throws {
        let fresh = model(FakeService { _, _, _ in throw MopError.cloudUnavailable })
        fresh.vault = ""; fresh.vaults = []
        fresh.discover(); try await finish(fresh)
        #expect(fresh.sheet == nil)
        #expect(fresh.error != nil)
    }
    @Test func startingDeviceConnectionDismissesSetupChecklist() {
        let app = model(FakeService())
        app.showsSetupChecklist = true
        app.presentSheet(.addDevice)
        #expect(app.sheet == .addDevice)
        #expect(!app.showsSetupChecklist)
    }
    @Test func removedDeviceShowsReconnectAndDoesNotSendEnrollment() async throws {
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            if case .discover = operation { result.deviceRemoved = true }
            return result
        }
        let app = model(service)
        app.discover(autoUnlock: true); try await finish(app)
        #expect(app.deviceRemoved)
        #expect(app.sheet == .enrollDevice)
        #expect(app.vaults.isEmpty)
        let count = service.state.withLock { $0.operations.count }
        #expect(service.state.withLock { $0.operations.count } == count)
        app.reconnectDevice(); try await finish(app)
        #expect(service.state.withLock { $0.operations.contains { if case .manage(.reconnect) = $0 { return true }; return false } })
    }

    @Test func trustFailureCanResetFromLockedScreenAndReachEnrollment() async throws {
        let service = FakeService { operation, _, _ in
            switch operation {
            case .catalog: throw MopError.vaultUntrusted
            case .manage(.resetCloudAccess): throw MopError.deviceRemoved
            case .discover:
                var result = VaultResult()
                result.vaults = [.init(id: UUID().uuidString, name: "personal", format: "mop-items-v2", enrolled: false)]
                return result
            default: return VaultResult()
            }
        }
        let app = model(service, repairEnabled: true)
        app.resetCloudAccess()
        #expect(service.state.withLock { $0.operations.isEmpty })
        app.unlock(); try await finish(app)
        #expect(app.sessionState == .needsRepair)
        app.error = nil // Dismissing the alert must leave repair available.
        app.offline = true // Cached catalog state survives the original trust failure.
        app.resetCloudAccess(); try await finish(app)
        #expect(app.deviceRemoved && app.sheet == .enrollDevice)
        #expect(app.catalog == nil && !app.authenticated)
        app.reconnectDevice(); try await finish(app)
        #expect(!app.deviceRemoved && app.sessionState != .needsRepair)
        #expect(app.sheet == .enrollDevice)
        #expect(app.vaults.count == 1 && !app.vaults[0].enrolled)
        #expect(!app.offline)
    }

    @Test func secondaryVaultTrustFailureLeavesRepairAvailable() async throws {
        let demo = UUID().uuidString, personal = UUID().uuidString
        let service = FakeService { _, id, _ in
            if id == personal { throw MopError.vaultUntrusted }
            var result = VaultResult(); result.catalog = Self.catalog; return result
        }
        service.authenticate()
        let app = model(service, repairEnabled: true)
        app.vault = demo
        app.vaults = [demo, personal].map { .init(id: $0, name: $0, format: "mop-items-v2", enrolled: true) }
        app.unlock(); try await finish(app)
        #expect(!app.authenticated && app.sessionState == .needsRepair)
        #expect(app.error?.contains("Repair iCloud Connection") == true)
        app.error = nil
        #expect(app.sessionState == .needsRepair)
    }

    @Test func removalDuringUnlockClearsViewAndOffersReconnect() async throws {
        let app = model(FakeService { _, _, _ in throw MopError.deviceRemoved })
        app.unlock(); try await finish(app)
        #expect(app.deviceRemoved && !app.authenticated)
        #expect(app.sheet == .enrollDevice)
        #expect(app.error == nil && app.catalog == nil)
    }
    private func finish(_ model: AppModel) async throws {
        for _ in 0..<500 {
            if !model.busy && !model.refreshing && !model.loadingVaults { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        Issue.record("Operation did not finish")
    }
    private func entered(_ barrier: Barrier) async throws {
        for _ in 0..<500 {
            if await barrier.entered { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        Issue.record("Operation did not reach barrier")
    }
    nonisolated private static var catalog: ItemCatalog {
        ItemCatalog(vault: "personal", revision: "r1", items: [VaultItem(name: "github", fields: [
            ItemField(path: "username", type: .username, value: "alice"), ItemField(path: "token")
        ])])
    }
    @Test func fingerprintRemainsInSettings() async throws {
        let service = FakeService { operation, _, _ in
            guard case .manage(.fingerprint) = operation else { throw MopError.invalidProcess }
            var result = VaultResult()
            result.message = String(repeating: "a", count: 64)
            return result
        }
        service.authenticate()
        let model = model(service)
        model.settingsVisible = true
        model.management(.fingerprint, keepSheet: true)
        try await finish(model)
        #expect(model.settingsVisible && model.sheet == nil)
        #expect(model.notice == String(repeating: "a", count: 64))
        #expect(model.error == nil)
    }

    @Test func vaultMenuTargetsItsRowWithoutStartingAnUnlock() throws {
        let service = FakeService(); service.authenticate()
        let model = model(service)
        let target = UUID().uuidString
        model.vaults = [VaultDescriptor(id: target, name: "personal", format: "mop-items-v2", enrolled: true)]
        model.allVaults = true
        model.catalogs[target] = Self.catalog; model.authenticated = true
        #expect(model.prepareVaultAction(target))
        #expect(model.vault == target && !model.allVaults)
        #expect(model.authenticated && model.catalog?.vault == "personal")
        #expect(!model.busy && service.state.withLock { $0.operations.isEmpty })
        #expect(!model.prepareVaultAction(UUID().uuidString))
        model.busy = true
        #expect(!model.prepareVaultAction(target))
    }

    @Test func backgroundKeepsSessionAndConcealsValues() throws {
        let service = FakeService(); service.authenticate()
        let model = model(service)
        try model.applyCatalog(Self.catalog); model.authenticated = true; model.revealed = "secret"
        model.deactivate()
        #expect(!model.isActive && model.revealed == nil)
        #expect(model.authenticated && model.catalog != nil && service.isAuthenticated)
        model.activate()
        #expect(model.authenticated && model.isActive)
    }
    @Test func timeoutUsesOnlyGUIActivityAndExpiresInBackground() {
        let clock = Clock(), service = FakeService(); service.authenticate()
        let model = model(service, clock: clock)
        model.checkExpiration()
        clock.time = 299; model.activity()
        clock.time = 500; model.deactivate(); model.activity()
        #expect(service.isAuthenticated)
        clock.time = 599; model.checkExpiration()
        #expect(!service.isAuthenticated && model.status == "Locked")
        model.activate(); #expect(!model.authenticated)
    }
    @Test func settingsApplyImmediatelyAndClampToWholeMinuteRange() {
        let clock = Clock(), service = FakeService(); service.authenticate()
        let model = model(service, clock: clock)
        #expect(model.autoLockMinutes == 5)
        model.checkExpiration(); clock.time = 121
        model.autoLockMinutes = 2
        #expect(!service.isAuthenticated)
        model.autoLockMinutes = 0; #expect(model.autoLockMinutes == 1)
        model.autoLockMinutes = 80; #expect(model.autoLockMinutes == 60)
    }
    @Test func manualLockClearsCatalogAndInvalidatesEditors() throws {
        let service = FakeService(); service.authenticate()
        let model = model(service)
        try model.applyCatalog(Self.catalog); model.authenticated = true; model.revealed = "secret"
        model.sheet = .createVault; model.search = "private"; model.deleteConfirmation = true
        let generation = model.editorGeneration
        model.lock()
        #expect(!service.isAuthenticated && !model.authenticated)
        #expect(model.catalog == nil && model.references.isEmpty && model.revealed == nil)
        #expect(model.sheet == nil && model.search.isEmpty && !model.deleteConfirmation)
        #expect(model.editorGeneration > generation)
    }
    @Test func lockDiscardsPendingIndex() async throws {
        let barrier = Barrier()
        let service = FakeService { _, _, _ in await barrier.wait(); var r = VaultResult(); r.catalog = Self.catalog; return r }
        service.authenticate()
        let model = model(service)
        model.unlock(); try await entered(barrier); model.lock()
        await barrier.release(); try await finish(model)
        #expect(model.catalog == nil && !model.authenticated && model.status == "Locked")
    }
    @Test func backgroundIndexCompletionRetainsCoveredSession() async throws {
        let barrier = Barrier()
        let service = FakeService { _, _, _ in await barrier.wait(); var r = VaultResult(); r.catalog = Self.catalog; return r }
        service.authenticate()
        let model = model(service)
        model.unlock(); try await entered(barrier); model.deactivate()
        await barrier.release(); try await finish(model)
        #expect(model.authenticated && !model.isActive)
        model.activate(); #expect(model.authenticated)
    }
    @Test func lostFocusDiscardsPendingRevealEvenAfterReturning() async throws {
        let barrier = Barrier()
        let service = FakeService { _, _, _ in await barrier.wait(); var r = VaultResult(); r.value = "secret"; return r }
        service.authenticate()
        let model = model(service)
        model.selected = try SecretReference("sp://personal/github/token")
        model.read(copy: false); try await entered(barrier)
        model.deactivate(); model.activate(); await barrier.release(); try await finish(model)
        #expect(model.revealed == nil && service.isAuthenticated)
    }
    @Test func switchingVaultUsesExistingSession() async throws {
        let service = FakeService { _, _, _ in var r = VaultResult(); r.catalog = Self.catalog; return r }
        service.authenticate()
        let model = model(service)
        model.vault = UUID().uuidString; model.changedVault(); try await finish(model)
        #expect(model.authenticated && service.state.withLock { $0.locks } == 0)
    }
    @Test func uncertainCreationRetainsReconciliationUUID() async throws {
        let service = FakeService { _, _, _ in throw MopError.cloudUncertain }
        let model = model(service)
        let old = model.vault
        model.createVault(name: "personal")
        try await finish(model)
        #expect(model.vault != old && model.vaults.contains { $0.id == model.vault })
        #expect(model.catalog == nil && model.error == MopError.cloudUncertain.errorDescription)
    }
    @Test func portableRestoreImmediatelySelectsRestoredVaultAndClosesSheet() async throws {
        let service = FakeService { _, _, _ in var result = VaultResult(); result.catalog = Self.catalog; return result }
        service.authenticate()
        let model = model(service)
        let restoredID = UUID().uuidString
        model.sheet = .restoreBackup
        var result = VaultResult(); result.catalog = Self.catalog; result.message = "Restored"
        model.perform { token in try await model.completePortableRestore(result, id: restoredID, token: token) }
        try await finish(model)
        #expect(model.vault == restoredID)
        #expect(model.vaults.contains { $0.id == restoredID })
        #expect(model.catalog?.items == Self.catalog.items)
        #expect(model.sheet == nil)
        #expect(model.notice == "Restored")
    }
    @Test func portableRestoreCompletionAfterLockDoesNotExposeCatalog() async throws {
        let service = FakeService()
        service.authenticate()
        let model = model(service)
        let restoredID = UUID().uuidString
        var result = VaultResult(); result.catalog = Self.catalog; result.message = "Restored"
        model.perform { token in
            model.lock()
            try await model.completePortableRestore(result, id: restoredID, token: token)
        }
        try await finish(model)
        #expect(model.catalog == nil && model.notice == nil)
        #expect(!model.vaults.contains { $0.id == restoredID })
    }
    @Test func deletionRequiresExactConfirmationAndFixedUUID() async throws {
        let service = FakeService { op, id, offline in
            guard case .deleteVault = op else { Issue.record("Wrong operation"); return VaultResult() }
            #expect(id != nil && !offline); return VaultResult()
        }
        let model = model(service)
        let target = VaultDescriptor(id: model.vault, name: "personal", format: "mop-items-v2", enrolled: true)
        model.vaults = [target]
        model.deleteVault(target: target, confirmation: "wrong")
        #expect(!model.busy)
        model.deleteVault(target: target, confirmation: "personal"); try await finish(model)
        #expect(model.vault.isEmpty && model.vaults.isEmpty)
    }
    @Test func renameRetainsAuthenticationAndReplacesOldReferences() async throws {
        let service = FakeService { _, _, _ in var r = VaultResult(); r.catalog = Self.catalog; r.catalog?.vault = "private"; return r }
        service.authenticate()
        let model = model(service)
        model.authenticated = true
        model.renameVault(to: "private"); try await finish(model)
        #expect(model.authenticated && model.vaultName == "private")
        #expect(model.references.allSatisfy { $0.vault == "private" })
    }
    @Test func lockDuringSaveDiscardsCompletionAndDoesNotReopenSheet() async throws {
        let barrier = Barrier()
        let service = FakeService { _, _, _ in await barrier.wait(); var r = VaultResult(); r.catalog = Self.catalog; return r }
        service.authenticate()
        let model = model(service); try model.applyCatalog(Self.catalog); model.sheet = .createVault
        model.saveItem(Self.catalog.items[0], create: false); try await entered(barrier)
        model.lock(); await barrier.release(); try await finish(model)
        #expect(model.sheet == nil && model.catalog == nil && model.notice == nil)
    }
    @Test func arbitraryFrameworkDiagnosticsAreNotDisplayed() async throws {
        let service = FakeService { _, _, _ in throw NSError(domain: "SECRET", code: 1, userInfo: [NSLocalizedDescriptionKey: "SECRET"]) }
        let model = model(service); model.unlock(); try await finish(model)
        #expect(model.error == "The operation could not be completed.")
    }
}

extension AppModelTests {
    @Test(arguments: [false, true]) func deviceRemovalClearsBusyProgressOnSuccessAndFailure(fails: Bool) async throws {
        let service = FakeService { operation, _, _ in
            guard case .manage(.removeAccountDevice) = operation else { return VaultResult() }
            if fails { throw MopError.cloudUnavailable }
            var result = VaultResult(); result.message = "Device removed."
            return result
        }
        service.authenticate()
        let app = model(service)
        app.removeDevice(UUID())
        #expect(app.busy && app.removingDevice && app.removalProgress != nil)
        try await finish(app)
        #expect(!app.busy && !app.removingDevice && app.removalProgress == nil)
        if fails { #expect(app.error != nil) }
        else { #expect(app.notice == "Device removed.") }
    }

    @Test func exportUsesSelectedUUIDAndAutomaticAvailability() async throws {
        let id = UUID().uuidString, output = URL(fileURLWithPath: "/tmp/unused-export.mopfile")
        let service = FakeService { operation, vault, offline in
            guard case .export(let url) = operation else { Issue.record("Wrong operation"); return VaultResult() }
            #expect(vault == id && !offline && url == output); return VaultResult()
        }
        let model = model(service)
        model.vault = id; model.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-items-v2", enrolled: true)]
        model.offline = true; model.sheet = .deleteVault
        model.exportBackup(to: output); try await finish(model)
        #expect(model.sheet == .deleteVault && model.notice?.contains("backup exported") == true)
    }
    @Test func fieldActionsUseAtomicTypedItemEdits() async throws {
        let service = FakeService { operation, _, _ in
            guard case .save(let edit) = operation else { Issue.record("Wrong operation"); return VaultResult() }
            #expect(edit.revision == "r1" && !edit.create)
            #expect(edit.item.fields.last?.path == "extra" && edit.item.fields.last?.value == "new")
            var result = VaultResult(); result.catalog = ItemCatalog(vault: "personal", revision: "r2", items: [edit.item]); return result
        }
        service.authenticate()
        let model = model(service); try model.applyCatalog(Self.catalog)
        let reference = try SecretReference("sp://personal/github/extra")
        model.write(reference: reference, value: "new", replace: false); try await finish(model)
        #expect(model.items == ["github"] && model.catalog?.revision == "r2")
    }
    @Test func lockBeforeTaskStartsDoesNotBeginAuthentication() async throws {
        let service = FakeService()
        let model = model(service); model.unlock(); model.lock(); try await finish(model)
        #expect(service.state.withLock { $0.operations.isEmpty })
    }
    @Test func authenticationCompletionStartsDeadlineWithoutUserInteraction() async throws {
        let barrier = Barrier(), clock = Clock()
        let service = FakeService { _, _, _ in await barrier.wait(); var result = VaultResult(); result.catalog = Self.catalog; return result }
        let model = model(service, clock: clock); model.unlock(); try await entered(barrier)
        clock.time = 100; service.authenticate(at: 100); model.checkExpiration()
        clock.time = 401; model.checkExpiration()
        #expect(!service.isAuthenticated && model.status == "Locked")
        await barrier.release(); try await finish(model)
        #expect(model.catalog == nil)
    }
}

extension AppModelTests {
    @Test func inlineSaveUsesOriginalRevisionAndPersistsFieldOrder() async throws {
        let service = FakeService { operation, _, _ in
            guard case .save(let edit) = operation else { Issue.record("Wrong operation"); return VaultResult() }
            #expect(edit.revision == "r1")
            #expect(edit.item.fields.map(\.path) == ["token", "username"])
            #expect(edit.item.fields[0].value == nil)
            var result = VaultResult(); result.catalog = ItemCatalog(vault: "personal", revision: "r3", items: [edit.item]); return result
        }
        service.authenticate()
        let model = model(service); try model.applyCatalog(Self.catalog); model.authenticated = true; model.selectedItem = "github"
        model.beginItemEditing()
        let fields = try #require(model.itemDraft?.fields)
        model.itemDraft?.move(fields[0].id, to: fields[1].id)
        // A refresh must not silently rebase an unsaved draft onto another revision.
        var refreshed = Self.catalog; refreshed.revision = "r2"; try model.applyCatalog(refreshed)
        model.saveItemDraft(); try await finish(model)
        #expect(model.itemDraft == nil && model.catalog?.revision == "r3")
        #expect(model.itemFields.map(\.field) == ["token", "username"])
    }
    @Test func inlineFailureRetainsDraftButLockDiscardsIt() async throws {
        let service = FakeService { _, _, _ in throw MopError.vaultConflict }
        service.authenticate()
        let model = model(service); try model.applyCatalog(Self.catalog); model.authenticated = true; model.selectedItem = "github"
        model.beginItemEditing(replacing: "token")
        model.itemDraft?.fields[1].value = "new-secret"
        model.saveItemDraft(); try await finish(model)
        #expect(model.itemDraft?.fields[1].value == "new-secret")
        #expect(model.error == MopError.vaultConflict.errorDescription)
        model.lock(); #expect(model.itemDraft == nil)
    }
    @Test func cancellingInlineEditLeavesCatalogUntouchedAndOfflineRejectsEditing() throws {
        let service = FakeService(); service.authenticate()
        let model = model(service); try model.applyCatalog(Self.catalog); model.authenticated = true; model.selectedItem = "github"
        model.beginItemEditing(); model.itemDraft?.fields.removeFirst(); model.cancelItemEditing()
        #expect(model.catalog?.items == Self.catalog.items && model.itemDraft == nil)
        model.offline = true; model.beginItemEditing(); #expect(model.itemDraft == nil)
    }
}

extension AppModelTests {
    @Test func launchUnlocksOnceAndAllVaultsKeepDuplicateNamesSeparate() async throws {
        let first = UUID().uuidString, second = UUID().uuidString
        let service = FakeService { operation, id, _ in
            var result = VaultResult()
            switch operation {
            case .discover:
                result.vaults = [VaultDescriptor(id: first, name: "personal", format: "mop-items-v2", enrolled: true),
                                VaultDescriptor(id: second, name: "work", format: "mop-items-v2", enrolled: true)]
                result.defaultVault = first
            case .catalog:
                result.catalog = ItemCatalog(vault: id == first ? "personal" : "work", revision: "r1", items: Self.catalog.items)
            default: Issue.record("Unexpected operation")
            }
            return result
        }
        service.authenticate()
        let model = model(service); model.vault = ""
        model.start(); try await finish(model)
        #expect(model.authenticated && model.allVaults && model.displayedItems.count == 2)
        #expect(Set(model.displayedItems.map(\.id)).count == 2)
        model.selectedRow = .init(vault: second, name: "github")
        #expect(model.vault == second && model.vaultName == "work" && model.selectedItem == "github")
        #expect(model.displayedItems.count == 2)
        let count = service.state.withLock { $0.operations.count }
        model.lock(); model.start(); try await finish(model)
        #expect(service.state.withLock { $0.operations.count } == count)
        #expect(model.catalogs.isEmpty && model.displayedItems.isEmpty)
    }
    @Test func cancelledLaunchAuthenticationDoesNotPromptAgain() async throws {
        let id = UUID().uuidString
        let service = FakeService { operation, _, _ in
            if case .discover = operation {
                var result = VaultResult(); result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-items-v2", enrolled: true)]; return result
            }
            throw MopError.authentication
        }
        let model = model(service); model.vault = ""
        model.start(); try await finish(model); model.start(); try await finish(model)
        #expect(service.state.withLock { $0.operations.count } == 2)
        #expect(!model.authenticated)
    }
    @Test func inlineRenameSendsOriginalIdentityAndSelectsNewName() async throws {
        let service = FakeService { operation, _, _ in
            guard case .save(let edit) = operation else { Issue.record("Wrong operation"); return VaultResult() }
            #expect(edit.originalName == "github" && edit.item.name == "GitHub account")
            var result = VaultResult(); result.catalog = ItemCatalog(vault: "personal", revision: "r2", items: [edit.item]); return result
        }
        service.authenticate()
        let model = model(service); try model.applyCatalog(Self.catalog); model.authenticated = true; model.selectedItem = "github"
        model.beginItemEditing(); model.itemDraft?.name = "GitHub account"
        model.saveItemDraft(); try await finish(model)
        #expect(model.selectedItem == "GitHub account" && model.itemDraft == nil)
        #expect(model.references.allSatisfy { $0.item == "GitHub account" })
    }
}

extension AppModelTests {
    @Test(arguments: [false, true]) func passwordEditingLoadsCurrentValue(singleField: Bool) async throws {
        let service = FakeService { operation, _, _ in
            guard case .read(let reference) = operation else { Issue.record("Expected password read"); return VaultResult() }
            #expect(reference.field == "token")
            var result = VaultResult(); result.value = "current-password"; return result
        }
        service.authenticate()
        let model = model(service)
        var catalog = Self.catalog; catalog.items[0].fields[1].type = .password
        try model.applyCatalog(catalog); model.authenticated = true; model.selectedItem = "github"
        model.beginItemEditing(replacing: singleField ? "token" : nil)
        try await finish(model)
        #expect(model.itemDraft?.fields[1].value == "current-password")
        #expect(model.itemDraft?.item.fields[1].value == nil)
        model.itemDraft?.fields[1].value = "replacement"
        #expect(model.itemDraft?.item.fields[1].value == "replacement")
        model.itemDraft?.fields[1].value = ""
        #expect(model.itemDraft?.item.fields[1].value == "")
    }

    @Test(arguments: ["lock", "cancel", "focus", "typing"])
    func latePasswordReadCannotRestoreOrOverwriteDraft(event: String) async throws {
        let barrier = Barrier()
        let service = FakeService { _, _, _ in
            await barrier.wait()
            var result = VaultResult(); result.value = "old-password"; return result
        }
        service.authenticate()
        let model = model(service)
        var catalog = Self.catalog; catalog.items[0].fields[1].type = .password
        try model.applyCatalog(catalog); model.authenticated = true; model.selectedItem = "github"
        model.beginItemEditing(replacing: "token")
        try await entered(barrier)
        switch event {
        case "lock": model.lock()
        case "cancel": model.cancelItemEditing()
        case "focus": model.deactivate(); model.activate()
        default: model.itemDraft?.fields[1].value = "typed-password"
        }
        await barrier.release(); try await finish(model)
        if event == "typing" { #expect(model.itemDraft?.fields[1].value == "typed-password") }
        else if event == "focus" {
            #expect(model.itemDraft?.fields[1].value == "old-password")
            #expect(model.itemDraft?.isModified == false)
        } else { #expect(model.itemDraft == nil) }
    }
}

extension AppModelTests {
    @Test func generatorSettingsSurviveLockAndAppRelaunch() throws {
        let suite = "mop-generator-test-" + UUID().uuidString
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let first = AppModel(breachClient: TestBreachClient(), service: FakeService(), defaults: defaults, automaticTimer: false)
        var options = PasswordOptions()
        options.length = 48; options.lowercase = false; options.uppercase = true
        options.numbers = false; options.symbols = false
        options.readable = true; options.pronounceable = true
        first.passwordGeneratorOptions = options
        first.lock()
        #expect(first.passwordGeneratorOptions == options)
        let reopened = AppModel(breachClient: TestBreachClient(), service: FakeService(), defaults: defaults, automaticTimer: false)
        #expect(reopened.passwordGeneratorOptions == options)
        defaults.set(Data("invalid".utf8), forKey: "passwordGeneratorOptions")
        let fallback = AppModel(breachClient: TestBreachClient(), service: FakeService(), defaults: defaults, automaticTimer: false)
        #expect(fallback.passwordGeneratorOptions == PasswordOptions())
    }
}

extension AppModelTests {
    @Test func templateFieldsCannotBeDeletedOrRenamedThroughGUISaves() throws {
        let service = FakeService(); service.authenticate()
        let model = model(service)
        let item = VaultItem(name: "login", type: .login, fields: [
            ItemField(path: "username", type: .username, value: "alice"),
            ItemField(path: "notes", type: .notes, value: "")
        ])
        try model.applyCatalog(ItemCatalog(vault: "personal", revision: "r1", items: [item]))
        model.authenticated = true; model.selectedItem = "login"
        model.selected = try SecretReference("sp://personal/login/username")
        model.delete()
        var changed = item
        changed.fields.removeFirst()
        model.saveItem(changed, create: false)
        changed = item; changed.fields[0].path = "renamed"
        model.saveItem(changed, create: false)
        #expect(service.state.withLock { $0.operations.isEmpty })
        #expect(model.catalog?.items == [item])
    }
}

extension AppModelTests {
    @Test func searchIncludesVisibleValuesButNeverConcealedValues() throws {
        let service = FakeService(); let model = model(service)
        let fields = FieldType.allCases.map { ItemField(path: $0.rawValue, type: $0, value: "value-" + $0.rawValue + "-needle") }
        let catalog = ItemCatalog(vault: "personal", revision: "r1", items: [VaultItem(name: "entry", fields: fields)])
        try model.applyCatalog(catalog)
        for all in [false, true] {
            model.allVaults = all
            for type in FieldType.allCases {
                model.search = "VALUE-" + type.rawValue + "-NEEDLE"
                #expect(model.searchResults.count == (type.concealed ? 0 : 1))
                #expect(model.displayedItems.count == (type.concealed ? 0 : 1))
            }
        }
        #expect(service.state.withLock { $0.operations.isEmpty })
    }

    @Test func searchMatchesSSHUsernameNameAndValue() throws {
        let service = FakeService(), model = model(service)
        let item = VaultItem(name: "server", fields: [ItemField(path: "ssh%20username", type: .username, value: "sshd")])
        try model.applyCatalog(ItemCatalog(vault: "personal", revision: "1", items: [item]))
        for all in [false, true] {
            model.allVaults = all
            for query in ["ss", "ssh", "sshd", "Ssh Username"] {
                model.search = query
                #expect(model.searchResults.map(\.row.item.name) == ["server"])
            }
        }
        #expect(service.state.withLock { $0.operations.isEmpty })
    }

    @Test func searchFiltersListAndOpensMatchingVault() throws {
        let service = FakeService(), model = model(service)
        let first = model.vault, second = UUID().uuidString
        let one = ItemCatalog(vault: "personal", revision: "1", items: [VaultItem(name: "entry", fields: [ItemField(path: "username", type: .username, value: "alice")])])
        let two = ItemCatalog(vault: "work", revision: "2", items: [VaultItem(name: "entry", fields: [ItemField(path: "email", type: .email, value: "bob@example.test"), ItemField(path: "password", type: .password, value: "hidden")])])
        try model.applyCatalog(one); model.catalogs[second] = two; model.allVaults = true
        model.search = "EXAMPLE.TEST"
        let result = try #require(model.searchResults.first)
        #expect(model.searchResults.count == 1 && result.row.id.vault == second)
        #expect(result.detail == "email: bob@example.test")
        #expect(model.displayedItems.count == 1)
        model.selectedRow = result.id
        #expect(model.selectedItem == "entry" && model.vault == second && model.catalog?.revision == "2")
        #expect(model.displayedItems.count == 1 && model.catalogs[first] != nil)
        model.search = "password"
        #expect(model.searchResults.isEmpty)
        #expect(service.state.withLock { $0.operations.isEmpty })
    }

    @Test func allVaultsCreationUsesDestinationRevisionAndRemembersChoice() async throws {
        let first = UUID().uuidString, second = UUID().uuidString
        let suite = "mop-create-vault-test-" + UUID().uuidString
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let service = FakeService { operation, vault, _ in
            guard case .save(let edit) = operation else { Issue.record("Expected save"); return VaultResult() }
            #expect(vault == second && edit.revision == "work-r1" && edit.create)
            var result = VaultResult()
            result.catalog = ItemCatalog(vault: "work", revision: "work-r2", items: [edit.item])
            return result
        }
        service.authenticate(at: ProcessInfo.processInfo.systemUptime)
        let model = AppModel(breachClient: TestBreachClient(), service: service, defaults: defaults, automaticTimer: false)
        let vaults = [VaultDescriptor(id: first, name: "personal", format: "mop-items-v2", enrolled: true),
                      VaultDescriptor(id: second, name: "work", format: "mop-items-v2", enrolled: true)]
        model.vaults = vaults; model.vault = first; model.allVaults = true; model.authenticated = true
        model.catalogs = [first: Self.catalog, second: ItemCatalog(vault: "work", revision: "work-r1", items: [])]
        model.createItem(VaultItem(name: "new", fields: [ItemField(path: "text", type: .text, value: "visible")]), in: second)
        try await finish(model)
        #expect(model.allVaults && model.vault == second && model.selectedItem == "new")
        #expect(model.catalogs[first]?.revision == "r1" && model.catalogs[second]?.revision == "work-r2")
        let reopened = AppModel(breachClient: TestBreachClient(), service: FakeService(), defaults: defaults, automaticTimer: false)
        reopened.allVaults = true; reopened.vault = first; reopened.vaults = vaults; reopened.catalogs = model.catalogs
        #expect(reopened.preferredCreationVault == second)
        reopened.catalogs.removeValue(forKey: second)
        #expect(reopened.preferredCreationVault == first)
        reopened.allVaults = false
        #expect(reopened.preferredCreationVault == first)
    }
}

extension AppModelTests {
    @Test func newItemUsesInlineDraftAndVaultSwitchPreservesInput() throws {
        let service = FakeService(); service.authenticate()
        let model = model(service)
        let first = model.vault, second = UUID().uuidString
        model.vaults = [VaultDescriptor(id: first, name: "personal", format: "mop-items-v2", enrolled: true),
                        VaultDescriptor(id: second, name: "work", format: "mop-items-v2", enrolled: true)]
        model.catalogs = [first: Self.catalog, second: ItemCatalog(vault: "work", revision: "r2", items: [])]
        model.allVaults = true; model.authenticated = true
        model.beginCreatingItem()
        #expect(model.sheet == nil && model.itemDraft?.isNew == true)
        #expect(model.itemDraft?.fields.allSatisfy { !$0.existing && $0.isTemplate } == true)
        model.itemDraft?.name = "new login"
        model.itemDraft?.fields[0].value = "alice"
        model.chooseCreationVault(second)
        #expect(model.itemDraft?.vault == second && model.itemDraft?.name == "new login")
        #expect(model.itemDraft?.fields[0].value == "alice")
        model.cancelItemEditing()
        model.beginCreatingItem()
        #expect(model.itemDraft?.vault == second && model.itemDraft?.name == "")
        model.changeDraftType(.database)
        #expect(model.itemDraft?.fields.map(\.path) == ItemType.database.template.map(\.path))
        model.lock()
        #expect(model.itemDraft == nil)
    }
}

extension AppModelTests {
    @Test func deletingFromAllVaultsTargetsRowAndKeepsDeletedItemsSeparate() async throws {
        let first = UUID().uuidString, second = UUID().uuidString
        let deletion = ItemDeletion(originalName: "github", deletedAt: Date())
        var archived = Self.catalog.items[0]
        archived.name = "mop-deleted-" + deletion.id.uuidString; archived.deletion = deletion
        let archivedItem = archived
        let service = FakeService { operation, vault, _ in
            guard case .trashItem(let name, let revision) = operation else { Issue.record("Expected trash"); return VaultResult() }
            #expect(vault == second && name == "github" && revision == "r1")
            var result = VaultResult()
            result.catalog = ItemCatalog(vault: "work", revision: "r2", items: [])
            result.deletedCatalog = ItemCatalog(vault: "work", revision: "r2", items: [archivedItem])
            return result
        }
        service.authenticate()
        let model = model(service); model.vault = first; model.allVaults = true; model.authenticated = true
        try model.applyCatalog(Self.catalog)
        model.catalogs[second] = Self.catalog
        let row = ItemRow(id: .init(vault: second, name: "github"), vaultName: "work", item: Self.catalog.items[0])
        model.trashItem(row); try await finish(model)
        #expect(model.displayedItems.count == 1 && model.displayedItems[0].id.vault == first)
        #expect(model.deletedRows.count == 1 && model.deletedRows[0].id.vault == second)
        model.lock()
        #expect(model.deletedCatalogs.isEmpty && model.deletedRows.isEmpty && model.itemToDelete == nil)
    }

    @Test func lockingDuringTrashCommitCannotRestoreDeletedMetadata() async throws {
        let barrier = Barrier()
        let service = FakeService { _, _, _ in
            await barrier.wait()
            var result = VaultResult(); result.catalog = Self.catalog; result.deletedCatalog = Self.catalog; return result
        }
        service.authenticate()
        let model = model(service); try model.applyCatalog(Self.catalog); model.authenticated = true
        let row = ItemRow(id: .init(vault: model.vault, name: "github"), vaultName: "personal", item: Self.catalog.items[0])
        model.trashItem(row); try await entered(barrier)
        model.lock(); await barrier.release(); try await finish(model)
        #expect(!model.authenticated && model.catalogs.isEmpty && model.deletedCatalogs.isEmpty && model.notice == nil)
    }

    @Test func retentionHidesExpiredItemsOfflineAndPrunesWhenOnline() async throws {
        let clock = Clock()
        let start = Date(timeIntervalSince1970: 1_000_000)
        let service = FakeService { operation, _, _ in
            guard case .recentlyDeleted = operation else { Issue.record("Expected retention cleanup"); return VaultResult() }
            var result = VaultResult()
            result.catalog = ItemCatalog(vault: "personal", revision: "r2", items: [])
            result.deletedCatalog = ItemCatalog(vault: "personal", revision: "r2", items: [])
            return result
        }
        service.authenticate()
        let defaults = UserDefaults(suiteName: "mop-retention-test-" + UUID().uuidString)!
        let model = AppModel(breachClient: TestBreachClient(), service: service, defaults: defaults, now: { 0 }, automaticTimer: false,
                             wallNow: { start.addingTimeInterval(clock.time) })
        model.vault = UUID().uuidString; model.authenticated = true
        var archived = Self.catalog.items[0]
        archived.deletion = ItemDeletion(originalName: archived.name, deletedAt: start)
        archived.name = "mop-deleted-" + archived.deletion!.id.uuidString
        model.deletedCatalogs[model.vault] = ItemCatalog(vault: "personal", revision: "r1", items: [archived])
        #expect(model.deletedRows.count == 1)
        model.offline = true; clock.time = ItemDeletion.retention
        model.checkRetention()
        #expect(model.deletedRows.isEmpty && service.state.withLock { $0.operations.isEmpty })
        model.offline = false; model.checkRetention(); try await finish(model)
        #expect(model.deletedCatalogs[model.vault]?.items.isEmpty == true)
        #expect(service.state.withLock { $0.operations.count } == 1)
    }
}

extension AppModelTests {
    @Test func navigatingUnlockedVaultsAndDeletedAreaReusesCatalogs() throws {
        let service = FakeService(); service.authenticate()
        let model = model(service)
        let first = model.vault, second = UUID().uuidString
        model.vaults = [VaultDescriptor(id: first, name: "personal", format: "mop-items-v2", enrolled: true),
                        VaultDescriptor(id: second, name: "work", format: "mop-items-v2", enrolled: true)]
        model.catalogs = [first: Self.catalog, second: ItemCatalog(vault: "work", revision: "work-r1", items: [])]
        model.authenticated = true
        model.chooseVault(second)
        #expect(model.catalog?.vault == "work" && !model.busy)
        model.chooseVault(first)
        #expect(model.catalog?.vault == "personal" && model.catalogs.count == 2)
        model.chooseAllVaults()
        #expect(model.allVaults && model.authenticated && !model.busy)
        model.chooseRecentlyDeleted()
        #expect(model.page == .recentlyDeleted && model.catalogs.count == 2)
        #expect(service.state.withLock { $0.operations.isEmpty })
        model.lock()
        #expect(model.catalogs.isEmpty && !model.authenticated)
    }

    @Test func selectingAnUnopenedVaultLoadsOnlyThatVault() async throws {
        let target = UUID().uuidString
        let service = FakeService { operation, vault, _ in
            guard case .catalog = operation else { Issue.record("Expected catalog"); return VaultResult() }
            #expect(vault == target)
            var result = VaultResult(); result.catalog = ItemCatalog(vault: "work", revision: "work-r1", items: []); return result
        }
        service.authenticate()
        let model = model(service)
        let first = model.vault
        model.catalogs[first] = Self.catalog; model.authenticated = true
        model.vaults.append(VaultDescriptor(id: target, name: "work", format: "mop-items-v2", enrolled: true))
        model.chooseVault(target); try await finish(model)
        #expect(model.catalog?.vault == "work" && model.catalogs[first]?.revision == "r1")
        model.chooseVault(first)
        #expect(model.catalog?.vault == "personal")
        #expect(service.state.withLock { $0.operations.count } == 1)
    }
}

@MainActor private final class TestClipboard: SecretClipboardAccess {
    var clears = 0
    func copy(_ value: SecretBytes, concealed: Bool) {}
    func clear() { clears += 1 }
}
@MainActor private final class TestLifecycle: AppLifecycleMonitoring {
    var receive: (@MainActor (AppLifecycleEvent) -> Void)?
    func start(_ receive: @escaping @MainActor (AppLifecycleEvent) -> Void) { self.receive = receive }
    func stop() { receive = nil }
}

extension AppModelTests {
    @Test func backgroundPreservesSessionButDeviceLockEndsIt() {
        let service = FakeService()
        service.authenticate()
        let clipboard = TestClipboard(), lifecycle = TestLifecycle()
        let model = AppModel(breachClient: TestBreachClient(), service: service, clipboard: clipboard, lifecycle: lifecycle, now: { 1 }, automaticTimer: false)
        model.authenticated = true
        model.catalog = Self.catalog
        model.revealed = "secret"
        model.startMonitoringActivity()
        lifecycle.receive?(.inactive)
        #expect(model.revealed == nil && !model.isActive)
        #expect(service.isAuthenticated)
        #expect(clipboard.clears == 0)
        lifecycle.receive?(.active)
        #expect(model.isActive && model.authenticated)
        lifecycle.receive?(.background)
        #expect(service.isAuthenticated && model.authenticated)
        #expect(model.catalog != nil && model.itemDraft == nil)
        #expect(clipboard.clears == 0)
        lifecycle.receive?(.lock)
        #expect(!service.isAuthenticated && !model.authenticated && model.catalog == nil)
        #expect(clipboard.clears == 1)
        model.shutdown()
        #expect(lifecycle.receive == nil)
    }
}

extension AppModelTests {
    @Test func lateBackupPickerCannotReauthenticateAfterLock() throws {
        let service = FakeService()
        let model = model(service)
        model.vaults = [VaultDescriptor(id: model.vault, name: "personal", format: "mop-items-v2", enrolled: true)]
        model.chooseExportBackup()
        let request = try #require(model.documentRequest)
        model.lock()
        model.completeBackupSelection(folder: FileManager.default.temporaryDirectory, request: request)
        #expect(!model.busy)
        #expect(service.state.withLock { $0.operations.isEmpty })

    }
}

extension AppModelTests {
    @Test func untrustedVaultOffersHardwareRecoveryGuidance() async throws {
        let service = FakeService { operation, _, _ in
            if case .catalog = operation { throw MopError.vaultUntrusted }
            return VaultResult()
        }
        let model = model(service)
        model.unlock()
        try await finish(model)
        #expect(model.error?.contains("offline recovery copy") == true)
        #expect(model.error?.contains("Repair iCloud Connection") == false)
        #expect(!model.cloudConnectionRepairEnabled)
        #expect(model.error?.contains("mop vault trust") == false)
        #expect(!model.authenticated)
    }
}

extension AppModelTests {
}


extension AppModelTests {
    @Test func unavailableSecondaryVaultDoesNotCloseSelectedVault() async throws {
        let first = UUID().uuidString, second = UUID().uuidString, unconnected = UUID().uuidString
        let attempts = Mutex<[String]>([])
        let service = FakeService { _, id, _ in
            attempts.withLock { $0.append(id!) }
            if id == second { throw MopError.cloudUnavailable }
            var result = VaultResult(); result.catalog = Self.catalog; return result
        }
        service.authenticate()
        let model = model(service)
        model.vault = first
        model.vaults = [first, second, unconnected].map {
            VaultDescriptor(id: $0, name: $0, format: "mop-items-v2", enrolled: $0 != unconnected)
        }
        model.unlock(); try await finish(model)
        #expect(attempts.withLock { $0 } == [first, second])
        #expect(model.authenticated && service.isAuthenticated)
        #expect(model.catalogs[first] != nil && model.catalogs[second] == nil)
        #expect(model.notice?.contains("could not be loaded") == true)
        #expect(model.vaultIcon(try #require(model.vaults.first { $0.id == unconnected })) == "externaldrive.badge.plus")
        #expect(model.vaultIcon(try #require(model.vaults.first { $0.id == first })) == "lock.open")
        #expect(model.vaultIcon(try #require(model.vaults.first { $0.id == second })) == "lock.rectangle")
    }

    @Test func backgroundReturnReusesSessionUntilInactivityExpires() async throws {
        let id = UUID().uuidString, clock = Clock()
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            if case .discover = operation {
                result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-items-v2", enrolled: true)]
            } else { result.catalog = Self.catalog }
            return result
        }
        service.authenticate()
        let model = model(service, clock: clock); model.vault = ""
        model.start(); try await finish(model)
        clock.time = 290; model.activity()
        model.background(); clock.time = 500; model.activate()
        #expect(model.authenticated && service.isAuthenticated)
        #expect(service.state.withLock { $0.operations.count } == 2)
        model.background(); clock.time = 801; model.checkExpiration()
        #expect(!model.authenticated && model.catalogs.isEmpty)
        service.authenticate(at: clock.time)
        model.activate()
        try await Task.sleep(for: .milliseconds(20)); try await finish(model)
        #expect(!model.authenticated)
        #expect(service.state.withLock { $0.operations.count } == 2)
        model.unlock(); try await finish(model)
        #expect(model.authenticated)
        #expect(service.state.withLock { $0.operations.count } == 3)
        model.shutdown()
    }

    @Test func cancelledAutomaticAuthenticationRequiresExplicitUnlock() async throws {
        let id = UUID().uuidString
        let service = FakeService { operation, _, _ in
            if case .discover = operation {
                var result = VaultResult()
                result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-items-v2", enrolled: true)]
                return result
            }
            throw MopError.authentication
        }
        let model = model(service); model.vault = ""
        model.start(); try await finish(model)
        model.error = nil
        model.deactivate(); model.activate(); model.checkExpiration()
        try await Task.sleep(for: .milliseconds(20))
        #expect(service.state.withLock { $0.operations.count } == 2)
        model.activity()
        try await Task.sleep(for: .milliseconds(20)); try await finish(model)
        #expect(service.state.withLock { $0.operations.count } == 2)
        model.unlock(); try await finish(model)
        #expect(service.state.withLock { $0.operations.count } == 3)
        model.shutdown()
    }
}

extension AppModelTests {
    @Test func trustFailureDoesNotLoopOnTapsOrFaceIDLifecycle() async throws {
        let id = UUID().uuidString
        let service = FakeService { operation, _, _ in
            if case .discover = operation {
                var result = VaultResult()
                result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-items-v2", enrolled: true)]
                return result
            }
            throw MopError.vaultUntrusted
        }
        let model = model(service); model.vault = ""
        model.start(); try await finish(model)
        #expect(model.error != nil)
        model.error = nil
        for _ in 0..<3 {
            model.activity(); model.deactivate(); model.activate()
            model.background(); model.activate(); model.checkExpiration()
            try await Task.sleep(for: .milliseconds(20))
        }
        #expect(service.state.withLock { $0.operations.count } == 2)
        #expect(!model.authenticated && model.catalogs.isEmpty)
        // Refresh only discovers; retrying authentication requires Unlock.
        model.discover(); try await finish(model)
        try await Task.sleep(for: .milliseconds(20)); try await finish(model)
        #expect(service.state.withLock { $0.operations.count } == 3)
        model.unlock(); try await finish(model)
        #expect(service.state.withLock { $0.operations.count } == 4)
        model.shutdown()
    }
}


extension AppModelTests {
    @Test func serviceInvalidationDuringOpeningPreservesTrustFailure() async throws {
        let barrier = Barrier()
        let service = FakeService { _, _, _ in
            await barrier.wait()
            throw MopError.vaultUntrusted
        }
        let model = model(service)
        model.unlock(); try await entered(barrier)
        service.authenticate(); model.checkExpiration()
        service.lock(); model.checkExpiration()
        await barrier.release(); try await finish(model)
        #expect(model.error?.contains("This device could not verify its saved vault connection") == true)
        #expect(!model.authenticated && model.catalogs.isEmpty)
    }
}

extension AppModelTests {
    @Test func itemBackendCapabilitiesPreventUnsupportedManagementSheets() {
        let service = FakeService()
        service.state.withLock { $0.capabilities = [.portableBackup] }
        let app = model(service)
        app.presentSheet(.addDevice)
        #expect(app.sheet == nil && app.error != nil)
        app.error = nil
        app.presentSheet(.enrollDevice)
        #expect(app.sheet == nil && app.error != nil)
        #expect(service.state.withLock { $0.operations.isEmpty })
    }
    @Test func newlyConnectedVaultShowsDownloadingUntilItemsArrive() async throws {
        let id = UUID().uuidString
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            if case .discover = operation {
                result.vaults = [.init(id: id, name: "personal", format: "mop-items-v2", enrolled: true)]
            }
            return result
        }
        var pending = VaultResult()
        pending.catalog = ItemCatalog(vault: "personal", revision: "metadata-only", items: [])
        pending.catalogLoadedCount = 0; pending.catalogTotalCount = 1; pending.catalogDownloading = true
        service.state.withLock { $0.displayResult = pending }
        service.authenticate()
        let app = model(service); app.vault = id; app.start()
        try await finish(app)
        #expect(app.authenticated && app.displayedItems.isEmpty)
        #expect(app.catalogTransferStatus?.contains("Connected to iCloud") == true)
        #expect(app.catalogTransferStatus?.contains("Downloading") == true)
        #expect(app.catalogTransferFraction == 0)
        #expect(app.showsCloudProgress)
        app.refreshing = true
        #expect(app.showsCloudProgress)
        app.refreshing = false
        #expect(app.showsCloudProgress)
        var complete = VaultResult()
        complete.catalog = ItemCatalog(vault: "personal", revision: "downloaded", items: [VaultItem(name: "first", type: .login, fields: [])])
        service.state.withLock { $0.displayResult = complete }
        service.notifyChange()
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while app.catalog?.revision != "downloaded", ContinuousClock.now < deadline { await Task.yield() }
        #expect(app.catalog?.items.count == 1)
        #expect(app.catalogTransferStatus == nil)
        #expect(app.catalogTransferFraction == nil)
        #expect(!app.showsCloudProgress)
    }

    @Test func progressiveOpeningShowsUsablePartialCatalogAndUpdatesFromNotifications() async throws {
        let id = UUID().uuidString
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            if case .discover = operation {
                result.vaults = [.init(id: id, name: "personal", format: "mop-items-v2", enrolled: true)]
            } else if case .catalog = operation { Issue.record("Progressive UI opening must not request a full catalog") }
            return result
        }
        var partial = VaultResult()
        var first = VaultItem(name: "first", type: .login, fields: [ItemField(path: "password", type: .password)])
        first.storageID = UUID().uuidString
        first.fields[0].recordVersion = "stable-record"
        partial.catalog = ItemCatalog(vault: "personal", revision: "partial", items: [first])
        partial.catalogLoadedCount = 1; partial.catalogTotalCount = 2
        service.state.withLock { $0.displayResult = partial }
        service.authenticate()
        let app = model(service); app.vault = id; app.start()
        try await finish(app)
        #expect(app.authenticated && !app.busy && app.catalog?.items.count == 1)
        #expect(app.isUpdatingCatalog && app.catalogTransferStatus == nil)
        app.selectedItem = "first"
        app.selected = try SecretReference("sp://personal/first/password")
        app.revealed = SecretBytes(utf8: "selected-secret")
        #expect(service.state.withLock { $0.displayCalls } > 0)
        var complete = partial
        complete.catalogLoadedCount = nil; complete.catalogTotalCount = nil
        complete.catalog = ItemCatalog(vault: "personal", revision: "complete", items: [first, VaultItem(name: "second", type: .login, fields: [])])
        service.state.withLock { $0.displayResult = complete }
        service.notifyChange()
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while app.catalog?.revision != "complete", ContinuousClock.now < deadline { await Task.yield() }
        #expect(app.catalog?.items.count == 2 && app.authenticated)
        #expect(!app.isUpdatingCatalog && app.catalogTransferStatus == nil)
        #expect(app.selectedItem == "first" && app.revealed == SecretBytes(utf8: "selected-secret"))
    }

    @Test func cloudNotificationRefreshesCatalogAndPreservesVaultSelection() async throws {
        let id = UUID().uuidString
        let revision = Mutex("before")
        let service = FakeService { operation, _, offline in
            #expect(!offline)
            var result = VaultResult()
            switch operation {
            case .discover:
                result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-items-v2", enrolled: true)]
            case .catalog:
                result.catalog = ItemCatalog(vault: "personal", revision: revision.withLock { $0 }, items: [])
            default: break
            }
            return result
        }
        service.authenticate()
        let model = model(service); model.vault = id; model.start()
        try await finish(model)
        model.allVaults = false
        #expect(model.catalog?.revision == "before")
        #expect(service.observerCount == 1)
        #expect(model.isActive && model.sheet == nil && model.authenticated)
        revision.withLock { $0 = "after" }
        service.notifyChange()
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while model.catalog?.revision != "after", ContinuousClock.now < deadline { await Task.yield() }
        try await finish(model)
        #expect(model.catalog?.revision == "after")
        #expect(model.vault == id && !model.allVaults)
        #expect(service.state.withLock { $0.locks } == 0)
    }

    @Test func notificationsCoalesceWhileEditingAndRefreshAfterEditing() async throws {
        let id = UUID().uuidString
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            if case .discover = operation {
                result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-items-v2", enrolled: true)]
            } else if case .catalog = operation { result.catalog = Self.catalog }
            return result
        }
        service.authenticate()
        let model = model(service); model.vault = id; model.start()
        try await finish(model)
        model.selectedItem = "github"; model.beginItemEditing()
        #expect(model.itemDraft != nil)
        let draft = model.itemDraft?.id
        let count = service.state.withLock { $0.operations.count }
        service.notifyChange(); service.notifyChange()
        for _ in 0..<10 { await Task.yield() }
        #expect(!model.busy && model.itemDraft?.id == draft)
        #expect(service.state.withLock { $0.operations.count } == count)
        model.cancelItemEditing(); model.refreshCloudIfNeeded()
        try await finish(model)
        #expect(service.state.withLock { $0.operations.count } == count + 2)
    }
    @Test func backgroundRefreshLeavesReadsAvailableAndUpdatesSelectedItem() async throws {
        let id = UUID().uuidString, barrier = Barrier(), refresh = Mutex(false)
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            switch operation {
            case .discover:
                result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-items-v2", enrolled: true)]
            case .catalog:
                if refresh.withLock({ $0 }) { await barrier.wait() }
                result.catalog = ItemCatalog(vault: "personal", revision: refresh.withLock { $0 } ? "new" : "old", items: Self.catalog.items)
            case .read: result.value = SecretBytes(utf8: "available")
            default: break
            }
            return result
        }
        service.authenticate()
        let model = model(service); model.vault = id; model.start(); try await finish(model)
        model.selectedItem = "github"
        refresh.withLock { $0 = true }; model.cloudChanged(); try await entered(barrier)
        #expect(model.refreshing && !model.busy)
        #expect(model.catalog?.revision == "old")
        let result = try await service.execute(.read(SecretReference("sp://personal/github/password")), vault: id, offline: false)
        #expect(result.value == "available")
        await barrier.release(); try await finish(model)
        #expect(model.catalog?.revision == "new" && model.selectedItem == "github")
    }

    @Test func draftStartedDuringRefreshIsPreserved() async throws {
        let id = UUID().uuidString, barrier = Barrier(), refresh = Mutex(false)
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            if case .discover = operation {
                result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-items-v2", enrolled: true)]
            } else if case .catalog = operation {
                if refresh.withLock({ $0 }) { await barrier.wait() }
                result.catalog = Self.catalog
            }
            return result
        }
        service.authenticate()
        let model = model(service); model.vault = id; model.start(); try await finish(model)
        model.selectedItem = "github"
        refresh.withLock { $0 = true }; model.cloudChanged(); try await entered(barrier)
        model.beginItemEditing(); let draft = model.itemDraft?.id
        #expect(draft != nil)
        await barrier.release(); try await finish(model)
        #expect(model.itemDraft?.id == draft)
    }

}

extension AppModelTests {
    private func editingModel(_ service: FakeService, clock: Clock = Clock()) throws -> AppModel {
        service.authenticate(at: clock.time)
        let app = model(service, clock: clock)
        app.authenticated = true
        let item = VaultItem(name: "original", type: .custom, fields: [ItemField(path: "value", type: .text, value: "before")])
        try app.applyCatalog(ItemCatalog(vault: "personal", revision: "r1", items: [item]))
        app.selectedItem = item.name
        app.beginItemEditing()
        app.itemDraft?.fields[0].value = "after"
        return app
    }

    @Test func manualLockAndTimeoutNeverUnlockFromActivityOrWake() async throws {
        let clock = Clock(), service = FakeService { operation, _, _ in
            var result = VaultResult()
            if case .catalog = operation { result.catalog = Self.catalog }
            return result
        }
        let app = try editingModel(service, clock: clock)
        app.lock()
        for _ in 0..<3 { app.activity(); app.deactivate(); app.activate(); app.checkExpiration() }
        try await Task.sleep(for: .milliseconds(20))
        #expect(!app.authenticated && app.itemDraft == nil)
        #expect(service.state.withLock { $0.operations.isEmpty })
        service.authenticate(at: clock.time)
        app.unlock(); try await finish(app)
        #expect(app.authenticated)
        clock.time = 301; app.checkExpiration()
        app.activity(); app.activate()
        try await Task.sleep(for: .milliseconds(20))
        #expect(app.sessionState == .locked(.timeout))
        #expect(service.state.withLock { $0.operations.count } == 1)
    }

    @Test func navigationWaitsForDiscardOrCancel() throws {
        let app = try editingModel(FakeService())
        app.chooseAllVaults()
        #expect(app.showsUnsavedChanges && !app.allVaults)
        #expect(app.itemDraft?.fields[0].value == "after")
        app.cancelPendingTransition()
        #expect(!app.showsUnsavedChanges && app.selectedItem == "original")
        app.chooseRecentlyDeleted()
        #expect(app.page == .secrets)
        app.discardAndContinue()
        #expect(app.page == .recentlyDeleted && app.itemDraft == nil)
    }

    @Test func saveCompletesNavigationOnlyAfterPersistence() async throws {
        let barrier = Barrier()
        let service = FakeService { operation, _, _ in
            guard case .save(let edit) = operation else { return VaultResult() }
            await barrier.wait()
            var result = VaultResult()
            result.catalog = ItemCatalog(vault: "personal", revision: "r2", items: [edit.item])
            return result
        }
        let app = try editingModel(service)
        app.chooseRecentlyDeleted(); app.saveAndContinue()
        try await entered(barrier)
        #expect(app.page == .secrets && app.itemDraft != nil)
        await barrier.release(); try await finish(app)
        #expect(app.page == .recentlyDeleted && app.itemDraft == nil)
        #expect(app.pendingTransition == nil)
    }

    @Test(arguments: [MopError.cloudUnavailable, .vaultConflict])
    func failedSavePreservesDraftAndCancelsNavigation(_ failure: MopError) async throws {
        let service = FakeService { _, _, _ in throw failure }
        let app = try editingModel(service)
        var completed: Bool?
        app.requestTransition(.quit) { completed = $0 }
        app.saveAndContinue(); try await finish(app)
        #expect(completed == false && app.pendingTransition == nil)
        #expect(app.selectedItem == "original" && app.itemDraft?.fields[0].value == "after")
        #expect(app.draftConflict == (failure == .vaultConflict))
    }

    @Test func lockWhileSavingCancelsQuitAndRejectsLateResult() async throws {
        let barrier = Barrier()
        let service = FakeService { operation, _, _ in
            await barrier.wait()
            var result = VaultResult()
            if case .save(let edit) = operation { result.catalog = ItemCatalog(vault: "personal", revision: "r2", items: [edit.item]) }
            return result
        }
        let app = try editingModel(service)
        var completed: Bool?
        app.requestTransition(.quit) { completed = $0 }
        app.saveAndContinue(); try await entered(barrier)
        app.lock(reason: .system)
        await barrier.release(); try await finish(app)
        #expect(completed == false && app.pendingTransition == nil)
        #expect(app.itemDraft == nil && app.catalog == nil && !app.authenticated)
    }

    @Test func appSwitchAndMobileBackgroundKeepDraftUntilTimeout() throws {
        let clock = Clock(), app = try editingModel(FakeService(), clock: clock)
        let id = app.itemDraft?.id
        app.deactivate(); app.activate(); app.background()
        #expect(app.itemDraft?.id == id && app.itemDraft?.fields[0].value == "after")
        clock.time = 301; app.checkExpiration()
        #expect(app.itemDraft == nil && !app.authenticated)
    }

    @Test func offlineAndInvalidDraftsCanCancelOrDiscardButCannotSave() throws {
        let app = try editingModel(FakeService())
        app.offline = true
        app.chooseAllVaults(); app.saveAndContinue()
        #expect(app.itemDraft != nil && !app.busy && !app.allVaults)
        #expect(app.draftSaveUnavailableReason?.contains("iCloud") == true)
        app.cancelPendingTransition()
        app.offline = false; app.itemDraft?.name = ""
        app.chooseAllVaults(); app.saveAndContinue()
        #expect(app.itemDraft != nil && !app.busy)
        #expect(app.draftSaveUnavailableReason != nil)
        app.discardAndContinue()
        #expect(app.itemDraft == nil && app.allVaults)
    }

    @Test func cleanDraftDoesNotPromptAndSettingsDoNotAuthenticate() throws {
        let service = FakeService(), app = try editingModel(service)
        app.itemDraft?.fields[0].value = "before"
        app.chooseAllVaults()
        #expect(app.itemDraft == nil && app.pendingTransition == nil && app.allVaults)
        app.lock(); app.loadDevices()
        #expect(!app.busy && service.state.withLock { $0.operations.isEmpty })
    }

    @Test func closeAndQuitUseTheSameGuardAndCompleteOnlyOnDecision() throws {
        for intent in [PendingTransition.closeWindow, .quit] {
            let app = try editingModel(FakeService())
            var completed: Bool?
            app.requestTransition(intent) { completed = $0 }
            #expect(completed == nil && app.hasUnsavedChanges)
            app.cancelPendingTransition(); #expect(completed == false)
            app.requestTransition(intent) { completed = $0 }
            app.discardAndContinue(); #expect(completed == true && app.itemDraft == nil)
        }
    }
}

extension AppModelTests {
    @Test func everyDestructiveNavigationEntryPointPreservesDraftUntilDecision() throws {
        for route in ["item", "vault", "settings-vault", "sheet", "refresh", "trash"] {
            let service = FakeService(), app = try editingModel(service)
            let other = UUID().uuidString
            app.vaults.append(VaultDescriptor(id: other, name: "other", format: "mop-items-v2", enrolled: true))
            app.catalogs[other] = ItemCatalog(vault: "other", revision: "r1", items: [])
            let originalVault = app.vault
            switch route {
            case "item": app.selectedRow = .init(vault: other, name: "another")
            case "vault": app.chooseVault(other)
            case "settings-vault": #expect(!app.prepareVaultAction(other))
            case "sheet": app.presentSheet(.createVault)
            case "refresh": app.refresh()
            default:
                app.trashItem(ItemRow(id: .init(vault: originalVault, name: "original"), vaultName: "personal", item: app.selectedTypedItem!))
            }
            #expect(app.showsUnsavedChanges && app.pendingTransition != nil)
            #expect(app.vault == originalVault && app.selectedItem == "original")
            #expect(app.itemDraft?.fields[0].value == "after")
            #expect(!app.busy && service.state.withLock { $0.operations.isEmpty })
            app.cancelPendingTransition()
            #expect(app.hasUnsavedChanges)
        }
    }

    @Test func newItemSaveCompletesPendingClose() async throws {
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            if case .save(let edit) = operation {
                #expect(edit.create)
                result.catalog = ItemCatalog(vault: "personal", revision: "r2", items: [edit.item])
            }
            return result
        }
        let app = try editingModel(service)
        app.cancelItemEditing(); app.beginCreatingItem()
        app.itemDraft?.name = "New login"
        app.itemDraft?.fields[1].value = "generated-value"
        var closed = false
        app.requestTransition(.closeWindow) { closed = $0 }
        app.saveAndContinue(); try await finish(app)
        #expect(closed && app.itemDraft == nil && app.selectedItem == "New login")
    }

    @Test func recoverablePasswordReadFailureKeepsEditor() async throws {
        let service = FakeService { _, _, _ in throw MopError.cloudUnavailable }
        service.authenticate()
        let app = model(service)
        var catalog = Self.catalog; catalog.items[0].fields[1].type = .password
        try app.applyCatalog(catalog); app.authenticated = true; app.selectedItem = "github"
        app.beginItemEditing(); try await finish(app)
        #expect(app.itemDraft != nil && app.itemDraft?.isModified == false)
        #expect(app.itemDraft?.fields[1].value == nil)
    }
}

extension AppModelTests {
}

extension AppModelTests {
}


extension AppModelTests {
    @Test func filteringPreservesHiddenSelectionAndDraft() throws {
        let app = try editingModel(FakeService())
        let selection = app.selectedRow
        app.search = "no matching item"
        #expect(app.displayedItems.isEmpty)
        app.listSelection = nil
        #expect(app.selectedRow == selection && app.hasUnsavedChanges)
        #expect(app.pendingTransition == nil)
        app.search = ""
        #expect(app.listSelection == selection)
    }
    @Test func recoveryTestResetClearsVaultsAndRoutesToRecovery() throws {
        let service = FakeService(), app = try editingModel(service)
        app.sheetRequest = SheetRequest(kind: .setupRecovery, inSettings: true, target: nil)
        app.showRecoveryTestReset()
        #expect(app.deviceRemoved)
        #expect(app.vaults.isEmpty)
        #expect(app.sheetRequest?.kind == .recover && app.sheetRequest?.inSettings == true)
    }
    @Test func settingsCategoriesDoNotChangeVaultOrDraft() throws {
        let service = FakeService(), app = try editingModel(service)
        let selected = app.selectedRow
        for category in SettingsCategory.allCases { app.showSettingsCategory(category) }
        #expect(app.selectedRow == selected && app.hasUnsavedChanges)
        #expect(service.state.withLock { $0.operations.isEmpty })
    }
    @Test func detailsUsesDraftGuardAndReturnsToSelectedItem() throws {
        let app = try editingModel(FakeService())
        let target = try #require(app.selectedVaultDescriptor), selection = app.selectedRow
        app.openVaultDetails(target)
        #expect(app.vaultDetailsTarget == nil && app.showsUnsavedChanges)
        app.cancelPendingTransition()
        #expect(app.hasUnsavedChanges)
        app.openVaultDetails(target); app.discardAndContinue()
        #expect(app.vaultDetailsTarget?.id == target.id && app.selectedRow == selection)
        app.openVaultDetails(nil)
        #expect(app.vaultDetailsTarget == nil && app.selectedRow == selection)
    }
    @Test func sheetTargetIsCapturedBeforeDraftDecision() throws {
        let app = try editingModel(FakeService())
        let target = try #require(app.selectedVaultDescriptor)
        app.presentSheet(.renameVault, target: target)
        app.vaultDetailsTarget = VaultDescriptor(id: UUID().uuidString, name: "other", format: "mop-items-v2", enrolled: true)
        app.discardAndContinue()
        #expect(app.sheetRequest?.target?.id == target.id)
    }
    @Test func backupPickerRetainsTargetAcrossNavigationAndExpiresOnLock() async throws {
        let targetID = UUID().uuidString
        let service = FakeService { operation, vault, _ in
            guard case .export(let url) = operation else { Issue.record("Expected export"); return VaultResult() }
            #expect(vault == targetID)
            #expect(url.lastPathComponent.hasPrefix("sp-personal-"))
            return VaultResult()
        }
        let app = model(service)
        let target = VaultDescriptor(id: targetID, name: "personal", format: "mop-items-v2", enrolled: true)
        app.vaults.append(target)
        app.chooseExportBackup(target: target)
        let request = try #require(app.documentRequest)
        app.completeBackupSelection(folder: URL(fileURLWithPath: "/tmp"), request: request)
        try await finish(app)
        #expect(app.lastBackupURL != nil)
        app.lock()
        app.completeBackupSelection(folder: URL(fileURLWithPath: "/tmp"), request: request)
        #expect(!app.busy && service.state.withLock { $0.operations.count } == 1)
    }
}


extension AppModelTests {
    @Test func renamingAnotherVaultDoesNotRetargetOpenItem() async throws {
        let targetID = UUID().uuidString
        let service = FakeService { operation, vault, _ in
            guard case .rename(let name) = operation else { Issue.record("Expected rename"); return VaultResult() }
            #expect(vault == targetID && name == "renamed")
            var result = VaultResult(); result.catalog = ItemCatalog(vault: name, revision: "r2", items: [])
            return result
        }
        service.authenticate()
        let app = model(service); app.authenticated = true
        try app.applyCatalog(Self.catalog)
        app.selectedRow = .init(vault: app.vault, name: "github")
        let selected = app.selectedRow
        let target = VaultDescriptor(id: targetID, name: "other", format: "mop-items-v2", enrolled: true)
        app.vaults.append(target); app.openVaultDetails(target)
        app.renameVault(to: "renamed", target: target); try await finish(app)
        #expect(app.selectedRow == selected && app.vaultName == "personal")
        #expect(app.vaultDetailsTarget?.name == "renamed" && app.catalogs[targetID]?.vault == "renamed")
    }
    @Test func creatingFromDetailsShowsEditor() throws {
        let app = model(FakeService()); app.authenticated = true
        try app.applyCatalog(Self.catalog)
        app.openVaultDetails(app.selectedVaultDescriptor)
        app.beginCreatingItem()
        #expect(app.itemDraft?.isNew == true && app.vaultDetailsTarget == nil)
    }
    @Test func deletedFilteringPreservesSelectionAndExcludesSecrets() throws {
        let app = model(FakeService())
        var item = VaultItem(name: "deleted-key", fields: [ItemField(path: "password", type: .password, value: "sensitive"), ItemField(path: "username", type: .username, value: "visible")])
        item.deletion = ItemDeletion(originalName: "original", deletedAt: Date())
        app.deletedCatalogs[app.vault] = ItemCatalog(vault: "personal", revision: "r1", items: [item])
        app.page = .recentlyDeleted; app.selectedDeleted = .init(vault: app.vault, name: item.name)
        for query in ["sensitive", "password"] {
            app.search = query; app.deletedListSelection = nil
            #expect(app.deletedRows.isEmpty && app.selectedDeletedItem?.item.name == item.name)
        }
        app.search = "visible"
        #expect(app.deletedRows.count == 1)
    }
}


extension AppModelTests {
    @Test func openingSettingsDoesNotMoveAnExistingTaskSheet() throws {
        let app = model(FakeService())
        app.presentSheet(.renameVault)
        let requestID = app.sheetRequest?.id
        app.settingsVisible = true
        #expect(app.sheetRequest?.inSettings == false && app.sheetRequest?.id == requestID)
        app.sheet = nil
        app.presentSheet(.addDevice, inSettings: true)
        app.settingsVisible = false
        #expect(app.sheetRequest?.inSettings == true)
    }
}

@Test @MainActor func importDestinationAndMetadataFilters() {
    let defaults = UserDefaults(suiteName: "mop-import-ui-" + UUID().uuidString)!
    let model = AppModel(breachClient: TestBreachClient(), service: FakeService(), defaults: defaults, automaticTimer: false)
    model.authenticated = true; model.vault = "v"
    model.vaults = [VaultDescriptor(id: "v", name: "personal", format: "mop-items-v2", enrolled: true)]
    var active = VaultItem(name: "Active", type: .password, fields: [ItemField(path: "password", type: .password)])
    active.metadata = ItemMetadata(tags: ["work"], favorite: true)
    var archived = active; archived.name = "Archived"; archived.metadata?.archived = true
    var catalog = ItemCatalog(vault: "personal", revision: "r", items: [active, archived]); catalog.canEdit = true
    model.catalog = catalog; model.catalogs["v"] = catalog
    #expect(model.displayedItems.map { $0.item.name } == ["Active"])
    model.showArchived = true
    #expect(model.displayedItems.map { $0.item.name } == ["Archived"])
    model.search = "missing"
    #expect(model.displayedItems.isEmpty)
    model.beginImport(); #expect(model.sheet == .importItems)
    catalog.canEdit = false; model.catalogs["v"] = catalog
    #expect(model.itemCreationVaults.isEmpty)
}

extension AppModelTests {
    @Test(arguments: [false, true]) func pendingAttachmentExportIsDiscardedOnSecurityTransition(lock: Bool) async throws {
        let barrier = Barrier()
        let encoded = try Attachment(fileName: "proof.bin", data: Data([0, 255])).encodedValue()
        let service = FakeService { _, _, _ in
            await barrier.wait()
            var result = VaultResult(); result.value = SecretBytes(utf8: encoded); return result
        }
        service.authenticate()
        let app = model(service)
        let reference = try SecretReference("sp://personal/github/token")
        var delivered = false
        app.loadAttachment(reference) { _ in delivered = true }
        try await entered(barrier)
        if lock { app.lock() } else { app.deactivate(); app.activate() }
        await barrier.release(); try await finish(app)
        #expect(!delivered)
    }
}

@Test @MainActor func importDismissesSheetAndReportsCompletionOutsideIt() async throws {
    let gate = Barrier()
    let document = ImportDocument(format: .auto, records: [ImportRecord(id: 0, item: VaultItem(name: "example", fields: [.init(path: "password", type: .password, value: "synthetic")]))])
    let previewReport = try ImportPlanner.prepare(document, existing: []).report
    var completed = previewReport; completed.imported = 1; completed.committed = true
    let completedReport = completed
    let service = FakeService { operation, _, _ in
        guard case .commitImport = operation else { return VaultResult() }
        await gate.wait()
        var result = VaultResult(); result.importReport = completedReport
        result.catalog = ItemCatalog(vault: "personal", revision: "new", items: [])
        return result
    }
    service.authenticate()
    let defaults = UserDefaults(suiteName: "import-completion-" + UUID().uuidString)!
    let model = AppModel(breachClient: TestBreachClient(), service: service, defaults: defaults, now: { 0 }, automaticTimer: false)
    model.authenticated = true; model.vault = UUID().uuidString
    model.presentSheet(.importItems)
    model.commitImport(document, preview: ImportPreview(vault: UUID(), revision: "old", report: previewReport), selected: [0], destination: model.vault)
    #expect(model.sheet == nil)
    while !(await gate.entered) { await Task.yield() }
    #expect(model.importing)
    #expect(model.importStatus == "Preparing import…")
    service.state.withLock { $0.progress = "Encrypting items: 1 of 2"; $0.fraction = 0.5 }
    model.refreshImportProgress()
    #expect(model.importFraction == 0.5)
    #expect(model.importStatus == "Encrypting items: 1 of 2")
    await gate.release()
    for _ in 0..<2000 where model.busy { try await Task.sleep(for: .milliseconds(1)) }
    #expect(!model.busy && !model.importing)
    #expect(model.importReport?.imported == 1)
    #expect(model.importStatus?.contains("Import complete") == true)
    #expect(model.catalog?.revision == "new")
    #expect(model.error == nil)
}

@Test @MainActor func uncertainImportRetainsStatusWithoutClaimingSuccess() async throws {
    let service = FakeService { _, _, _ in throw MopError.cloudUncertain }
    service.authenticate()
    let model = AppModel(breachClient: TestBreachClient(), service: service, defaults: UserDefaults(suiteName: "import-error-" + UUID().uuidString)!, now: { 0 }, automaticTimer: false)
    model.authenticated = true
    let document = ImportDocument(format: .auto, records: [])
    let report = try ImportPlanner.prepare(document, existing: []).report
    model.commitImport(document, preview: ImportPreview(vault: UUID(), revision: "old", report: report), selected: [], destination: "personal")
    for _ in 0..<2000 where model.busy { try await Task.sleep(for: .milliseconds(1)) }
    #expect(!model.busy && !model.importing)
    #expect(model.importFailed)
    #expect(model.importReport == nil)
    #expect(model.importStatus?.contains("confirmation is pending") == true)
}


extension AppModelTests {
    @Test func searchHighlightDoesNotBecomeNavigationSelection() throws {
        let service = FakeService(); service.authenticate()
        let app = model(service); app.authenticated = true
        try app.applyCatalog(Self.catalog)
        app.search = "github"; app.searchIsFocused = true
        let row = try #require(app.displayedItems.first)
        app.searchHighlighted = row.id
        #expect(app.listSelection == nil && app.selectedRow == nil)
        #expect(app.deletedListSelection == nil && app.selectedDeleted == nil)
        app.search = "no matching result"
        app.searchHighlighted = nil
        #expect(app.listSelection == nil && app.selectedRow == nil)
        app.search = "github"
        app.selectedRow = row.id // Explicit open, as on Return or a row tap.
        #expect(app.listSelection == row.id)
    }

    @Test func allItemsSearchIncludesLocalCredentialsAndPreservesTheirBackend() throws {
        let service = FakeService(); service.authenticate()
        let app = model(service); app.authenticated = true
        try app.applyCatalog(Self.catalog)
        let cloudVault = app.vault
        let key = P256.Signing.PrivateKey()
        let ssh = try LocalIdentity(name: "deployment", algorithm: .p256Signing, protocolType: .ssh, publicKey: key.publicKey.x963Representation)
        let metadata = try PasskeyMetadata(relyingParty: "example.test", userName: "local-alice", userHandle: Data([1]), credentialID: Data(repeating: 1, count: 32))
        let passkey = try LocalIdentity(name: "internal-passkey", algorithm: .p256Signing, protocolType: .webauthn, publicKey: key.publicKey.x963Representation, metadata: .passkey(metadata))
        app.collection = .all
        _ = app.displayedItems // Build the index before the async local list arrives.
        app.localIdentities = [ssh, passkey]
        for query in ["example.test", "local-alice", "internal-passkey"] {
            app.search = query
            #expect(app.displayedItems.count == 1)
            #expect(app.displayedItems.first?.localIdentity?.id == passkey.id)
        }
        app.search = "deployment"
        let row = try #require(app.displayedItems.first)
        #expect(row.id.vault == LocalVault.id)
        #expect(row.item.fields.allSatisfy { !$0.type.concealed })
        app.selectedRow = row.id
        #expect(app.collection == .all && app.vault == cloudVault)
        #expect(app.selectedLocalIdentity?.id == ssh.id && app.selectedItem == nil)
        #expect(app.listSelection == row.id && app.itemDraft == nil)
        app.localIdentities = [passkey]
        #expect(app.displayedItems.isEmpty && app.selectedLocalIdentity == nil)
        app.search = "local-alice"
        app.collection = .vault(cloudVault)
        #expect(app.displayedItems.isEmpty)
        #expect(service.state.withLock { $0.operations.isEmpty })
    }

    @Test(arguments: [true, false])
    func invalidSSHSaveKeepsDraftAndDoesNotWrite(_ creating: Bool) async throws {
        let item = VaultItem(name: "server", type: .sshKey, fields: [ItemField(path: "privateKey", type: .privateKey, value: "invalid key")])
        var catalog = ItemCatalog(vault: "personal", revision: "r1", items: creating ? [] : [item])
        catalog.canEdit = true
        let source = catalog
        let service = FakeService { operation, _, _ in
            guard case .catalog = operation else { Issue.record("Invalid key must not reach a write"); throw MopError.invalidVault }
            var result = VaultResult(); result.catalog = source; return result
        }
        service.authenticate()
        let app = model(service); app.authenticated = true
        try app.applyCatalog(source)
        app.selectedItem = creating ? nil : item.name
        app.itemDraft = ItemDraft(vault: app.vault, revision: source.revision, item: item, isNew: creating)
        app.itemDraft?.fields[0].value = "changed invalid key"
        let id = app.itemDraft?.id
        app.saveItemDraft(); try await finish(app)
        #expect(app.error != nil)
        #expect(app.itemDraft?.id == id && app.itemDraft?.name == item.name)
        #expect(app.itemDraft?.fields.first?.value == "changed invalid key")
        #expect(!service.state.withLock { $0.operations.contains { if case .save = $0 { return true }; return false } })
    }

    @Test func favoritesSaveWithoutReadingConcealedFields() async throws {
        let service = FakeService { operation, _, _ in
            guard case .save(let edit) = operation else { throw MopError.invalidProcess }
            #expect(edit.item.isFavorite)
            #expect(edit.item.fields.first { $0.path == "password" }?.value == nil)
            var result = VaultResult()
            result.catalog = ItemCatalog(vault: "personal", revision: "r2", items: [edit.item])
            return result
        }
        service.authenticate()
        let app = model(service); app.authenticated = true
        let item = VaultItem(name: "Login", type: .login, fields: [ItemField(path: "password", type: .password)])
        try app.applyCatalog(ItemCatalog(vault: "personal", revision: "r1", items: [item]))
        app.selectedItem = item.name
        app.toggleFavorite()
        try await finish(app)
        #expect(app.selectedTypedItem?.isFavorite == true)
        #expect(app.itemDraft == nil && app.error == nil)
    }

    @Test func virtualCollectionsResetFiltersAndRespectUnsavedDrafts() throws {
        let service = FakeService(); service.authenticate()
        let app = model(service); app.authenticated = true
        try app.applyCatalog(Self.catalog)
        app.sidebarSelection = "favorites"
        #expect(app.favoritesOnly && !app.showArchived && app.allVaults)
        #expect(app.searchScope == "Favorites")
        app.sidebarSelection = "archive"
        #expect(!app.favoritesOnly && app.showArchived && app.sidebarSelection == "archive")
        app.sidebarSelection = "vault:" + app.vault
        #expect(!app.favoritesOnly && !app.showArchived)
        app.selectedItem = "github"; app.beginItemEditing()
        app.itemDraft?.name = "Changed"
        app.sidebarSelection = "archive"
        #expect(app.showsUnsavedChanges && !app.showArchived)
        app.discardAndContinue()
        #expect(app.showArchived && app.itemDraft == nil)
    }

    @Test(arguments: ["passkeys", "ssh-keys"])
    func credentialCollectionsDismissUnchangedEditors(_ selection: String) throws {
        let service = FakeService(); service.authenticate()
        let app = model(service); app.authenticated = true
        try app.applyCatalog(Self.catalog)
        app.selectedItem = "github"; app.beginItemEditing()
        #expect(app.itemDraft != nil && !app.hasUnsavedChanges)
        app.sidebarSelection = selection
        #expect(app.sidebarSelection == selection)
        #expect(app.itemDraft == nil && app.selectedRow == nil)
        #expect(!app.showsUnsavedChanges)
    }

    @Test(arguments: ["passkeys", "ssh-keys"])
    func credentialCollectionsClearSelectionAndRespectUnsavedDrafts(_ selection: String) throws {
        let service = FakeService(); service.authenticate()
        let app = model(service); app.authenticated = true
        try app.applyCatalog(Self.catalog)
        app.selectedItem = "github"; app.beginItemEditing()
        app.itemDraft?.name = "Changed"
        let previous = app.sidebarSelection
        app.sidebarSelection = selection
        #expect(app.showsUnsavedChanges && app.sidebarSelection == previous)
        app.discardAndContinue()
        #expect(app.sidebarSelection == selection && app.itemDraft == nil)
        #expect(app.selectedRow == nil && app.listSelection == nil)
        #expect(app.selectedDeleted == nil && !app.searchIsFocused)
        #expect(app.allVaults && app.authenticated)
        app.sidebarSelection = selection
        #expect(app.sidebarSelection == selection && app.selectedRow == nil)
    }

    @Test func developerErrorsIncludeUnderlyingFailureAndClearStaleDetails() async throws {
        let defaults = UserDefaults(suiteName: "mop-diagnostics-" + UUID().uuidString)!
        defaults.set(true, forKey: DeveloperPreferences.key)
        let app = AppModel(breachClient: TestBreachClient(), service: FakeService(), defaults: defaults, automaticTimer: false)
        app.perform(operation: "Test operation") { _ in
            throw NSError(domain: "ExampleFailure", code: 42, userInfo: [NSLocalizedDescriptionKey: "Useful diagnostic"])
        }
        try await finish(app)
        #expect(app.errorMessage.contains("ExampleFailure"))
        #expect(app.errorMessage.contains("42"))
        #expect(app.errorMessage.contains("Test operation"))
        #expect(app.errorMessage.contains("Useful diagnostic"))
        defaults.set(false, forKey: DeveloperPreferences.key)
        #expect(!app.errorMessage.contains("ExampleFailure"))
        app.error = nil
        #expect(app.errorDetails == nil)
    }
}


extension AppModelTests {
    @Test func searchMatchesPartialTagsAcrossCollections() throws {
        let app = model(FakeService())
        var item = VaultItem(name: "Login", fields: [ItemField(path: "password", type: .password, value: "hidden-secret")])
        item.metadata = ItemMetadata(tags: ["Shared Accounts"], favorite: true)
        try app.applyCatalog(ItemCatalog(vault: "personal", revision: "r1", items: [item]))
        app.search = "  ACCOUNTS  "
        #expect(app.displayedItems.count == 1)
        #expect(app.searchResults.first?.detail == "Tag: Shared Accounts")
        app.favoritesOnly = true
        #expect(app.displayedItems.count == 1)
        item.metadata?.archived = true
        try app.applyCatalog(ItemCatalog(vault: "personal", revision: "r2", items: [item]))
        app.showArchived = true
        #expect(app.displayedItems.count == 1)
        item.deletion = ItemDeletion(originalName: "Login", deletedAt: Date())
        app.deletedCatalogs[app.vault] = ItemCatalog(vault: "personal", revision: "r3", items: [item])
        #expect(app.deletedRows.count == 1)
        app.search = "hidden-secret"
        #expect(app.displayedItems.isEmpty && app.deletedRows.isEmpty)
    }
}

extension AppModelTests {
    @Test func searchCacheTracksCatalogEditsScopeAndLock() throws {
        let app = model(FakeService())
        var item = VaultItem(name: "Entry", fields: [ItemField(path: "username", type: .username, value: "first")])
        item.metadata = ItemMetadata(tags: ["team"], favorite: true)
        try app.applyCatalog(ItemCatalog(vault: "personal", revision: "r1", items: [item]))
        app.search = "first"
        #expect(app.displayedItems.first?.searchDetail == "username: first")
        app.catalog?.items[0].fields[0].value = "second"
        #expect(app.displayedItems.isEmpty)
        app.search = "second"
        #expect(app.displayedItems.count == 1)
        app.showArchived = true
        #expect(app.displayedItems.isEmpty)
        app.collection = .vault(app.vault)
        #expect(app.displayedItems.count == 1)
        app.allVaults = true
        #expect(app.displayedItems.isEmpty)
        app.catalogs[app.vault]?.items[0].fields[0].value = "second"
        #expect(app.displayedItems.count == 1)
        app.catalogs[app.vault]?.items[0].metadata?.favorite = false
        app.favoritesOnly = true
        #expect(app.displayedItems.isEmpty)
        app.favoritesOnly = false
        #expect(app.displayedItems.count == 1)
        app.lock()
        #expect(app.displayedItems.isEmpty && app.searchResults.isEmpty && app.deletedRows.isEmpty)
    }

    @Test func largeCatalogSearchTiming() throws {
        let app = model(FakeService())
        let items = (0..<5_000).map { index in
            var item = VaultItem(name: "Account \(index)", type: .login, fields: [
                ItemField(path: "username", type: .username, value: "person\(index)@example.test"),
                ItemField(path: "website", type: .website, value: "https://example.test/\(index)"),
                ItemField(path: "notes", type: .notes, value: "A sample account for search benchmarking."),
                ItemField(path: "password", type: .password, value: "never-search-this")
            ])
            item.metadata = ItemMetadata(tags: ["Shared Accounts"])
            return item
        }
        try app.applyCatalog(ItemCatalog(vault: "personal", revision: "r1", items: items))
        let clock = ContinuousClock()
        let indexing = clock.measure { _ = app.displayedItems }
        var firstQuery = Duration.zero
        var slowest = Duration.zero
        for query in ["s", "sh", "sha", "shar", "share", "shared", "shared ", "shared a", "shared ac", "shared acc"] {
            let elapsed = clock.measure {
                app.search = query
                #expect(app.displayedItems.count == 5_000)
                _ = app.searchResults
                _ = app.listSelection
                // Simulate rendering visible rows; each carries its own match text.
                for row in app.displayedItems.prefix(50) { #expect(row.searchDetail != nil) }
            }
            if query == "s" { firstQuery = elapsed }
            slowest = max(slowest, elapsed)
        }
        print("Search benchmark: 5,000 items, index \(indexing), first query \(firstQuery), slowest query + 50 row reads \(slowest)")
        app.search = "never-search-this"
        #expect(app.displayedItems.isEmpty)
    }
}

private actor RecentUsageMemory: ItemUsageStoring {
    var values: [ItemUsageIdentity: Date] = [:]
    func load(accounts: Set<String>) -> [ItemUsageIdentity: Date] { values.filter { accounts.contains($0.key.account) } }
    func record(_ identities: Set<ItemUsageIdentity>, at date: Date) { for id in identities { values[id] = max(values[id] ?? .distantPast, date) } }
    func prune(account: String, vault: String, keeping items: Set<String>, before date: Date) {}
}

extension AppModelTests {
    @Test func recentCollectionsLimitBeforeSearchAndExcludeUnknownArchivedDeleted() async throws {
        let service = FakeService(), store = RecentUsageMemory(), date = Date(timeIntervalSince1970: 1_700_000_000)
        let app = AppModel(breachClient: TestBreachClient(), service: service, defaults: UserDefaults(suiteName: UUID().uuidString)!, usageStore: store, now: { 0 }, automaticTimer: false, wallNow: { date })
        let account = UUID().uuidString, vault = UUID().uuidString
        app.vault = vault
        app.vaults = [VaultDescriptor(id: vault, name: "personal", format: "mop-items-v2", enrolled: true)]
        var items = (0..<60).map { n in
            var item = VaultItem(name: String(format: "Item %02d", n), type: .login, fields: [])
            item.storageID = UUID().uuidString
            item.metadata = ItemMetadata(addedAt: date.addingTimeInterval(Double(n)), updatedAt: date.addingTimeInterval(Double(60 - n)))
            return item
        }
        var unknown = VaultItem(name: "Unknown", type: .login, fields: [])
        unknown.storageID = UUID().uuidString
        var archived = items[59]; archived.name = "Archived"; archived.metadata?.archived = true
        var deleted = items[59]; deleted.name = "Deleted"; deleted.deletion = ItemDeletion(originalName: "Deleted", deletedAt: date)
        items += [unknown, archived, deleted]
        var catalog = ItemCatalog(vault: "personal", revision: "r", items: items); catalog.usageScope = account
        app.catalogs = [vault: catalog]; app.catalog = catalog
        service.authenticate(); app.authenticated = true
        app.chooseRecent(.recentlyAdded)
        #expect(app.displayedItems.count == 50)
        #expect(app.displayedItems.first?.item.name == "Item 59")
        app.search = "Item 00"
        #expect(app.displayedItems.isEmpty)
        app.search = ""
        app.chooseRecent(.recentlyChanged)
        #expect(app.displayedItems.count == 50)
        #expect(app.displayedItems.first?.item.name == "Item 00")
        app.chooseRecent(.recentlyUsed)
        #expect(app.displayedItems.isEmpty)
        let id = try #require(catalog.usageIdentity(for: items[20], vaultID: vault))
        app.recordUsage(id)
        #expect(app.displayedItems.map(\.item.name) == ["Item 20"])
        app.selectedRow = app.displayedItems.first?.id
        let selected = app.selectedRow
        app.recordUsage(try #require(catalog.usageIdentity(for: items[21], vaultID: vault)))
        #expect(app.selectedRow == selected)
        #expect(app.displayedItems.map(\.item.name) == ["Item 20", "Item 21"])
        app.lock()
        #expect(app.lastUsed.isEmpty)
        #expect(app.catalogs.isEmpty)
    }

    @Test func recentCollectionsUseVaultAndStableIDForDateTies() {
        let app = model(FakeService()), date = Date()
        var first = VaultItem(name: "Same", type: .login, fields: [])
        first.storageID = "b"; first.metadata = ItemMetadata(addedAt: date)
        var second = first; second.storageID = "a"
        app.catalogs = ["b": ItemCatalog(vault: "A", revision: "r", items: [first]),
                        "a": ItemCatalog(vault: "Z", revision: "r", items: [first, second])]
        app.collection = .recentlyAdded
        #expect(app.displayedItems.map(\.id.vault) == ["a", "a", "b"])
        #expect(app.displayedItems.map(\.item.storageID) == ["a", "b", "b"])
    }
}

extension AppModelTests {
    @Test func recentCollectionPreparationPerformance() {
        let app = model(FakeService()), date = Date(), clock = ContinuousClock()
        let items = (0..<5_000).map { n in
            var item = VaultItem(name: "Item \(n)", type: .login, fields: [ItemField(path: "username", type: .username, value: "user\(n)@example.test")])
            item.storageID = UUID().uuidString
            item.metadata = ItemMetadata(addedAt: date.addingTimeInterval(Double(n)), updatedAt: date.addingTimeInterval(Double(n)))
            return item
        }
        let load = clock.measure { app.catalogs = [app.vault: ItemCatalog(vault: "personal", revision: "r", items: items)] }
        app.collection = .recentlyAdded
        let prepare = clock.measure { #expect(app.displayedItems.count == 50) }
        let search = clock.measure { app.search = "user4999"; #expect(app.displayedItems.count == 1) }
        print("RECENT_PERFORMANCE 5000 items: catalog assignment \(load), recent preparation \(prepare), first search \(search)")
    }
}

extension AppModelTests {
    @Test func explicitAccessCountsButPreloadsOTPAndReferencesDoNot() async throws {
        let store = RecentUsageMemory(), date = Date()
        let id = ItemUsageIdentity(account: UUID().uuidString, vault: UUID().uuidString, item: UUID().uuidString)
        let service = FakeService { operation, _, offline in
            var result = VaultResult()
            if case .read = operation {
                #expect(offline)
                result.value = SecretBytes(utf8: "123456"); result.usageIdentity = id
                result.otpExpiresAt = date.addingTimeInterval(30); result.otpPeriod = 30
            }
            return result
        }
        let app = AppModel(breachClient: TestBreachClient(), service: service, defaults: UserDefaults(suiteName: UUID().uuidString)!, usageStore: store, now: { 0 }, automaticTimer: false, wallNow: { date })
        app.vault = id.vault
        var item = VaultItem(name: "Login", type: .login, fields: [ItemField(path: "password", type: .password)])
        item.storageID = id.item
        var catalog = ItemCatalog(vault: "personal", revision: "r", items: [item]); catalog.usageScope = id.account
        try app.applyCatalog(catalog)
        service.authenticate(); app.authenticated = true; app.selectedItem = item.name
        let ref = try SecretReference(vault: "personal", relativePath: "Login/password")
        app.selected = ref
        app.beginItemEditing(); try await finish(app)
        #expect(service.state.withLock { $0.exactReadIDs.last } == id.item)
        #expect(app.lastUsed.isEmpty)
        app.cancelItemEditing()
        app.selected = ref
        _ = try await app.currentOTP(ref)
        app.copyReference()
        #expect(app.lastUsed.isEmpty)
        app.read(copy: false)
        #expect(app.busy && !app.showsCloudProgress)
        try await finish(app)
        #expect(app.lastUsed[id] == date)
        app.read(copy: true)
        #expect(app.busy && !app.showsCloudProgress)
        try await finish(app)
        #expect(app.copyFeedback != nil)
        app.lock()
        #expect(app.lastUsed.isEmpty)
    }
}

private struct DelayedUsageStore: ItemUsageStoring {
    let barrier: Barrier
    let identity: ItemUsageIdentity
    func load(accounts: Set<String>) async throws -> [ItemUsageIdentity: Date] {
        await barrier.wait()
        return [identity: Date()]
    }
    func record(_ identities: Set<ItemUsageIdentity>, at date: Date) async throws {}
    func prune(account: String, vault: String, keeping items: Set<String>, before date: Date) async throws {}
}
extension AppModelTests {
    @Test func usageLoadingNeverBlocksUnlockStateOrRestoresDataAfterLock() async throws {
        let barrier = Barrier(), identity = ItemUsageIdentity(account: UUID().uuidString, vault: UUID().uuidString, item: UUID().uuidString)
        let app = AppModel(breachClient: TestBreachClient(), service: FakeService(), defaults: UserDefaults(suiteName: UUID().uuidString)!,
                           usageStore: DelayedUsageStore(barrier: barrier, identity: identity), now: { 0 }, automaticTimer: false)
        var catalog = ItemCatalog(vault: "personal", revision: "r", items: []); catalog.usageScope = identity.account
        app.catalogs = [identity.vault: catalog]
        app.authenticated = true
        #expect(app.authenticated && app.lastUsed.isEmpty)
        while !(await barrier.entered) { await Task.yield() }
        app.lock()
        await barrier.release()
        for _ in 0..<20 { await Task.yield() }
        #expect(!app.authenticated && app.lastUsed.isEmpty)
    }
}

extension AppModelTests {
    private func selectionModel(_ catalogs: [String: ItemCatalog], defaults: UserDefaults,
                                deleted: [String: ItemCatalog] = [:]) -> (AppModel, FakeService) {
        let service = FakeService { operation, id, _ in
            var result = VaultResult()
            if case .catalog = operation, let id { result.catalog = catalogs[id]; result.deletedCatalog = deleted[id] }
            return result
        }
        service.authenticate()
        let app = AppModel(breachClient: TestBreachClient(), service: service, defaults: defaults, usageStore: RecentUsageMemory(), now: { 0 }, automaticTimer: false)
        app.vaults = catalogs.map { VaultDescriptor(id: $0.key, name: $0.value.vault, format: "mop-items-v2", enrolled: true) }
        return (app, service)
    }

    @Test func selectionSurvivesLockRestartAndItemRenameUsingDeviceLocalIDs() async throws {
        let suite = "selection-test-" + UUID().uuidString, account = UUID().uuidString, vault = UUID().uuidString
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        var item = VaultItem(name: "Private Item Name", fields: [ItemField(path: "password")]); item.storageID = UUID().uuidString
        var catalog = ItemCatalog(vault: "personal", revision: "r", items: [item]); catalog.usageScope = account
        let (app, service) = selectionModel([vault: catalog], defaults: defaults)
        app.unlock(); try await finish(app)
        app.chooseVault(vault)
        app.selectedRow = .init(vault: vault, name: item.name)
        app.lock()
        #expect(app.selectedItem == nil && app.catalogs.isEmpty)
        let saved = try #require(defaults.data(forKey: "lastSelection." + account))
        #expect(!String(decoding: saved, as: UTF8.self).contains(item.name))
        service.authenticate(); app.unlock(); try await finish(app)
        #expect(app.collection == .vault(vault) && app.selectedItem == item.name)
        item.name = "Renamed Item"; catalog.items = [item]
        let (restarted, _) = selectionModel([vault: catalog], defaults: defaults)
        #expect(restarted.selectedItem == nil)
        restarted.unlock(); try await finish(restarted)
        #expect(restarted.selectedItem == item.name && restarted.vault == vault)
        let (otherDevice, _) = selectionModel([vault: catalog], defaults: UserDefaults(suiteName: UUID().uuidString)!)
        otherDevice.unlock(); try await finish(otherDevice)
        #expect(otherDevice.selectedItem == nil)
    }

    @Test func restoresVirtualCollectionsAndIgnoresMissingOrOtherAccountItems() async throws {
        let account = UUID().uuidString, vault = UUID().uuidString
        var item = VaultItem(name: "Entry", fields: []); item.storageID = UUID().uuidString
        item.metadata = ItemMetadata(favorite: true, addedAt: Date(), updatedAt: Date())
        var catalog = ItemCatalog(vault: "personal", revision: "r", items: [item]); catalog.usageScope = account
        for collection: ItemCollection in [.all, .favorites, .recentlyAdded, .recentlyChanged, .recentlyUsed, .archive, .recentlyDeleted] {
            let suite = UUID().uuidString, defaults = UserDefaults(suiteName: suite)!
            defer { defaults.removePersistentDomain(forName: suite) }
            var source = catalog
            source.items[0].metadata?.archived = collection == .archive
            var trash = item; trash.deletion = ItemDeletion(originalName: item.name, deletedAt: Date())
            let deleted = [vault: ItemCatalog(vault: "personal", revision: "r", items: [trash])]
            let (first, _) = selectionModel([vault: source], defaults: defaults, deleted: deleted)
            first.unlock(); try await finish(first)
            first.collection = collection
            if collection == .recentlyDeleted { first.selectedDeleted = .init(vault: vault, name: item.name) }
            else { first.selectedRow = .init(vault: vault, name: item.name) }
            first.lock()
            let (next, _) = selectionModel([vault: source], defaults: defaults, deleted: deleted)
            next.unlock(); try await finish(next)
            #expect(next.collection == collection)
            #expect(collection == .recentlyDeleted ? next.selectedDeleted?.name == item.name : next.selectedItem == item.name)
            var other = source; other.usageScope = UUID().uuidString
            let (isolated, _) = selectionModel([vault: other], defaults: defaults)
            isolated.unlock(); try await finish(isolated)
            #expect(isolated.selectedItem == nil && isolated.selectedDeleted == nil)
            source.items = []
            let (missing, _) = selectionModel([vault: source], defaults: defaults)
            missing.unlock(); try await finish(missing)
            #expect(missing.selectedItem == nil && missing.selectedDeleted == nil)
        }
    }
}

extension AppModelTests {
    @Test func rememberedVaultWinsDefaultButNotExplicitChoiceAndMissingVaultFallsBack() async throws {
        let suite = UUID().uuidString, defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let account = UUID().uuidString, firstID = UUID().uuidString, secondID = UUID().uuidString
        var item = VaultItem(name: "Entry", fields: []); item.storageID = UUID().uuidString
        var first = ItemCatalog(vault: "first", revision: "r", items: [item]); first.usageScope = account
        var second = ItemCatalog(vault: "second", revision: "r", items: []); second.usageScope = account
        let catalogs = [firstID: first, secondID: second]
        let (original, _) = selectionModel(catalogs, defaults: defaults)
        original.unlock(); try await finish(original)
        original.chooseVault(firstID); original.selectedRow = .init(vault: firstID, name: item.name)
        original.lock()
        let saved = try #require(defaults.data(forKey: "lastSelection." + account))
        let (restored, _) = selectionModel(catalogs, defaults: defaults)
        restored.vault = secondID
        restored.unlock(); try await finish(restored)
        #expect(restored.vault == firstID && restored.selectedItem == item.name)
        let (chosen, _) = selectionModel(catalogs, defaults: defaults)
        chosen.chooseVault(secondID); try await finish(chosen)
        #expect(chosen.vault == secondID && chosen.selectedItem == nil)
        defaults.set(saved, forKey: "lastSelection." + account)
        let (removed, _) = selectionModel([secondID: second], defaults: defaults)
        removed.unlock(); try await finish(removed)
        #expect(removed.vault == secondID && removed.selectedItem == nil && removed.collection == .all)
    }
}


extension AppModelTests {
    @Test func unlockRemovesDeletedVaultAndOpensRemainingVaults() async throws {
        let gone = UUID().uuidString, retained = UUID().uuidString
        let service = FakeService { operation, id, _ in
            var result = VaultResult()
            if case .discover = operation {
                result.vaults = [VaultDescriptor(id: retained, name: "personal", format: "mop-items-v2", enrolled: true)]
            } else if id == gone { throw MopError.vaultMissing }
            else { result.catalog = Self.catalog }
            return result
        }
        service.authenticate()
        let app = model(service)
        app.vault = gone
        app.vaults = [gone, retained].map { VaultDescriptor(id: $0, name: $0, format: "mop-items-v2", enrolled: true) }
        app.unlock(); try await finish(app)
        #expect(app.error == nil)
        #expect(app.authenticated)
        #expect(app.vault == retained)
        #expect(app.vaults.map(\.id) == [retained])
        #expect(app.catalogs[gone] == nil && app.catalogs[retained] != nil)
    }
    @Test func unlockAfterLastVaultDeletionOffersCreation() async throws {
        let service = FakeService { operation, _, _ in
            if case .discover = operation { return VaultResult() }
            throw MopError.vaultMissing
        }
        let app = model(service)
        app.unlock(); try await finish(app)
        #expect(app.error == nil)
        #expect(!app.authenticated && app.vaults.isEmpty && app.vault.isEmpty)
        #expect(app.sheet == .createVault)
    }
}


extension AppModelTests {
    @Test func selectedVaultUnlocksBeforeConcurrentBackgroundCatalogs() async throws {
        let first = UUID().uuidString, second = UUID().uuidString, third = UUID().uuidString
        let secondGate = Barrier(), thirdGate = Barrier()
        let calls = Mutex<[String]>([])
        let service = FakeService { _, id, _ in
            calls.withLock { $0.append(id!) }
            if id == second { await secondGate.wait() }
            if id == third { await thirdGate.wait() }
            var result = VaultResult(); result.catalog = Self.catalog; return result
        }
        service.authenticate()
        let app = model(service); app.vault = first
        app.vaults = [second, third, first].map { VaultDescriptor(id: $0, name: $0, format: "mop-items-v2", enrolled: true) }
        app.unlock()
        try await entered(secondGate); try await entered(thirdGate)
        #expect(calls.withLock { $0.first } == first)
        #expect(app.authenticated && !app.busy && app.loadingVaults)
        #expect(app.catalogs.count == 1 && app.catalogs[first] != nil)
        await secondGate.release(); await thirdGate.release()
        try await finish(app)
        #expect(app.catalogs.count == 3 && app.authenticated)
    }

    @Test func lockDiscardsLateBackgroundCatalogs() async throws {
        let first = UUID().uuidString, second = UUID().uuidString, barrier = Barrier()
        let service = FakeService { _, id, _ in
            if id == second { await barrier.wait() }
            var result = VaultResult(); result.catalog = Self.catalog; return result
        }
        service.authenticate()
        let app = model(service); app.vault = first
        app.vaults = [first, second].map { VaultDescriptor(id: $0, name: $0, format: "mop-items-v2", enrolled: true) }
        app.unlock(); try await entered(barrier)
        #expect(app.authenticated)
        app.lock(); await barrier.release()
        try await Task.sleep(for: .milliseconds(30))
        #expect(!app.authenticated && !app.loadingVaults && app.catalogs.isEmpty)
    }
}


extension AppModelTests {
    @Test func backgroundCatalogCannotOverwriteForegroundUpdate() async throws {
        let first = UUID().uuidString, second = UUID().uuidString, barrier = Barrier()
        let service = FakeService { _, id, _ in
            if id == second { await barrier.wait() }
            var result = VaultResult(); result.catalog = Self.catalog; return result
        }
        service.authenticate()
        let app = model(service); app.vault = first
        app.vaults = [first, second].map { VaultDescriptor(id: $0, name: $0, format: "mop-items-v2", enrolled: true) }
        app.unlock(); try await entered(barrier)
        app.perform { _ in
            app.catalogs[second] = ItemCatalog(vault: "updated", revision: "new", items: [])
        }
        while app.busy { try await Task.sleep(for: .milliseconds(1)) }
        await barrier.release(); try await finish(app)
        #expect(app.authenticated && app.catalogs[second]?.revision == "new")
    }

    @Test func backgroundDeletionRemovesReferenceWithoutClosingSelectedVault() async throws {
        let first = UUID().uuidString, deleted = UUID().uuidString
        let service = FakeService { operation, id, _ in
            var result = VaultResult()
            if case .discover = operation {
                result.vaults = [VaultDescriptor(id: first, name: "personal", format: "mop-items-v2", enrolled: true)]
            } else if id == deleted { throw MopError.vaultMissing }
            else { result.catalog = Self.catalog }
            return result
        }
        service.authenticate()
        let app = model(service); app.vault = first
        app.vaults = [first, deleted].map { VaultDescriptor(id: $0, name: $0, format: "mop-items-v2", enrolled: true) }
        app.unlock(); try await finish(app)
        #expect(app.authenticated && app.vault == first && app.error == nil)
        #expect(app.vaults.map(\.id) == [first])
    }
}


extension AppModelTests {
    @Test func cachedSelectedVaultOpensBeforeItsSyncAndBecomesWritableAfterward() async throws {
        let barrier = Barrier()
        let service = FakeService(cached: { _ in
            var result = VaultResult(); result.catalog = Self.catalog
            result.usingCache = true; result.offlineDate = Date(timeIntervalSince1970: 100)
            return result
        }) { _, _, _ in
            await barrier.wait()
            var result = VaultResult()
            result.catalog = ItemCatalog(vault: "personal", revision: "fresh", items: Self.catalog.items)
            return result
        }
        service.authenticate()
        let app = model(service); app.unlock(); try await entered(barrier)
        #expect(app.authenticated && !app.busy && app.offline && app.loadingVaults)
        #expect(app.catalog?.revision == Self.catalog.revision)
        // Local interaction must not cause the background sync to be discarded.
        app.perform(local: true) { _ in }
        while app.busy { try await Task.sleep(for: .milliseconds(1)) }
        await barrier.release(); try await finish(app)
        #expect(app.authenticated && !app.offline && app.catalog?.revision == "fresh")
    }

    @Test func failedBackgroundSyncKeepsCachedVaultReadOnly() async throws {
        let service = FakeService(cached: { _ in
            var result = VaultResult(); result.catalog = Self.catalog
            result.usingCache = true; result.offlineDate = Date(); return result
        }) { _, _, _ in throw MopError.cloudUnavailable }
        service.authenticate()
        let app = model(service); app.unlock(); try await finish(app)
        #expect(app.authenticated && app.offline && app.catalog != nil)
        #expect(app.notice != nil && app.error == nil)
    }

    @Test func deletionDuringCachedUnlockClearsSelectedVault() async throws {
        let service = FakeService(cached: { _ in
            var result = VaultResult(); result.catalog = Self.catalog
            result.usingCache = true; result.offlineDate = Date(); return result
        }) { operation, _, _ in
            if case .discover = operation { return VaultResult() }
            throw MopError.vaultMissing
        }
        service.authenticate()
        let app = model(service); app.unlock(); try await finish(app)
        #expect(!app.authenticated && app.catalogs.isEmpty && app.vaults.isEmpty)
        #expect(app.sheet == .createVault)
    }
}

@MainActor @Test func healthResultsCannotReturnAfterLockOrNewRevision() async throws {
    let gate = Barrier()
    let service = FakeService { operation, _, _ in
        if case .read = operation { await gate.wait(); var result = VaultResult(); result.value = "password"; return result }
        return VaultResult()
    }
    service.authenticate()
    let app = AppModel(breachClient: TestBreachClient(), service: service,
        defaults: UserDefaults(suiteName: "health-race-" + UUID().uuidString)!, automaticTimer: false, healthStartupDelay: .zero, healthIdleDelay: .zero)
    let catalog = ItemCatalog(vault: "personal", revision: "a", items: [VaultItem(name: "login", fields: [ItemField(path: "password", type: .password)])])
    app.catalogs = ["v": catalog]; app.authenticated = true
    while !(await gate.entered) { try await Task.sleep(for: .milliseconds(10)) }
    app.lock()
    await gate.release()
    try await Task.sleep(for: .milliseconds(50))
    #expect(app.healthReport.findings.isEmpty)
    #expect(!app.healthChecking)
    #expect(app.historySelection == nil)
}

@MainActor @Test func observedLocalRemovalInvalidatesOfflineBackupProjection() {
    let app = AppModel(breachClient: TestBreachClient(), service: FakeService(), automaticTimer: false, healthStartupDelay: .zero, healthIdleDelay: .zero)
    var account = CredentialAccount(service: "service", account: "alice")
    var local = CredentialRegistration(protocolName: "ssh", publicIdentifier: "a", deviceID: "here", deviceLabel: "Mac", localIdentityID: UUID())
    local.state = .confirmed
    var other = CredentialRegistration(protocolName: "ssh", publicIdentifier: "b", deviceID: "there", deviceLabel: "Other", external: true)
    other.state = .confirmed; account.registrations = [local, other]
    var catalog = ItemCatalog(vault: "v", revision: "1", items: [])
    catalog.currentDeviceID = "here"; catalog.security = VaultSecurityMetadata(); catalog.security?.accounts = [account]
    app.catalogs = ["v": catalog]; app.localReady = true; app.offline = true
    #expect(!app.credentialAccounts(in: "v")[0].hasConfirmedAlternate)
    app.localError = "Unavailable"
    #expect(app.credentialAccounts(in: "v")[0].hasConfirmedAlternate) // A listing failure is not evidence of deletion.
}

@MainActor @Test func healthRefreshDuringEditingKeepsTheSavedValueReport() {
    let service = FakeService(); service.authenticate()
    let app = AppModel(breachClient: TestBreachClient(), service: service, automaticTimer: false, healthStartupDelay: .zero, healthIdleDelay: .zero)
    let item = VaultItem(name: "login", fields: [ItemField(path: "password", type: .password)])
    app.catalogs = ["v": ItemCatalog(vault: "v", revision: "1", items: [item])]
    app.authenticated = true
    app.healthReport.checked = 1; app.healthReport.total = 1
    app.healthReport.completedAt = Date(timeIntervalSince1970: 100)
    app.itemDraft = ItemDraft(vault: "v", revision: "1", item: item)
    app.refreshHealth()
    #expect(app.healthReport.checked == 1)
    #expect(app.healthReport.completedAt == Date(timeIntervalSince1970: 100))
    app.lock()
}

@MainActor @Test func unchangedCatalogDoesNotRestartHealthChecks() async throws {
    let reads = Mutex(0)
    let service = FakeService { operation, _, _ in
        if case .read = operation {
            reads.withLock { $0 += 1 }
            var result = VaultResult(); result.value = "password"; return result
        }
        return VaultResult()
    }
    service.authenticate()
    let app = AppModel(breachClient: TestBreachClient(), service: service, automaticTimer: false, healthStartupDelay: .zero, healthIdleDelay: .zero)
    let catalog = ItemCatalog(vault: "v", revision: "1", items: [VaultItem(name: "login", fields: [ItemField(path: "password", type: .password)])])
    app.catalogs = ["v": catalog]; app.authenticated = true
    let token = app.healthToken
    app.catalogs = ["v": catalog]
    app.refreshHealth()
    #expect(app.healthToken == token)
    for _ in 0..<200 {
        if !app.healthChecking && !app.healthScheduled { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(!app.healthChecking)
    #expect(reads.withLock { $0 } == 1)
    app.catalogs = ["v": catalog]
    app.refreshHealth()
    #expect(app.healthToken == token)
    #expect(!app.healthChecking)
    app.refreshHealth(force: true)
    #expect(app.healthToken != token)
    app.lock()
    #expect(app.healthWakeTask == nil)
    #expect(app.healthReport.findings.isEmpty)
}

@MainActor @Test func publishingHealthCacheDoesNotRestartChecks() async throws {
    let reads = Mutex(0), writes = Mutex(0)
    var field = ItemField(path: "password", type: .password); field.recordVersion = "record"
    var initial = ItemCatalog(vault: "v", revision: "1", items: [VaultItem(name: "login", fields: [field])])
    initial.canEdit = true; initial.securityEnabled = true; initial.security = VaultSecurityMetadata()
    let stored = Mutex(initial)
    let service = FakeService { operation, _, _ in
        var result = VaultResult()
        switch operation {
        case .read:
            reads.withLock { $0 += 1 }; result.value = "password"
        case .savePasswordChecks(let checks, let revision):
            writes.withLock { $0 += 1 }
            result.catalog = stored.withLock { catalog in
                #expect(catalog.revision == revision)
                catalog.revision = "saved"; catalog.security?.passwordChecks = checks
                return catalog
            }
        default: break
        }
        return result
    }
    service.authenticate()
    let app = AppModel(breachClient: TestBreachClient(), service: service, automaticTimer: false, healthStartupDelay: .zero, healthIdleDelay: .zero)
    app.breachChecksEnabled = false; app.catalogs = ["v": initial]; app.authenticated = true
    await app.healthTask?.value
    #expect(reads.withLock { $0 } == 1)
    #expect(writes.withLock { $0 } == 1)
    #expect(app.catalogs["v"]?.revision == "saved")
    app.refreshHealth()
    #expect(!app.healthChecking)
    app.lock()
    let reopened = AppModel(breachClient: TestBreachClient(), service: service, automaticTimer: false, healthStartupDelay: .zero, healthIdleDelay: .zero)
    service.authenticate()
    reopened.breachChecksEnabled = false
    reopened.catalogs = ["v": stored.withLock { $0 }]; reopened.authenticated = true
    await reopened.healthTask?.value
    #expect(reopened.healthReport.usedCloudCache)
    #expect(reads.withLock { $0 } == 1)
    #expect(writes.withLock { $0 } == 1)
    reopened.lock()
}

@MainActor @Test func automaticHealthWaitsForStartupAndIdleButManualCheckBypassesDelay() async throws {
    let reads = Mutex(0)
    let service = FakeService { operation, _, _ in
        if case .read = operation { reads.withLock { $0 += 1 }; var result = VaultResult(); result.value = "password"; return result }
        return VaultResult()
    }
    service.authenticate()
    let app = AppModel(breachClient: TestBreachClient(), service: service, now: { 1 }, automaticTimer: false,
        healthStartupDelay: .seconds(30), healthIdleDelay: .seconds(5))
    app.catalogs = ["v": ItemCatalog(vault: "v", revision: "1", items: [VaultItem(name: "login", fields: [ItemField(path: "password", type: .password)])])]
    app.authenticated = true
    try await Task.sleep(for: .milliseconds(100))
    #expect(app.healthScheduled && !app.healthChecking)
    #expect(reads.withLock { $0 } == 0)
    app.refreshHealth(force: true)
    await app.healthTask?.value
    #expect(reads.withLock { $0 } == 1)
    app.lock()
    #expect(!app.healthScheduled)
}

@MainActor @Test func automaticHealthYieldsToForegroundWorkAndUserActivity() async throws {
    let reads = Mutex(0)
    let service = FakeService { operation, _, _ in
        if case .read = operation { reads.withLock { $0 += 1 }; var result = VaultResult(); result.value = "password"; return result }
        return VaultResult()
    }
    service.authenticate()
    let app = AppModel(breachClient: TestBreachClient(), service: service, now: { 1 }, automaticTimer: false,
        healthStartupDelay: .zero, healthIdleDelay: .seconds(30))
    app.catalogs = ["v": ItemCatalog(vault: "v", revision: "1", items: [VaultItem(name: "login", fields: [ItemField(path: "password", type: .password)])])]
    app.authenticated = true
    app.activity()
    try await Task.sleep(for: .milliseconds(100))
    #expect(app.healthScheduled && reads.withLock { $0 } == 0)
    app.busy = true
    app.healthLastInteraction = ContinuousClock.now.advanced(by: .seconds(-31))
    try await Task.sleep(for: .milliseconds(100))
    #expect(reads.withLock { $0 } == 0)
    app.busy = false
    await app.healthTask?.value
    #expect(reads.withLock { $0 } == 1)
    app.lock()
}

@MainActor @Test(arguments: [false, true]) func healthBatchesReachUIAndSyncQueueBeforeScanFinishes(lockDuringScan: Bool) async throws {
    let gate = Barrier(), reads = Mutex(0), writes = Mutex(0)
    let items = ["a", "b", "c"].map { name in
        var field = ItemField(path: "password", type: .password); field.recordVersion = name
        return VaultItem(name: name, fields: [field])
    }
    var initial = ItemCatalog(vault: "v", revision: "1", items: items)
    initial.canEdit = true; initial.securityEnabled = true; initial.security = VaultSecurityMetadata()
    let old = CachedPasswordCheck(record: "c", context: ["c", ""], weak: true, exposed: false,
        checkedAt: Date().addingTimeInterval(-60), breachCheckedAt: nil, reuseGroup: nil,
        scope: String(repeating: "a", count: 64), batch: UUID())
    initial.security?.passwordChecks = [old]
    let stored = Mutex(initial)
    let service = FakeService { operation, _, _ in
        var result = VaultResult()
        switch operation {
        case .read:
            let count = reads.withLock { $0 += 1; return $0 }
            if count == 2 { await gate.wait() }
            result.value = "password"
        case .savePasswordChecks(let checks, let revision):
            writes.withLock { $0 += 1 }
            result.catalog = stored.withLock { catalog in
                #expect(catalog.revision == revision)
                catalog.security?.passwordChecks = checks
                return catalog
            }
        default: break
        }
        return result
    }
    service.authenticate()
    let app = AppModel(breachClient: SuccessfulBatchBreachClient(), service: service, automaticTimer: false,
        healthStartupDelay: .zero, healthIdleDelay: .zero)
    app.breachChecksEnabled = true; app.catalogs = ["v": initial]; app.authenticated = true
    let task = app.healthTask, token = app.healthToken
    for _ in 0..<300 {
        if await gate.entered { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(await gate.entered)
    #expect(app.healthChecking)
    #expect(app.healthReport.state == .incomplete)
    #expect(app.healthReport.findings.contains { $0.item == "a" && $0.kinds.contains(.weak) })
    #expect(writes.withLock { $0 } == 1)
    let partial = stored.withLock { $0.security?.passwordChecks ?? [] }
    #expect(partial.first { $0.record == "a" }?.strengthResult != nil)
    #expect(partial.first { $0.record == "a" }?.breachResult != nil)
    #expect(partial.first { $0.record == "a" }?.reuseResult == nil)
    #expect(partial.first { $0.record == "c" } == old)
    app.refreshHealth()
    #expect(app.healthToken == token) // Our own batch must not restart the scan.
    if lockDuringScan { app.lock() }
    await gate.release()
    await task?.value
    if lockDuringScan {
        #expect(app.healthReport.findings.isEmpty)
        #expect(writes.withLock { $0 } == 1) // The committed batch survives, late work does not publish.
    } else {
        #expect(!app.healthChecking && app.healthToken == token)
        #expect(app.healthReport.state == .checked)
        #expect(reads.withLock { $0 } == 3)
        #expect(writes.withLock { $0 } == 2)
        #expect(stored.withLock { $0.security?.passwordChecks?.count } == 3)
        app.lock()
    }
}

private struct SuccessfulBatchBreachClient: BreachChecking {
    func contains(_ password: Data, force: Bool) async throws -> Bool { true }
    func clear() async {}
}

private actor EditedPasswordBreachClient: BreachChecking {
    let gate: Barrier
    init(gate: Barrier) { self.gate = gate }
    func contains(_ password: Data, force: Bool) async throws -> Bool {
        if String(decoding: password, as: UTF8.self) == "9k!Q7v#L2m@R8x$T4z%N6p" { await gate.wait() }
        return false
    }
    func clear() async {}
}

@MainActor @Test func savedStrongPasswordClearsWeakFindingsBeforeBreachResponse() async throws {
    let gate = Barrier(), reads = Mutex<[String]>([])
    var field = ItemField(path: "password", type: .password); field.recordVersion = "old"
    var other = field; other.recordVersion = "other"
    var initial = ItemCatalog(vault: "v", revision: "1", items: [
        VaultItem(name: "login", fields: [field]), VaultItem(name: "other", fields: [other])])
    initial.canEdit = true; initial.securityEnabled = true; initial.security = VaultSecurityMetadata()
    let stored = Mutex(initial)
    let service = FakeService { operation, _, _ in
        var result = VaultResult()
        switch operation {
        case .read(let reference):
            reads.withLock { $0.append(reference.item) }
            result.value = reference.item == "other" ? "7G!xR4@vB9#nC2$mK8%wT5" :
                stored.withLock { $0.revision == "1" ? "password" : "9k!Q7v#L2m@R8x$T4z%N6p" }
        case .save:
            result.catalog = stored.withLock {
                $0.revision = "2"; $0.items[0].fields[0].recordVersion = "replacement"
                $0.security?.passwordChecks?.removeAll { $0.record == "old" }
                return $0
            }
        case .savePasswordChecks(let checks, _):
            result.catalog = stored.withLock { $0.security?.passwordChecks = checks; return $0 }
        default: break
        }
        return result
    }
    service.authenticate()
    let app = AppModel(breachClient: EditedPasswordBreachClient(gate: gate), service: service,
        defaults: UserDefaults(suiteName: "health-edited-" + UUID().uuidString)!, now: { 1 }, automaticTimer: false,
        healthStartupDelay: .seconds(60), healthIdleDelay: .seconds(60))
    app.vault = "v"; try app.applyCatalog(initial); app.authenticated = true
    app.refreshHealth(force: true)
    await app.healthTask?.value
    #expect(app.healthReport.findings.contains { $0.item == "login" && $0.kinds.contains(.weak) })
    reads.withLock { $0 = [] }
    var replacement = initial.items[0]; replacement.fields[0].value = "9k!Q7v#L2m@R8x$T4z%N6p"
    app.activity()
    app.saveItem(replacement, create: false)
    for _ in 0..<300 {
        if await gate.entered { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(await gate.entered) // Saved edits bypass both 60-second delays.
    #expect(app.error == nil && app.healthChecking)
    #expect(!app.healthReport.findings.contains { $0.item == "login" }) // Both Weak and All use this list.
    #expect(stored.withLock { $0.security?.passwordChecks?.first { $0.record == "replacement" }?.strengthResult?.weak } == false)
    #expect(reads.withLock { $0 } == ["login"])
    let task = app.healthTask
    await gate.release(); await task?.value
    #expect(!app.healthReport.findings.contains { $0.item == "login" })
    #expect(app.healthReport.state == .checked)
    #expect(reads.withLock { $0 } == ["login"])
    app.lock()
}

@MainActor @Test func savedPasswordStrengthReloadsAndSurvivesHealthCatalogUpdates() async throws {
    let quality = Mutex<PasswordQuality>(.weak), requests = Mutex(0)
    let service = FakeService { operation, _, _ in
        var result = VaultResult()
        if case .passwordQuality = operation {
            requests.withLock { $0 += 1 }; result.passwordQuality = ["password": quality.withLock { $0 }]
        }
        return result
    }
    service.authenticate()
    let app = AppModel(breachClient: TestBreachClient(), service: service, now: { 1 }, automaticTimer: false)
    var field = ItemField(path: "password", type: .password); field.recordVersion = "old"
    var catalog = ItemCatalog(vault: "v", revision: "1", items: [VaultItem(name: "login", fields: [field])])
    app.vault = "v"; app.selectedItem = "login"; app.authenticated = true
    try app.applyCatalog(catalog)
    let originalIdentity = app.passwordQualityIdentity
    await app.loadPasswordQuality()
    #expect(app.passwordQuality(for: "password") == .weak)
    quality.withLock { $0 = .veryStrong }
    catalog.revision = "2"; catalog.items[0].fields[0].recordVersion = "replacement"
    try app.applyCatalog(catalog)
    #expect(app.passwordQualityIdentity != originalIdentity)
    #expect(app.passwordQuality(for: "password") == nil) // Never reuse the old password's score.
    await app.loadPasswordQuality()
    #expect(app.passwordQuality(for: "password") == .veryStrong)
    let savedIdentity = app.passwordQualityIdentity
    catalog.security = VaultSecurityMetadata()
    try app.applyCatalog(catalog) // A background health batch republishes the same item.
    #expect(app.passwordQualityIdentity == savedIdentity)
    #expect(app.passwordQuality(for: "password") == .veryStrong)
    await app.loadPasswordQuality()
    #expect(requests.withLock { $0 } == 2)
    app.lock()
    #expect(app.passwordQuality(for: "password") == nil)
}

@MainActor @Test func latePasswordStrengthCannotReplaceEditedPasswordsScore() async throws {
    let gate = Barrier(), count = Mutex(0)
    let service = FakeService { operation, _, _ in
        var result = VaultResult()
        if case .passwordQuality = operation {
            let call = count.withLock { $0 += 1; return $0 }
            if call == 1 { await gate.wait() }
            result.passwordQuality = ["password": call == 1 ? .weak : .veryStrong]
        }
        return result
    }
    service.authenticate()
    let app = AppModel(breachClient: TestBreachClient(), service: service, now: { 1 }, automaticTimer: false)
    var field = ItemField(path: "password", type: .password); field.recordVersion = "old"
    var catalog = ItemCatalog(vault: "v", revision: "1", items: [VaultItem(name: "login", fields: [field])])
    app.vault = "v"; app.selectedItem = "login"; app.authenticated = true; try app.applyCatalog(catalog)
    let previous = Task { await app.loadPasswordQuality() }
    for _ in 0..<300 {
        if await gate.entered { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(await gate.entered)
    catalog.revision = "2"; catalog.items[0].fields[0].recordVersion = "replacement"
    try app.applyCatalog(catalog)
    await app.loadPasswordQuality()
    #expect(app.passwordQuality(for: "password") == .veryStrong)
    await gate.release(); await previous.value
    #expect(app.passwordQuality(for: "password") == .veryStrong)
    app.lock()
}

@MainActor @Test func synchronizedStrengthDisplaysWithoutRequestAndOldObservationsUseLocalFallback() async throws {
    let calls = Mutex(0)
    let service = FakeService { operation, _, offline in
        var result = VaultResult()
        if case .passwordQuality = operation {
            #expect(offline)
            calls.withLock { $0 += 1 }; result.passwordQuality = ["password": .veryWeak]
        }
        return result
    }
    service.authenticate()
    let app = AppModel(breachClient: TestBreachClient(), service: service, now: { 1 }, automaticTimer: false)
    var field = ItemField(path: "password", type: .password); field.recordVersion = "synced"
    field.passwordQuality = .veryStrong
    var catalog = ItemCatalog(vault: "v", revision: "1", items: [VaultItem(name: "login", fields: [field])])
    app.vault = "v"; app.selectedItem = "login"; app.authenticated = true; try app.applyCatalog(catalog)
    await app.loadPasswordQuality()
    #expect(app.passwordQuality(for: "password") == .veryStrong)
    #expect(calls.withLock { $0 } == 0)
    catalog.items[0].fields[0].recordVersion = "older-observation"
    catalog.items[0].fields[0].passwordQuality = nil
    try app.applyCatalog(catalog)
    await app.loadPasswordQuality()
    #expect(app.passwordQuality(for: "password") == .veryWeak)
    #expect(calls.withLock { $0 } == 1)
    app.lock()
}
