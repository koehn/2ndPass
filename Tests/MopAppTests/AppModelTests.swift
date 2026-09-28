import Foundation
import Synchronization
import Testing
import MopCore
import MopAppSupport
@testable import MopUI

private final class FakeService: VaultService, Sendable {
    struct State {
        var started: TimeInterval?
        var locks = 0
        var operations: [VaultOperation] = []
        var progress: String?
        var fraction: Double?
    }
    let state = Mutex(State())
    let handler: @Sendable (VaultOperation, String?, Bool) async throws -> VaultResult
    init(_ handler: @escaping @Sendable (VaultOperation, String?, Bool) async throws -> VaultResult = { _, _, _ in VaultResult() }) { self.handler = handler }
    var authenticatedAt: TimeInterval? { state.withLock { $0.started } }
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
    private func model(_ service: FakeService, clock: Clock = Clock()) -> AppModel {
        let defaults = UserDefaults(suiteName: "mop-session-test-" + UUID().uuidString)!
        let model = AppModel(service: service, defaults: defaults, now: { clock.time }, automaticTimer: false)
        model.vault = UUID().uuidString
        model.vaults = [VaultDescriptor(id: model.vault, name: "personal", format: "mop-vault-v7", enrolled: true)]
        return model
    }
    @Test func firstLaunchGuidesCreationAndUnenrolledCloudVaultGuidesEnrollment() async throws {
        let empty = model(FakeService())
        empty.vault = ""; empty.vaults = []
        empty.discover(); try await finish(empty)
        #expect(empty.sheet == .createVault)
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            if case .discover = operation { result.vaults = [VaultDescriptor(id: "cloud-vault", name: "iCloud vault", format: "mop-vault-v7", enrolled: false)] }
            return result
        }
        let fresh = model(service); fresh.vault = ""; fresh.vaults = []
        fresh.discover(autoUnlock: true); try await finish(fresh)
        #expect(fresh.sheet == .enrollDevice)
        #expect(!fresh.authenticated)
        #expect(service.state.withLock { $0.operations.count } == 1)
    }
    @Test func failedDiscoveryDoesNotOfferAnEmptyAccountSetup() async throws {
        let fresh = model(FakeService { _, _, _ in throw MopError.cloudUnavailable })
        fresh.vault = ""; fresh.vaults = []
        fresh.discover(); try await finish(fresh)
        #expect(fresh.sheet == nil)
        #expect(fresh.error != nil)
    }
    @Test func enrollmentFailureShowsStatusAndManualCheckRetries() async throws {
        let service = FakeService { _, _, _ in throw MopError.cloudUnavailable }
        let fresh = model(service)
        fresh.vaults = [VaultDescriptor(id: UUID().uuidString, name: "personal", format: "mop-vault-v7", enrolled: false)]
        fresh.prepareEnrollmentSelection(); fresh.startEnrollment(); try await finish(fresh)
        #expect(fresh.enrollmentPaused)
        #expect(fresh.enrollmentLastCheck == nil)
        #expect(fresh.enrollmentLastAttempt != nil)
        #expect(fresh.enrollmentStatus.localizedCaseInsensitiveContains("retry"))
        #expect(fresh.cloudEnrollments.isEmpty)
        fresh.pollCloudEnrollment(owner: false, automatic: true)
        #expect(service.state.withLock { $0.operations.count } == 1)
        fresh.prepareEnrollmentSelection(); fresh.startEnrollment(); try await finish(fresh)
        #expect(service.state.withLock { $0.operations.count } == 2)
    }
    @Test func automaticEnrollmentNotifiesWithoutOpeningApprovalSheet() async throws {
        let device = UUID()
        let service = FakeService { operation, _, _ in
            if case .manage(.devices) = operation { return VaultResult() }
            guard case .manage(.automaticEnrollment) = operation else {
                Issue.record("Expected automatic enrollment")
                return VaultResult()
            }
            var result = VaultResult(); result.addedDevices = [device]; return result
        }
        service.authenticate()
        let app = model(service)
        app.pollCloudEnrollment(owner: true, automatic: true); try await finish(app)
        #expect(app.sheet == nil)
        #expect(app.deviceAddedNotice != nil)
        app.deviceAddedNotice = nil
        app.pollCloudEnrollment(owner: true, automatic: true); try await finish(app)
        #expect(app.deviceAddedNotice == nil)
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
        app.pollCloudEnrollment(owner: false)
        app.pollCloudEnrollment(owner: false, automatic: true)
        #expect(service.state.withLock { $0.operations.count } == count)
        app.reconnectDevice(); try await finish(app)
        #expect(service.state.withLock { $0.operations.contains { if case .manage(.reconnect) = $0 { return true }; return false } })
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
            if !model.busy && !model.refreshing && !model.enrollmentWorking { return }
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
        model.vaults = [VaultDescriptor(id: target, name: "personal", format: "mop-vault-v7", enrolled: true)]
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
        model.selected = try SecretReference("secondpass://personal/github/token")
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
        model.createVault(name: "personal", recovery: URL(fileURLWithPath: "/tmp/unused.key"), fingerprint: String(repeating: "a", count: 64))
        try await finish(model)
        #expect(model.vault != old && model.vaults.contains { $0.id == model.vault })
        #expect(model.catalog == nil && model.error == MopError.cloudUncertain.errorDescription)
    }
    @Test func deletionRequiresExactConfirmationAndFixedUUID() async throws {
        let service = FakeService { op, id, offline in
            guard case .deleteVault = op else { Issue.record("Wrong operation"); return VaultResult() }
            #expect(id != nil && !offline); return VaultResult()
        }
        let model = model(service)
        let target = VaultDescriptor(id: model.vault, name: "personal", format: "mop-vault-v7", enrolled: true)
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
        model.vault = id; model.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-vault-v7", enrolled: true)]
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
        let reference = try SecretReference("secondpass://personal/github/extra")
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
                result.vaults = [VaultDescriptor(id: first, name: "personal", format: "mop-vault-v7", enrolled: true),
                                VaultDescriptor(id: second, name: "work", format: "mop-vault-v7", enrolled: true)]
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
                var result = VaultResult(); result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-vault-v7", enrolled: true)]; return result
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
        let first = AppModel(service: FakeService(), defaults: defaults, automaticTimer: false)
        var options = PasswordOptions()
        options.length = 48; options.lowercase = false; options.uppercase = true
        options.numbers = false; options.symbols = false
        options.readable = true; options.pronounceable = true
        first.passwordGeneratorOptions = options
        first.lock()
        #expect(first.passwordGeneratorOptions == options)
        let reopened = AppModel(service: FakeService(), defaults: defaults, automaticTimer: false)
        #expect(reopened.passwordGeneratorOptions == options)
        defaults.set(Data("invalid".utf8), forKey: "passwordGeneratorOptions")
        let fallback = AppModel(service: FakeService(), defaults: defaults, automaticTimer: false)
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
        model.selected = try SecretReference("secondpass://personal/login/username")
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
        let model = AppModel(service: service, defaults: defaults, automaticTimer: false)
        let vaults = [VaultDescriptor(id: first, name: "personal", format: "mop-vault-v7", enrolled: true),
                      VaultDescriptor(id: second, name: "work", format: "mop-vault-v7", enrolled: true)]
        model.vaults = vaults; model.vault = first; model.allVaults = true; model.authenticated = true
        model.catalogs = [first: Self.catalog, second: ItemCatalog(vault: "work", revision: "work-r1", items: [])]
        model.createItem(VaultItem(name: "new", fields: [ItemField(path: "text", type: .text, value: "visible")]), in: second)
        try await finish(model)
        #expect(model.allVaults && model.vault == second && model.selectedItem == "new")
        #expect(model.catalogs[first]?.revision == "r1" && model.catalogs[second]?.revision == "work-r2")
        let reopened = AppModel(service: FakeService(), defaults: defaults, automaticTimer: false)
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
        model.vaults = [VaultDescriptor(id: first, name: "personal", format: "mop-vault-v7", enrolled: true),
                        VaultDescriptor(id: second, name: "work", format: "mop-vault-v7", enrolled: true)]
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
        let model = AppModel(service: service, defaults: defaults, now: { 0 }, automaticTimer: false,
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
        model.vaults = [VaultDescriptor(id: first, name: "personal", format: "mop-vault-v7", enrolled: true),
                        VaultDescriptor(id: second, name: "work", format: "mop-vault-v7", enrolled: true)]
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
        model.vaults.append(VaultDescriptor(id: target, name: "work", format: "mop-vault-v7", enrolled: true))
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
        let model = AppModel(service: service, clipboard: clipboard, lifecycle: lifecycle, now: { 1 }, automaticTimer: false)
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
        model.vaults = [VaultDescriptor(id: model.vault, name: "personal", format: "mop-vault-v7", enrolled: true)]
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
        #expect(model.error?.contains("separate hardware recovery device") == true)
        #expect(model.error?.contains("Older vault formats are unsupported") == true)
        #expect(model.error?.contains("mop vault trust") == false)
        #expect(!model.authenticated)
    }
}

extension AppModelTests {
}


extension AppModelTests {
    @Test func openingSelectedVaultOpensEveryConnectedVaultAtomically() async throws {
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
            VaultDescriptor(id: $0, name: $0, format: "mop-vault-v7", enrolled: $0 != unconnected)
        }
        model.unlock(); try await finish(model)
        #expect(attempts.withLock { $0 } == [first, second])
        #expect(!model.authenticated && !service.isAuthenticated)
        #expect(model.catalogs.isEmpty && model.catalog == nil && model.references.isEmpty)
        #expect(model.vaultIcon(model.vaults[2]) == "externaldrive.badge.plus")
        #expect(model.vaultIcon(model.vaults[0]) == "lock.rectangle")
    }

    @Test func backgroundReturnReusesSessionUntilInactivityExpires() async throws {
        let id = UUID().uuidString, clock = Clock()
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            if case .discover = operation {
                result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-vault-v7", enrolled: true)]
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
                result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-vault-v7", enrolled: true)]
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
                result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-vault-v7", enrolled: true)]
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
        #expect(model.error?.contains("Automatic unlocking is paused") == true)
        #expect(!model.authenticated && model.catalogs.isEmpty)
    }
}

extension AppModelTests {
    @Test func cloudNotificationRefreshesCatalogAndPreservesVaultSelection() async throws {
        let id = UUID().uuidString
        let revision = Mutex("before")
        let service = FakeService { operation, _, offline in
            #expect(!offline)
            var result = VaultResult()
            switch operation {
            case .discover:
                result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-vault-v7", enrolled: true)]
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
        revision.withLock { $0 = "after" }
        model.cloudChanged(); try await finish(model)
        #expect(model.catalog?.revision == "after")
        #expect(model.vault == id && !model.allVaults)
        #expect(service.state.withLock { $0.locks } == 0)
    }

    @Test func notificationsCoalesceWhileEditingAndRefreshAfterEditing() async throws {
        let id = UUID().uuidString
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            if case .discover = operation {
                result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-vault-v7", enrolled: true)]
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
        model.cloudChanged(); model.cloudChanged()
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
                result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-vault-v7", enrolled: true)]
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
        let result = try await service.execute(.read(SecretReference("secondpass://personal/github/password")), vault: id, offline: false)
        #expect(result.value == "available")
        await barrier.release(); try await finish(model)
        #expect(model.catalog?.revision == "new" && model.selectedItem == "github")
    }

    @Test func draftStartedDuringRefreshIsPreserved() async throws {
        let id = UUID().uuidString, barrier = Barrier(), refresh = Mutex(false)
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            if case .discover = operation {
                result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-vault-v7", enrolled: true)]
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
            app.vaults.append(VaultDescriptor(id: other, name: "other", format: "mop-vault-v7", enrolled: true))
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
    @Test(arguments: [false, true]) func enrollmentLoadsFirstVaultBeforeClosing(syncFails: Bool) async throws {
        let id = UUID().uuidString
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            switch operation {
            case .manage(.requestEnrollment): result.enrollmentCompleted = true
            case .catalog:
                if syncFails { throw MopError.cloudUnavailable }
                result.catalog = Self.catalog
            default: Issue.record("Unexpected enrollment operation")
            }
            return result
        }
        service.authenticate()
        let app = model(service)
        app.vault = ""
        app.vaults = [VaultDescriptor(id: id, name: "iCloud vault", format: "mop-vault-v7", enrolled: false)]
        app.sheet = .enrollDevice
        app.prepareEnrollmentSelection(); app.startEnrollment(); try await finish(app)
        if syncFails {
            #expect(app.sheet == .enrollDevice)
            if case .failed = app.enrollmentProgress[id]?.phase {} else { Issue.record("Expected sync failure") }
        } else {
            #expect(app.sheet == nil && app.vault == id)
            #expect(app.catalog?.items.first?.name == "github")
            #expect(app.vaults.first?.name == Self.catalog.vault)
        }
    }

    @Test func joiningExistingVaultDoesNotShowNewVaultSetupChecklist() async throws {
        let service = FakeService { operation, _, _ in
            var result = VaultResult()
            switch operation {
            case .manage(.requestEnrollment): result.enrollmentCompleted = true
            case .catalog: result.catalog = Self.catalog
            case .manage(.automaticEnrollment): throw MopError.cloudUnavailable
            default: Issue.record("Unexpected enrollment operation")
            }
            return result
        }
        service.authenticate()
        let app = model(service)
        app.vaults = [VaultDescriptor(id: app.vault, name: "personal", format: "mop-vault-v7", enrolled: false)]
        app.sheet = .enrollDevice
        app.prepareEnrollmentSelection(); app.startEnrollment(); try await finish(app)
        #expect(app.enrollmentProgress[app.vault]?.phase == .connected)
        #expect(app.vaults.first?.enrolled == true)
        #expect(app.authenticated && app.catalog?.items.first?.name == "github")
        #expect(!app.showsSetupChecklist)
        #expect(app.sheet == nil)
        app.pollCloudEnrollment(owner: true); try await finish(app)
        #expect(app.enrollmentProgress[app.vault]?.phase == .connected)
        if case .failed = app.ownerEnrollmentProgress[app.vault]?.phase {} else { Issue.record("Expected independent owner-check failure") }
    }

    @Test func enrollmentTracksEveryVaultAndDoesNotDiscardEditing() async throws {
        let failedID = UUID().uuidString, successID = UUID().uuidString
        let service = FakeService { operation, id, _ in
            if case .manage(.requestEnrollment) = operation {
                if id == failedID { throw MopError.cloudUnavailable }
                var result = VaultResult(); result.enrollmentCompleted = true; return result
            }
            return VaultResult()
        }
        service.authenticate()
        let app = model(service)
        app.authenticated = true
        let selected = app.vault
        app.vaults += [VaultDescriptor(id: failedID, name: "failed", format: "mop-vault-v7", enrolled: false), VaultDescriptor(id: successID, name: "connected", format: "mop-vault-v7", enrolled: false)]
        app.itemDraft = ItemDraft(vault: selected, revision: "r", item: VaultItem(name: "draft", type: .login, fields: ItemType.login.template))
        app.itemDraft?.name = "unsaved"
        app.prepareEnrollmentSelection(); app.startEnrollment()
        #expect(!app.busy && app.enrollmentWorking)
        try await finish(app)
        #expect(app.enrollmentProgress[successID]?.phase == .connected)
        if case .failed = app.enrollmentProgress[failedID]?.phase {} else { Issue.record("Expected per-vault failure") }
        #expect(app.itemDraft?.name == "unsaved" && app.vault == selected)
        #expect(app.vaults.first { $0.id == successID }?.enrolled == true)
    }
    @Test func closingEnrollmentKeepsPollingButLockPausesWithoutPrompting() async throws {
        let service = FakeService()
        service.authenticate()
        let app = model(service)
        app.vaults = [VaultDescriptor(id: app.vault, name: "personal", format: "mop-vault-v7", enrolled: false)]
        app.sheet = .enrollDevice; app.prepareEnrollmentSelection(); app.startEnrollment()
        try await finish(app)
        app.sheet = nil
        app.checkEnrollmentInboxIfNeeded(); try await finish(app)
        #expect(service.state.withLock { $0.operations.count } == 2)
        app.lock()
        #expect(app.enrollmentProgress[app.vault]?.phase == .paused)
        let count = service.state.withLock { $0.operations.count }
        app.activity(); app.checkEnrollmentInboxIfNeeded()
        #expect(service.state.withLock { $0.operations.count } == count)
    }
    @Test func uncertainEnrollmentCancellationIsNotReportedAsCancelled() async throws {
        let service = FakeService { operation, _, _ in
            if case .manage(.cancelEnrollment) = operation { throw MopError.cloudUnavailable }
            return VaultResult()
        }
        let app = model(service)
        app.cancelCloudEnrollment(app.vault); try await finish(app)
        if case .failed(let message) = app.enrollmentProgress[app.vault]?.phase { #expect(message.contains("did not confirm")) }
        else { Issue.record("Cancellation must remain unconfirmed") }
    }
    @Test func lockRejectsLateEnrollmentCompletion() async throws {
        let barrier = Barrier()
        let service = FakeService { _, _, _ in
            await barrier.wait()
            var result = VaultResult(); result.enrollmentCompleted = true; return result
        }
        let app = model(service)
        app.vaults = [VaultDescriptor(id: app.vault, name: "personal", format: "mop-vault-v7", enrolled: false)]
        app.prepareEnrollmentSelection(); app.startEnrollment(); try await entered(barrier)
        app.lock(); await barrier.release()
        try await Task.sleep(for: .milliseconds(20))
        #expect(!app.authenticated && app.vaults.first?.enrolled == false)
        #expect(app.enrollmentProgress[app.vault]?.phase == .paused)
    }
}

extension AppModelTests {
    @Test func joiningChecksDoNotStarveOwnerEnrollment() async throws {
        let service = FakeService()
        service.authenticate()
        let app = model(service)
        let joining = UUID().uuidString
        app.vaults.append(VaultDescriptor(id: joining, name: "second", format: "mop-vault-v7", enrolled: false))
        app.enrollmentSelection = [joining]; app.startEnrollment(); try await finish(app)
        app.checkEnrollmentInboxIfNeeded(); try await finish(app)
        app.cloudChanged(); app.checkEnrollmentInboxIfNeeded(); try await finish(app)
        #expect(service.state.withLock { state in state.operations.contains { if case .manage(.automaticEnrollment) = $0 { true } else { false } } })
        #expect(service.state.withLock { state in state.operations.filter { if case .manage(.requestEnrollment) = $0 { true } else { false } }.count } == 2)
    }
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
        app.vaultDetailsTarget = VaultDescriptor(id: UUID().uuidString, name: "other", format: "mop-vault-v7", enrolled: true)
        app.discardAndContinue()
        #expect(app.sheetRequest?.target?.id == target.id)
    }
    @Test func backupPickerRetainsTargetAcrossNavigationAndExpiresOnLock() async throws {
        let targetID = UUID().uuidString
        let service = FakeService { operation, vault, _ in
            guard case .export(let url) = operation else { Issue.record("Expected export"); return VaultResult() }
            #expect(vault == targetID)
            #expect(url.lastPathComponent.hasPrefix("2ndpass-personal-"))
            return VaultResult()
        }
        let app = model(service)
        let target = VaultDescriptor(id: targetID, name: "personal", format: "mop-vault-v7", enrolled: true)
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
        let target = VaultDescriptor(id: targetID, name: "other", format: "mop-vault-v7", enrolled: true)
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
    let model = AppModel(service: FakeService(), defaults: defaults, automaticTimer: false)
    model.authenticated = true; model.vault = "v"
    model.vaults = [VaultDescriptor(id: "v", name: "personal", format: "mop-vault-v7", enrolled: true)]
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
        let reference = try SecretReference("secondpass://personal/github/token")
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
    let model = AppModel(service: service, defaults: defaults, now: { 0 }, automaticTimer: false)
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
    let model = AppModel(service: service, defaults: UserDefaults(suiteName: "import-error-" + UUID().uuidString)!, now: { 0 }, automaticTimer: false)
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

    @Test func developerErrorsIncludeUnderlyingFailureAndClearStaleDetails() async throws {
        let defaults = UserDefaults(suiteName: "mop-diagnostics-" + UUID().uuidString)!
        defaults.set(true, forKey: DeveloperPreferences.key)
        let app = AppModel(service: FakeService(), defaults: defaults, automaticTimer: false)
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
        let app = AppModel(service: service, defaults: UserDefaults(suiteName: UUID().uuidString)!, usageStore: store, now: { 0 }, automaticTimer: false, wallNow: { date })
        let account = UUID().uuidString, vault = UUID().uuidString
        app.vault = vault
        app.vaults = [VaultDescriptor(id: vault, name: "personal", format: "mop-vault-v7", enrolled: true)]
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
        let app = AppModel(service: service, defaults: UserDefaults(suiteName: UUID().uuidString)!, usageStore: store, now: { 0 }, automaticTimer: false, wallNow: { date })
        app.vault = id.vault
        var item = VaultItem(name: "Login", type: .login, fields: [ItemField(path: "password", type: .password)])
        item.storageID = id.item
        var catalog = ItemCatalog(vault: "personal", revision: "r", items: [item]); catalog.usageScope = id.account
        try app.applyCatalog(catalog)
        service.authenticate(); app.authenticated = true; app.selectedItem = item.name
        let ref = try SecretReference(vault: "personal", relativePath: "Login/password")
        app.selected = ref
        app.beginItemEditing(); try await finish(app)
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
        let app = AppModel(service: FakeService(), defaults: UserDefaults(suiteName: UUID().uuidString)!,
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
        let app = AppModel(service: service, defaults: defaults, usageStore: RecentUsageMemory(), now: { 0 }, automaticTimer: false)
        app.vaults = catalogs.map { VaultDescriptor(id: $0.key, name: $0.value.vault, format: "mop-vault-v7", enrolled: true) }
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
