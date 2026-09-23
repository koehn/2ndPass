import Foundation
import Synchronization
import Testing
import MopCore
import MopAppSupport
@testable import MopApp

private final class FakeService: VaultService, Sendable {
    struct State {
        var started: TimeInterval?
        var locks = 0
        var operations: [VaultOperation] = []
    }
    let state = Mutex(State())
    let handler: @Sendable (VaultOperation, String?, Bool) async throws -> VaultResult
    init(_ handler: @escaping @Sendable (VaultOperation, String?, Bool) async throws -> VaultResult = { _, _, _ in VaultResult() }) { self.handler = handler }
    var authenticatedAt: TimeInterval? { state.withLock { $0.started } }
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
        return model
    }
    private func finish(_ model: AppModel) async throws {
        for _ in 0..<500 {
            if !model.busy { return }
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
    @Test func vaultMenuTargetsItsRowWithoutStartingAnUnlock() throws {
        let service = FakeService(); service.authenticate()
        let model = model(service)
        let target = UUID().uuidString
        model.vaults = [VaultDescriptor(id: target, name: "personal", format: "mop-vault-v4", enrolled: true)]
        model.allVaults = true
        model.catalogs[target] = Self.catalog
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
        model.selected = try SecretReference("mop://personal/github/token")
        model.read(copy: false); try await entered(barrier)
        model.deactivate(); model.activate(); await barrier.release(); try await finish(model)
        #expect(model.revealed == nil && service.isAuthenticated)
    }
    @Test func switchingVaultUsesExistingSessionAndOfflineSwitchLocks() async throws {
        let service = FakeService { _, _, _ in var r = VaultResult(); r.catalog = Self.catalog; return r }
        service.authenticate()
        let model = model(service)
        model.vault = UUID().uuidString; model.changedVault(); try await finish(model)
        #expect(model.authenticated && service.state.withLock { $0.locks } == 0)
        model.offline = true; model.changedContext()
        #expect(!service.isAuthenticated && model.catalog == nil)
    }
    @Test func failedEnrollmentRefreshKeepsDevicesButClearsOldRequests() async throws {
        let service = FakeService { operation, _, _ in
            if case .devices = operation { var r = VaultResult(); r.devices = [MacRecord(name: "Mac", fingerprint: "current")]; return r }
            throw MopError.cloudInvalidRequest
        }
        service.authenticate()
        let model = model(service)
        model.requests = [Enrollment(request: "old", name: "Old", fingerprint: "old")]
        model.loadDevices(); try await finish(model)
        #expect(model.devices.count == 1 && model.requests.isEmpty)
        #expect(model.error == MopError.cloudInvalidRequest.errorDescription)
    }
    @Test func uncertainCreationRetainsReconciliationUUID() async throws {
        let service = FakeService { _, _, _ in throw MopError.cloudUncertain }
        let model = model(service)
        let old = model.vault
        model.createVault(name: "personal", deviceName: "Mac", strict: false, recovery: URL(fileURLWithPath: "/tmp/unused.key"))
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
        let target = VaultDescriptor(id: model.vault, name: "personal", format: "mop-vault-v4", enrolled: true)
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
    @Test func exportUsesSelectedUUIDAndExplicitOfflineMode() async throws {
        let id = UUID().uuidString, output = URL(fileURLWithPath: "/tmp/unused-export.mopfile")
        let service = FakeService { operation, vault, offline in
            guard case .export(let url) = operation else { Issue.record("Wrong operation"); return VaultResult() }
            #expect(vault == id && offline && url == output); return VaultResult()
        }
        let model = model(service)
        model.vault = id; model.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-vault-v4", enrolled: true)]
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
        let reference = try SecretReference("mop://personal/github/extra")
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
                result.vaults = [VaultDescriptor(id: first, name: "personal", format: "mop-vault-v4", enrolled: true),
                                VaultDescriptor(id: second, name: "work", format: "mop-vault-v4", enrolled: true)]
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
                var result = VaultResult(); result.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-vault-v4", enrolled: true)]; return result
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
        else { #expect(model.itemDraft == nil) }
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
        model.selected = try SecretReference("mop://personal/login/username")
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
                #expect(model.displayedItems.count == (type.concealed ? 0 : 1))
            }
        }
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
        let vaults = [VaultDescriptor(id: first, name: "personal", format: "mop-vault-v4", enrolled: true),
                      VaultDescriptor(id: second, name: "work", format: "mop-vault-v4", enrolled: true)]
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
        model.vaults = [VaultDescriptor(id: first, name: "personal", format: "mop-vault-v4", enrolled: true),
                        VaultDescriptor(id: second, name: "work", format: "mop-vault-v4", enrolled: true)]
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
        model.vaults = [VaultDescriptor(id: first, name: "personal", format: "mop-vault-v4", enrolled: true),
                        VaultDescriptor(id: second, name: "work", format: "mop-vault-v4", enrolled: true)]
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
        model.chooseVault(target); try await finish(model)
        #expect(model.catalog?.vault == "work" && model.catalogs[first]?.revision == "r1")
        model.chooseVault(first)
        #expect(model.catalog?.vault == "personal")
        #expect(service.state.withLock { $0.operations.count } == 1)
    }
}
