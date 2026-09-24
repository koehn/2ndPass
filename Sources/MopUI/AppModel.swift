import SwiftUI
import MopCore
import MopAppSupport

enum AppPage: String, CaseIterable { case secrets = "Secrets", recentlyDeleted = "Recently Deleted" }
enum AppSheet: String, Identifiable { case createVault, renameVault, deleteVault, vaultSettings, trust, recover
    var id: String { rawValue }
}

@MainActor @Observable
final class AppModel {
    let service: any VaultService
    let documents: any DocumentAccessing
    let clipboard: any SecretClipboardAccess
    var isActive = true
    var vaults: [VaultDescriptor] = []
    var vault = ""
    var allVaults = false
    var catalogs: [String: ItemCatalog] = [:]
    var deletedCatalogs: [String: ItemCatalog] = [:]
    var selectedDeleted: ItemRow.ID?
    var itemToDelete: ItemRow?
    var retentionDate = Date()
    private var nextRetentionSweep = Date.distantPast
    @ObservationIgnored private let wallNow: () -> Date
    var passwordQualities: [String: PasswordQuality] = [:]
    private var launchAttempted = false
    var page = AppPage.secrets
    var selectedItem: String?
    var catalog: ItemCatalog?
    var references: [SecretReference] = []
    var selected: SecretReference?
    var search = ""
    var members: [VaultMemberRecord] = []
    var offline = false
    private var cloudRefreshPending = false
    private var nextCloudRefresh = Date.distantPast
    var authenticated = false
    var revealed: SecretBytes?
    var busy = false
    var refreshing = false
    private var foregroundRevision = 0
    @ObservationIgnored private var refreshTask: Task<Void, Never>?
    var error: String?
    var notice: String?
    struct CopyFeedback {
        let id = UUID()
        let reference: SecretReference
        let message: String
    }
    var copyFeedback: CopyFeedback?
    var status = "Select a vault to begin"
    var sheet: AppSheet?
    var deleteConfirmation = false
    var documentRequest: DocumentRequest?
    private var generation = 0
    private var visibilityGeneration = 0
    @ObservationIgnored private let lifecycle: any AppLifecycleMonitoring
    private var concealTask: Task<Void, Never>?

    @ObservationIgnored private let now: () -> TimeInterval
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private var inactivityTask: Task<Void, Never>?
    @ObservationIgnored private var operationTask: Task<Void, Never>?
    private var lastActivity: TimeInterval?
    private var automaticUnlockBlocked = false
    private var automaticUnlockNeedsRepair = false
    private var wasBackgrounded = false
    private var needsAccountDiscovery = false
    @ObservationIgnored private var automaticUnlockTask: Task<Void, Never>?
    var editorGeneration = 0
    var itemDraft: ItemDraft?
    var passwordGeneratorOptions = PasswordOptions() {
        didSet {
            if let data = try? JSONEncoder().encode(passwordGeneratorOptions) {
                defaults.set(data, forKey: "passwordGeneratorOptions")
            }
        }
    }
    var autoLockMinutes: Int {
        didSet {
            let bounded = min(60, max(1, autoLockMinutes))
            if bounded != autoLockMinutes { autoLockMinutes = bounded }
            defaults.set(bounded, forKey: "autoLockMinutes")
            checkExpiration()
        }
    }

    init(service: any VaultService = NativeVaultService(), clipboard: (any SecretClipboardAccess)? = nil,
         defaults: UserDefaults = .standard, lifecycle: (any AppLifecycleMonitoring)? = nil,
         documents: any DocumentAccessing = SystemDocumentAccess(),
         now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         automaticTimer: Bool = true, wallNow: @escaping () -> Date = Date.init) {
        self.lifecycle = lifecycle ?? SystemAppLifecycleMonitor()
        self.wallNow = wallNow; retentionDate = wallNow()
        self.service = service
        self.documents = documents
        self.clipboard = clipboard ?? SecretClipboard()
        self.defaults = defaults; self.now = now
        let saved = defaults.object(forKey: "autoLockMinutes") as? Int ?? 5
        autoLockMinutes = min(60, max(1, saved))
        if let data = defaults.data(forKey: "passwordGeneratorOptions"),
           var options = try? JSONDecoder().decode(PasswordOptions.self, from: data) {
            options.length = min(128, max(8, options.length))
            passwordGeneratorOptions = options
        }
        if automaticTimer {
            inactivityTask = Task { [weak self] in
                while !Task.isCancelled {
                    try? await Task.sleep(for: .milliseconds(250))
                    guard !Task.isCancelled else { return }
                    self?.checkExpiration()
                    self?.checkRetention()
                    self?.refreshCloudIfNeeded()
                }
            }
        }
    }
    deinit { inactivityTask?.cancel(); automaticUnlockTask?.cancel() }
    func checkExpiration() {
        if let started = service.authenticatedAt {
            if lastActivity == nil { lastActivity = started }
            if now() - (lastActivity ?? started) >= Double(autoLockMinutes * 60) {
                lock(); automaticUnlockBlocked = false
            }
        } else if lastActivity != nil {
            if busy && !authenticated {
                // Let an in-flight opening report its failure after the service
                // invalidates authentication. Invalidating its generation here
                // would swallow that error and its automatic-retry pause.
                lastActivity = nil; automaticUnlockBlocked = true; conceal()
            } else { lock() }
        }
        scheduleAutomaticUnlock()
    }
    private func scheduleAutomaticUnlock() {
        if needsAccountDiscovery, isActive, !busy {
            needsAccountDiscovery = false
            Task { [weak self] in self?.discover(autoUnlock: true) }
            return
        }
        guard launchAttempted, isActive, !authenticated, !busy, !automaticUnlockBlocked, !automaticUnlockNeedsRepair,
              error == nil, sheet == nil, !requestedVaultIDs.isEmpty,
              automaticUnlockTask == nil else { return }
        automaticUnlockTask = Task { [weak self] in
            await Task.yield()
            guard let self else { return }
            self.automaticUnlockTask = nil
            guard !Task.isCancelled, self.isActive, !self.authenticated, !self.busy,
                  !self.automaticUnlockBlocked, !self.automaticUnlockNeedsRepair, self.error == nil,
                  self.sheet == nil, !self.requestedVaultIDs.isEmpty else { return }
            self.unlock()
        }
    }
    func activity() {
        checkExpiration()
        guard isActive else { return }
        if service.isAuthenticated { lastActivity = now() }
        if !busy, error == nil { automaticUnlockBlocked = false }
        scheduleAutomaticUnlock()
    }
    var selectedVaultDescriptor: VaultDescriptor? { vaults.first { $0.id == vault } }
    var canExportBackup: Bool { !allVaults && !vault.isEmpty && (selectedVaultDescriptor?.supported == true || authenticated) }
    var vaultName: String { catalog?.vault ?? references.first?.vault ?? vaults.first { $0.id == vault }?.name ?? "" }
    var filtered: [SecretReference] {
        references.filter { search.isEmpty || $0.description.localizedCaseInsensitiveContains(search) }
    }
    var items: [String] { Array(Set(filtered.map(\.item))).sorted() }
    var displayedItems: [ItemRow] {
        let included = allVaults ? catalogs : catalog.map { [vault: $0] } ?? [:]
        return included.flatMap { id, catalog in
            catalog.items.map { item in
                ItemRow(id: .init(vault: id, name: item.name), vaultName: catalog.vault, item: item)
            }
        }.sorted { ($0.item.name, $0.vaultName, $0.id.vault) < ($1.item.name, $1.vaultName, $1.id.vault) }
    }
    var searchResults: [ItemSearchResult] {
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return [] }
        return displayedItems.compactMap { row in
            let field = row.item.fields.first { field in
                guard !field.type.concealed else { return false }
                let label = field.path.removingPercentEncoding ?? field.path
                return label.localizedCaseInsensitiveContains(query) || field.value?.localizedCaseInsensitiveContains(query) == true
            }
            guard field != nil || row.item.name.localizedCaseInsensitiveContains(query)
                    || row.vaultName.localizedCaseInsensitiveContains(query) else { return nil }
            return ItemSearchResult(row: row, field: field)
        }
    }

    var deletedRows: [ItemRow] {
        deletedCatalogs.flatMap { id, catalog in
            catalog.items.compactMap { item -> ItemRow? in
                guard let deletion = item.deletion, !deletion.isExpired(at: retentionDate) else { return nil }
                let matches = search.isEmpty || deletion.originalName.localizedCaseInsensitiveContains(search)
                    || catalog.vault.localizedCaseInsensitiveContains(search)
                    || item.fields.contains { !$0.type.concealed && $0.value?.localizedCaseInsensitiveContains(search) == true }
                return matches ? ItemRow(id: .init(vault: id, name: item.name), vaultName: catalog.vault, item: item) : nil
            }
        }.sorted { ($0.item.deletion?.deletedAt ?? .distantPast) > ($1.item.deletion?.deletedAt ?? .distantPast) }
    }
    var selectedDeletedItem: ItemRow? { deletedRows.first { $0.id == selectedDeleted } }
    func chooseRecentlyDeleted() {
        guard !busy else { return }
        page = .recentlyDeleted; allVaults = false
        changedVault()
        scheduleAutomaticUnlock()
    }
    func trashItem(_ row: ItemRow) {
        guard !busy, !offline, authenticated, let source = catalogs[row.id.vault],
              source.items.contains(where: { $0.name == row.id.name }) else { return }
        itemToDelete = nil; cancelItemEditing(); conceal(); clearClipboard()
        perform { token in
            let result = try await self.service.execute(.trashItem(name: row.id.name, revision: source.revision), vault: row.id.vault, offline: false)
            guard self.current(token) else { return }
            try self.applyDeletionResult(result, vault: row.id.vault)
            if self.vault == row.id.vault && self.selectedItem == row.id.name { self.selectedItem = nil; self.selected = nil }
            self.notice = "Item moved to Recently Deleted for 30 days."
        }
    }
    func restoreDeletedItem(_ row: ItemRow) {
        guard !busy, !offline, authenticated, let deletion = row.item.deletion,
              !deletion.isExpired(at: wallNow()), let source = deletedCatalogs[row.id.vault] else { return }
        perform { token in
            let result = try await self.service.execute(.restoreItem(id: deletion.id, revision: source.revision), vault: row.id.vault, offline: false)
            guard self.current(token) else { return }
            try self.applyDeletionResult(result, vault: row.id.vault)
            self.selectedDeleted = nil
            self.notice = "Item restored to " + row.vaultName + "."
        }
    }
    private func applyDeletionResult(_ result: VaultResult, vault id: String) throws {
        let catalog = try result.requireCatalog()
        catalogs[id] = catalog; deletedCatalogs[id] = result.deletedCatalog
        if vault == id { try applyCatalog(catalog) }
        retentionDate = wallNow()
    }
    func checkRetention() {
        let date = wallNow()
        if date.timeIntervalSince(retentionDate) >= 1 { retentionDate = date }
        guard authenticated, service.isAuthenticated, !offline, !busy, itemDraft == nil, date >= nextRetentionSweep else { return }
        let ids = deletedCatalogs.filter { $0.value.items.contains { $0.deletion?.isExpired(at: date) == true } }.map(\.key)
        guard !ids.isEmpty else { return }
        nextRetentionSweep = date.addingTimeInterval(60)
        perform { token in
            for id in ids {
                let result = try await self.service.execute(.recentlyDeleted, vault: id, offline: false)
                guard self.current(token) else { return }
                try self.applyDeletionResult(result, vault: id)
            }
        }
    }

    var selectedRow: ItemRow.ID? {
        get { selectedItem.map { .init(vault: vault, name: $0) } }
        set {
            guard !busy, newValue != selectedRow else { return }
            cancelItemEditing(); selected = nil; passwordQualities = [:]
            guard let newValue else { selectedItem = nil; return }
            if let cached = catalogs[newValue.vault] {
                vault = newValue.vault
                try? applyCatalog(cached)
                selectedItem = newValue.name
            }
        }
    }
    func chooseVault(_ id: String) {
        guard !busy else { return }
        allVaults = false; page = .secrets; vault = id
        changedVault()
        scheduleAutomaticUnlock()
    }
    /// Target the row's vault without starting an unlock that could race the action.
    func prepareVaultAction(_ id: String) -> Bool {
        checkExpiration()
        guard !busy, vaults.contains(where: { $0.id == id }) else { return false }
        if allVaults || vault != id || page != .secrets {
            let cached = service.isAuthenticated ? catalogs[id] : nil
            clearSelection()
            vault = id; allVaults = false; page = .secrets
            if let cached {
                try? applyCatalog(cached)
            }
            status = authenticated ? "Unlocked" : "Ready to authenticate"
        }
        return true
    }

    func chooseAllVaults() {
        guard !busy else { return }
        allVaults = true; page = .secrets
        changedVault()
        scheduleAutomaticUnlock()
    }
    var sidebarSelection: String {
        get { page == .recentlyDeleted ? "deleted" : allVaults ? "all" : "vault:" + vault }
        set {
            guard newValue != sidebarSelection else { return }
            if newValue == "deleted" { chooseRecentlyDeleted() }
            else if newValue == "all" { chooseAllVaults() }
            else if newValue.hasPrefix("vault:") { chooseVault(String(newValue.dropFirst(6))) }
        }
    }
    var selectedTypedItem: VaultItem? { catalog?.items.first { $0.name == selectedItem } }
    var itemFields: [SecretReference] {
        let refs = references.filter { $0.item == selectedItem }.sorted()
        let paths = selectedTypedItem?.fields.map { SecretReference.encode(selectedItem ?? "") + "/" + $0.path } ?? []
        return refs.sorted { (paths.firstIndex(of: $0.relativePath) ?? Int.max) < (paths.firstIndex(of: $1.relativePath) ?? Int.max) }
    }
    func metadata(_ ref: SecretReference) -> ItemField? {
        catalog?.items.first { $0.name == ref.item }?.fields.first { ref.relativePath == SecretReference.encode(ref.item) + "/" + $0.path }
    }
    func applyCatalog(_ catalog: ItemCatalog) throws {
        let refs = try catalog.items.flatMap { item in
            try item.fields.map { try SecretReference(vault: catalog.vault, relativePath: SecretReference.encode(item.name) + "/" + $0.path) }
        }
        self.catalog = catalog; self.references = refs.sorted()
        if !vault.isEmpty { catalogs[vault] = catalog }
        passwordQualities = [:]
    }
    var itemCreationVaults: [VaultDescriptor] {
        vaults.filter { $0.supported && $0.enrolled && catalogs[$0.id] != nil }
            .sorted { ($0.name ?? "", $0.id) < ($1.name ?? "", $1.id) }
    }
    var preferredCreationVault: String {
        guard allVaults else { return vault }
        let saved = defaults.string(forKey: "allVaultsCreationVault")
        if let saved, itemCreationVaults.contains(where: { $0.id == saved }) { return saved }
        if itemCreationVaults.contains(where: { $0.id == vault }) { return vault }
        return itemCreationVaults.first?.id ?? ""
    }
    func beginCreatingItem() {
        guard !busy, !offline, authenticated, itemDraft == nil else { return }
        let destination = preferredCreationVault
        guard itemCreationVaults.contains(where: { $0.id == destination }), let catalog = catalogs[destination] else { return }
        conceal(); selected = nil; selectedItem = nil
        itemDraft = ItemDraft(vault: destination, revision: catalog.revision,
            item: VaultItem(name: "", type: .login, fields: ItemType.login.template), isNew: true)
    }
    func chooseCreationVault(_ id: String) {
        guard !busy, itemDraft?.isNew == true, itemCreationVaults.contains(where: { $0.id == id }) else { return }
        itemDraft?.vault = id
        if allVaults { defaults.set(id, forKey: "allVaultsCreationVault") }
    }
    func changeDraftType(_ type: ItemType) {
        guard !busy, var draft = itemDraft else { return }
        draft.type = type
        if draft.isNew {
            if draft.fields.allSatisfy({ ($0.value ?? "").isEmpty }) {
                draft.fields = type.template.map { ItemDraft.Field($0, existing: false) }
            } else {
                for field in type.template where !draft.fields.contains(where: { $0.encodedPath == field.path }) {
                    draft.fields.append(ItemDraft.Field(field, existing: false))
                }
            }
        }
        itemDraft = draft
    }

    func createItem(_ item: VaultItem, in destination: String) {
        guard !busy, !offline, authenticated,
              itemCreationVaults.contains(where: { $0.id == destination }),
              let target = catalogs[destination] else { return }
        let remember = allVaults
        let edit = ItemEdit(revision: target.revision, item: item, create: true)
        perform { token in
            let result = try await self.service.execute(.save(edit), vault: destination, offline: false)
            guard self.current(token) else { return }
            let catalog = try result.requireCatalog()
            self.vault = destination
            try self.applyCatalog(catalog)
            self.itemDraft = nil
            self.selectedItem = item.name; self.selected = nil; self.sheet = nil
            self.conceal(); self.notice = "Item saved to iCloud."
            if remember { self.defaults.set(destination, forKey: "allVaultsCreationVault") }
        }
    }

    func saveItem(_ item: VaultItem, create: Bool, revision: String? = nil, draftID: UUID? = nil, originalName: String? = nil) {
        guard !offline, let catalog else { return }
        if !create, let stored = catalog.items.first(where: { $0.name == (originalName ?? item.name) }) {
            guard stored.fields.filter({ stored.isTemplateField($0) }).allSatisfy({ required in
                item.fields.contains { $0.path == required.path }
            }) else { return }
        }
        let edit = ItemEdit(revision: revision ?? catalog.revision, item: item, create: create, originalName: originalName)
        perform { token in
            let result = try await self.service.execute(.save(edit), vault: self.selectedVault, offline: false)
            guard self.current(token) else { return }
            try self.applyCatalog(result.requireCatalog())
            self.selectedItem = item.name; self.selected = nil; self.sheet = nil
            if self.itemDraft?.id == draftID { self.itemDraft = nil }
            self.conceal(); self.notice = originalName != nil && originalName != item.name ? "Item renamed. Update references that use the old name." : "Item saved to iCloud."
        }
    }
    func beginItemEditing(replacing path: String? = nil, addField: Bool = false) {
        guard !busy, !offline, authenticated, itemDraft == nil, let catalog, let item = selectedTypedItem else { return }
        guard path == nil || item.fields.contains(where: { $0.path == path }) else { return }
        conceal()
        itemDraft = ItemDraft(vault: vault, revision: catalog.revision, item: item,
                              mode: path.map { .value($0) } ?? .item)
        if addField { itemDraft?.fields.append(ItemDraft.Field(ItemField(path: "", value: ""), existing: false)) }
        let passwords = item.fields.filter { $0.type == .password && $0.value == nil && (path == nil || $0.path == path) }
        guard !passwords.isEmpty, let draft = itemDraft else { return }
        let visibility = visibilityGeneration
        perform { token in
            do {
                for field in passwords {
                    let reference = try SecretReference(vault: catalog.vault,
                        relativePath: SecretReference.encode(item.name) + "/" + field.path)
                    let result = try await self.service.execute(.read(reference), vault: draft.vault, offline: false)
                    guard self.current(token), self.itemDraft?.id == draft.id,
                          self.vault == draft.vault, self.selectedItem == draft.originalName else { return }
                    guard self.isActive, self.visibilityGeneration == visibility else {
                        self.cancelItemEditing(); return
                    }
                    guard let value = result.value else { throw MopError.invalidVault }
                    guard let index = self.itemDraft?.fields.firstIndex(where: { $0.path == field.path }) else { continue }
                    // Preserve input if an edit was made while this read was pending.
                    guard self.itemDraft?.fields[index].value == draft.fields.first(where: { $0.path == field.path })?.value else { continue }
                    let password = String(decoding: value, as: UTF8.self)
                    self.itemDraft?.fields[index].loadedPassword = password
                    self.itemDraft?.fields[index].value = password
                }
            } catch {
                if self.itemDraft?.id == draft.id { self.cancelItemEditing() }
                throw error
            }
        }
    }
    func cancelItemEditing() { itemDraft = nil; conceal() }
    func saveItemDraft() {
        if let draft = itemDraft, draft.isNew {
            guard let target = catalogs[draft.vault], draft.valid(vaultName: target.vault) else { return }
            createItem(draft.item, in: draft.vault)
            return
        }
        guard let draft = itemDraft, draft.vault == vault, draft.originalName == selectedItem,
              draft.valid(vaultName: vaultName) else { return }
        saveItem(draft.item, create: false, revision: draft.revision, draftID: draft.id, originalName: draft.originalName)
    }
    func selectField(_ reference: SecretReference) { if selected != reference { conceal() }; selected = reference }
    func vaultLabel(_ descriptor: VaultDescriptor) -> String {
        guard let name = descriptor.name else { return "Legacy · " + descriptor.id }
        return vaults.filter { $0.name == name }.count > 1 ? name + " · " + descriptor.id : name
    }
    var selectedVault: String? { vault.isEmpty ? nil : vault }

    func conceal() { revealed = nil; concealTask?.cancel() }
    func clearClipboard() { clipboard.clear() }
    func startMonitoringActivity() {
        lifecycle.start { [weak self] event in
            guard let self else { return }
            switch event {
            case .active: self.activate()
            case .cloudChanged: self.cloudChanged()
            case .inactive: self.deactivate()
            case .background: self.background()
            case .lock: self.deactivate(); self.lock(); self.wasBackgrounded = true
            case .accountChanged:
                self.lock(); self.vaults = []; self.vault = ""
                self.automaticUnlockBlocked = false
                self.automaticUnlockNeedsRepair = false
                self.needsAccountDiscovery = true
                self.scheduleAutomaticUnlock()
            case .terminate: self.shutdown()
            case .activity: self.activity()
            }
        }
    }
    func shutdown() { isActive = false; lock(); inactivityTask?.cancel(); lifecycle.stop() }
    func background() {
        deactivate(); wasBackgrounded = true
        // A temporary app switch preserves the authenticated vault session.
        // Pending authentication cannot continue in the background.
        cancelItemEditing()
        if busy && !authenticated { lock(clearClipboard: false) }
        checkExpiration()
    }
    func deactivate() { isActive = false; visibilityGeneration += 1; conceal(); automaticUnlockTask?.cancel(); automaticUnlockTask = nil }
    func activate() {
        checkExpiration(); isActive = true
        if wasBackgrounded { automaticUnlockBlocked = false; wasBackgrounded = false }
        if service.isAuthenticated, !busy { lastActivity = now() }
        scheduleAutomaticUnlock(); checkRetention()
        if launchAttempted && authenticated { cloudChanged() }
    }
    private func clearSelection() {
        generation += 1; editorGeneration += 1; itemDraft = nil
        selectedDeleted = nil; itemToDelete = nil
        conceal(); catalog = nil; passwordQualities = [:]; references = []; selected = nil; members = []
        selectedItem = nil; sheet = nil; notice = nil
        search = ""; deleteConfirmation = false; documentRequest = nil; error = nil
    }
    private func clearView() {
        clearSelection()
        catalogs = [:]; deletedCatalogs = [:]; authenticated = false
    }
    func lock(clearClipboard: Bool = true) {
        automaticUnlockBlocked = true
        automaticUnlockTask?.cancel(); automaticUnlockTask = nil
        service.lock(); operationTask?.cancel(); refreshTask?.cancel(); lastActivity = nil
        clearView(); if clearClipboard { self.clearClipboard() }
        status = "Locked"
    }
    func changedVault() {
        checkExpiration()
        clearSelection()
        guard service.isAuthenticated else { authenticated = false; status = "Ready to authenticate"; return }
        let ids = requestedVaultIDs
        if !ids.isEmpty && ids.allSatisfy({ catalogs[$0] != nil }) {
            if let cached = catalogs[vault] { try? applyCatalog(cached) }
            authenticated = true
            status = offline ? "Read only · verified cached catalogs" : "Unlocked"
        } else {
            authenticated = false
            status = "Opening vaults"
            perform { token in try await self.unlockContents(token, refresh: false) }
        }
    }
    private var requestedVaultIDs: [String] {
        vaults.filter { $0.supported && $0.enrolled }.map(\.id)
    }
    var hasConnectedVaults: Bool { !requestedVaultIDs.isEmpty }
    func vaultIcon(_ descriptor: VaultDescriptor) -> String {
        if !descriptor.supported { return "exclamationmark.triangle" }
        if !descriptor.enrolled { return "externaldrive.badge.plus" }
        return authenticated ? "lock.open" : "lock.rectangle"
    }
    func vaultConnectionLabel(_ descriptor: VaultDescriptor) -> String {
        if !descriptor.supported { return "Unsupported vault" }
        if !descriptor.enrolled { return "Not owned by this account" }
        return authenticated ? "Unlocked" : "Locked"
    }

    func perform(_ action: @escaping @MainActor (Int) async throws -> Void) {
        checkExpiration()
        guard !busy else { return }
        foregroundRevision += 1
        busy = true; error = nil; notice = nil
        let token = generation
        operationTask = Task {
            defer { busy = false; checkExpiration() }
            guard self.current(token) else { return }
            do { try await action(token) }
            catch {
                if token == generation {
                    self.automaticUnlockBlocked = true
                    // A trust/account/data failure needs repair. Taps and Face ID
                    // lifecycle notifications must not repeat the same failure.
                    if (!self.authenticated && error as? MopError != .authentication) || error as? MopError == .vaultUntrusted {
                        self.automaticUnlockNeedsRepair = true
                    }
                    if let failure = error as? MopError,
                       [.authentication, .signing, .invalidIdentity, .invalidVault, .vaultUntrusted, .notVaultMember, .cloudAccount].contains(failure) { self.lock() }
                    // Framework errors may contain arbitrary diagnostics. Only
                    // domain errors have user-safe messages.
                    if error as? MopError == .vaultUntrusted {
                        self.error = "Vault trust could not be verified. Automatic unlocking is paused. Refresh after iCloud Keychain finishes syncing. For a v5 vault, verify independent fingerprint evidence or use recovery. Older vault formats are unsupported."
                    } else {
                        self.error = (error as? MopError)?.errorDescription ?? "The operation could not be completed."
                    }
                }
            }
        }
    }
    func current(_ token: Int) -> Bool { checkExpiration(); return token == generation }

    func start() {
        guard !launchAttempted else { return }
        launchAttempted = true
        discover(autoUnlock: true)
    }
    func discover(autoUnlock: Bool = false, selectedOnly: Bool = false) {
        automaticUnlockNeedsRepair = false
        if !autoUnlock { automaticUnlockBlocked = false }
        perform { token in
            let result = try await self.service.execute(.discover, vault: nil, offline: false)
            self.offline = result.usingCache
            let rows = result.vaults
            let ids = rows.map(\.id)
            guard self.current(token) else { return }
            self.vaults = rows
            self.catalogs = self.catalogs.filter { ids.contains($0.key) }
            self.deletedCatalogs = self.deletedCatalogs.filter { ids.contains($0.key) }
            // Use the repository's account-scoped default, never an arbitrary vault.
            if self.vault.isEmpty {
                if let id = result.defaultVault, ids.contains(id) { self.vault = id }
            } else if !ids.contains(self.vault) {
                self.vault = ""; self.lock(); self.automaticUnlockBlocked = false
                return
            }
            self.status = ids.isEmpty ? "Create your first vault" : "Vaults available"
            if self.authenticated && self.requestedVaultIDs.contains(where: { self.catalogs[$0] == nil }) {
                self.authenticated = false
            }
            if autoUnlock, self.isActive, !self.automaticUnlockBlocked,
               rows.contains(where: { $0.supported && $0.enrolled }) {
                if !selectedOnly { self.allVaults = true }
                try await self.unlockContents(token)
            }
        }
    }
    func unlock() {
        guard !busy else { return }
        cancelItemEditing(); conceal(); catalog = nil; catalogs = [:]; deletedCatalogs = [:]
        passwordQualities = [:]; references = []; authenticated = false
        perform { token in try await self.unlockContents(token) }
    }
    private func unlockContents(_ token: Int, refresh: Bool = true) async throws {
        do {
            let ids = requestedVaultIDs
            guard !ids.isEmpty else { status = "Connect this device to a vault to get started."; return }
            var loaded = refresh ? [:] : catalogs.filter { ids.contains($0.key) }
            var deleted = refresh ? [:] : deletedCatalogs.filter { ids.contains($0.key) }
            var dates: [String: Date] = [:]
            for id in ids where refresh || loaded[id] == nil {
                let result = try await service.execute(.catalog, vault: id, offline: false)
                guard current(token) else { return }
                loaded[id] = try result.requireCatalog()
                deleted[id] = result.deletedCatalog
                dates[id] = result.offlineDate
            }
            guard current(token) else { return }
            offline = !dates.isEmpty
            catalogs = loaded; deletedCatalogs = deleted; retentionDate = wallNow()
            if vault.isEmpty { vault = ids[0] }
            if let catalog = loaded[vault] { try applyCatalog(catalog) }
            else { catalog = nil; references = [] }
            authenticated = true
            if lastActivity == nil { lastActivity = now() }
            for (id, catalog) in loaded {
                vaults.removeAll { $0.id == id }
                vaults.append(VaultDescriptor(id: id, name: catalog.vault, format: "mop-vault-v5", enrolled: true))
            }
            if let item = selectedItem, catalog?.items.contains(where: { $0.name == item }) != true { selectedItem = nil }
            if let selected, !references.contains(selected) { self.selected = nil }
            let date = dates.values.min().map { ISO8601DateFormatter().string(from: $0) } ?? "unknown time"
            status = offline ? "Read only · oldest verified cache from \(date)" : "Unlocked · \(loaded.count) vault\(loaded.count == 1 ? "" : "s")"
        } catch {
            // Publish no partial unlocked state, even for a network failure in a
            // later vault after earlier vaults have successfully authenticated.
            service.lock(); lastActivity = nil; authenticated = false
            catalog = nil; catalogs = [:]; deletedCatalogs = [:]; references = []
            passwordQualities = [:]; conceal(); clearClipboard()
            throw error
        }
    }
    func loadPasswordQuality() async {
        passwordQualities = [:]
        guard authenticated, service.isAuthenticated, let item = selectedTypedItem,
              item.fields.contains(where: { $0.type == .password }) else { return }
        let token = generation, id = vault, name = item.name
        do {
            let result = try await service.execute(.passwordQuality(item: name), vault: id, offline: false)
            guard current(token), !Task.isCancelled, vault == id, selectedItem == name else { return }
            passwordQualities = result.passwordQuality
        } catch {
            // Scores are optional. Authentication/account failures still clear the
            // session through the service and expiry check; never expose diagnostics.
            checkExpiration()
        }
    }
    func copyReference() {
        guard let selected else { return }
        clipboard.copy(SecretBytes(utf8: selected.description), concealed: false)
        copyFeedback = CopyFeedback(reference: selected, message: "Reference copied")
    }
    func currentOTP(_ reference: SecretReference) async throws -> (code: String, expires: Date, period: Int) {
        let token = generation, visibility = visibilityGeneration, id = vault, item = selectedItem
        guard isActive, authenticated, service.isAuthenticated else { throw MopError.authentication }
        let result = try await service.execute(.read(reference), vault: id, offline: false)
        guard current(token), !Task.isCancelled, isActive, visibilityGeneration == visibility,
              vault == id, selectedItem == item, let value = result.value else { throw MopError.authentication }
        guard let expires = result.otpExpiresAt, let period = result.otpPeriod else { throw MopError.invalidOTP }
        return (String(decoding: value, as: UTF8.self), expires, period)
    }

    func read(copy: Bool) {
        guard let selected else { return }
        conceal()
        let visibility = visibilityGeneration
        perform { token in
            let result = try await self.service.execute(.read(selected), vault: self.selectedVault, offline: false)
            guard self.current(token), self.selected == selected, self.isActive, self.visibilityGeneration == visibility else { return }
            guard let value = result.value else { throw MopError.invalidVault }
            if copy {
                self.clipboard.copy(value, concealed: result.valueIsConcealed)
                self.copyFeedback = CopyFeedback(reference: selected, message: "Copied")
            } else {
                self.revealed = value
                self.concealTask = Task { [weak self = self] in
                    try? await Task.sleep(for: .seconds(30))
                    guard !Task.isCancelled else { return }; self?.conceal()
                }
            }
            if self.offline { self.status = "Read only · verified cache from \(result.offlineDate.map { ISO8601DateFormatter().string(from: $0) } ?? "unknown time")" }
        }
    }
    func write(reference: SecretReference, value: String, replace: Bool) {
        guard !offline else { return }
        if var item = catalog?.items.first(where: { $0.name == reference.item }) {
            let path = [reference.section, reference.field].compactMap { $0 }.map(SecretReference.encode).joined(separator: "/")
            if let i = item.fields.firstIndex(where: { $0.path == path }) {
                guard replace else { error = MopError.duplicate.errorDescription; return }
                item.fields[i].value = value
            } else {
                guard !replace else { error = MopError.notFound.errorDescription; return }
                item.fields.append(ItemField(path: path, value: value))
            }
            saveItem(item, create: false); return
        }
        let value = SecretBytes(utf8: value)
        perform { token in
            let result = try await self.service.execute(.write(reference, value, replace: replace), vault: self.selectedVault, offline: false)
            guard self.current(token) else { return }
            try self.applyCatalog(result.requireCatalog())
            try await self.unlockContents(token, refresh: false)
            self.selected = reference; self.selectedItem = reference.item
            self.sheet = nil; self.conceal(); self.notice = "Secret saved to iCloud."
        }
    }
    func delete() {
        guard let selected, !offline else { return }
        if let item = selectedTypedItem, let field = metadata(selected), item.isTemplateField(field) { return }
        if var item = selectedTypedItem, item.fields.count > 1 {
            item.fields.removeAll { selected.relativePath == SecretReference.encode(item.name) + "/" + $0.path }
            saveItem(item, create: false); return
        }
        perform { token in
            let result = try await self.service.execute(.delete(selected), vault: self.selectedVault, offline: false)
            guard self.current(token) else { return }
            try self.applyCatalog(result.requireCatalog())
            self.selected = nil; self.conceal()
            if self.itemFields.isEmpty { self.selectedItem = nil }
            self.notice = "Secret deleted. Historical encrypted copies remain."
        }
    }
    func loadMembers() {
        guard !offline else { return }
        perform { token in
            let result = try await self.service.execute(.members, vault: self.selectedVault, offline: false)
            guard self.current(token) else { return }
            self.members = result.members
            self.status = "Account membership verified"
        }
    }
    func management(_ action: VaultManagement, keepSheet: Bool = false) {
        guard !offline else { return }
        perform { token in
            let result = try await self.service.execute(.manage(action), vault: self.selectedVault, offline: false)
            guard self.current(token) else { return }
            if let catalog = result.catalog { try self.applyCatalog(catalog) }
            if !keepSheet { self.sheet = nil }
            self.notice = result.message
            self.automaticUnlockNeedsRepair = false; self.automaticUnlockBlocked = false
        }
    }
    func cloudChanged() {
        cloudRefreshPending = true
        nextCloudRefresh = .distantPast
        refreshCloudIfNeeded()
    }
    func refreshCloudIfNeeded() {
        guard launchAttempted, isActive, !busy, !refreshing, itemDraft == nil, sheet == nil,
              !automaticUnlockNeedsRepair, wallNow() >= nextCloudRefresh else { return }
        guard cloudRefreshPending || authenticated else { return }
        cloudRefreshPending = false
        // Push delivery is best effort. Reconcile periodically as well as on
        // notifications, foregrounding and network reconnection.
        nextCloudRefresh = wallNow().addingTimeInterval(60)
        guard authenticated else { discover(); return }
        let token = generation, revision = foregroundRevision, editing = editorGeneration
        let selectedVault = vault, requested = requestedVaultIDs
        refreshing = true
        refreshTask = Task {
            defer { refreshing = false }
            guard current(token), !Task.isCancelled, isActive else { return }
            do {
                let discovery = try await service.execute(.discover, vault: nil, offline: false)
                guard current(token), !Task.isCancelled else { return }
                let available = Set(discovery.vaults.map(\.id))
                guard requested.allSatisfy({ available.contains($0) }) else { lock(); return }
                var loaded: [String: ItemCatalog] = [:], deleted: [String: ItemCatalog] = [:]
                var dates: [Date] = []
                for id in requested {
                    let result = try await service.execute(.catalog, vault: id, offline: false)
                    guard current(token), !Task.isCancelled else { return }
                    loaded[id] = try result.requireCatalog(); deleted[id] = result.deletedCatalog
                    if let date = result.offlineDate { dates.append(date) }
                }
                // A foreground operation or draft may have started while fetching.
                // Never replace its state with an earlier refresh result.
                guard isActive, !busy, itemDraft == nil, sheet == nil,
                      revision == foregroundRevision, editing == editorGeneration,
                      vault == selectedVault, requestedVaultIDs == requested else {
                    cloudRefreshPending = true; nextCloudRefresh = .distantPast; return
                }
                if catalog?.revision != loaded[vault]?.revision { conceal() }
                vaults = discovery.vaults; catalogs = loaded; deletedCatalogs = deleted
                retentionDate = wallNow(); offline = !dates.isEmpty
                if let next = loaded[vault] { try applyCatalog(next) }
                if let item = selectedItem, catalog?.items.contains(where: { $0.name == item }) != true { selectedItem = nil }
                if let selected, !references.contains(selected) { self.selected = nil }
                let date = dates.min().map { ISO8601DateFormatter().string(from: $0) } ?? "unknown time"
                status = offline ? "Read only · oldest verified cache from \(date)" : "Unlocked · \(loaded.count) vault\(loaded.count == 1 ? "" : "s")"
            } catch {
                guard token == generation, !Task.isCancelled else { return }
                if let failure = error as? MopError,
                   [.authentication, .signing, .invalidIdentity, .invalidVault, .vaultUntrusted, .notVaultMember, .cloudAccount].contains(failure) {
                    lock()
                    self.error = failure.errorDescription
                } else {
                    cloudRefreshPending = true
                }
            }
        }
    }
    func createPreparedVault(_ intent: PendingVaultCreation) {
        guard !offline, !busy, intent.exported else { return }
        clearView()
        allVaults = false; vault = intent.id.uuidString
        if !vaults.contains(where: { $0.id == vault }) {
            vaults.append(VaultDescriptor(id: vault, name: intent.name, format: "mop-vault-v5", enrolled: true))
        }
        status = "Creating or reconciling vault " + vault
        perform { token in
            let result = try await self.service.execute(.createPrepared, vault: intent.id.uuidString, offline: false)
            guard self.current(token) else { return }
            try self.applyCatalog(result.requireCatalog())
            try await self.unlockContents(token, refresh: false)
            self.sheet = nil; self.notice = result.message
            self.status = "Vault created"
        }
    }

    func createVault(name: String, recovery: URL) {
        guard !offline, !busy else { return }
        conceal(); catalog = nil; catalogs = [:]; passwordQualities = [:]; references = []; selected = nil; members = []; authenticated = false
        let id = UUID().uuidString
        perform { token in
            // Retain this UUID even on a failed/uncertain initialization for reconciliation.
            self.allVaults = false; self.vault = id; self.vaults.append(VaultDescriptor(id: id, name: name, format: "mop-vault-v5", enrolled: true))
            self.status = "Creating vault \(id) · retain any recovery file written"
            let result = try await self.service.execute(.create(name: name, recovery: recovery), vault: id, offline: false)
            guard self.current(token) else { return }
            try self.applyCatalog(result.requireCatalog())
            try await self.unlockContents(token, refresh: false)
            self.selected = nil; self.sheet = nil
            self.notice = result.message; self.status = "Vault created · move the recovery credential offline"
        }
    }
    func renameVault(to name: String) {
        guard !offline, !vault.isEmpty else { return }
        let id = vault
        perform { token in
            let result = try await self.service.execute(.rename(name), vault: id, offline: false)
            guard self.current(token), self.vault == id else { return }
            try self.applyCatalog(result.requireCatalog())
            try await self.unlockContents(token, refresh: false)
            self.sheet = nil; self.selected = nil; self.conceal()
            if let index = self.vaults.firstIndex(where: { $0.id == id }) {
                let old = self.vaults[index]
                self.vaults[index] = VaultDescriptor(id: id, name: name, format: old.format, enrolled: old.enrolled)
            }
            self.notice = "Vault renamed. Update existing references."
        }
    }
    func deleteVault(target: VaultDescriptor, confirmation: String) {
        guard !offline, !busy, vault == target.id, confirmation == (target.name ?? target.id) else { return }
        conceal(); clearClipboard(); catalog = nil; references = []; selected = nil; selectedItem = nil; authenticated = false
        perform { token in
            _ = try await self.service.execute(.deleteVault, vault: target.id, offline: false)
            guard self.current(token), self.vault == target.id else { return }
            self.lock()
            self.vaults.removeAll { $0.id == target.id }
            self.catalogs[target.id] = nil
            self.vault = ""
            self.notice = "Vault deleted. Backups and caches on other devices remain."
            self.status = "Vault deleted"
        }
    }

    func chooseExportBackup() {
        guard canExportBackup, !busy else { return }
        documentRequest = DocumentRequest(vault: vault, generation: editorGeneration)
    }
    func completeBackupSelection(folder: URL, request: DocumentRequest) {
        guard editorGeneration == request.generation, vault == request.vault else { return }
        exportBackup(to: folder.appendingPathComponent("mop-backup-" + UUID().uuidString + ".mopfile"))
    }
    func exportBackup(to url: URL) {
        guard canExportBackup, !busy else { return }
        let id = vault
        perform { token in
            _ = try await self.service.execute(.export(url), vault: id, offline: false)
            guard self.current(token) else { return }; self.notice = "Encrypted backup exported. Keep your recovery key separately."
        }
    }
}
