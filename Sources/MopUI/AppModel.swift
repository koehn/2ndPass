import SwiftUI
import OSLog
import MopCore
import MopAppSupport
import MopVaultNext

enum AppPage: String, CaseIterable { case secrets = "Secrets", recentlyDeleted = "Recently Deleted" }
enum AppSheet: String, Identifiable { case createVault, enrollDevice, addDevice, shareAccount, setupRecovery, renameVault, deleteVault, recover, importItems
    var id: String { rawValue }
}

@MainActor @Observable
final class AppModel {
    let service: any VaultService
    let documents: any DocumentAccessing
    let clipboard: any SecretClipboardAccess
    var isActive = true
    var vaults: [VaultDescriptor] = []
    var vault = "" {
        didSet {
            if case .vault = collection { collection = .vault(vault) }
            invalidateItemSearch()
        }
    }
    var collection: ItemCollection = .vault("") { didSet { invalidateItemSearch() } }
    // Convenience accessors for actions, backed by one collection state.
    var allVaults: Bool {
        get { if case .vault = collection { return false }; return collection != .recentlyDeleted }
        set { collection = newValue ? .all : .vault(vault) }
    }
    var catalogs: [String: ItemCatalog] = [:] { didSet { invalidateItemSearch(); reloadUsage() } }
    var deletedCatalogs: [String: ItemCatalog] = [:] { didSet { invalidateDeletedSearch() } }
    var selectedDeleted: ItemRow.ID? { didSet { rememberSelection() } }
    var itemToDelete: ItemRow?
    var retentionDate = Date() { didSet { invalidateDeletedSearch() } }
    private var nextRetentionSweep = Date.distantPast
    @ObservationIgnored private let wallNow: () -> Date
    var passwordQualities: [String: PasswordQuality] = [:]
    private var launchAttempted = false
    var page: AppPage {
        get { collection == .recentlyDeleted ? .recentlyDeleted : .secrets }
        set { if newValue == .recentlyDeleted { collection = .recentlyDeleted }
            else if collection == .recentlyDeleted { collection = .vault(vault) } }
    }
    var selectedItem: String? { didSet { rememberSelection() } }
    var catalog: ItemCatalog? { didSet { invalidateItemSearch() } }
    var references: [SecretReference] = []
    var selected: SecretReference?
    var importAfterCreation = false
    var importing = false
    var importStatus: String?
    var importFraction: Double?
    var importReport: ImportReport?
    var importFailed = false
    var showArchived: Bool {
        get { collection == .archive }
        set { if newValue { collection = .archive } else if collection == .archive { collection = .all } }
    }
    var favoritesOnly: Bool {
        get { collection == .favorites }
        set { if newValue { collection = .favorites } else if collection == .favorites { collection = .all } }
    }
    var search = ""
    var searchIsFocused = false
    var searchHighlighted: ItemRow.ID?
    var searchScope: String { collection.title ?? (vaultName.isEmpty ? "Items" : vaultName) }
    var members: [VaultMemberRecord] = []
    var settingsVisible = false
    var devices: [VaultDeviceRecord] = []
    var deviceRemoved = false
    var removalCleanupPending = false
    private var cachedVaults: Set<String> = []
    var offline = false
    private var cloudRefreshPending = false
    private var nextCloudRefresh = Date.distantPast
    var authenticated = false { didSet { if authenticated { reloadUsage() } } }
    var revealed: SecretBytes?
    var busy = false
    private(set) var localOperation = false
    var showsCloudProgress: Bool { !offline && ((busy && !localOperation) || refreshing) }
    var refreshing = false
    private var foregroundRevision = 0
    @ObservationIgnored private var refreshTask: Task<Void, Never>?
    @ObservationIgnored private var catalogLoadTask: Task<Void, Never>?
    private var catalogLoadGeneration = 0
    private(set) var loadingVaults = false
    private func cancelCatalogLoading() {
        catalogLoadGeneration += 1
        catalogLoadTask?.cancel(); catalogLoadTask = nil; loadingVaults = false
    }
    private static let logger = Logger(subsystem: "com.koehn.mop", category: "App")
    var errorDetails: String?
    var developerDiagnosticsEnabled: Bool { defaults.bool(forKey: DeveloperPreferences.key) }
    var error: String? {
        didSet {
            errorDetails = nil
            if let error { Self.logger.error("Operation failed: \(error, privacy: .private)") }
        }
    }
    var errorMessage: String {
        guard developerDiagnosticsEnabled else { return error ?? "" }
        return (error ?? "") + "\n\n" + (errorDetails ?? "App validation: " + (error ?? "Unknown error"))
    }
    func recordError(_ failure: Error, operation: String) {
        let ns = failure as NSError
        Self.logger.error("\(operation, privacy: .public): \(ns.domain, privacy: .public) (\(ns.code)) — \(String(reflecting: failure), privacy: .private)")
        if developerDiagnosticsEnabled {
            errorDetails = "Operation: \(operation)\nType: \(String(reflecting: type(of: failure)))\nDomain: \(ns.domain)\nCode: \(ns.code)\n\(String(reflecting: failure))\nUser info: \(ns.userInfo)"
        }
    }
    func copyErrorDetails() {
        clipboard.copy(SecretBytes(utf8: errorMessage), concealed: true)
    }
    var notice: String?
    struct CopyFeedback {
        let id = UUID()
        let reference: SecretReference
        let message: String
    }
    var copyFeedback: CopyFeedback?
    var status = "Select a vault to begin"
    var sheetRequest: SheetRequest?
    var sheet: AppSheet? {
        get { sheetRequest?.kind }
        set { sheetRequest = newValue.map { SheetRequest(kind: $0, inSettings: sheetRequest?.inSettings ?? false, target: vaultDetailsTarget ?? selectedVaultDescriptor) } }
    }
    var vaultDetailsTarget: VaultDescriptor?
    var settingsCategory: SettingsCategory = .security {
        didSet { defaults.set(settingsCategory.rawValue, forKey: "settingsCategory") }
    }
    var searchFocusRequest = 0
    var lastBackupURL: URL?
    var lastBackupVaultID: String?
    var membersVaultID: String?
    var securityGeneration = 0
    var deleteConfirmation = false
    var documentRequest: DocumentRequest?
    private var generation = 0
    private var visibilityGeneration = 0
    @ObservationIgnored private let lifecycle: any AppLifecycleMonitoring
    private var concealTask: Task<Void, Never>?

    @ObservationIgnored private let now: () -> TimeInterval
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private var restoreLastSelection = true
    @ObservationIgnored private var restoringSelection = false
    private struct SavedSelection: Codable {
        let collection: ItemCollection
        let vault: String
        let item: String?
    }
    // Device-local defaults contain only opaque account/vault/item IDs. Names and
    // field values remain in the encrypted vault, and are resolved after unlock.
    private func rememberSelection() {
        guard authenticated, !unlocking, !restoringSelection else { return }
        let id = collection == .recentlyDeleted ? selectedDeleted?.vault ?? vault : vault
        guard let account = catalogs[id]?.usageScope else { return }
        let item = collection == .recentlyDeleted
            ? deletedCatalogs[id]?.items.first(where: { $0.name == selectedDeleted?.name })
            : catalogs[id]?.items.first(where: { $0.name == selectedItem })
        let selection = SavedSelection(collection: collection, vault: id, item: item?.storageID)
        if let bytes = try? JSONEncoder().encode(selection) {
            defaults.set(bytes, forKey: "lastSelection." + account)
        }
    }
    private func restoreSelection() {
        guard restoreLastSelection,
              let account = catalogs[vault]?.usageScope ?? catalogs.sorted(by: { $0.key < $1.key }).first?.value.usageScope,
              let bytes = defaults.data(forKey: "lastSelection." + account),
              let saved = try? JSONDecoder().decode(SavedSelection.self, from: bytes) else { return }
        restoringSelection = true
        defer { restoringSelection = false }
        guard let source = catalogs[saved.vault], source.usageScope == account else {
            collection = .all; selectedItem = nil; selectedDeleted = nil
            return
        }
        vault = saved.vault
        collection = saved.collection
        try? applyCatalog(source)
        selectedItem = nil; selectedDeleted = nil
        guard let id = saved.item else { return }
        if collection == .recentlyDeleted {
            if let item = deletedCatalogs[vault]?.items.first(where: { $0.storageID == id && $0.deletion?.isExpired(at: wallNow()) == false }) {
                selectedDeleted = .init(vault: vault, name: item.name)
            }
        } else if let item = source.items.first(where: { $0.storageID == id && $0.deletion == nil }),
                  item.isArchived == (collection == .archive), collection != .favorites || item.isFavorite {
            selectedItem = item.name
        }
    }
    @ObservationIgnored private var inactivityTask: Task<Void, Never>?
    @ObservationIgnored private var operationTask: Task<Void, Never>?
    private var lastActivity: TimeInterval?
    private var launchUnlockAvailable = true
    private var accessNeedsRepair = false
    enum LockReason: Equatable { case initial, manual, timeout, system, accessFailure }
    enum SessionState: Equatable { case locked(LockReason), unlocking, unlocked, needsRepair }
    private var lockReason = LockReason.initial
    private(set) var unlocking = false
    var sessionState: SessionState {
        if unlocking { return .unlocking }
        if authenticated { return .unlocked }
        if accessNeedsRepair { return .needsRepair }
        return .locked(lockReason)
    }
    var sessionStatus: String {
        if unlocking { return "Unlocking 2ndPass…" }
        if authenticated || !hasConnectedVaults { return status }
        if accessNeedsRepair { return "Access needs attention — choose Unlock to retry after repairing access." }
        return lockReason == .timeout ? "Locked after inactivity" : "Locked"
    }
    var canUnlock: Bool { !authenticated && !busy && hasConnectedVaults && !deviceRemoved }
    private(set) var pendingTransition: PendingTransition?
    var showsUnsavedChanges = false
    private(set) var selectionGeneration = 0
    private var transitionCompletion: ((Bool) -> Void)?
    private var applyingTransition = false
    private var savingTransition = false
    var draftConflict = false

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
         usageStore: any ItemUsageStoring = ItemUsageStore(),
         now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         automaticTimer: Bool = true, wallNow: @escaping () -> Date = Date.init) {
        self.lifecycle = lifecycle ?? SystemAppLifecycleMonitor()
        self.wallNow = wallNow; retentionDate = wallNow()
        self.service = service
        self.usageStore = usageStore
        self.documents = documents
        self.clipboard = clipboard ?? SecretClipboard()
        self.defaults = defaults; self.now = now
        settingsCategory = SettingsCategory(rawValue: defaults.string(forKey: "settingsCategory") ?? "") ?? .security
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
                    if self?.removingDevice == true { self?.removalProgress = self?.service.operationProgress ?? "Preparing device removal…" }
                    self?.refreshImportProgress()
                    self?.checkEnrollmentInboxIfNeeded()
                    self?.refreshCloudIfNeeded()
                }
            }
        }
    }
    deinit { catalogLoadTask?.cancel(); usageLoadTask?.cancel(); inactivityTask?.cancel(); automaticUnlockTask?.cancel(); enrollmentTask?.cancel() }
    func checkExpiration() {
        if let started = service.authenticatedAt {
            if lastActivity == nil { lastActivity = started }
            if now() - (lastActivity ?? started) >= Double(autoLockMinutes * 60) {
                lock(reason: .timeout)
            }
        } else if lastActivity != nil {
            if busy && !authenticated {
                // Let an in-flight opening report its failure after the service
                // invalidates authentication. Invalidating its generation here
                // would swallow that error and its automatic-retry pause.
                lastActivity = nil; launchUnlockAvailable = false; conceal()
            } else { lock() }
        }
        scheduleAutomaticUnlock()
    }
    private func scheduleAutomaticUnlock() {
        if needsAccountDiscovery, isActive, !busy {
            needsAccountDiscovery = false
            Task { [weak self] in self?.discover() }
            return
        }
        guard launchAttempted, isActive, !authenticated, !busy, launchUnlockAvailable, !accessNeedsRepair,
              error == nil, sheet == nil, !requestedVaultIDs.isEmpty,
              automaticUnlockTask == nil else { return }
        automaticUnlockTask = Task { [weak self] in
            await Task.yield()
            guard let self else { return }
            self.automaticUnlockTask = nil
            guard !Task.isCancelled, self.isActive, !self.authenticated, !self.busy,
                  self.launchUnlockAvailable, !self.accessNeedsRepair, self.error == nil,
                  self.sheet == nil, !self.requestedVaultIDs.isEmpty else { return }
            self.unlock()
        }
    }
    func activity() {
        checkExpiration()
        guard isActive else { return }
        if service.isAuthenticated { lastActivity = now() }
    }
    private let usageStore: any ItemUsageStoring
    private(set) var lastUsed: [ItemUsageIdentity: Date] = [:] {
        didSet { if collection == .recentlyUsed { invalidateItemSearch() } }
    }
    @ObservationIgnored private var usageLoadTask: Task<Void, Never>?
    private var usageLoadGeneration = 0
    func reloadUsage() {
        guard authenticated else { return }
        usageLoadTask?.cancel()
        usageLoadGeneration += 1
        let load = usageLoadGeneration, security = securityGeneration
        let accounts = Set(catalogs.values.compactMap(\.usageScope))
        let store = usageStore
        usageLoadTask = Task { [weak self] in
            do {
                let loaded = try await store.load(accounts: accounts)
                guard let self, !Task.isCancelled, self.authenticated,
                      self.securityGeneration == security, self.usageLoadGeneration == load else { return }
                self.lastUsed = loaded.merging(self.lastUsed.filter { accounts.contains($0.key.account) }, uniquingKeysWith: max)
            } catch { if !Task.isCancelled { ItemUsageLogging.failure(error) } }
        }
    }
    func recordUsage(_ identity: ItemUsageIdentity?) {
        guard authenticated, isActive, let identity else { return }
        let date = wallNow()
        lastUsed[identity] = max(lastUsed[identity] ?? .distantPast, date)
        let store = usageStore
        Task { await ItemUsageLogging.record([identity], at: date, store: store) }
    }
    func recordSelectedItemUsage() {
        guard let item = selectedTypedItem else { return }
        recordUsage(catalog?.usageIdentity(for: item, vaultID: vault))
    }
    func lastUsedDate(for item: VaultItem, vaultID: String) -> Date? {
        guard let identity = catalogs[vaultID]?.usageIdentity(for: item, vaultID: vaultID) else { return nil }
        return lastUsed[identity]
    }
    func recentDate(for row: ItemRow) -> Date? {
        switch collection {
        case .recentlyAdded: row.item.metadata?.addedAt
        case .recentlyChanged: row.item.metadata?.updatedAt
        case .recentlyUsed: lastUsedDate(for: row.item, vaultID: row.id.vault)
        default: nil
        }
    }
    var selectedVaultDescriptor: VaultDescriptor? { vaults.first { $0.id == vault } }
    var canExportBackup: Bool { !allVaults && !vault.isEmpty && (selectedVaultDescriptor?.supported == true || authenticated) }
    var vaultName: String { catalog?.vault ?? references.first?.vault ?? vaults.first { $0.id == vault }?.name ?? "" }
    var filtered: [SecretReference] {
        references.filter { search.isEmpty || $0.description.localizedCaseInsensitiveContains(search) }
    }
    var items: [String] { Array(Set(filtered.map(\.item))).sorted() }
    // Revisions keep Observation informed even when the underlying cache is reused.
    private var itemSearchRevision = 0
    private var deletedSearchRevision = 0
    @ObservationIgnored private var itemSearchIndex: ItemSearchIndex?
    @ObservationIgnored private var deletedSearchIndex: ItemSearchIndex?
    private func invalidateItemSearch() {
        itemSearchIndex = nil
        itemSearchRevision &+= 1
    }
    private func invalidateDeletedSearch() {
        deletedSearchIndex = nil
        deletedSearchRevision &+= 1
    }
    private var activeIndex: ItemSearchIndex {
        _ = itemSearchRevision
        if let itemSearchIndex { return itemSearchIndex }
        let included = allVaults ? catalogs : catalog.map { [vault: $0] } ?? [:]
        var rows = included.flatMap { id, catalog in
            catalog.items.filter { $0.deletion == nil && $0.isArchived == showArchived && (!favoritesOnly || $0.isFavorite) }.map { item in
                ItemRow(id: .init(vault: id, name: item.name), vaultName: catalog.vault, item: item)
            }
        }
        if collection.isRecent {
            rows = rows.compactMap { row in
                guard let date = recentDate(for: row) else { return nil }
                var result = row; result.recentDate = date; return result
            }.sorted {
                if $0.recentDate != $1.recentDate { return $0.recentDate! > $1.recentDate! }
                return ($0.item.name, $0.id.vault, $0.item.storageID ?? "") < ($1.item.name, $1.id.vault, $1.item.storageID ?? "")
            }
            rows = Array(rows.prefix(50))
        } else {
            rows.sort { ($0.item.name, $0.vaultName, $0.id.vault) < ($1.item.name, $1.vaultName, $1.id.vault) }
        }
        let index = ItemSearchIndex(rows: rows)
        itemSearchIndex = index
        return index
    }
    private var deletedIndex: ItemSearchIndex {
        _ = deletedSearchRevision
        if let deletedSearchIndex { return deletedSearchIndex }
        let rows = deletedCatalogs.flatMap { id, catalog in
            catalog.items.compactMap { item -> ItemRow? in
                guard let deletion = item.deletion, !deletion.isExpired(at: retentionDate) else { return nil }
                return ItemRow(id: .init(vault: id, name: item.name), vaultName: catalog.vault, item: item)
            }
        }.sorted { ($0.item.deletion?.deletedAt ?? .distantPast) > ($1.item.deletion?.deletedAt ?? .distantPast) }
        let index = ItemSearchIndex(rows: rows, deleted: true)
        deletedSearchIndex = index
        return index
    }
    var unfilteredItems: [ItemRow] { activeIndex.rows }
    var displayedItems: [ItemRow] { activeIndex.search(search).rows }
    var listSelection: ItemRow.ID? {
        get {
            if searchIsFocused, !search.isEmpty { return searchHighlighted }
            return selectedRow.flatMap { activeIndex.search(search).ids.contains($0) ? $0 : nil }
        }
        set {
            if newValue == nil, let selectedRow, !activeIndex.search(search).ids.contains(selectedRow) { return }
            self.selectedRow = newValue
        }
    }
    var searchResults: [ItemSearchResult] { activeIndex.search(search).results }
    var allDeletedRows: [ItemRow] { deletedIndex.rows }
    var deletedRows: [ItemRow] { deletedIndex.search(search).rows }
    var deletedListSelection: ItemRow.ID? {
        get { searchIsFocused && !search.isEmpty ? searchHighlighted : selectedDeleted.flatMap { deletedIndex.search(search).ids.contains($0) ? $0 : nil } }
        set {
            if newValue == nil, let selectedDeleted, !deletedIndex.search(search).ids.contains(selectedDeleted) { return }
            selectedDeleted = newValue
        }
    }
    var selectedDeletedItem: ItemRow? { allDeletedRows.first { $0.id == selectedDeleted } }
    func chooseRecentlyDeleted() {
        guard !busy, allowTransition(.recentlyDeleted) else { return }
        collection = .recentlyDeleted
        changedVault()
        scheduleAutomaticUnlock()
    }
    func trashItem(_ row: ItemRow) {
        guard !busy, !offline, authenticated, let source = catalogs[row.id.vault],
              source.items.contains(where: { $0.name == row.id.name }) else { return }
        guard allowTransition(.trash(row)) else { return }
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
            guard !busy, (newValue != selectedRow || vaultDetailsTarget != nil), allowTransition(.item(newValue)) else { return }
            vaultDetailsTarget = nil
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
        guard !busy, allowTransition(.vault(id)) else { return }
        showArchived = false; favoritesOnly = false
        allVaults = false; page = .secrets; vault = id
        changedVault()
        if vaults.first(where: { $0.id == id })?.enrolled == false { sheet = .enrollDevice; return }
        scheduleAutomaticUnlock()
    }
    /// Target the row's vault without starting an unlock that could race the action.
    func prepareVaultAction(_ id: String) -> Bool {
        checkExpiration()
        guard !busy, vaults.contains(where: { $0.id == id }), allowTransition(.vaultTarget(id)) else { return false }
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
        guard !busy, allowTransition(.allItems) else { return }
        showArchived = false; favoritesOnly = false
        allVaults = true; page = .secrets
        changedVault()
        scheduleAutomaticUnlock()
    }
    func chooseCollection(archived: Bool) {
        guard !busy, allowTransition(.collection(archived: archived)) else { return }
        collection = archived ? .archive : .favorites
        changedVault()
    }
    func chooseRecent(_ collection: ItemCollection) {
        guard collection.isRecent, !busy, allowTransition(.recent(collection)) else { return }
        self.collection = collection
        changedVault()
    }
    func toggleFavorite() {
        guard authenticated, !busy, !offline, itemDraft == nil, let item = selectedTypedItem else { return }
        guard let catalog else { return }
        itemDraft = ItemDraft(vault: vault, revision: catalog.revision, item: item)
        if itemDraft?.metadata == nil { itemDraft?.metadata = ItemMetadata() }
        itemDraft?.metadata?.favorite = !item.isFavorite
        saveItemDraft()
    }
    var sidebarSelection: String {
        get { collection.sidebarID }
        set {
            guard newValue != sidebarSelection else { return }
            if newValue == "recent-added" { chooseRecent(.recentlyAdded) }
            else if newValue == "recent-changed" { chooseRecent(.recentlyChanged) }
            else if newValue == "recent-used" { chooseRecent(.recentlyUsed) }
            else if newValue == "archive" { chooseCollection(archived: true) }
            else if newValue == "favorites" { chooseCollection(archived: false) }
            else if newValue == "deleted" { chooseRecentlyDeleted() }
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
        vaults.filter { $0.supported && $0.enrolled && catalogs[$0.id] != nil && catalogs[$0.id]?.canEdit != false }
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
        conceal(); selected = nil; selectedItem = nil; vaultDetailsTarget = nil
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
        let protectedFields = item.fields.filter { ($0.type == .password || $0.type.isCompound) && $0.value == nil && (path == nil || $0.path == path) }
        guard !protectedFields.isEmpty, let draft = itemDraft else { return }
        perform(local: true) { token in
            do {
                for field in protectedFields {
                    let reference = try SecretReference(vault: catalog.vault,
                        relativePath: SecretReference.encode(item.name) + "/" + field.path)
                    let result = try await self.service.readLocal(reference, vault: draft.vault)
                    guard self.current(token), self.itemDraft?.id == draft.id,
                          self.vault == draft.vault, self.selectedItem == draft.originalName else { return }
                    guard let value = result.value else { throw MopError.invalidVault }
                    guard let index = self.itemDraft?.fields.firstIndex(where: { $0.path == field.path }) else { continue }
                    // Preserve input if an edit was made while this read was pending.
                    guard self.itemDraft?.fields[index].value == draft.fields.first(where: { $0.path == field.path })?.value else { continue }
                    let plaintext = String(decoding: value, as: UTF8.self)
                    if field.type.isCompound {
                        _ = try CompoundField(plaintext)
                        self.itemDraft?.fields[index].loadedCompound = plaintext
                    } else { self.itemDraft?.fields[index].loadedPassword = plaintext }
                    self.itemDraft?.fields[index].value = plaintext
                }
            } catch {
                // Keep the draft on recoverable read failures; nil still means unchanged.
                throw error
            }
        }
    }
    func cancelItemEditing() { itemDraft = nil; draftConflict = false; conceal() }
    func saveItemDraft() {
        guard !busy, authenticated, !offline, !draftConflict else { return }
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
        guard let name = descriptor.name else { return "Unnamed vault · " + String(descriptor.id.prefix(8)) }
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
            case .lock: self.deactivate(); self.lock(reason: .system)
            case .accountChanged:
                self.lock(); self.submittedEnrollments = []; self.enrollmentSelection = []; self.enrollmentProgress = [:]; self.vaults = []; self.vault = ""
                self.launchUnlockAvailable = false
                self.accessNeedsRepair = false
                self.needsAccountDiscovery = true
                self.scheduleAutomaticUnlock()
            case .terminate: self.shutdown()
            case .activity: self.activity()
            }
        }
    }
    func shutdown() { isActive = false; lock(); inactivityTask?.cancel(); lifecycle.stop() }
    func background() {
        deactivate()
        // A temporary app switch preserves the authenticated vault session.
        // Pending authentication cannot continue in the background.
        if (busy || enrollmentWorking) && !authenticated { lock(clearClipboard: false) }
        checkExpiration()
    }
    func deactivate() { isActive = false; visibilityGeneration += 1; conceal(); automaticUnlockTask?.cancel(); automaticUnlockTask = nil }
    func activate() {
        checkExpiration(); isActive = true
        reloadUsage()
        if service.isAuthenticated, !busy { lastActivity = now() }
        scheduleAutomaticUnlock(); checkRetention()
        if launchAttempted && authenticated { cloudChanged() }
    }
    private func clearSelection() {
        generation += 1; editorGeneration += 1; itemDraft = nil; draftConflict = false
        selectedDeleted = nil; itemToDelete = nil
        conceal(); catalog = nil; passwordQualities = [:]; references = []; selected = nil; members = []
        selectedItem = nil; sheet = nil; notice = nil
        importing = false; importStatus = nil; importFraction = nil; importReport = nil; importFailed = false
        vaultDetailsTarget = nil; deleteConfirmation = false; documentRequest = nil; error = nil
    }
    private func clearView() {
        authenticated = false
        clearSelection()
        catalogs = [:]; deletedCatalogs = [:]; cachedVaults = []
    }
    func lock(clearClipboard: Bool = true, reason: LockReason = .manual) {
        rememberSelection(); restoreLastSelection = true
        enrollmentGeneration += 1; enrollmentTask?.cancel(); enrollmentTask = nil; enrollmentWorking = false
        for id in submittedEnrollments { enrollmentProgress[id, default: EnrollmentProgress()].phase = .paused }
        securityGeneration += 1
        usageLoadTask?.cancel(); usageLoadGeneration += 1; lastUsed = [:]
        search = ""; searchHighlighted = nil; searchIsFocused = false; lastBackupURL = nil
        lockReason = reason; unlocking = false; launchUnlockAvailable = false
        cancelPendingTransition()
        copyFeedback = nil; exchangeOutput = ""
        automaticUnlockTask?.cancel(); automaticUnlockTask = nil
        cancelCatalogLoading()
        service.lock(); operationTask?.cancel(); refreshTask?.cancel(); lastActivity = nil
        clearView(); if clearClipboard { self.clearClipboard() }
        status = "Locked"
    }
    func changedVault() {
        restoreLastSelection = false
        checkExpiration()
        clearSelection()
        guard service.isAuthenticated else { authenticated = false; status = "Ready to authenticate"; return }
        let ids = requestedVaultIDs
        if !ids.isEmpty && catalogs[vault] != nil {
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
        return authenticated && catalogs[descriptor.id] != nil ? "lock.open" : "lock.rectangle"
    }
    func vaultConnectionLabel(_ descriptor: VaultDescriptor) -> String {
        if !descriptor.supported { return "Unsupported vault" }
        if !descriptor.enrolled { return "Not connected to this device" }
        return authenticated && catalogs[descriptor.id] != nil ? "Unlocked" : "Locked"
    }

    func beginImport() {
        importAfterCreation = itemCreationVaults.isEmpty
        presentSheet(importAfterCreation ? .createVault : .importItems)
    }
    func refreshImportProgress() {
        guard importing else { return }
        importStatus = service.operationProgress ?? "Preparing import…"
        importFraction = service.operationFraction
    }
    func commitImport(_ document: ImportDocument, preview: ImportPreview, selected: Set<Int>, destination: String) {
        guard !busy else { return }
        perform { token in
            self.importing = true; self.importFailed = false; self.importReport = nil
            self.importStatus = "Preparing import…"; self.importFraction = nil
            defer { self.importing = false; self.importFraction = nil }
            do {
                let result = try await self.service.execute(.commitImport(document, selected: selected, vault: preview.vault, revision: preview.revision), vault: destination, offline: self.offline)
                guard self.current(token), !Task.isCancelled else { return }
                guard let report = result.importReport else { throw MopError.invalidVault }
                self.importReport = report
                self.importStatus = report.committed ? "Import complete. " + report.summary : "Import not completed. " + report.summary
                self.importFailed = !report.committed
                if let catalog = result.catalog {
                    self.catalogs[destination] = catalog
                    if self.vault == destination { self.catalog = catalog }
                }
            } catch {
                if self.current(token) {
                    self.importFailed = true
                    self.importStatus = error as? MopError == .cloudUncertain
                        ? "Import confirmation is pending. Refresh to check whether it completed before trying again."
                        : "Import did not complete. " + ((error as? MopError)?.errorDescription ?? (error as? ImportFailure)?.errorDescription ?? (error as? AttachmentFailure)?.errorDescription ?? "Refresh the vault and try again.")
                }
                throw error
            }
        }
        if busy { sheet = nil }
    }
    func cancelImportOperation() { operationTask?.cancel() }

    func perform(local: Bool = false, operation: String = #function, file: String = #fileID, line: Int = #line, _ action: @escaping @MainActor (Int) async throws -> Void) {
        checkExpiration()
        guard !busy else { return }
        foregroundRevision += 1
        busy = true; localOperation = local; error = nil; notice = nil
        let token = generation
        operationTask = Task {
            defer {
                busy = false; localOperation = false; checkExpiration()
                removingDevice = false; removalProgress = nil
                if savingTransition {
                    if itemDraft == nil && error == nil && token == generation { completePendingTransition() }
                    else { cancelPendingTransition() }
                }
            }
            guard self.current(token) else { return }
            do { try await action(token) }
            catch {
                if token == generation && !Task.isCancelled {
                    if error as? MopError == .deviceRemoved || error as? MopError == .deviceRemovalPending {
                        self.showDeviceRemoved(pending: error as? MopError == .deviceRemovalPending); return
                    }
                    self.launchUnlockAvailable = false
                    self.cancelPendingTransition()
                    if error as? MopError == .vaultConflict, self.itemDraft != nil { self.draftConflict = true }
                    // A trust/account/data failure needs repair. Taps and Face ID
                    // lifecycle notifications must not repeat the same failure.
                    if (!self.authenticated && error as? MopError != .authentication) || error as? MopError == .vaultUntrusted {
                        self.accessNeedsRepair = true
                    }
                    if let failure = error as? MopError,
                       [.authentication, .signing, .invalidIdentity, .invalidVault, .vaultUntrusted, .notVaultMember, .cloudAccount].contains(failure) { self.lock(reason: .accessFailure) }
                    // Framework errors may contain arbitrary diagnostics. Only
                    // domain errors have user-safe messages.
                    if error as? MopError == .vaultUntrusted {
                        self.error = "Vault trust could not be verified. Automatic unlocking is paused. Repair access from an authorized owner device or use the separate hardware recovery device. Older vault formats are unsupported."
                    } else {
                        self.error = (error as? MopError)?.errorDescription ?? (error as? ImportFailure)?.errorDescription ?? (error as? AttachmentFailure)?.errorDescription ?? (error as? CompoundFieldFailure)?.errorDescription ?? "The operation could not be completed."
                    }
                    self.recordError(error, operation: "\(operation) at \(file):\(line)")
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
        guard !busy, allowTransition(.refresh) else { return }
        let refreshContents = authenticated
        perform { token in
            let result = try await self.service.execute(.discover, vault: nil, offline: false)
            if result.deviceRemoved { self.showDeviceRemoved(); return }
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
                self.vault = ""; self.lock(reason: .accessFailure)
                if rows.isEmpty { self.sheet = .createVault }
                else if !rows.contains(where: { $0.supported && $0.enrolled }) { self.sheet = .enrollDevice }
                return
            }
            self.status = ids.isEmpty ? "Create your first vault" : self.authenticated ? "Refreshing vaults…" : "Locked"
            if self.sheet == nil {
                if rows.isEmpty { self.sheet = .createVault }
                else if !rows.contains(where: { $0.supported && $0.enrolled }) {
                    self.status = "Connect this device to your iCloud vault"
                    self.sheet = .enrollDevice
                }
            }
            if self.authenticated && self.requestedVaultIDs.contains(where: { self.catalogs[$0] == nil }) {
                self.authenticated = false
            }
            if self.isActive, (refreshContents || (autoUnlock && self.launchUnlockAvailable)),
               rows.contains(where: { $0.supported && $0.enrolled }) {
                if !selectedOnly && !refreshContents { self.allVaults = true }
                try await self.unlockContents(token)
            }
        }
    }
    func unlock() {
        guard !busy, !authenticated, isActive, !deviceRemoved else { return }
        launchUnlockAvailable = false; accessNeedsRepair = false
        cancelItemEditing(); conceal(); catalog = nil; catalogs = [:]; deletedCatalogs = [:]
        passwordQualities = [:]; references = []; authenticated = false
        perform { token in try await self.unlockContents(token) }
    }
    private func unlockContents(_ token: Int, refresh: Bool = true) async throws {
        cancelCatalogLoading()
        launchUnlockAvailable = false
        let openingSession = !authenticated
        if openingSession { unlocking = true }
        defer { if openingSession { unlocking = false; if !loadingVaults { rememberSelection() } } }
        do {
            let requested = requestedVaultIDs
            let ids = requested.contains(vault) ? [vault] + requested.filter { $0 != vault } : requested
            guard !ids.isEmpty else { status = "Connect this device to a vault to get started."; return }
            var loaded = refresh ? [:] : catalogs.filter { ids.contains($0.key) }
            var deleted = refresh ? [:] : deletedCatalogs.filter { ids.contains($0.key) }
            var dates: [String: Date] = [:]
            for id in ids {
                if loaded[id] != nil { break }
                let result: VaultResult
                do {
                    if openingSession, let cached = try await service.cachedCatalog(vault: id) { result = cached }
                    else { result = try await service.execute(.catalog, vault: id, offline: false) }
                }
                catch MopError.vaultMissing {
                    let discovery = try await service.execute(.discover, vault: nil, offline: false)
                    guard current(token) else { return }
                    guard !discovery.vaults.contains(where: { $0.id == id }) else { throw MopError.vaultMissing }
                    vaults = discovery.vaults
                    loaded.removeValue(forKey: id); deleted.removeValue(forKey: id)
                    if vault == id { vault = "" }
                    continue
                }
                guard current(token) else { return }
                loaded[id] = try result.requireCatalog()
                deleted[id] = result.deletedCatalog
                dates[id] = result.offlineDate
                if result.usingCache { cachedVaults.insert(id) } else { cachedVaults.remove(id) }
                break
            }
            guard current(token) else { return }
            offline = !cachedVaults.isEmpty || !dates.isEmpty
            catalogs = loaded; deletedCatalogs = deleted; retentionDate = wallNow()
            guard !loaded.isEmpty else {
                service.lock(); authenticated = false; lastActivity = nil
                catalog = nil; references = []; vault = ""
                status = vaults.isEmpty ? "Create your first vault" : "Connect this device to a vault to get started."
                sheet = vaults.isEmpty ? .createVault : .enrollDevice
                return
            }
            if vault.isEmpty { vault = ids.first(where: { loaded[$0] != nil }) ?? "" }
            if let catalog = loaded[vault] { try applyCatalog(catalog) }
            else { catalog = nil; references = [] }
            authenticated = true; accessNeedsRepair = false
            if openingSession { restoreSelection() }
            if lastActivity == nil { lastActivity = now() }
            for (id, catalog) in loaded {
                vaults.removeAll { $0.id == id }
                vaults.append(VaultDescriptor(id: id, name: catalog.vault, format: "mop-vault-v7", enrolled: true))
            }
            if let item = selectedItem, catalog?.items.contains(where: { $0.name == item }) != true { selectedItem = nil }
            if let selected, !references.contains(selected) { self.selected = nil }
            let date = dates.values.min().map { ISO8601DateFormatter().string(from: $0) } ?? "unknown time"
            status = offline ? "Read only · oldest verified cache from \(date)" : "Unlocked · \(loaded.count) vault\(loaded.count == 1 ? "" : "s")"
            loadRemainingCatalogs(ids.filter { (loaded[$0] == nil || cachedVaults.contains($0)) && requestedVaultIDs.contains($0) }, token: token)
        } catch {
            // The selected vault must verify before opening the session.
            service.lock(); lastActivity = nil; authenticated = false
            catalog = nil; catalogs = [:]; deletedCatalogs = [:]; references = []
            passwordQualities = [:]; conceal(); clearClipboard()
            throw error
        }
    }
    private func loadRemainingCatalogs(_ ids: [String], token: Int) {
        guard !ids.isEmpty else { return }
        let load = catalogLoadGeneration, editing = editorGeneration
        let revisions = catalogs.mapValues(\.revision)
        let service = service
        loadingVaults = true
        catalogLoadTask = Task { [weak self] in
            await withTaskGroup(of: (String, Result<VaultResult, Error>).self) { group in
                for id in ids {
                    group.addTask {
                        do { return (id, .success(try await service.execute(.catalog, vault: id, offline: false))) }
                        catch { return (id, .failure(error)) }
                    }
                }
                for await (id, outcome) in group {
                    guard let self, !Task.isCancelled, self.current(token), self.authenticated,
                          self.catalogLoadGeneration == load else { group.cancelAll(); return }
                    do {
                        let result = try outcome.get()
                        // A foreground edit/refresh supersedes this snapshot.
                        guard self.catalogs[id]?.revision == revisions[id], self.editorGeneration == editing, self.itemDraft == nil else {
                            self.cloudRefreshPending = true; continue
                        }
                        guard self.requestedVaultIDs.contains(id) else { continue }
                        let fresh = try result.requireCatalog()
                        if self.vault == id, self.catalog?.revision != fresh.revision { self.conceal() }
                        try self.applyTargetCatalog(fresh, id: id)
                        self.deletedCatalogs[id] = result.deletedCatalog
                        if let index = self.vaults.firstIndex(where: { $0.id == id }), let catalog = result.catalog {
                            self.vaults[index] = VaultDescriptor(id: id, name: catalog.vault, format: "mop-vault-v7", enrolled: true)
                        }
                        self.restoreSelection()
                        if self.vault == id {
                            if let item = self.selectedItem, !fresh.items.contains(where: { $0.name == item }) { self.selectedItem = nil }
                            if let selected = self.selected, !self.references.contains(selected) { self.selected = nil }
                        }
                        if result.usingCache { self.cachedVaults.insert(id) } else { self.cachedVaults.remove(id) }
                        self.offline = !self.cachedVaults.isEmpty
                        if !self.offline { self.status = "Unlocked · \(self.catalogs.count) vaults" }
                    } catch {
                        if error as? MopError == .deviceRemoved || error as? MopError == .deviceRemovalPending {
                            self.showDeviceRemoved(pending: error as? MopError == .deviceRemovalPending)
                            group.cancelAll(); return
                        }
                        if let failure = error as? MopError,
                           [.authentication, .cloudAccount, .signing, .invalidIdentity, .invalidVault, .vaultUntrusted, .notVaultMember].contains(failure) {
                            self.lock(reason: .accessFailure)
                            self.error = failure.errorDescription
                            group.cancelAll(); return
                        }
                        if error as? MopError == .vaultMissing {
                            do {
                                let discovery = try await service.execute(.discover, vault: nil, offline: false)
                                guard self.current(token), !Task.isCancelled, self.catalogLoadGeneration == load else { group.cancelAll(); return }
                                if discovery.deviceRemoved {
                                    self.showDeviceRemoved(); group.cancelAll(); return
                                }
                                if !discovery.vaults.contains(where: { $0.id == id }) {
                                    self.vaults.removeAll { $0.id == id }
                                    self.catalogs[id] = nil; self.deletedCatalogs[id] = nil
                                    self.cachedVaults.remove(id)
                                    if self.vault == id {
                                        self.vault = ""; self.lock(reason: .accessFailure)
                                        if self.vaults.isEmpty { self.sheet = .createVault }
                                        group.cancelAll(); return
                                    }
                                    self.offline = !self.cachedVaults.isEmpty
                                    continue
                                }
                            } catch {
                                if error as? MopError == .cloudAccount {
                                    self.lock(reason: .accessFailure)
                                    self.error = MopError.cloudAccount.errorDescription
                                    group.cancelAll(); return
                                }
                                // Preserve references when discovery fails.
                            }
                        }
                        // A slow/unavailable secondary vault must not close the
                        // verified selected vault. Periodic refresh retries it.
                        self.notice = "Some vaults could not be loaded. Refresh to retry."
                        self.cloudRefreshPending = true
                    }
                }
            }
            guard let self, self.catalogLoadGeneration == load else { return }
            self.loadingVaults = false; self.catalogLoadTask = nil
            self.rememberSelection()
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
        let result = try await service.readLocal(reference, vault: id)
        guard current(token), !Task.isCancelled, isActive, visibilityGeneration == visibility,
              vault == id, selectedItem == item, let value = result.value else { throw MopError.authentication }
        guard let expires = result.otpExpiresAt, let period = result.otpPeriod else { throw MopError.invalidOTP }
        return (String(decoding: value, as: UTF8.self), expires, period)
    }

    func loadAttachment(_ reference: SecretReference, completion: @escaping @MainActor (Attachment) -> Void) {
        let visibility = visibilityGeneration, id = selectedVault, item = selectedItem
        perform { token in
            let result = try await self.service.execute(.read(reference), vault: id, offline: self.offline)
            guard self.current(token), self.isActive, self.visibilityGeneration == visibility,
                  self.selectedVault == id, self.selectedItem == item, let value = result.value else { return }
            completion(try Attachment.decode(String(decoding: value, as: UTF8.self)))
        }
    }

    func read(copy: Bool) {
        guard let selected else { return }
        conceal()
        let visibility = visibilityGeneration
        perform(local: true) { token in
            let result = try await self.service.readLocal(selected, vault: self.selectedVault)
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
            self.recordUsage(result.usageIdentity)
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
    func loadDevices() {
        guard !offline, authenticated, service.isAuthenticated, pendingTransition == nil else { return }
        perform { token in
            let result = try await self.service.execute(.manage(.devices), vault: self.selectedVault, offline: false)
            guard self.current(token) else { return }
            self.devices = result.devices
        }
    }
    var removingDevice = false
    var removalProgress: String?
    func removeDevice(_ id: UUID) {
        guard !offline, !busy else { return }
        removingDevice = true; removalProgress = "Preparing device removal…"
        perform { token in
            let result = try await self.service.execute(.manage(.removeAccountDevice(id)), vault: self.selectedVault, offline: false)
            guard self.current(token) else { return }
            self.devices = result.devices
            if result.deviceRemovalIncomplete { self.error = result.message }
            else { self.notice = result.message }
        }
    }
    private func showDeviceRemoved(pending: Bool = false) {
        removalCleanupPending = pending
        for vault in vaults { defaults.removeObject(forKey: "enrollment-notified-" + vault.id) }
        lock(); deviceAddedNotice = nil
        submittedEnrollments = []; enrollmentProgress = [:]; enrollmentSelection = []
        deviceRemoved = true; vaults = []; vault = ""; devices = []; cloudEnrollments = []
        error = nil; sheet = .enrollDevice
        enrollmentPaused = true
    }
    func reconnectDevice() {
        perform { token in
            _ = try await self.service.execute(.manage(.reconnect), vault: nil, offline: false)
            guard self.current(token) else { return }
            self.deviceRemoved = false; self.removalCleanupPending = false; self.enrollmentPaused = false
            self.launchUnlockAvailable = false
            let discovery = try await self.service.execute(.discover, vault: nil, offline: false)
            self.vaults = discovery.vaults
            self.sheet = .enrollDevice
            self.enrollmentStatus = "Ready to connect."
        }
    }
    func loadMembers(target: VaultDescriptor? = nil) {
        guard !offline else { return }
        let id = target?.id ?? selectedVault
        perform { token in
            let result = try await self.service.execute(.members, vault: id, offline: false)
            guard self.current(token) else { return }
            self.members = result.members; self.membersVaultID = id
            self.status = "Account membership verified"
        }
    }
    func management(_ action: VaultManagement, keepSheet: Bool = false, target: VaultDescriptor? = nil) {
        guard !offline else { return }
        let id = target?.id ?? selectedVault
        let requestID = sheetRequest?.id
        perform { token in
            let result = try await self.service.execute(.manage(action), vault: id, offline: false)
            guard self.current(token) else { return }
            if let catalog = result.catalog, let id { try self.applyTargetCatalog(catalog, id: id) }
            if !keepSheet && self.sheetRequest?.id == requestID { self.sheet = nil }
            self.notice = result.message
            self.accessNeedsRepair = false; self.launchUnlockAvailable = false
        }
    }
    var deviceAddedNotice: String?
    enum EnrollmentPhase: Equatable {
        case contacting, waiting, paused, offline, connected, cancelled, failed(String)
        var message: String {
            switch self {
            case .contacting: "Contacting iCloud…"
            case .waiting: "Open and unlock 2ndPass on another connected device."
            case .paused: "Unlock 2ndPass to continue connecting."
            case .offline: "Offline. Reconnect to iCloud, then retry."
            case .connected: "Connected"
            case .cancelled: "Connection request cancelled."
            case .failed(let message): message
            }
        }
    }
    struct EnrollmentProgress: Equatable {
        var phase: EnrollmentPhase = .paused
        var lastAttempt: Date?
        var lastContact: Date?
    }
    var enrollmentProgress: [String: EnrollmentProgress] = [:]
    var ownerEnrollmentProgress: [String: EnrollmentProgress] = [:]
    private func updateEnrollmentProgress(_ id: String, owner: Bool, _ update: (inout EnrollmentProgress) -> Void) {
        if owner { update(&ownerEnrollmentProgress[id, default: EnrollmentProgress()]) }
        else { update(&enrollmentProgress[id, default: EnrollmentProgress()]) }
    }
    var enrollmentSelection: Set<String> = []
    private var submittedEnrollments: Set<String> = []
    @ObservationIgnored private var enrollmentTask: Task<Void, Never>?
    private var enrollmentGeneration = 0
    var enrollmentWorking = false
    var enrollmentSessionActive: Bool { service.isAuthenticated }
    var cloudEnrollments: [EnrollmentExchange] = []
    var enrollmentVault: String?
    var enrollmentStatus = "Choose the vaults to connect."
    var enrollmentLastCheck: Date?
    var enrollmentLastAttempt: Date?
    var enrollmentPaused = false
    private var nextEnrollmentPoll = Date.distantPast
    private var checkJoiningNext = true

    func prepareEnrollmentSelection() {
        if enrollmentSelection.isEmpty { enrollmentSelection = Set(vaults.filter { !$0.enrolled }.map(\.id)) }
    }
    var canStartEnrollment: Bool {
        enrollmentSelection.contains { id in enrollmentProgress[id] == nil && vaults.contains { $0.id == id && !$0.enrolled } }
    }
    func startEnrollment() {
        submittedEnrollments.formUnion(enrollmentSelection.filter { id in enrollmentProgress[id] == nil && vaults.contains { $0.id == id && !$0.enrolled } })
        pollCloudEnrollment(owner: false)
    }
    func checkEnrollmentInboxIfNeeded() {
        guard !deviceRemoved, service.isAuthenticated, !busy, !refreshing, !enrollmentWorking,
              wallNow() >= nextEnrollmentPoll else { return }
        #if os(iOS)
        guard isActive else { return }
        #endif
        let joining = submittedEnrollments.contains { id in
            switch enrollmentProgress[id]?.phase {
            case .failed, .cancelled, .connected: false
            default: true
            }
        }
        let ownsVaults = vaults.contains { $0.enrolled }
        guard joining || ownsVaults else { return }
        nextEnrollmentPoll = wallNow().addingTimeInterval(15)
        let owner = ownsVaults && (!joining || !checkJoiningNext)
        checkJoiningNext = owner
        pollCloudEnrollment(owner: owner, automatic: true)
    }
    func pollCloudEnrollment(owner: Bool, automatic: Bool = false) {
        #if os(iOS)
        guard isActive else { return }
        #endif
        guard !deviceRemoved, !busy, !refreshing, !enrollmentWorking else { return }
        // Only an explicit Connect/Retry may begin authentication on a joining device.
        guard !automatic || service.isAuthenticated else { return }
        guard !owner || service.isAuthenticated else {
            enrollmentStatus = "Unlock 2ndPass to connect another device."; return
        }
        let ids = owner ? vaults.filter { $0.enrolled }.map(\.id) : submittedEnrollments.sorted().filter {
            if automatic, let phase = enrollmentProgress[$0]?.phase {
                switch phase { case .cancelled, .failed: return false; default: break }
            }
            return true
        }
        guard !ids.isEmpty else { enrollmentStatus = "Choose at least one vault to connect."; return }
        guard !offline else {
            for id in ids { updateEnrollmentProgress(id, owner: owner) { $0.phase = .offline } }
            enrollmentStatus = "Offline. Reconnect to iCloud, then retry."; return
        }
        enrollmentPaused = false; enrollmentWorking = true
        let token = enrollmentGeneration
        enrollmentTask = Task { [weak self] in
            guard let self else { return }
            defer { if token == self.enrollmentGeneration { self.enrollmentWorking = false; self.enrollmentTask = nil } }
            for id in ids {
                guard token == self.enrollmentGeneration, !Task.isCancelled else { return }
                // A user operation queued during the preceding check takes priority.
                if self.busy || self.refreshing { break }
                self.enrollmentVault = id
                self.enrollmentLastAttempt = self.wallNow()
                self.updateEnrollmentProgress(id, owner: owner) { $0.lastAttempt = self.wallNow() }
                self.updateEnrollmentProgress(id, owner: owner) { $0.phase = .contacting }
                self.enrollmentStatus = "Contacting iCloud…"
                do {
                    let result = try await self.service.execute(.manage(owner ? .automaticEnrollment : .requestEnrollment(name: ProcessInfo.processInfo.hostName)), vault: id, offline: false)
                    guard token == self.enrollmentGeneration, !Task.isCancelled else { return }
                    self.enrollmentLastCheck = self.wallNow()
                    self.updateEnrollmentProgress(id, owner: owner) { $0.lastContact = self.wallNow() }
                    self.cloudEnrollments = result.enrollments
                    if owner {
                        // An empty inbox poll is not enrollment. Dismiss once a
                        // request is underway or signed membership shows another device,
                        // even if its notification was already acknowledged.
                        if result.enrollments.contains(where: { !$0.rejected }) || !result.addedDevices.isEmpty {
                            self.showsSetupChecklist = false
                        }
                        let key = "enrollment-notified-" + id
                        var seen = Set(self.defaults.stringArray(forKey: key) ?? [])
                        let added = result.addedDevices.filter { !seen.contains($0.uuidString) }
                        if !added.isEmpty {
                            let devicesResult = try await self.service.execute(.manage(.devices), vault: id, offline: false)
                            guard token == self.enrollmentGeneration, !Task.isCancelled else { return }
                            self.mergeDevices(devicesResult.devices)
                            let names = added.map { addedID in devicesResult.devices.first { $0.id == addedID }?.name ?? "Connected device" }
                            let vaultName = self.vaults.first { $0.id == id }?.name ?? "your vault"
                            self.deviceAddedNotice = names.joined(separator: ", ") + " connected to " + vaultName + "."
                            seen.formUnion(added.map(\.uuidString)); self.defaults.set(Array(seen), forKey: key)
                        }
                        self.updateEnrollmentProgress(id, owner: owner) { $0.phase = .connected }
                    } else if result.enrollmentCompleted {
                        self.defaults.set(result.addedDevices.map(\.uuidString), forKey: "enrollment-notified-" + id)
                        self.submittedEnrollments.remove(id)
                        // Joining an existing vault already requires another connected device.
                        // The setup checklist belongs to vault creation, not device enrollment.
                        self.updateEnrollmentProgress(id, owner: owner) { $0.phase = .connected }
                        self.vaults = self.vaults.map { $0.id == id ? VaultDescriptor(id: id, name: $0.name, format: "mop-vault-v7", enrolled: true) : $0 }
                        // Enrollment must never replace a selection or a live draft.
                        var opened = false
                        if self.itemDraft == nil && !self.busy && !self.refreshing {
                            let catalogResult = try await self.service.execute(.catalog, vault: id, offline: false)
                            guard token == self.enrollmentGeneration, !Task.isCancelled else { return }
                            do {
                                let catalog = try catalogResult.requireCatalog()
                                self.catalogs[id] = catalog
                                self.vaults = self.vaults.map { $0.id == id ? VaultDescriptor(id: id, name: catalog.vault, format: "mop-vault-v7", enrolled: true) : $0 }
                                if self.vault.isEmpty { self.vault = id }
                                if self.vault == id { try self.applyCatalog(catalog) }
                                self.authenticated = true
                                opened = true
                            }
                        }
                        self.notice = "Connected. Your vault is ready to open."
                        if opened && self.submittedEnrollments.isEmpty && self.sheet == .enrollDevice { self.sheet = nil }
                    } else {
                        let cancelled = !result.enrollments.isEmpty && result.enrollments.allSatisfy(\.rejected)
                        self.updateEnrollmentProgress(id, owner: owner) { $0.phase = cancelled ? .cancelled : .waiting }
                        if cancelled { self.submittedEnrollments.remove(id) }
                    }
                } catch {
                    guard token == self.enrollmentGeneration, !Task.isCancelled else { return }
                    if error as? MopError == .deviceRemoved || error as? MopError == .deviceRemovalPending {
                        self.showDeviceRemoved(pending: error as? MopError == .deviceRemovalPending); return
                    }
                    if owner, error as? MopError == .cloudPermission {
                        self.ownerEnrollmentProgress.removeValue(forKey: id); continue
                    }
                    let phase: EnrollmentPhase
                    switch error as? MopError {
                    case .authentication: phase = .paused; self.enrollmentPaused = true
                    case .vaultConflict: phase = .waiting
                    default: phase = .failed(((error as? MopError)?.errorDescription ?? "Could not contact iCloud.") + " Choose Retry to try again."); self.enrollmentPaused = true
                    }
                    self.updateEnrollmentProgress(id, owner: owner) { $0.phase = phase }
                }
                self.enrollmentStatus = (owner ? self.ownerEnrollmentProgress[id] : self.enrollmentProgress[id])?.phase.message ?? ""
            }
        }
    }
    private func mergeDevices(_ incoming: [VaultDeviceRecord]) {
        for device in incoming {
            devices.removeAll { $0.id == device.id }; devices.append(device)
        }
        devices.sort { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }
    func retryEnrollment(_ id: String) {
        submittedEnrollments.insert(id)
        enrollmentProgress[id, default: EnrollmentProgress()].phase = .waiting
        pollCloudEnrollment(owner: false)
    }
    func restartCloudEnrollment(_ id: String? = nil) { changeCloudEnrollment(id: id, restart: true) }
    func cancelCloudEnrollment(_ id: String? = nil) { changeCloudEnrollment(id: id, restart: false) }
    private func changeCloudEnrollment(id: String?, restart: Bool) {
        guard !busy, !enrollmentWorking, let id = id ?? enrollmentVault else { return }
        guard !offline else { enrollmentProgress[id, default: EnrollmentProgress()].phase = .offline; return }
        enrollmentWorking = true
        enrollmentProgress[id, default: EnrollmentProgress()].phase = .contacting
        let token = enrollmentGeneration
        enrollmentTask = Task { [weak self] in
            guard let self else { return }
            defer { if token == self.enrollmentGeneration { self.enrollmentWorking = false; self.enrollmentTask = nil } }
            do {
                let action: VaultManagement = restart ? .restartEnrollment(name: ProcessInfo.processInfo.hostName) : .cancelEnrollment
                let result = try await self.service.execute(.manage(action), vault: id, offline: false)
                guard token == self.enrollmentGeneration, !Task.isCancelled else { return }
                self.cloudEnrollments = result.enrollments
                self.enrollmentProgress[id, default: EnrollmentProgress()].lastContact = self.wallNow()
                self.enrollmentProgress[id, default: EnrollmentProgress()].phase = restart ? .waiting : .cancelled
                if restart { self.submittedEnrollments.insert(id) } else { self.submittedEnrollments.remove(id) }
            } catch {
                guard token == self.enrollmentGeneration, !Task.isCancelled else { return }
                self.enrollmentProgress[id, default: EnrollmentProgress()].phase = .failed("iCloud did not confirm the change. Retry to confirm the request’s state.")
            }
            self.enrollmentStatus = self.enrollmentProgress[id]?.phase.message ?? ""
        }
    }
    var autoFillRefreshMessage: String?
    func refreshAutoFillSuggestions() {
        guard authenticated, service.isAuthenticated, !busy, !refreshing else { return }
        requestTransition(.refresh) { [weak self] accepted in
            guard accepted, let self else { return }
            self.perform { token in
                var failures = 0
                for vault in self.vaults where vault.enrolled {
                    do {
                        let result = try await self.service.execute(.catalog, vault: vault.id, offline: self.offline)
                        guard self.current(token) else { return }
                        if let catalog = result.catalog { try await AutoFillPublisher.shared.publish(catalog: catalog, vaultID: vault.id) }
                    } catch { failures += 1 }
                    guard self.current(token) else { return }
                }
                self.autoFillRefreshMessage = failures == 0 ? "Suggestions refreshed." : "Could not refresh \(failures) vault(s). Existing suggestions for those vaults were retained. Try again when available."
            }
        }
    }
    var exchangeOutput = ""
    func exchange(_ action: VaultManagement, target: VaultDescriptor? = nil) {
        guard !offline else { return }
        let id = target?.id ?? selectedVault
        let requestID = sheetRequest?.id
        perform { token in
            let result = try await self.service.execute(.manage(action), vault: id, offline: false)
            guard self.current(token) else { return }
            if self.sheetRequest?.id == requestID { self.exchangeOutput = result.document.map { String(decoding: $0, as: UTF8.self) } ?? "" }
            self.notice = result.message
            if let catalog = result.catalog, let id { try self.applyTargetCatalog(catalog, id: id) }
            self.cloudRefreshPending = true
        }
    }
    func cloudChanged() {
        nextEnrollmentPoll = .distantPast
        cloudRefreshPending = true
        nextCloudRefresh = .distantPast
        refreshCloudIfNeeded()
    }
    func refreshCloudIfNeeded() {
        guard launchAttempted, isActive, !busy, !refreshing, !loadingVaults, itemDraft == nil, sheet == nil,
              !accessNeedsRepair, pendingTransition == nil, wallNow() >= nextCloudRefresh else { return }
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
                guard requested.allSatisfy({ available.contains($0) }) else {
                    vaults = discovery.vaults
                    if !available.contains(vault) { vault = "" }
                    lock()
                    if vaults.isEmpty { sheet = .createVault }
                    return
                }
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
                retentionDate = wallNow(); cachedVaults = []; offline = !dates.isEmpty
                if let next = loaded[vault] { try applyCatalog(next) }
                if let item = selectedItem, catalog?.items.contains(where: { $0.name == item }) != true { selectedItem = nil }
                if let selected, !references.contains(selected) { self.selected = nil }
                let date = dates.min().map { ISO8601DateFormatter().string(from: $0) } ?? "unknown time"
                status = offline ? "Read only · oldest verified cache from \(date)" : "Unlocked · \(loaded.count) vault\(loaded.count == 1 ? "" : "s")"
            } catch {
                guard token == generation, !Task.isCancelled else { return }
                if error as? MopError == .deviceRemoved || error as? MopError == .deviceRemovalPending {
                    showDeviceRemoved(pending: error as? MopError == .deviceRemovalPending); return
                }
                if let failure = error as? MopError,
                   [.authentication, .signing, .invalidIdentity, .invalidVault, .vaultUntrusted, .notVaultMember, .cloudAccount].contains(failure) {
                    lock()
                    self.error = failure.errorDescription
                } else {
                    cloudRefreshPending = true
                }
                recordError(error, operation: "Background cloud refresh")
            }
        }
    }
    var showsSetupChecklist = false
    func createVault(name: String, recovery: URL? = nil, fingerprint: String? = nil) {
        guard !offline, !busy else { return }
        restoreLastSelection = false
        conceal(); catalog = nil; catalogs = [:]; passwordQualities = [:]; references = []; selected = nil; members = []; authenticated = false
        let id = UUID().uuidString
        perform { token in
            // Retain this UUID even on a failed/uncertain initialization for reconciliation.
            self.allVaults = false; self.vault = id; self.vaults.append(VaultDescriptor(id: id, name: name, format: "mop-vault-v7", enrolled: true))
            self.status = "Creating vault \(id) · retain this UUID if publication is interrupted"
            let result = try await self.service.execute(.create(name: name, recovery: recovery, fingerprint: fingerprint), vault: id, offline: false)
            guard self.current(token) else { return }
            try self.applyCatalog(result.requireCatalog())
            try await self.unlockContents(token, refresh: false)
            self.selected = nil; self.sheet = self.importAfterCreation ? .importItems : nil; self.importAfterCreation = false; self.showsSetupChecklist = true
            self.notice = result.message; self.status = "Vault created · add devices or optional recovery in settings"
        }
    }
    private func applyTargetCatalog(_ catalog: ItemCatalog, id: String) throws {
        catalogs[id] = catalog
        if vault == id { try applyCatalog(catalog) }
    }
    func renameVault(to name: String, target: VaultDescriptor? = nil) {
        guard !offline, let target = target ?? selectedVaultDescriptor else { return }
        let id = target.id, requestID = sheetRequest?.id
        perform { token in
            let result = try await self.service.execute(.rename(name), vault: id, offline: false)
            guard self.current(token) else { return }
            try self.applyTargetCatalog(result.requireCatalog(), id: id)
            if self.vault == id { self.selected = nil; self.conceal() }
            if self.sheetRequest?.id == requestID { self.sheet = nil }
            if let index = self.vaults.firstIndex(where: { $0.id == id }) {
                let updated = VaultDescriptor(id: id, name: name, format: target.format, enrolled: target.enrolled)
                self.vaults[index] = updated
                if self.vaultDetailsTarget?.id == id { self.vaultDetailsTarget = updated }
            }
            self.notice = "Vault renamed. Update existing references."
        }
    }

    func deleteVault(target: VaultDescriptor, confirmation: String) {
        guard !offline, !busy, confirmation == (target.name ?? target.id) else { return }
        conceal(); clearClipboard(); catalog = nil; references = []; selected = nil; selectedItem = nil; authenticated = false
        perform { token in
            _ = try await self.service.execute(.deleteVault, vault: target.id, offline: false)
            guard self.current(token) else { return }
            self.lock()
            self.vaults.removeAll { $0.id == target.id }
            self.catalogs[target.id] = nil
            self.vault = ""
            self.notice = "Vault deleted. Backups and caches on other devices remain."
            self.status = "Vault deleted"
        }
    }

    func chooseExportBackup(target: VaultDescriptor? = nil) {
        guard !busy, let target = target ?? selectedVaultDescriptor, target.enrolled else { return }
        documentRequest = DocumentRequest(vault: target.id, generation: securityGeneration)
    }
    func completeBackupSelection(folder: URL, request: DocumentRequest) {
        guard securityGeneration == request.generation else { return }
        let rawName = vaults.first { $0.id == request.vault }?.name ?? "vault"
        let name = String(rawName.prefix(80).map { $0.isLetter || $0.isNumber || $0 == "-" ? $0 : "-" })
        let date = wallNow().formatted(.iso8601.year().month().day().dateSeparator(.dash))
        exportBackup(to: folder.appendingPathComponent("2ndpass-" + name + "-" + date + "-" + String(UUID().uuidString.prefix(8)) + ".mopfile"), vaultID: request.vault)
    }
    func exportBackup(to url: URL, vaultID: String? = nil) {
        guard !busy, let id = vaultID ?? selectedVault, vaults.contains(where: { $0.id == id && $0.enrolled }) else { return }
        perform { token in
            _ = try await self.service.execute(.export(url), vault: id, offline: false)
            guard self.current(token) else { return }
            self.lastBackupURL = url; self.lastBackupVaultID = id
            self.notice = "Encrypted backup exported. Keep your hardware recovery device separately."
        }
    }

}

/// User-initiated transitions that can replace the single, session-local draft.
enum PendingTransition {
    case item(ItemRow.ID?), vault(String), allItems, recentlyDeleted
    case collection(archived: Bool)
    case recent(ItemCollection)
    case vaultTarget(String), sheet(AppSheet), presentation(SheetRequest), details(VaultDescriptor?), refresh, trash(ItemRow)
    case closeWindow, quit
}

extension AppModel {
    var hasUnsavedChanges: Bool { itemDraft?.isModified == true }
    var draftSaveUnavailableReason: String? {
        guard let draft = itemDraft else { return "There is no draft to save." }
        if !authenticated { return "Unlock 2ndPass to save changes." }
        if offline { return "Connect to iCloud to save changes." }
        if let mappingError = itemDraft?.autoFill.validationError(in: itemDraft?.fields.map(\.field) ?? []) { return mappingError }
        if draftConflict { return "This item changed in iCloud. Your edits are retained. Discard them and refresh before editing the latest version." }
        let name = catalogs[draft.vault]?.vault ?? vaultName
        if !draft.valid(vaultName: name) { return "Enter a valid item name and fields before saving." }
        return nil
    }

    /// Return false without changing the selection when a decision is required.
    private func allowTransition(_ intent: PendingTransition) -> Bool {
        if applyingTransition { return true }
        guard pendingTransition == nil else { return false }
        if hasUnsavedChanges {
            pendingTransition = intent; showsUnsavedChanges = true
            return false
        }
        cancelItemEditing()
        return true
    }

    func requestTransition(_ intent: PendingTransition, completion: ((Bool) -> Void)? = nil) {
        guard !busy, pendingTransition == nil else { completion?(false); return }
        if hasUnsavedChanges {
            pendingTransition = intent; transitionCompletion = completion; showsUnsavedChanges = true
        } else {
            cancelItemEditing()
            executeTransition(intent, completion: completion)
        }
    }

    func presentSheet(_ kind: AppSheet, target: VaultDescriptor? = nil, inSettings: Bool = false) {
        requestTransition(.presentation(SheetRequest(kind: kind, inSettings: inSettings, target: target ?? vaultDetailsTarget ?? selectedVaultDescriptor)))
    }
    func openVaultDetails(_ target: VaultDescriptor?) { requestTransition(.details(target)) }
    func showSettingsCategory(_ category: SettingsCategory) { settingsCategory = category }

    func refresh() { requestTransition(.refresh) }

    func cancelPendingTransition() {
        let completion = transitionCompletion
        pendingTransition = nil; transitionCompletion = nil
        savingTransition = false; showsUnsavedChanges = false
        // SwiftUI lists can keep an optimistic native selection after a binding veto.
        // Reconcile them to the unchanged model selection after cancellation/failure.
        selectionGeneration += 1
        completion?(false)
    }

    func discardAndContinue() {
        guard !busy, pendingTransition != nil else { return }
        cancelItemEditing()
        completePendingTransition()
    }

    func saveAndContinue() {
        guard !busy, pendingTransition != nil, draftSaveUnavailableReason == nil else { return }
        showsUnsavedChanges = false; savingTransition = true
        saveItemDraft()
        if !busy { cancelPendingTransition() }
    }

    private func completePendingTransition() {
        guard let intent = pendingTransition else { return }
        let completion = transitionCompletion
        pendingTransition = nil; transitionCompletion = nil
        showsUnsavedChanges = false; savingTransition = false
        executeTransition(intent, completion: completion)
    }

    private func executeTransition(_ intent: PendingTransition, completion: ((Bool) -> Void)?) {
        applyingTransition = true
        defer { applyingTransition = false }
        switch intent {
        case .item(let id): selectedRow = id
        case .vault(let id): chooseVault(id)
        case .allItems: chooseAllVaults()
        case .collection(let archived): chooseCollection(archived: archived)
        case .recent(let collection): chooseRecent(collection)
        case .recentlyDeleted: chooseRecentlyDeleted()
        case .vaultTarget(let id):
            guard prepareVaultAction(id) else { completion?(false); return }
        case .sheet(let kind): sheet = kind
        case .presentation(let request):
            sheetRequest = request
            if request.kind == .addDevice { showsSetupChecklist = false }
        case .details(let target): conceal(); vaultDetailsTarget = target
        case .refresh: discover()
        case .trash(let row): trashItem(row)
        case .closeWindow, .quit: break
        }
        completion?(true)
    }
}
