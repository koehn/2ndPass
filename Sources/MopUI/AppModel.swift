import MopLocalIdentity
import SwiftUI
import OSLog
import MopCore
import MopSubscriptions
import MopAppSupport
import MopAuth
import LocalAuthentication
import MopVaultNext

enum AppPage: String, CaseIterable { case security = "Security", secrets = "Secrets", recentlyDeleted = "Recently Deleted" }
enum AppSheet: String, Identifiable { case createVault, enrollDevice, addDevice, shareAccount, setupRecovery, renameVault, deleteVault, recover, importItems, portableBackup, restoreBackup
    var id: String { rawValue }
}

@MainActor @Observable
final class AppModel {
    var securityVisible = false
    var healthReport = PasswordHealthReport()
    var healthChecking = false
    var healthScheduled = false
    @ObservationIgnored var healthNotBefore: ContinuousClock.Instant?
    @ObservationIgnored var healthLastInteraction = ContinuousClock.now
    let healthStartupDelay: Duration
    let healthIdleDelay: Duration
    var healthRestoringCache = false
    var healthProgress = 0.0
    var healthToken = UUID()
    @ObservationIgnored var healthSession = PasswordHealthSession()
    @ObservationIgnored var healthRequest: String?
    @ObservationIgnored var healthRequestCache: [String: [CachedPasswordCheck]] = [:]
    @ObservationIgnored var healthPublishing: UUID?
    var healthCacheNotice: String?
    @ObservationIgnored var healthSessionGeneration: Int?
    @ObservationIgnored var healthWakeTask: Task<Void, Never>?
    @ObservationIgnored var healthTask: Task<Void, Never>?
    @ObservationIgnored var breachClient: any BreachChecking = PwnedPasswordsClient()
    var breachChecksEnabled = true {
        didSet { defaults.set(breachChecksEnabled, forKey: "breachChecksEnabled"); refreshHealth() }
    }
    var historySelection: HistorySelection?
    var pendingSecurityUpgrade: (String, String)?
    private(set) var conflictPreviews: [ItemVaultConflictPreview] = []
    private(set) var conflictFailure: String?
    var conflictReviewPresented = false
    var conflictReviewItem: ItemRow.ID?
    @ObservationIgnored private var conflictRefreshTask: Task<Void, Never>?
    private var conflictRefreshGeneration = 0
    var conflictItems: Set<ItemRow.ID> {
        Set(conflictPreviews.map { .init(vault: $0.conflict.local.scope.vaultID.uuidString, name: $0.local.item.name) })
    }
    func reviewConflict(_ item: ItemRow.ID? = nil) {
        conflictReviewItem = item
        conflictReviewPresented = true
        refreshConflicts()
    }
    func refreshConflicts() {
        conflictRefreshGeneration += 1
        let token = conflictRefreshGeneration
        conflictRefreshTask?.cancel(); conflictRefreshTask = nil
        guard authenticated, isActive else {
            conflictPreviews = []; conflictFailure = nil
            conflictReviewPresented = false; conflictReviewItem = nil
            return
        }
        let vaultIDs = catalogs.keys.sorted()
        conflictRefreshTask = Task { [weak self, service] in
            do {
                var loaded: [ItemVaultConflictPreview] = []
                for id in vaultIDs {
                    loaded += try await service.conflicts(vault: id)
                    try Task.checkCancellation()
                }
                guard let self, self.conflictRefreshGeneration == token, self.authenticated, self.isActive else { return }
                self.conflictPreviews = loaded; self.conflictFailure = nil
            } catch {
                guard !Task.isCancelled, let self, self.conflictRefreshGeneration == token else { return }
                self.conflictFailure = "Conflict status could not be refreshed. Try again."
            }
        }
    }
    let service: any VaultService
    let documents: any DocumentAccessing
    let clipboard: any SecretClipboardAccess
    var keyCreationPresented = false
    var isActive = true { didSet { if oldValue != isActive { refreshConflicts() } } }
    var vaults: [VaultDescriptor] = []
    var vault = "" {
        didSet {
            switch collection {
            case .vault, .local: collection = vault == LocalVault.id ? .local : .vault(vault)
            default: break
            }
            invalidateItemSearch()
        }
    }
    var collection: ItemCollection = .vault("") { didSet { invalidateItemSearch() } }
    // Convenience accessors for actions, backed by one collection state.
    var allVaults: Bool {
        get { if case .vault = collection { return false }; return collection != .recentlyDeleted && collection != .local }
        set { collection = newValue ? .all : (vault == LocalVault.id ? .local : .vault(vault)) }
    }
    var catalogs: [String: ItemCatalog] = [:] { didSet { invalidateItemSearch(); reloadUsage(); refreshHealth(); if Set(oldValue.keys) != Set(catalogs.keys) { refreshConflicts() } } }
    var deletedCatalogs: [String: ItemCatalog] = [:] { didSet { invalidateDeletedSearch() } }
    var selectedDeleted: ItemRow.ID? { didSet { rememberSelection() } }
    var itemToDelete: ItemRow?
    var retentionDate = Date() { didSet { invalidateDeletedSearch() } }
    private var nextRetentionSweep = Date.distantPast
    @ObservationIgnored private let wallNow: () -> Date
    var passwordQualities: [String: PasswordQuality] = [:]
    var passwordQualitySource: [String]?
    private var launchAttempted = false
    var page: AppPage {
        get { securityVisible ? .security : collection == .recentlyDeleted ? .recentlyDeleted : .secrets }
        set { securityVisible = newValue == .security
            if newValue == .recentlyDeleted { collection = .recentlyDeleted }
            else if collection == .recentlyDeleted { collection = .vault(vault) } }
    }
    var selectedItem: String? { didSet { rememberSelection() } }
    var catalog: ItemCatalog? { didSet { invalidateItemSearch() } }

    // Device-local vault: fixed, Secure Enclave-backed, non-exportable. It has no
    // account, sync, or recovery and is independent of the cloud session state.
    var localIdentities: [LocalIdentity] = [] {
        didSet {
            localListCache = nil
            invalidateItemSearch()
            if let id = selectedLocalIdentityID, !localIdentities.contains(where: { $0.id == id }) {
                selectedLocalIdentityID = nil
            }
        }
    }
    var selectedLocalIdentityID: UUID? { didSet { rememberSelection() } }
    var selectedLocalIdentity: LocalIdentity? {
        guard isLocalVaultSelected || collection == .all else { return nil }
        return localIdentities.first { $0.id == selectedLocalIdentityID }
    }
    @ObservationIgnored private var localListCache: (query: String, rows: [LocalIdentity], targets: [AlphabetTarget<UUID>])?
    var displayedLocalIdentities: [LocalIdentity] {
        _ = localIdentities // Keep observation tracking even when the cache is warm.
        if let localListCache, localListCache.query == search { return localListCache.rows }
        let rows = localIdentities.filter {
            let credential = CredentialPresentation(identity: $0)
            return search.isEmpty || [credential.title, credential.account ?? "", $0.name, $0.protocolType.rawValue]
                .contains { $0.localizedCaseInsensitiveContains(search) }
        }.sorted { CredentialPresentation(identity: $0).title.localizedStandardCompare(CredentialPresentation(identity: $1).title) == .orderedAscending }
        localListCache = (search, rows, AlphabetTarget.build(rows,
            title: { CredentialPresentation(identity: $0).title }, id: { $0.id }))
        return rows
    }
    var localAlphabetTargets: [AlphabetTarget<UUID>] {
        _ = displayedLocalIdentities
        return localListCache?.targets ?? []
    }
    var localReady = false
    var localLoading = false
    var localError: String?
    var localCreating = false
    var localCreatePresented = false
    var localCreateAcknowledged = false
    @ObservationIgnored private var localAuthorization: LocalAuthorization?
    var localCreateName = ""
    var localCreateProtocol: LocalIdentityProtocol = .ssh
    var localDeleting: UUID?
    var localDeleteInProgress = false
    @ObservationIgnored private var localService: (any LocalVaultServing)?
    @ObservationIgnored private let authorizeLocal: (String, Set<UUID>, Set<LocalIdentityProtocol>, Set<LocalKeyOperation>) async throws -> LocalAuthorization
    var isLocalVaultSelected: Bool { collection == .local }
    /// The always-present local vault is a UI-level entry: it is shown in the sidebar
    /// but never appears in the cloud `vaults` list that account operations run against.
    var vaultList: [VaultPresentation] { vaults.map(VaultPresentation.cloud) + [.local] }
    var vaultSelection: VaultSelection? { isLocalVaultSelected ? .local : (try? CloudVaultID(vault)).map(VaultSelection.cloud) }
    /// Cloud vaults only, so onboarding empty-states are not fooled by the always-present local vault.
    var cloudVaults: [VaultDescriptor] { vaults.filter { $0.id != LocalVault.id } }
    var cloudVaultsPresent: Bool { !cloudVaults.isEmpty }
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
    private var pendingDisplayVaults: Set<String> = []
    var authenticated = false { didSet { if authenticated { reloadUsage(); refreshHealth() } else { clearHealth() }; refreshConflicts() } }
    var revealed: SecretBytes?
    @ObservationIgnored private var storeChangesTask: Task<Void, Never>?
    var busy = false
    private(set) var localOperation = false
    // Local projection refreshes are not evidence of network activity. Keep the
    // indicator stable across the whole initial connection/download instead.
    var showsCloudProgress: Bool { !offline && ((busy && !localOperation) || isConnectingVaults || hasCatalogDownloads || requestingSynchronization) }
    private var connectionUnlockPending = false
    var isConnectingVaults: Bool {
        connectionUnlockPending || (authenticated && vaults.contains { $0.supported && !$0.enrolled })
    }
    private(set) var syncIssue: String?
    private var syncIssueDetails: String?
    func showSyncIssue() {
        guard let issue = syncIssue else { return }
        error = issue
        errorDetails = syncIssueDetails
    }
    private(set) var requestingSynchronization = false
    @ObservationIgnored private var syncWakeTask: Task<Void, Never>?
    private var syncWakeID: UUID?
    private var syncWakeAgain = false

    /// Only lifecycle, push, explicit refresh and unlock call this. Store changes
    /// update the view without generating another cloud request feedback loop.
    func requestBackgroundSynchronization() {
        Self.logger.notice("Sync trace: UI wake; active=\(self.isActive) authenticated=\(self.authenticated) serviceAuthenticated=\(self.service.isAuthenticated)")
        guard isActive, authenticated, service.isAuthenticated else { return }
        syncWakeAgain = true
        guard syncWakeTask == nil else { return }
        let id = UUID(), token = generation
        syncWakeID = id; requestingSynchronization = true
        syncWakeTask = Task { [weak self] in
            guard let self else { return }
            defer {
                if self.syncWakeID == id {
                    self.syncWakeTask = nil; self.syncWakeID = nil
                    self.requestingSynchronization = false
                }
            }
            repeat {
                self.syncWakeAgain = false
                do {
                    try await self.service.requestSynchronization()
                    guard self.generation == token, !Task.isCancelled else { return }
                    self.syncIssue = nil; self.syncIssueDetails = nil
                } catch {
                    guard self.generation == token, !Task.isCancelled else { return }
                    self.syncIssue = "iCloud sync could not resume. Local changes are saved. Tap Refresh to retry."
                    self.recordError(error, operation: "Resume iCloud synchronization")
                    self.syncIssueDetails = self.errorDetails
                }
            } while self.syncWakeAgain && self.isActive && self.authenticated && self.generation == token && !Task.isCancelled
        }
    }
    var refreshing = false
    struct CatalogLoadProgress { let loaded: Int; let total: Int; var waiting: Int = 0; var downloading = false }
    private(set) var catalogLoadProgress: [String: CatalogLoadProgress] = [:]
    private(set) var catalogUpdatePaused = false
    var isUpdatingCatalog: Bool { !catalogLoadProgress.isEmpty }
    var hasCatalogDownloads: Bool { catalogLoadProgress.values.contains { $0.downloading || $0.waiting > 0 } }
    private var selectedCatalogProgress: [CatalogLoadProgress] {
        if !allVaults { return catalogLoadProgress[vault].map { [$0] } ?? [] }
        let completed = catalogs.filter { catalogLoadProgress[$0.key] == nil }.values.map {
            CatalogLoadProgress(loaded: $0.items.count, total: $0.items.count)
        }
        return Array(catalogLoadProgress.values) + completed
    }
    var catalogTransferFraction: Double? {
        guard hasCatalogDownloads else { return nil }
        let values = selectedCatalogProgress
        let total = values.reduce(0) { $0 + $1.total }
        guard total > 0, !catalogUpdatePaused else { return nil }
        return min(1, Double(values.reduce(0) { $0 + $1.loaded }) / Double(total))
    }
    var catalogTransferStatus: String? {
        guard isUpdatingCatalog else { return nil }
        if catalogUpdatePaused { return "Local catalog update paused. Refresh to retry." }
        let values = selectedCatalogProgress
        guard !values.isEmpty else { return nil }
        if values.contains(where: { $0.downloading }) {
            return offline ? "Connected vault · Download paused while offline" : "Connected to iCloud · \(values.reduce(0) { $0 + $1.loaded }) of \(values.reduce(0) { $0 + $1.total }) items ready · Downloading remaining items"
        }
        if values.contains(where: { $0.waiting > 0 }) { return "Connecting encrypted items · \(values.reduce(0) { $0 + $1.loaded }) of \(values.reduce(0) { $0 + $1.total }) ready · Waiting for another device to sync" }
        return nil
    }
    private func recordCatalogProgress(_ result: VaultResult, vaultID: String) {
        catalogUpdatePaused = false
        if let loaded = result.catalogLoadedCount, let total = result.catalogTotalCount, loaded < total {
            catalogLoadProgress[vaultID] = CatalogLoadProgress(loaded: loaded, total: total, waiting: result.catalogWaitingCount ?? 0, downloading: result.catalogDownloading)
        } else { catalogLoadProgress[vaultID] = nil }
    }
    private func selectedItemChanged(in next: ItemCatalog?, vaultID: String) -> Bool {
        guard vault == vaultID, let selectedItem,
              let previous = catalogs[vaultID]?.items.first(where: { $0.name == selectedItem }) else { return false }
        guard let updated = next?.items.first(where: { $0.storageID == previous.storageID && $0.name == previous.name }) else {
            return catalogLoadProgress[vaultID] == nil
        }
        return previous != updated
    }
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
    var cloudConnectionRepairEnabled: Bool { defaults.bool(forKey: "icloud-connection-repair-enabled") }
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
    var sheetRequest: SheetRequest? { didSet { if sheetRequest == nil { reconcileDeferredStoreChange() } } }
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
    private(set) var visibilityGeneration = 0
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
        var localItem: UUID? = nil
    }
    @ObservationIgnored private var pendingLocalSelection: UUID?
    // Device-local defaults contain only opaque account/vault/item IDs. Names and
    // field values remain in the encrypted vault, and are resolved after unlock.
    private func rememberSelection() {
        guard !unlocking, !restoringSelection, pendingLocalSelection == nil else { return }
        if collection == .local {
            let selection = SavedSelection(collection: .local, vault: LocalVault.id, item: nil,
                                           localItem: selectedLocalIdentityID)
            if let bytes = try? JSONEncoder().encode(selection) {
                defaults.set(bytes, forKey: "lastSelection.local")
                defaults.set(true, forKey: "lastSelectionWasLocal")
            }
            return
        }
        guard authenticated else { return }
        let candidate = collection == .recentlyDeleted ? selectedDeleted?.vault ?? vault : vault
        let id = catalogs[candidate] != nil ? candidate : catalogs.keys.sorted().first ?? candidate
        guard let account = catalogs[id]?.usageScope else { return }
        if catalogLoadProgress[id] != nil, selectedItem == nil, selectedDeleted == nil { return }
        let item = collection == .recentlyDeleted
            ? deletedCatalogs[id]?.items.first(where: { $0.name == selectedDeleted?.name })
            : catalogs[id]?.items.first(where: { $0.name == selectedItem })
        let selection = SavedSelection(collection: collection, vault: id, item: item?.storageID,
                                       localItem: collection == .all ? selectedLocalIdentityID : nil)
        if let bytes = try? JSONEncoder().encode(selection) {
            defaults.set(bytes, forKey: "lastSelection." + account)
            defaults.set(false, forKey: "lastSelectionWasLocal")
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
        // Retired type-specific sidebar selections reopen in All Items.
        collection = saved.collection == .passkeys || saved.collection == .sshKeys ? .all : saved.collection
        try? applyCatalog(source)
        selectedItem = nil; selectedDeleted = nil
        if collection == .all, let localID = saved.localItem {
            pendingLocalSelection = localID
            openLocalVault()
            return
        }
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
    private var connectionRepairMessage: String {
        cloudConnectionRepairEnabled
            ? "This device could not verify its saved vault connection. Choose Repair iCloud Connection on the unlock screen to connect again using another authorized device, or use your offline recovery copy."
            : "This device could not verify its saved vault connection. Repair access from another authorized device or use your offline recovery copy."
    }
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
        if accessNeedsRepair { return "Vault access needs repair. Connect again using another authorized device or your offline recovery copy." }
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
    var itemDraft: ItemDraft? {
        didSet {
            if itemDraft != nil { healthTask?.cancel(); healthToken = UUID(); healthChecking = false; healthScheduled = false }
            else if oldValue != nil { refreshHealth(); reconcileDeferredStoreChange() }
        }
    }
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

    init(breachClient: any BreachChecking = PwnedPasswordsClient(), service: any VaultService = ItemVaultService(), clipboard: (any SecretClipboardAccess)? = nil,
         defaults: UserDefaults = .standard, lifecycle: (any AppLifecycleMonitoring)? = nil,
         documents: any DocumentAccessing = SystemDocumentAccess(),
         usageStore: any ItemUsageStoring = ItemUsageStore(),
         now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         automaticTimer: Bool = true, healthStartupDelay: Duration = .seconds(30), healthIdleDelay: Duration = .seconds(5), wallNow: @escaping () -> Date = Date.init,
         localService: (any LocalVaultServing)? = nil,
         authorizeLocal: @escaping (String, Set<UUID>, Set<LocalIdentityProtocol>, Set<LocalKeyOperation>) async throws -> LocalAuthorization = { try await LocalAuthorization.authorizeAsync(reason: $0, ids: $1, purposes: $2, operations: $3) }) {
        self.healthStartupDelay = healthStartupDelay; self.healthIdleDelay = healthIdleDelay
        self.breachClient = breachClient
        self.localService = localService
        self.authorizeLocal = authorizeLocal
        self.lifecycle = lifecycle ?? SystemAppLifecycleMonitor()
        self.wallNow = wallNow; retentionDate = wallNow()
        self.service = service
        self.usageStore = usageStore
        self.documents = documents
        self.clipboard = clipboard ?? SecretClipboard()
        self.defaults = defaults; self.now = now
        breachChecksEnabled = defaults.object(forKey: "breachChecksEnabled") as? Bool ?? true
        settingsCategory = SettingsCategory(rawValue: defaults.string(forKey: "settingsCategory") ?? "") ?? .security
        let saved = defaults.object(forKey: "autoLockMinutes") as? Int ?? 5
        autoLockMinutes = min(60, max(1, saved))
        if let data = defaults.data(forKey: "passwordGeneratorOptions"),
           var options = try? JSONDecoder().decode(PasswordOptions.self, from: data) {
            options.length = min(128, max(8, options.length))
            passwordGeneratorOptions = options
        }
        storeChangesTask = Task { [weak self, service] in
            for await event in await service.events() {
                guard !Task.isCancelled else { return }
                switch event {
                case .store: self?.cloudChanged()
                case .display(let vault):
                    self?.pendingDisplayVaults.insert(vault)
                    self?.refreshCloudIfNeeded()
                }
            }
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
                }
            }
        }
    }
    deinit { conflictRefreshTask?.cancel(); syncWakeTask?.cancel(); catalogLoadTask?.cancel(); usageLoadTask?.cancel(); inactivityTask?.cancel(); automaticUnlockTask?.cancel(); storeChangesTask?.cancel() }
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
        guard launchAttempted, isActive, !isLocalVaultSelected, !authenticated, !busy, launchUnlockAvailable, !accessNeedsRepair,
              error == nil, sheet == nil, !requestedVaultIDs.isEmpty,
              automaticUnlockTask == nil else { return }
        automaticUnlockTask = Task { [weak self] in
            await Task.yield()
            guard let self else { return }
            self.automaticUnlockTask = nil
            guard !Task.isCancelled, self.isActive, !self.isLocalVaultSelected, !self.authenticated, !self.busy,
                  self.launchUnlockAvailable, !self.accessNeedsRepair, self.error == nil,
                  self.sheet == nil, !self.requestedVaultIDs.isEmpty else { return }
            self.unlock()
        }
    }
    func activity() {
        service.userActivity()
        healthLastInteraction = .now
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
    var canExportBackup: Bool { !isLocalVaultSelected && !allVaults && !vault.isEmpty && (selectedVaultDescriptor?.supported == true || authenticated) }
    var vaultName: String { isLocalVaultSelected ? LocalVault.name : (catalog?.vault ?? vaults.first { $0.id == vault }?.name ?? "") }
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
            catalog.items.filter { $0.deletion == nil && $0.isArchived == showArchived && (!favoritesOnly || $0.isFavorite) && (collection != .passkeys || $0.type == .passkey) && (collection != .sshKeys || $0.type == .sshKey) }.map { item in
                ItemRow(id: .init(vault: id, name: item.name), vaultName: catalog.vault, item: item)
            }
        }
        if collection == .all { rows += localIdentities.map(ItemRow.local) }
        if collection.isRecent {
            rows = rows.compactMap { row in
                guard let date = recentDate(for: row) else { return nil }
                var result = row; result.recentDate = date; return result
            }.sorted {
                if $0.recentDate != $1.recentDate { return $0.recentDate! > $1.recentDate! }
                let titleOrder = $0.item.displayTitle.localizedStandardCompare($1.item.displayTitle)
                if titleOrder != .orderedSame { return titleOrder == .orderedAscending }
                return ($0.id.vault, $0.item.storageID ?? "", $0.item.name) < ($1.id.vault, $1.item.storageID ?? "", $1.item.name)
            }
            rows = Array(rows.prefix(50))
        } else {
            rows.sort {
                let titleOrder = $0.item.displayTitle.localizedStandardCompare($1.item.displayTitle)
                if titleOrder != .orderedSame { return titleOrder == .orderedAscending }
                let vaultOrder = $0.vaultName.localizedStandardCompare($1.vaultName)
                if vaultOrder != .orderedSame { return vaultOrder == .orderedAscending }
                return ($0.id.vault, $0.item.storageID ?? "", $0.item.name) < ($1.id.vault, $1.item.storageID ?? "", $1.item.name)
            }
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
    var alphabetTargets: [AlphabetTarget<ItemRow.ID>] { activeIndex.alphabetTargets(search) }
    var listSelection: ItemRow.ID? {
        get {
            // A keyboard highlight is not a navigation selection. Feeding it
            // into List(selection:) makes iOS push a detail screen while typing.
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
        get { selectedDeleted.flatMap { deletedIndex.search(search).ids.contains($0) ? $0 : nil } }
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
        get {
            if collection == .all, let identity = selectedLocalIdentity {
                return .init(vault: LocalVault.id, name: identity.id.uuidString)
            }
            return selectedItem.map { .init(vault: vault, name: $0) }
        }
        set {
            guard !busy, (newValue != selectedRow || vaultDetailsTarget != nil), allowTransition(.item(newValue)) else { return }
            vaultDetailsTarget = nil
            cancelItemEditing(); selected = nil; passwordQualities = [:]; passwordQualitySource = nil
            selectedLocalIdentityID = nil
            guard let newValue else { selectedItem = nil; return }
            if newValue.vault == LocalVault.id, collection == .all,
               let identity = localIdentities.first(where: { $0.id.uuidString == newValue.name }) {
                selectedItem = nil
                selectedLocalIdentityID = identity.id
                return
            }
            if let cached = catalogs[newValue.vault] {
                // Selection reuses the display projection; it is not a catalog update.
                if vault != newValue.vault || catalog == nil {
                    vault = newValue.vault
                    catalog = cached
                }
                selectedItem = newValue.name
            }
        }
    }
    func chooseVault(_ id: String) {
        guard !busy, allowTransition(.vault(id)) else { return }
        showArchived = false; favoritesOnly = false
        allVaults = false; page = .secrets; vault = id
        if id == LocalVault.id {
            restoreLastSelection = false
            pendingLocalSelection = nil
            collection = .local
            clearSelection()
            openLocalVault()
            return
        }
        changedVault()
        if vaults.first(where: { $0.id == id })?.enrolled == false { enrollmentAction(.automaticEnrollment, vaultID: id); return }
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
    func chooseCredentials(_ collection: ItemCollection) {
        guard collection == .passkeys || collection == .sshKeys,
              !busy, allowTransition(.credentials(collection)) else { return }
        self.collection = collection
        searchHighlighted = nil
        searchIsFocused = false
        changedVault()
        scheduleAutomaticUnlock()
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
        get { securityVisible ? "security" : collection.sidebarID }
        set {
            guard newValue != sidebarSelection else { return }
            if newValue == "security" {
                guard itemDraft == nil else { return }
                conceal(); selectedItem = nil; selected = nil; selectedLocalIdentityID = nil
                vaultDetailsTarget = nil
                securityVisible = true; openLocalVault(); refreshHealth(); return
            }
            securityVisible = false
            if newValue == "passkeys" || newValue == "ssh-keys" {
                chooseCredentials(newValue == "passkeys" ? .passkeys : .sshKeys)
            }
            else if newValue == "recent-added" { chooseRecent(.recentlyAdded) }
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
        guard let catalog, let item = selectedTypedItem else { return [] }
        return item.fields.compactMap { field in
            try? SecretReference(vault: catalog.vault,
                relativePath: SecretReference.encode(item.name) + "/" + field.path)
        }
    }
    func metadata(_ ref: SecretReference) -> ItemField? {
        catalog?.items.first { $0.name == ref.item }?.fields.first { ref.relativePath == SecretReference.encode(ref.item) + "/" + $0.path }
    }
    func applyCatalog(_ catalog: ItemCatalog) throws {
        try VaultName.validate(catalog.vault)
        self.catalog = catalog
        if !vault.isEmpty { catalogs[vault] = catalog }
        if passwordQualitySource != passwordQualityIdentity { passwordQualities = [:]; passwordQualitySource = nil }
    }
    // MARK: - Device-local vault

    private func localStore() throws -> any LocalVaultServing {
        if let localService { return localService }
        let service = try LocalVaultService()
        localService = service
        return service
    }

    /// Load the device's local identities. Listing requires no authentication; the
    /// public keys are not secret.
    func openLocalVault() {
        guard !localLoading else { return }
        localLoading = true; localError = nil
        Task { @MainActor in
            defer { localLoading = false }
            do {
                localIdentities = try localStore().list()
                localReady = true
                if let id = pendingLocalSelection {
                    pendingLocalSelection = nil
                    selectedLocalIdentityID = localIdentities.first(where: { $0.id == id })?.id
                }
                reconcileLocalCredentialEvidence()
            } catch {
                localError = (error as? MopError)?.errorDescription ?? "Could not read the device-local vault."
            }
        }
    }

    func beginLocalCreate() {
        guard !localCreating, !localDeleteInProgress else { return }
        localCreateName = ""
        localCreateAcknowledged = false
        localCreateProtocol = .ssh
        selectedLocalIdentityID = nil
        localCreatePresented = true
    }

    func cancelLocalCreate() {
        localCreatePresented = false
        localCreateName = ""
    }

    func submitLocalCreate() {
        let name = localCreateName
        let protocolType = localCreateProtocol
        guard !localCreating, !name.isEmpty, localCreateAcknowledged, LocalIdentityProtocol.creatable.contains(protocolType) else { return }
        let securityToken = securityGeneration
        localCreating = true
        Task { @MainActor in
            defer { localCreating = false }
            do {
                let context = try await authorizeLocal("create a device-local identity in the Secure Enclave", [], [protocolType], [.create])
                defer { context.revoke(); localAuthorization = nil }
                guard securityGeneration == securityToken else { throw MopError.authentication }
                localAuthorization = context
                let created = try localStore().create(name: name, protocolType: protocolType, authorization: context)
                localIdentities = try localStore().list()
                localReady = true
                localError = nil
                localCreatePresented = false
                selectedLocalIdentityID = created.id
                localCreateName = ""
            } catch {
                localError = (error as? MopError)?.errorDescription ?? "Could not create the identity."
            }
        }
    }

    func requestLocalDelete(_ id: UUID) {
        guard !localDeleteInProgress, !localCreating else { return }
        localDeleting = id
    }
    func confirmLocalDelete() {
        guard let id = localDeleting, !localDeleteInProgress else { return }
        localDeleting = nil
        let securityToken = securityGeneration
        localDeleteInProgress = true
        Task { @MainActor in
            defer { localDeleteInProgress = false }
            do {
                guard let identity = localIdentities.first(where: { $0.id == id }) else { throw MopError.notFound }
                let context = try await authorizeLocal("delete a device-local identity", [id], [identity.protocolType], [.delete])
                defer { context.revoke(); localAuthorization = nil }
                guard securityGeneration == securityToken else { throw MopError.authentication }
                localAuthorization = context
                try Task.checkCancellation()
                try localStore().delete(id: id, authorization: context)
                localIdentities = try localStore().list()
                localReady = true
                reconcileLocalCredentialEvidence()
                localError = nil
            } catch {
                localError = "Could not delete the identity."
            }
        }
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
        let purpose = itemDraft?.sshPurpose ?? .ssh
        let passphrase = itemDraft.flatMap { $0.sshPassphrase.isEmpty ? nil : SecretBytes(utf8: $0.sshPassphrase) }
        perform { token in
            let edit = try await CloudCredentialService(self.service).prepareSSHSave(edit, vault: destination, purpose: purpose, passphrase: passphrase)
            guard self.current(token) else { return }
            let result = try await self.service.execute(.save(edit), vault: destination, offline: false)
            guard self.current(token) else { return }
            let catalog = try result.requireCatalog()
            self.vault = destination
            try self.applyCatalog(catalog)
            self.itemDraft = nil
            self.selectedItem = item.name; self.selected = nil; self.sheet = nil
            self.conceal(); self.notice = result.message
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
        var changes = item
        if !create, let stored = catalog.items.first(where: { $0.name == (originalName ?? item.name) }) {
            for index in changes.fields.indices {
                let field = changes.fields[index]
                if let original = stored.fields.first(where: { $0.path == field.path }),
                   original.type == field.type, original.value == field.value {
                    changes.fields[index].value = nil
                }
            }
        }
        let edit = ItemEdit(revision: revision ?? catalog.revision, item: changes, create: create, originalName: originalName)
        let destination = vault
        let purpose = itemDraft?.sshPurpose ?? .ssh
        let passphrase = itemDraft.flatMap { $0.sshPassphrase.isEmpty ? nil : SecretBytes(utf8: $0.sshPassphrase) }
        perform { token in
            let edit = try await CloudCredentialService(self.service).prepareSSHSave(edit, vault: destination, purpose: purpose, passphrase: passphrase)
            guard self.current(token) else { return }
            let result = try await self.service.execute(.save(edit), vault: destination, offline: false)
            guard self.current(token) else { return }
            try self.applyCatalog(result.requireCatalog())
            self.selectedItem = item.name; self.selected = nil; self.sheet = nil
            if self.itemDraft?.id == draftID { self.itemDraft = nil }
            self.refreshHealth(afterSave: true)
            self.conceal(); self.notice = originalName != nil && originalName != item.name ? "Item renamed. Update references that use the old name." : result.message
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
                    let result = try await self.service.readLocal(reference, vault: draft.vault, itemID: item.storageID)
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
            case .active: self.activate(); Task { await SubscriptionModel.shared.refresh() }
            case .cloudChanged: self.service.invalidateDiscovery(); self.requestBackgroundSynchronization(); self.cloudChanged()
            case .inactive: self.deactivate()
            case .background: self.background()
            case .lock: self.deactivate(); self.lock(reason: .system)
            case .accountChanged: SubscriptionModel.shared.accountChanged();
                self.lock(); self.vaults = []; self.vault = ""
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
        if busy && !authenticated { lock(clearClipboard: false) }
        checkExpiration()
    }
    func deactivate() { service.setMaintenanceActive(false); isActive = false; visibilityGeneration += 1; conceal(); automaticUnlockTask?.cancel(); automaticUnlockTask = nil }
    func activate() {
        service.setMaintenanceActive(true)
        Task { try? await AutoFillPublisher.shared.reconcile() }
        checkExpiration(); isActive = true
        reloadUsage()
        if service.isAuthenticated, !busy { lastActivity = now() }
        scheduleAutomaticUnlock(); checkRetention()
        if launchAttempted {
            requestBackgroundSynchronization()
            service.invalidateDiscovery()
            if authenticated || vaults.contains(where: { $0.supported && !$0.enrolled }) { cloudChanged() }
        }
    }
    private func clearSelection() {
        selectedLocalIdentityID = nil
        generation += 1; editorGeneration += 1; itemDraft = nil; draftConflict = false
        selectedDeleted = nil; itemToDelete = nil
        conceal(); catalog = nil; passwordQualities = [:]; passwordQualitySource = nil; selected = nil; members = []
        selectedItem = nil; sheet = nil; notice = nil
        importing = false; importStatus = nil; importFraction = nil; importReport = nil; importFailed = false
        vaultDetailsTarget = nil; deleteConfirmation = false; documentRequest = nil; error = nil
    }
    private func clearView() {
        let wasRestoring = restoringSelection
        restoringSelection = true
        defer { restoringSelection = wasRestoring }
        authenticated = false
        clearSelection()
        catalogLoadProgress = [:]; catalogUpdatePaused = false; pendingDisplayVaults.removeAll()
        catalogs = [:]; deletedCatalogs = [:]; cachedVaults = []
    }
    func lock(clearClipboard: Bool = true, reason: LockReason = .manual) {
        #if os(macOS)
        DistributedNotificationCenter.default().postNotificationName(LocalAuthorization.appLockNotification, object: nil, userInfo: nil, deliverImmediately: true)
        #endif
        keyCreationPresented = false
        localAuthorization?.revoke(); localAuthorization = nil
        rememberSelection(); restoreLastSelection = true
        securityGeneration += 1
        clearHealth(); pendingSecurityUpgrade = nil
        usageLoadTask?.cancel(); usageLoadGeneration += 1; lastUsed = [:]
        search = ""; searchHighlighted = nil; searchIsFocused = false; lastBackupURL = nil
        syncWakeTask?.cancel(); syncWakeTask = nil; syncWakeID = nil
        syncWakeAgain = false; requestingSynchronization = false; syncIssue = nil; syncIssueDetails = nil
        connectionUnlockPending = false
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
        pendingLocalSelection = nil
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
        if descriptor.id == LocalVault.id { return "internaldrive" }
        if !descriptor.supported { return "exclamationmark.triangle" }
        if !descriptor.enrolled { return "externaldrive.badge.plus" }
        return authenticated && catalogs[descriptor.id] != nil ? "lock.open" : "lock.rectangle"
    }
    func vaultConnectionLabel(_ descriptor: VaultDescriptor) -> String {
        if descriptor.id == LocalVault.id { return "Device-only · Secure Enclave" }
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
                if cloudRefreshPending || !pendingDisplayVaults.isEmpty { refreshCloudIfNeeded() }
                removingDevice = false; removalProgress = nil
                if savingTransition {
                    if itemDraft == nil && error == nil && token == generation { completePendingTransition() }
                    else { cancelPendingTransition() }
                }
            }
            guard self.current(token) else { return }
            do { try await action(token) }
            catch {
                let originalError = error
                let error: any Error = Authentication.requiresRenewal(originalError) ? MopError.authentication : originalError
                if token == generation && !Task.isCancelled {
                    if error as? MopError == .deviceRemoved || error as? MopError == .deviceRemovalPending {
                        self.showDeviceRemoved(pending: error as? MopError == .deviceRemovalPending); return
                    }
                    self.launchUnlockAvailable = false
                    self.connectionUnlockPending = false
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
                    if Authentication.requiresRenewal(originalError) {
                        self.error = "Unlock 2ndPass again to continue. Your device requires authentication."
                    } else if error as? MopError == .vaultUntrusted {
                        self.error = self.connectionRepairMessage
                    } else {
                        self.error = (error as? MopError)?.errorDescription ?? (error as? ItemVaultServiceFailure)?.errorDescription ?? (error as? PortableArchiveFailure)?.errorDescription ?? (error as? ImportFailure)?.errorDescription ?? (error as? AttachmentFailure)?.errorDescription ?? (error as? CompoundFieldFailure)?.errorDescription ?? "The operation could not be completed."
                    }
                    self.recordError(originalError, operation: "\(operation) at \(file):\(line)")
                }
            }
        }
    }
    func current(_ token: Int) -> Bool { checkExpiration(); return token == generation }

    func start() {
        guard !launchAttempted else { return }
        launchAttempted = true
        if defaults.bool(forKey: "lastSelectionWasLocal"),
           let bytes = defaults.data(forKey: "lastSelection.local"),
           let saved = try? JSONDecoder().decode(SavedSelection.self, from: bytes) {
            restoringSelection = true
            vault = LocalVault.id
            collection = .local
            pendingLocalSelection = saved.localItem
            restoringSelection = false
            restoreLastSelection = false
            openLocalVault()
            discover(autoUnlock: false)
        } else {
            discover(autoUnlock: true)
        }
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
            let connectedAutomatically = rows.contains { row in
                row.enrolled && self.vaults.contains { $0.id == row.id && !$0.enrolled }
            }
            self.vaults = rows
            self.catalogLoadProgress = self.catalogLoadProgress.filter { ids.contains($0.key) }
            self.catalogs = self.catalogs.filter { ids.contains($0.key) }
            self.deletedCatalogs = self.deletedCatalogs.filter { ids.contains($0.key) }
            // Use the repository's account-scoped default, never an arbitrary vault.
            if self.vault.isEmpty {
                if let id = result.defaultVault, ids.contains(id) { self.vault = id }
            } else if self.vault != LocalVault.id && !ids.contains(self.vault) {
                self.vault = ""; self.lock(reason: .accessFailure)
                if rows.isEmpty && result.discoveryComplete && !self.isLocalVaultSelected { self.sheet = .createVault }
                else if !rows.isEmpty && !rows.contains(where: { $0.supported && $0.enrolled }) { self.status = "Connecting iCloud vaults…" }
                return
            }
            self.status = ids.isEmpty ? (result.discoveryComplete ? "Create your first vault" : "Checking iCloud for vaults…") : self.authenticated ? "Refreshing vaults…" : "Locked"
            if self.sheet == nil {
                if rows.isEmpty && result.discoveryComplete && !self.isLocalVaultSelected { self.sheet = .createVault }
                else if !rows.isEmpty && !rows.contains(where: { $0.supported && $0.enrolled }) {
                    self.status = "Connecting iCloud vaults…"
                }
            }
            if autoUnlock && !rows.isEmpty && !rows.contains(where: { $0.supported && $0.enrolled }) {
                try await self.connectDiscoveredVaults(token)
            }
            if self.isActive, (refreshContents || self.connectionUnlockPending || ((autoUnlock || connectedAutomatically) && self.launchUnlockAvailable)),
               self.vaults.contains(where: { $0.supported && $0.enrolled }) {
                if !selectedOnly && !refreshContents { self.allVaults = true }
                try await self.unlockContents(token, refresh: !refreshContents)
            }
        }
    }
    func retryVaultConnection() {
        guard !busy, isActive, !authenticated else { return }
        service.invalidateDiscovery()
        discover(autoUnlock: true)
    }
    func unlock() {
        guard !busy, !authenticated, isActive, !deviceRemoved else { return }
        launchUnlockAvailable = false; accessNeedsRepair = false
        cancelItemEditing(); conceal(); catalog = nil; catalogs = [:]; deletedCatalogs = [:]
        passwordQualities = [:]; passwordQualitySource = nil; authenticated = false
        perform { token in try await self.unlockContents(token) }
    }
    private func connectDiscoveredVaults(_ token: Int) async throws {
        connectionUnlockPending = true
        status = "Connecting your iCloud vaults…"
        for descriptor in vaults where descriptor.supported && !descriptor.enrolled {
            let result = try await service.execute(.manage(.automaticEnrollment), vault: descriptor.id, offline: false)
            guard current(token) else { return }
            if !result.message.isEmpty { status = result.message }
        }
        let result = try await service.execute(.discover, vault: nil, offline: false)
        guard current(token) else { return }
        vaults = result.vaults
    }
    private func unlockContents(_ token: Int, refresh: Bool = true) async throws {
        if requestedVaultIDs.isEmpty, vaults.contains(where: { $0.supported && !$0.enrolled }) {
            try await connectDiscoveredVaults(token)
        }
        cancelCatalogLoading()
        launchUnlockAvailable = false
        let openingSession = !authenticated
        if openingSession { unlocking = true }
        defer { if openingSession { unlocking = false; if !loadingVaults { rememberSelection() } } }
        do {
            let requested = requestedVaultIDs
            let ids = requested.contains(vault) ? [vault] + requested.filter { $0 != vault } : requested
            guard !ids.isEmpty else { status = "Connecting iCloud vaults. Open 2ndPass on an existing device to finish syncing key access."; return }
            var loaded = refresh ? [:] : catalogs.filter { ids.contains($0.key) }
            var deleted = refresh ? [:] : deletedCatalogs.filter { ids.contains($0.key) }
            var dates: [String: Date] = [:]
            for id in ids {
                if loaded[id] != nil { break }
                let result: VaultResult
                do {
                    if openingSession, let cached = try await service.cachedCatalog(vault: id) { result = cached }
                    else { result = try await service.displayCatalog(vault: id) }
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
                recordCatalogProgress(result, vaultID: id)
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
                catalog = nil; vault = ""
                status = vaults.isEmpty ? "Create your first vault" : "Connect this device to a vault to get started."
                sheet = vaults.isEmpty ? .createVault : nil
                return
            }
            if vault.isEmpty { vault = ids.first(where: { loaded[$0] != nil }) ?? "" }
            if let catalog = loaded[vault] { try applyCatalog(catalog) }
            else { catalog = nil }
            authenticated = true; accessNeedsRepair = false; connectionUnlockPending = false
            if openingSession { restoreSelection() }
            if lastActivity == nil { lastActivity = now() }
            for (id, catalog) in loaded {
                vaults.removeAll { $0.id == id }
                vaults.append(VaultDescriptor(id: id, name: catalog.vault, format: "mop-items-v2", enrolled: true))
            }
            if catalogLoadProgress[vault] == nil, let item = selectedItem, catalog?.items.contains(where: { $0.name == item }) != true { selectedItem = nil }
            if catalogLoadProgress[vault] == nil, let selected, !itemFields.contains(selected) { self.selected = nil }
            let date = dates.values.min().map { ISO8601DateFormatter().string(from: $0) } ?? "unknown time"
            status = offline ? "Read only · oldest verified cache from \(date)" : "Unlocked · \(loaded.count) vault\(loaded.count == 1 ? "" : "s")"
            loadRemainingCatalogs(ids.filter { (loaded[$0] == nil || cachedVaults.contains($0)) && requestedVaultIDs.contains($0) }, token: token)
            if openingSession { requestBackgroundSynchronization() }
        } catch {
            // The selected vault must verify before opening the session.
            service.lock(); lastActivity = nil; authenticated = false
            catalog = nil; catalogs = [:]; deletedCatalogs = [:]
            passwordQualities = [:]; passwordQualitySource = nil; conceal(); clearClipboard()
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
                        do { return (id, .success(try await service.displayCatalog(vault: id))) }
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
                        self.recordCatalogProgress(result, vaultID: id)
                        if self.selectedItemChanged(in: fresh, vaultID: id) { self.conceal() }
                        try self.applyTargetCatalog(fresh, id: id)
                        self.deletedCatalogs[id] = result.deletedCatalog
                        if let index = self.vaults.firstIndex(where: { $0.id == id }), let catalog = result.catalog {
                            self.vaults[index] = VaultDescriptor(id: id, name: catalog.vault, format: "mop-items-v2", enrolled: true)
                        }
                        self.restoreSelection()
                        if self.vault == id {
                            if self.catalogLoadProgress[id] == nil, let item = self.selectedItem, !fresh.items.contains(where: { $0.name == item }) { self.selectedItem = nil }
                            if self.catalogLoadProgress[id] == nil, let selected = self.selected, !self.itemFields.contains(selected) { self.selected = nil }
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
                            if failure != .authentication { self.accessNeedsRepair = true }
                            self.lock(reason: .accessFailure)
                            self.error = failure == .vaultUntrusted ? self.connectionRepairMessage : failure.errorDescription
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
                                    self.catalogs[id] = nil; self.deletedCatalogs[id] = nil; self.catalogLoadProgress[id] = nil
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
                                // Preserve the displayed catalog when discovery fails.
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
            self.reconcileDeferredStoreChange()
        }
    }
    var passwordQualityIdentity: [String]? {
        guard authenticated, let item = selectedTypedItem, let catalog,
              item.fields.contains(where: { $0.type == .password }) else { return nil }
        return [String(generation), String(service.sessionGeneration), vault, item.name] + item.fields.flatMap { field in
            if field.type == .password { return [field.path, field.recordVersion ?? catalog.revision] }
            if field.type == .username || field.type == .email { return [field.path, field.value ?? ""] }
            return []
        }
    }
    func passwordQuality(for path: String) -> PasswordQuality? {
        guard passwordQualitySource == passwordQualityIdentity else { return nil }
        return passwordQualities[path]
    }
    func loadPasswordQuality() async {
        guard let request = passwordQualityIdentity, service.isAuthenticated, let item = selectedTypedItem else {
            passwordQualities = [:]; passwordQualitySource = nil; return
        }
        let passwords = item.fields.filter { $0.type == .password }
        if passwords.allSatisfy({ $0.passwordQuality != nil }) {
            passwordQualities = Dictionary(uniqueKeysWithValues: passwords.compactMap { field in field.passwordQuality.map { (field.path, $0) } })
            passwordQualitySource = request
            return
        }
        if passwordQualitySource == request && !passwordQualities.isEmpty { return }
        passwordQualities = [:]; passwordQualitySource = nil
        let token = generation, id = vault, name = item.name
        do {
            let result = try await service.execute(.passwordQuality(item: name), vault: id, offline: true)
            guard current(token), !Task.isCancelled, passwordQualityIdentity == request else { return }
            passwordQualities = result.passwordQuality; passwordQualitySource = request
        } catch {
            // Scores are optional; never expose service diagnostics.
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
        let result = try await service.readLocal(reference, vault: id, itemID: selectedTypedItem?.storageID)
        guard current(token), !Task.isCancelled, isActive, visibilityGeneration == visibility,
              vault == id, selectedItem == item, let value = result.value else { throw MopError.authentication }
        guard let expires = result.otpExpiresAt, let period = result.otpPeriod else { throw MopError.invalidOTP }
        return (String(decoding: value, as: UTF8.self), expires, period)
    }

    func loadAttachment(_ reference: SecretReference, completion: @escaping @MainActor (Attachment) -> Void) {
        let visibility = visibilityGeneration, id = selectedVault, item = selectedItem
        perform(local: true) { token in
            let result = try await self.service.readLocal(reference, vault: id, itemID: self.selectedTypedItem?.storageID)
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
            let result = try await self.service.readLocal(selected, vault: self.selectedVault, itemID: self.selectedTypedItem?.storageID)
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
            self.sheet = nil; self.conceal(); self.notice = result.message
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
        deviceRemoved = true; vaults = []; vault = ""; devices = []
        error = nil; sheet = .enrollDevice
    }
    func showRecoveryTestReset(pending: Bool = false) {
        let inSettings = sheetRequest?.inSettings ?? false
        showDeviceRemoved(pending: pending)
        sheetRequest = SheetRequest(kind: .recover, inSettings: inSettings, target: nil)
        if pending { error = "The device reset needs to finish local cleanup. Restart 2ndPass before continuing recovery." }
    }
    func resetCloudAccess() {
        guard supports(.enrollment), cloudConnectionRepairEnabled, sessionState == .needsRepair, !busy else { return }
        perform { _ in
            _ = try await self.service.execute(.manage(.resetCloudAccess), vault: nil, offline: false)
        }
    }
    func reconnectDevice() {
        perform { token in
            _ = try await self.service.execute(.manage(.reconnect), vault: nil, offline: false)
            guard self.current(token) else { return }
            self.deviceRemoved = false; self.removalCleanupPending = false
            self.accessNeedsRepair = false
            self.launchUnlockAvailable = false
            let discovery = try await self.service.execute(.discover, vault: nil, offline: false)
            guard self.current(token) else { return }
            self.offline = discovery.usingCache
            self.vaults = discovery.vaults
            self.sheet = .enrollDevice
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
    var enrollmentView: MopAppSupport.ItemEnrollmentView?
    func enrollmentAction(_ action: VaultManagement, vaultID: String) {
        guard !vaultID.isEmpty, !busy else { return }
        let requestID = sheetRequest?.id
        perform { token in
            let result = try await self.service.execute(.manage(action), vault: vaultID, offline: false)
            guard self.current(token), self.sheetRequest?.id == requestID else { return }
            self.enrollmentView = result.enrollment
            self.notice = result.message
            if result.enrollmentCompleted {
                self.vault = vaultID
                self.service.invalidateDiscovery()
                self.sheet = nil
                self.cloudRefreshPending = true
                self.accessNeedsRepair = false
                self.launchUnlockAvailable = true
            }
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
    var autoFillRefreshMessage: String?
    func refreshAutoFillSuggestions() {
        guard authenticated, service.isAuthenticated, !busy, !refreshing else { return }
        requestTransition(.refreshSuggestions) { [weak self] accepted in
            guard accepted, let self else { return }
            self.perform { token in
                self.autoFillRefreshMessage = nil
                let status = try await self.service.refreshAutoFillSuggestions(offline: self.offline)
                guard self.current(token) else { return }
                self.autoFillRefreshMessage = status.phase == .current ? "Suggestions refreshed." :
                    status.message ?? (status.phase == .disabled ? "Enable 2ndPass in AutoFill settings to show suggestions." : "Suggestions could not be refreshed. Try again.")
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
    private func reconcileDeferredStoreChange() {
        guard cloudRefreshPending || !pendingDisplayVaults.isEmpty else { return }
        Task { [weak self] in
            await Task.yield()
            self?.refreshCloudIfNeeded()
        }
    }
    /// Projection progress only reads already prepared rows for the affected
    /// vaults. It does not rediscover inventory, scan conflicts or start loaders.
    private func refreshDisplayIfNeeded() {
        guard authenticated, !pendingDisplayVaults.isEmpty else { pendingDisplayVaults.removeAll(); return }
        let ids = pendingDisplayVaults.intersection(Set(requestedVaultIDs))
        pendingDisplayVaults.removeAll()
        guard !ids.isEmpty else { return }
        let token = generation, revision = foregroundRevision, editing = editorGeneration
        refreshing = true
        refreshTask = Task {
            defer { refreshing = false; reconcileDeferredStoreChange() }
            do {
                for id in ids.sorted() {
                    guard let result = try await service.cachedCatalog(vault: id) else { continue }
                    guard current(token), !Task.isCancelled else { return }
                    guard isActive, !busy, itemDraft == nil, sheet == nil,
                          revision == foregroundRevision, editing == editorGeneration else {
                        pendingDisplayVaults.formUnion(ids); return
                    }
                    guard requestedVaultIDs.contains(id) else { continue }
                    let fresh = try result.requireCatalog()
                    recordCatalogProgress(result, vaultID: id)
                    if selectedItemChanged(in: fresh, vaultID: id) { conceal() }
                    try applyTargetCatalog(fresh, id: id)
                    deletedCatalogs[id] = result.deletedCatalog
                    if let index = vaults.firstIndex(where: { $0.id == id }) {
                        vaults[index] = VaultDescriptor(id: id, name: fresh.vault, format: vaults[index].format, enrolled: vaults[index].enrolled)
                    }
                    if vault == id, catalogLoadProgress[id] == nil {
                        if let item = selectedItem, !fresh.items.contains(where: { $0.name == item }) { selectedItem = nil }
                        if let selected, !itemFields.contains(selected) { self.selected = nil }
                    }
                }
                if selectedItem == nil && selectedDeleted == nil { restoreSelection() }
            } catch {
                guard current(token), !Task.isCancelled else { return }
                if let failure = error as? MopError,
                   [.authentication, .signing, .invalidIdentity, .invalidVault, .vaultUntrusted, .notVaultMember, .cloudAccount].contains(failure) {
                    if failure != .authentication { accessNeedsRepair = true }
                    lock(reason: .accessFailure)
                } else { catalogUpdatePaused = true }
                recordError(error, operation: "Local catalog refresh")
            }
        }
    }
    func cloudChanged() {
        refreshConflicts()
        cloudRefreshPending = true
        refreshCloudIfNeeded()
    }
    func refreshCloudIfNeeded() {
        guard launchAttempted, isActive, !busy, !refreshing, !loadingVaults, itemDraft == nil, sheet == nil,
              !accessNeedsRepair, pendingTransition == nil else { return }
        guard cloudRefreshPending else { refreshDisplayIfNeeded(); return }
        pendingDisplayVaults.removeAll()
        cloudRefreshPending = false
        // Store commits, foregrounding and network changes request reconciliation.
        // CKSyncEngine owns network scheduling; the UI has no sync polling timer.
        guard authenticated else { discover(); return }
        let token = generation, revision = foregroundRevision, editing = editorGeneration
        let selectedVault = vault, requested = requestedVaultIDs
        refreshing = true
        refreshTask = Task {
            var reconcileAgain = true
            defer { refreshing = false; if reconcileAgain { reconcileDeferredStoreChange() } }
            guard current(token), !Task.isCancelled, isActive else { return }
            do {
                let discovery = try await service.execute(.discover, vault: nil, offline: false)
                guard current(token), !Task.isCancelled else { return }
                let available = Set(discovery.vaults.map(\.id))
                guard requested.allSatisfy({ available.contains($0) }) else {
                    vaults = discovery.vaults
                    if vault != LocalVault.id && !available.contains(vault) { vault = "" }
                    lock()
                    if vaults.isEmpty { sheet = .createVault }
                    return
                }
                var loaded: [String: ItemCatalog] = [:], deleted: [String: ItemCatalog] = [:]
                var progressResults: [String: VaultResult] = [:]
                var dates: [Date] = []
                for id in requested {
                    let result = try await service.displayCatalog(vault: id)
                    guard current(token), !Task.isCancelled else { return }
                    progressResults[id] = result
                    loaded[id] = try result.requireCatalog(); deleted[id] = result.deletedCatalog
                    if let date = result.offlineDate { dates.append(date) }
                }
                // A foreground operation or draft may have started while fetching.
                // Never replace its state with an earlier refresh result.
                guard isActive, !busy, itemDraft == nil, sheet == nil,
                      revision == foregroundRevision, editing == editorGeneration,
                      vault == selectedVault, requestedVaultIDs == requested else {
                    cloudRefreshPending = true; return
                }
                for (id, result) in progressResults { recordCatalogProgress(result, vaultID: id) }
                if selectedItemChanged(in: loaded[vault], vaultID: vault) { conceal() }
                vaults = discovery.vaults; catalogs = loaded; deletedCatalogs = deleted
                // Newly connected vaults join the existing authenticated view;
                // do not return to the lock screen or discard already open rows.
                let newlyConnected = requestedVaultIDs.filter { !requested.contains($0) }
                loadRemainingCatalogs(newlyConnected, token: token)
                retentionDate = wallNow(); cachedVaults = []; offline = !dates.isEmpty
                if let next = loaded[vault] { try applyCatalog(next) }
                if selectedItem == nil && selectedDeleted == nil { restoreSelection() }
                if catalogLoadProgress[vault] == nil, let item = selectedItem, catalog?.items.contains(where: { $0.name == item }) != true { selectedItem = nil }
                if catalogLoadProgress[vault] == nil, let selected, !itemFields.contains(selected) { self.selected = nil }
                let date = dates.min().map { ISO8601DateFormatter().string(from: $0) } ?? "unknown time"
                status = offline ? "Read only · oldest verified cache from \(date)" : "Unlocked · \(loaded.count) vault\(loaded.count == 1 ? "" : "s")"
            } catch {
                reconcileAgain = false
                if isUpdatingCatalog { catalogUpdatePaused = true }
                guard token == generation, !Task.isCancelled else { return }
                if error as? MopError == .deviceRemoved || error as? MopError == .deviceRemovalPending {
                    showDeviceRemoved(pending: error as? MopError == .deviceRemovalPending); return
                }
                if let failure = error as? MopError,
                   [.authentication, .signing, .invalidIdentity, .invalidVault, .vaultUntrusted, .notVaultMember, .cloudAccount].contains(failure) {
                    if failure != .authentication { accessNeedsRepair = true }
                    lock(reason: .accessFailure)
                    self.error = failure == .vaultUntrusted ? self.connectionRepairMessage : failure.errorDescription
                } else {
                    cloudRefreshPending = true
                }
                recordError(error, operation: "Background cloud refresh")
            }
        }
    }
    var showsSetupChecklist = false
    func createVault(name: String) {
        guard !offline, !busy else { return }
        restoreLastSelection = false
        conceal(); catalog = nil; catalogs = [:]; passwordQualities = [:]; passwordQualitySource = nil; selected = nil; members = []; authenticated = false
        let id = UUID().uuidString
        perform { token in
            // Retain this UUID even on a failed/uncertain initialization for reconciliation.
            self.allVaults = false; self.vault = id; self.vaults.append(VaultDescriptor(id: id, name: name, format: "mop-items-v2", enrolled: true))
            self.status = "Creating vault \(id) · retain this UUID if publication is interrupted"
            let result = try await self.service.execute(.create(name: name), vault: id, offline: false)
            guard self.current(token) else { return }
            try self.applyCatalog(result.requireCatalog())
            try await self.unlockContents(token, refresh: false)
            self.selected = nil; self.sheet = self.importAfterCreation ? .importItems : nil; self.importAfterCreation = false; self.showsSetupChecklist = true
            self.notice = result.message; self.status = "Vault created · save a portable backup in settings"
        }
    }
    func completePortableRestore(_ result: VaultResult, id: String, token: Int) async throws {
        guard current(token) else { return }
        let restored = try result.requireCatalog()
        restoreLastSelection = false
        conceal(); selected = nil; selectedItem = nil
        allVaults = false; vault = id
        vaults.removeAll { $0.id == id }
        vaults.append(VaultDescriptor(id: id, name: restored.vault, format: "mop-items-v2", enrolled: true))
        try applyCatalog(restored)
        try await unlockContents(token, refresh: false)
        guard current(token) else { return }
        sheet = nil
        notice = result.message
        status = "Portable backup restored · verify contents before removing the original vault"
    }

    private func applyTargetCatalog(_ catalog: ItemCatalog, id: String) throws {
        catalogs[id] = catalog
        if vault == id { try applyCatalog(catalog) }
    }
    func renameVault(to name: String, target: VaultDescriptor? = nil) {
        guard !offline, let target = target ?? selectedVaultDescriptor else { return }
        guard target.id != LocalVault.id else { error = LocalVaultPolicy.disallowedReason(.renameVault) ?? ""; return }
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
        guard target.id != LocalVault.id else { error = LocalVaultPolicy.disallowedReason(.deleteVault) ?? ""; return }
        guard !offline, !busy, confirmation == (target.name ?? target.id) else { return }
        conceal(); clearClipboard(); catalog = nil; selected = nil; selectedItem = nil; authenticated = false
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
        guard target.id != LocalVault.id else { error = LocalVaultPolicy.disallowedReason(.export) ?? ""; return }
        pendingSecurityUpgrade = nil
        documentRequest = DocumentRequest(vault: target.id, generation: securityGeneration)
    }
    func completeBackupSelection(folder: URL, request: DocumentRequest) {
        guard securityGeneration == request.generation else { return }
        let rawName = vaults.first { $0.id == request.vault }?.name ?? "vault"
        let name = String(rawName.prefix(80).map { $0.isLetter || $0.isNumber || $0 == "-" ? $0 : "-" })
        let date = wallNow().formatted(.iso8601.year().month().day().dateSeparator(.dash))
        exportBackup(to: folder.appendingPathComponent("sp-" + name + "-" + date + "-" + String(UUID().uuidString.prefix(8)) + ".mopfile"), vaultID: request.vault)
    }
    func exportBackup(to url: URL, vaultID: String? = nil) {
        guard !busy, let id = vaultID ?? selectedVault, vaults.contains(where: { $0.id == id && $0.enrolled }) else { return }
        perform { token in
            let operation: VaultOperation
            if let upgrade = self.pendingSecurityUpgrade, upgrade.0 == id {
                operation = .upgradeSecurity(backup: url, revision: upgrade.1)
            } else { operation = .export(url) }
            self.pendingSecurityUpgrade = nil
            let result = try await self.service.execute(operation, vault: id, offline: false)
            if self.current(token), let updated = result.catalog {
                self.catalogs[id] = updated
                if self.vault == id { try self.applyCatalog(updated) }
            }
            guard self.current(token) else { return }
            self.lastBackupURL = url; self.lastBackupVaultID = id
            self.notice = "Encrypted backup exported. Keep your offline recovery copy separately."
        }
    }

}

/// User-initiated transitions that can replace the single, session-local draft.
enum PendingTransition {
    case item(ItemRow.ID?), vault(String), allItems, recentlyDeleted
    case collection(archived: Bool)
    case recent(ItemCollection)
    case credentials(ItemCollection)
    case vaultTarget(String), sheet(AppSheet), presentation(SheetRequest), details(VaultDescriptor?), refresh, trash(ItemRow)
    case refreshSuggestions, closeWindow, quit
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

    func supports(_ capability: VaultServiceCapability) -> Bool { service.capabilities.contains(capability) }
    func canPresent(_ kind: AppSheet) -> Bool {
        switch kind {
        case .enrollDevice, .addDevice: supports(.enrollment)
        case .shareAccount: supports(.sharing)
        case .setupRecovery, .recover: supports(.recovery)
        case .importItems: supports(.importDocuments)
        case .deleteVault: supports(.vaultDeletion)
        case .portableBackup, .restoreBackup: supports(.portableBackup)
        default: true
        }
    }
    func presentSheet(_ kind: AppSheet, target: VaultDescriptor? = nil, inSettings: Bool = false) {
        guard canPresent(kind) else { error = "This feature is not yet available for item vaults."; return }
        requestTransition(.presentation(SheetRequest(kind: kind, inSettings: inSettings, target: target ?? vaultDetailsTarget ?? selectedVaultDescriptor)))
    }
    func openVaultDetails(_ target: VaultDescriptor?) { requestTransition(.details(target)) }
    func showSettingsCategory(_ category: SettingsCategory) { settingsCategory = category }

    func refresh() {
        service.invalidateDiscovery()
        if isLocalVaultSelected { openLocalVault(); return }
        requestBackgroundSynchronization()
        requestTransition(.refresh)
    }

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
        case .credentials(let collection): chooseCredentials(collection)
        case .recentlyDeleted: chooseRecentlyDeleted()
        case .vaultTarget(let id):
            guard prepareVaultAction(id) else { completion?(false); return }
        case .sheet(let kind): sheet = kind
        case .presentation(let request):
            sheetRequest = request
            if request.kind == .addDevice { showsSetupChecklist = false }
        case .details(let target): conceal(); vaultDetailsTarget = target
        case .refresh:
            if collection == .all { openLocalVault() }
            discover()
        case .trash(let row): trashItem(row)
        // These transitions delegate their work to the completion. Starting a
        // general refresh here would set busy and suppress the suggestion rebuild.
        case .refreshSuggestions, .closeWindow, .quit: break
        }
        completion?(true)
    }
}
