import MopLocalIdentity
import SwiftUI
import MopCore
import MopAppSupport

struct ContentView: View {
    @Bindable var model: AppModel
    @State private var settingsPresented = false
    #if os(macOS)
    @Environment(\.openSettings) private var openSettings
    #endif
    @State private var availableWidth: CGFloat = 0
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    #endif
    private var compactLayout: Bool {
        #if os(iOS)
        sizeClass == .compact
        #else
        false
        #endif
    }
    private func showSettings(_ category: SettingsCategory = .security) {
        model.settingsCategory = category
        #if os(macOS)
        openSettings()
        #else
        settingsPresented = true
        #endif
    }
    private func showDetail() {
        compactColumn = .detail
        #if os(iOS)
        if availableWidth < 950 { columnVisibility = .detailOnly }
        #endif
    }
    @State private var columnVisibility = NavigationSplitViewVisibility.all
    @State private var compactColumn: NavigationSplitViewColumn = .sidebar
    @AppStorage("vaultSidebarExpanded") private var vaultsExpanded = true
    var body: some View { content }
    private var navigation: some View {
        NavigationSplitView(columnVisibility: $columnVisibility, preferredCompactColumn: $compactColumn) {
            VStack(alignment: .leading, spacing: 12) {
                List(selection: Binding<String?>(get: { model.sidebarSelection }, set: { if let value = $0 { model.sidebarSelection = value } })) {
                    NavigationLink(value: "all") { Label("All Items", systemImage: "square.stack.3d.up") }
                    NavigationLink(value: "favorites") { Label("Favorites", systemImage: "star") }
                    NavigationLink(value: "recent-added") { Label("Recently Added", systemImage: "plus.circle") }
                    NavigationLink(value: "recent-changed") { Label("Recently Changed", systemImage: "pencil.circle") }
                    NavigationLink(value: "recent-used") { Label("Recently Used", systemImage: "clock") }
                    Section("Vaults", isExpanded: $vaultsExpanded) {
                        ForEach(model.vaultList.sorted { ($0.name ?? "", $0.id) < ($1.name ?? "", $1.id) }) { vault in
                            switch vault {
                            case .cloud(let row):
                                NavigationLink(value: "vault:" + row.id) {
                                    Label(model.vaultLabel(row), systemImage: model.vaultIcon(row))
                                        .lineLimit(1).accessibilityValue(model.vaultConnectionLabel(row))
                                }.tag("vault:" + row.id)
                                .contextMenu { Button("Vault Details…") { model.openVaultDetails(row) }.disabled(model.busy) }
                            case .local:
                                NavigationLink(value: "vault:" + LocalVault.id) { Label("local", systemImage: "internaldrive") }
                                    .tag("vault:" + LocalVault.id)
                            }
                        }
                    }
                    NavigationLink(value: "archive") { Label("Archive", systemImage: "archivebox") }
                    NavigationLink(value: "deleted") { Label("Recently Deleted", systemImage: "trash") }
                }.listStyle(.sidebar).disabled(model.busy).id(model.selectionGeneration)
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 300)
            .mobileSessionToolbar(model: model, settings: $settingsPresented, compact: compactLayout)
        } content: {
            Group {
                if model.page == .secrets {
                VStack(spacing: 0) {
                    ItemSearchBar(model: model)
                    SearchSummary(model: model)

                    if model.isLocalVaultSelected {
                        LocalVaultView(model: model)
                    } else if !model.allVaults, let descriptor = model.selectedVaultDescriptor, !descriptor.enrolled {
                        ContentUnavailableView {
                            Label("Connect this device", systemImage: model.vaultIcon(descriptor))
                        } description: {
                            Text("This vault is not connected to this device. Open and unlock 2ndPass on another connected device to connect automatically.")
                            Button("Connect this device…") { model.presentSheet(.enrollDevice) }
                        }
                    } else if model.authenticated {
                        // Selection can be restored while catalogs change. Calling
                        // ScrollViewProxy.scrollTo during that update traps in
                        // SwiftUI's macOS OutlineListCoordinator. Let List manage
                        // its selection without forcing an outline traversal.
                        List(model.displayedItems, selection: $model.listSelection) { row in
                            NavigationLink(value: row.id) {
                                VaultItemRowLabel(title: row.item.displayTitle, symbol: row.item.type.symbol,
                                    subtitle: row.subtitle, vaultName: model.allVaults ? row.vaultName : nil,
                                    recentDate: row.recentDate, searchDetail: row.searchDetail)
                            }.tag(row.id).id(row.id)
                                .listRowBackground(model.searchIsFocused && !model.search.isEmpty && model.searchHighlighted == row.id ? Color.accentColor.opacity(0.12) : nil)
                                .contextMenu {
                                    if let identity = row.localIdentity {
                                        Button("Delete…", role: .destructive) { model.requestLocalDelete(identity.id) }
                                            .disabled(model.localDeleteInProgress || model.localCreating)
                                    } else {
                                        Button("Delete", role: .destructive) { model.itemToDelete = row }
                                            .disabled(model.offline || model.busy)
                                    }
                                }
                        }.disabled(model.busy).id(model.selectionGeneration)
                        .overlay {
                            if model.displayedItems.isEmpty {
                                ContentUnavailableView {
                                    Label(model.search.isEmpty ? emptyCollectionTitle : "No Search Results", systemImage: model.search.isEmpty ? "key" : "magnifyingglass")
                                } description: {
                                    if model.search.isEmpty && model.collection == .passkeys {
                                        Text("Create a passkey when signing up or signing in on a website that supports them.")
                                    }
                                } actions: {
                                    if !model.search.isEmpty { Button("Clear Search") { model.search = "" } }
                                    else if model.collection == .sshKeys {
                                        Button("Add SSH Key") { model.keyCreationPresented = true }
                                            .disabled(model.offline || model.busy)
                                    }
                                    else if model.collection != .passkeys {
                                        Button("Add Your First Login") { model.beginCreatingItem() }.disabled(model.offline || model.busy)
                                        Button("Import…") { model.beginImport() }.disabled(model.offline || model.busy)
                                    }
                                }
                            }
                        }
                    } else {
                        Label(model.unlocking ? "Opening items…" : "Items are locked", systemImage: "lock")
                            .foregroundStyle(.secondary).padding()
                        Spacer()
                    }
                }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            } else if model.page == .recentlyDeleted {
                RecentlyDeletedList(model: model)
            }
            }.mobileSessionToolbar(model: model, settings: $settingsPresented, compact: compactLayout)
        } detail: {
                ScrollView {
                    if model.page == .recentlyDeleted { RecentlyDeletedDetail(model: model) }
                    else if model.isLocalVaultSelected {
                        if model.localCreatePresented {
                            LocalCreateForm(model: model).padding()
                        } else if let identity = model.selectedLocalIdentity {
                            LocalIdentityDetailView(model: model, identity: identity).id(identity.id)
                        } else {
                            LocalVaultDetailHint()
                        }
                    }
                    else if let identity = model.selectedLocalIdentity {
                        LocalIdentityDetailView(model: model, identity: identity).id(identity.id)
                    }
                    else if let draft = model.itemDraft, draft.isNew, model.authenticated {
                        ItemDetailView(model: model, itemName: "").id(draft.id)
                    }
                    else if let item = model.selectedItem, model.authenticated { ItemDetailView(model: model, itemName: item).id(model.vault + ":" + item) }
                    else {
                        ContentUnavailableView {
                            Label(model.cloudVaults.isEmpty ? "Welcome to 2ndPass" : model.authenticated ? "Select an item" : model.unlocking ? "Unlocking 2ndPass" : "2ndPass is locked", systemImage: "key.horizontal")
                        } description: {
                            Text(model.cloudVaults.isEmpty ? "Create a vault, or refresh to find vaults in your iCloud account." : model.authenticated ? "Choose an item to view its details." : "Unlock 2ndPass to access your connected vaults.")
                        } actions: {
                            if model.unlocking {
                                ProgressView("Unlocking 2ndPass…")
                            } else if model.hasConnectedVaults && !model.authenticated {
                                Button("Unlock 2ndPass") { model.unlock() }
                                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                                    .disabled(!model.canUnlock)
                            }
                            if model.cloudVaults.isEmpty {
                                Button("Create vault…") { model.presentSheet(.createVault) }.disabled(model.offline || model.busy)
                            }
                        }.padding(.top, 60)
                    }
                    if model.showsSetupChecklist {
                        GroupBox("Finish setting up 2ndPass") {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Add another connected device or offline recovery so losing this device does not mean losing access.")
                                Button("Connect Another Device…") { model.presentSheet(.addDevice) }
                                Button("Set Up Offline Recovery…") { showSettings(.recovery) }
                                Button("Set Up AutoFill…") { showSettings(.autoFill) }
                                Button("Later") { model.showsSetupChecklist = false }
                            }
                        }.padding()
                    }
                    if let notice = model.deviceAddedNotice {
                        HStack {
                            Text(notice).font(.callout)
                            Button("Review Devices") { showSettings(.devices) }
                            Button("Dismiss") { model.deviceAddedNotice = nil }
                        }
                    }
                    if let notice = model.notice {
                        Text(notice).font(.callout).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading).padding()
                            .background(.quaternary, in: RoundedRectangle(cornerRadius: 8)).padding()
                    }
                }.accessibilityIdentifier("Item detail")
                .safeAreaInset(edge: .bottom, spacing: 0) {
                VStack(spacing: 0) {
                Divider()
                HStack(spacing: 8) {
                    if model.showsCloudProgress { ProgressView().controlSize(.small).accessibilityLabel("iCloud activity") }
                    Image(systemName: model.offline ? "icloud.slash" : "icloud")
                    Text(model.sessionStatus)
                        .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    Spacer()
                }.padding(12)
                }.background(.background)
            }.mobileSessionToolbar(model: model, settings: $settingsPresented, compact: compactLayout, isDetail: true)
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            if let status = model.importStatus {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(alignment: .top) {
                        Text(status).font(.callout).frame(maxWidth: .infinity, alignment: .leading)
                            .foregroundStyle(model.importFailed ? Color.red : Color.primary)
                        if !model.importing {
                            Button("Dismiss") { model.importStatus = nil; model.importReport = nil }
                        }
                    }
                    if model.importing {
                        ProgressView(value: model.importFraction).progressViewStyle(.linear)
                            .accessibilityLabel("Import progress")
                    } else if model.importReport?.committed == true {
                        Text("Check the results before deleting the unencrypted source file manually.").font(.caption).foregroundStyle(.secondary)
                    }
                }.padding().background(.regularMaterial).accessibilityIdentifier("Import status")
            }
        }
        .navigationSplitViewStyle(.balanced)
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { width in
            availableWidth = width

        }
        #if os(macOS)
        .toolbar { SessionToolbar(model: model, settings: $settingsPresented) }
        #endif
    }
    private var emptyCollectionTitle: String {
        switch model.collection {
        case .passkeys: "No Passkeys"
        case .sshKeys: "No SSH Keys"
        default: "No items"
        }
    }
    private var sessionContent: some View {
        Group {
            if !model.authenticated && model.cloudVaultsPresent && !model.isLocalVaultSelected {
                LockedView(model: model)
            } else {
                navigation
            }
        }
        .transaction { if !model.authenticated { $0.disablesAnimations = true } }
        .sheet(isPresented: $settingsPresented) { SessionSettings(model: model) }
        .documentTransfers(model: model)
        .task(id: model.notice) {
            let notice = model.notice
            let temporary = ["Value copied.", "Value copied. 2ndPass clears its clipboard entry after 30 seconds.",
                             "Reference copied.", "Item saved to iCloud.", "Secret saved to iCloud."]
            guard let notice, temporary.contains(notice) else { return }
            try? await Task.sleep(for: .seconds(5))
            if !Task.isCancelled, model.notice == notice { model.notice = nil }
        }
        .onChange(of: model.itemDraft?.isNew) { _, new in if new == true { showDetail() } }
        .onChange(of: model.error) { _, error in
            if error != nil, !model.authenticated { showDetail() }
        }
        .onChange(of: model.authenticated) { _, unlocked in if !unlocked { compactColumn = .sidebar } }
        .onChange(of: model.search) { _, _ in if model.authenticated { model.activity() } }
        .onChange(of: model.selectedRow) { _, row in if row != nil { model.activity(); showDetail() } }
        .onChange(of: model.selectedDeleted) { _, row in if row != nil { showDetail() } }
        .onChange(of: model.selectedItem) { _, _ in model.selected = nil }
        .onChange(of: model.selected) { _, _ in model.conceal() }
        .sheet(item: Binding<SheetRequest?>(get: { model.vaultDetailsTarget == nil && model.sheetRequest?.inSettings == false ? model.sheetRequest : nil }, set: { if model.sheetRequest?.inSettings == false { model.sheetRequest = $0 } })) { sheet in
            AppSheetView(model: model, request: sheet)
        }
    }
    private var content: some View {
        sessionContent
        .sheet(isPresented: $model.keyCreationPresented) { KeyCredentialCreateView(model: model) }
        .sheet(item: $model.vaultDetailsTarget) { target in
            VaultDetailsDialog(model: model, target: target)
        }
        .alert("Operation not completed", isPresented: Binding(get: { !model.settingsVisible && model.vaultDetailsTarget == nil && model.sheetRequest == nil && model.error != nil }, set: { if !$0 { model.error = nil } })) {
            if model.developerDiagnosticsEnabled { Button("Copy Details") { model.copyErrorDetails() } }
            Button("OK") { model.error = nil }
        } message: { Text(model.errorMessage) }
        .confirmationDialog("Move item to Recently Deleted?", isPresented: Binding(get: { model.itemToDelete != nil }, set: { if !$0 { model.itemToDelete = nil } }), titleVisibility: .visible) {
            if let row = model.itemToDelete {
                Button("Delete “" + row.item.name + "”…", role: .destructive) { model.trashItem(row) }
            }
        } message: { Text("You can restore the item for 30 days. It stays protected by its original vault.") }
        .confirmationDialog("Delete Field?", isPresented: $model.deleteConfirmation, titleVisibility: .visible) {
            Button("Delete Field", role: .destructive) { model.delete() }
        } message: { Text("This deletes the current field after authentication. Historical encrypted copies remain.") }
        .confirmationDialog("Delete this identity?", isPresented: Binding(get: { model.localDeleting != nil }, set: { if !$0 { model.localDeleting = nil } }), titleVisibility: .visible) {
            if let id = model.localDeleting, let identity = model.localIdentities.first(where: { $0.id == id }) {
                Button("Delete “" + identity.name + "”", role: .destructive) { model.confirmLocalDelete() }
            }
        } message: {
            Text(LocalIdentityWarning.deletion)
        }
        .task { model.start() }
        .task(id: model.collection) {
            if model.collection == .all { model.openLocalVault() }
        }
    }

}
