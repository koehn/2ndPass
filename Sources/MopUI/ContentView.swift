import SwiftUI
import MopCore
import MopAppSupport

struct ContentView: View {
    @Bindable var model: AppModel
    @State private var settingsPresented = false
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
                HStack(spacing: 10) {
                    Image(systemName: "lock.shield.fill").font(.title2).foregroundStyle(Color.accentColor)
                    Text("Mop").font(.title2.weight(.semibold))
                    Spacer()
                }.padding(.horizontal, 24).padding(.top, 8)
                List(selection: Binding<String?>(get: { model.sidebarSelection }, set: { if let value = $0 { model.sidebarSelection = value } })) {
                    NavigationLink(value: "all") { Label("All Items", systemImage: "square.stack.3d.up") }
                    Section {
                        if vaultsExpanded {
                            ForEach(model.vaults.sorted { ($0.name ?? "", $0.id) < ($1.name ?? "", $1.id) }) { vault in
                                HStack(spacing: 8) {
                                    NavigationLink(value: "vault:" + vault.id) {
                                        Label(model.vaultLabel(vault), systemImage: model.vaultIcon(vault))
                                            .lineLimit(1)
                                            .truncationMode(.tail)
                                            .accessibilityValue(model.vaultConnectionLabel(vault))
                                            .help(model.vaultConnectionLabel(vault))
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    vaultActions(vault)
                                }.tag("vault:" + vault.id)
                            }
                        }
                    } header: {
                        HStack(spacing: 4) {
                            Button { vaultsExpanded.toggle() } label: {
                                HStack {
                                    Text("Vaults")
                                    Image(systemName: vaultsExpanded ? "chevron.down" : "chevron.right")
                                        .font(.caption2.weight(.semibold))
                                }.frame(maxWidth: .infinity, alignment: .leading)
                                    .mopControlTarget()
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel(vaultsExpanded ? "Collapse vaults" : "Expand vaults")
                            Button { model.sheet = .createVault } label: {
                                Image(systemName: "plus").mopControlTarget()
                            }
                            .buttonStyle(.plain).help("Create vault")
                            .accessibilityLabel("Create vault").disabled(model.offline)
                        }
                    }
                    NavigationLink(value: "deleted") { Label("Recently Deleted", systemImage: "trash") }
                }.listStyle(.sidebar).disabled(model.busy)
            }
            .navigationSplitViewColumnWidth(min: 260, ideal: 290, max: 340)
            .mobileSessionToolbar(model: model, settings: $settingsPresented, compact: compactLayout)
        } content: {
            Group {
                if model.page == .secrets {
                VStack(spacing: 0) {
                    HStack {
                        Text(model.allVaults ? "All Items" : "Items").font(.headline)
                        Spacer()
                        Button { model.beginCreatingItem() } label: { Image(systemName: "plus") }
                            .help("New item").accessibilityLabel("New item").keyboardShortcut("n").disabled(model.busy || model.offline || !model.authenticated || model.itemCreationVaults.isEmpty || model.itemDraft != nil)
                    }.padding()
                    if !model.allVaults, let descriptor = model.selectedVaultDescriptor, !descriptor.enrolled {
                        ContentUnavailableView {
                            Label("Device not connected", systemImage: model.vaultIcon(descriptor))
                        } description: {
                            Text("Enable iCloud Passwords & Keychain using the same Apple Account, then refresh. Existing device-based vaults must first be converted on a previously connected device.")
                        }
                    } else if model.authenticated {
                        ItemSearchView(model: model, selected: { showDetail() }).padding(.horizontal).padding(.bottom, 8).zIndex(1)
                        ScrollViewReader { reader in
                        List(model.displayedItems, selection: $model.selectedRow) { row in
                            NavigationLink(value: row.id) { HStack(spacing: 10) {
                                Image(systemName: row.item.type.symbol)
                                    .foregroundStyle(Color.accentColor).frame(width: 22)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(row.item.name).fontWeight(.medium)
                                    if let subtitle = row.subtitle { Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1) }
                                    if model.allVaults { Text(row.vaultName).font(.caption).foregroundStyle(.secondary) }
                                }
                            }.padding(.vertical, 5) }.tag(row.id).id(row.id)
                                .contextMenu {
                                    Button("Delete…", role: .destructive) { model.itemToDelete = row }
                                        .disabled(model.offline || model.busy)
                                }
                        }.disabled(model.busy)
                        .onChange(of: model.selectedRow) { _, id in
                            if let id { reader.scrollTo(id, anchor: .center) }
                        }
                        }
                        if model.displayedItems.isEmpty { Text("No items").foregroundStyle(.secondary).padding() }
                    } else {
                        Label("Items are locked", systemImage: "lock")
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
                    else if let draft = model.itemDraft, draft.isNew, model.authenticated {
                        ItemDetailView(model: model, itemName: "").id(draft.id)
                    }
                    else if let item = model.selectedItem, model.authenticated { ItemDetailView(model: model, itemName: item).id(model.vault + ":" + item) }
                    else {
                        ContentUnavailableView {
                            Label(model.vaults.isEmpty ? "Welcome to Mop" : model.authenticated ? "Select an item" : "Mop is locked", systemImage: "key.horizontal")
                        } description: {
                            Text(model.vaults.isEmpty ? "Create a vault, or refresh to find vaults in your iCloud account." : model.authenticated ? "Choose an item to view its details." : "Authentication opens your connected vaults. Use Refresh to retry if access is interrupted.")
                        } actions: {
                            if model.vaults.isEmpty {
                                Button("Create vault…") { model.sheet = .createVault }.disabled(model.offline || model.busy)
                            }
                        }.padding(.top, 60)
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
                    if model.busy { ProgressView().controlSize(.small) }
                    Image(systemName: model.offline ? "icloud.slash" : "icloud")
                    Text(model.status + (model.busy && model.status == "Locked" ? " · submitted operation continues" : ""))
                        .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    Spacer()
                }.padding(12)
                }.background(.background)
            }.mobileSessionToolbar(model: model, settings: $settingsPresented, compact: compactLayout, isDetail: true)
        }
        .navigationSplitViewStyle(.balanced)
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { width in
            availableWidth = width
            if width >= 950 { columnVisibility = .all }
        }
        #if os(macOS)
        .toolbar { SessionToolbar(model: model, settings: $settingsPresented) }
        #endif
    }
    private var content: some View {
        navigation
        .sheet(isPresented: $settingsPresented) { SessionSettings(model: model) }
        .documentTransfers(model: model)
        .task(id: model.notice) {
            let notice = model.notice
            let temporary = ["Value copied.", "Value copied. Mop clears its clipboard entry after 30 seconds.",
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
        .onChange(of: model.selectedItem) { _, _ in model.selected = nil; if model.itemDraft?.isNew != true { model.cancelItemEditing() } }
        .onChange(of: model.selected) { _, _ in model.conceal() }
        .onChange(of: model.page) { _, _ in model.cancelItemEditing() }
        .sheet(item: $model.sheet) { sheet in
            AppSheetView(model: model, kind: sheet).id(model.editorGeneration)
        }
        .alert("Operation not completed", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK") { model.error = nil }
        } message: { Text(model.error ?? "") }
        .confirmationDialog("Move item to Recently Deleted?", isPresented: Binding(get: { model.itemToDelete != nil }, set: { if !$0 { model.itemToDelete = nil } }), titleVisibility: .visible) {
            if let row = model.itemToDelete {
                Button("Delete “" + row.item.name + "”…", role: .destructive) { model.trashItem(row) }
            }
        } message: { Text("You can restore the item for 30 days. It stays protected by its original vault.") }
        .confirmationDialog("Delete this secret?", isPresented: $model.deleteConfirmation, titleVisibility: .visible) {
            Button("Delete secret", role: .destructive) { model.delete() }
        } message: { Text("This deletes the current field after authentication. Historical encrypted copies remain.") }
        .task { model.start() }
    }

    private func vaultActions(_ vault: VaultDescriptor) -> some View {
        Button {
            if model.prepareVaultAction(vault.id) {
                model.notice = nil
                model.sheet = .vaultSettings
            }
        } label: {
            Image(systemName: "ellipsis").frame(width: 24, height: 24).mopControlTarget()
        }
        .buttonStyle(.borderless)
        .help("Settings for " + model.vaultLabel(vault))
        .accessibilityLabel("Settings for " + model.vaultLabel(vault))
        .disabled(model.busy)
    }
}
