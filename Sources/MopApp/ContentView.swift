import SwiftUI
import AppKit
import MopCore
import MopAppSupport

struct ContentView: View {
    @Bindable var model: AppModel
    @AppStorage("vaultSidebarExpanded") private var vaultsExpanded = true
    var body: some View { content }
    private var content: some View {
        NavigationSplitView {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    Image(systemName: "lock.shield.fill").font(.title2).foregroundStyle(Color.accentColor)
                    Text("Mop").font(.title2.weight(.semibold))
                    Spacer()
                    Button { model.discover() } label: { Image(systemName: "arrow.clockwise") }
                        .buttonStyle(.plain).help("Refresh vaults").disabled(model.busy)
                }.padding(.horizontal, 8).padding(.top, 8)
                List(selection: Binding<String?>(get: { model.sidebarSelection }, set: { if let value = $0 { model.sidebarSelection = value } })) {
                    Label("All Vaults", systemImage: "square.stack.3d.up").tag("all")
                    Section {
                        DisclosureGroup(isExpanded: $vaultsExpanded) {
                            ForEach(model.vaults.sorted { ($0.name ?? "", $0.id) < ($1.name ?? "", $1.id) }) { vault in
                                HStack {
                                    Label(model.vaultLabel(vault), systemImage: vault.enrolled ? "lock.rectangle" : "lock.rectangle.stack")
                                    Spacer(minLength: 4)
                                    vaultActions(vault)
                                }.tag("vault:" + vault.id)
                            }
                        } label: {
                            HStack {
                                Text("Vaults").font(.headline)
                                Spacer()
                                Button { model.sheet = .createVault } label: { Image(systemName: "plus") }
                                    .buttonStyle(.plain).help("Create vault")
                                    .accessibilityLabel("Create vault").disabled(model.offline)
                            }
                        }
                    }
                    Label("Recently Deleted", systemImage: "trash").tag("deleted")
                    Section {
                        Label("Trusted Macs", systemImage: "laptopcomputer").tag("devices")
                            .disabled(model.allVaults || model.vault.isEmpty)
                    }
                }.listStyle(.sidebar).disabled(model.busy)
                Toggle("Offline snapshot", isOn: $model.offline).disabled(model.busy)
                Button("Select vault by UUID…") { model.sheet = .selectVault }
                    .buttonStyle(.plain).font(.caption).foregroundStyle(.secondary).disabled(model.busy)
            }.padding(16)
            .navigationSplitViewColumnWidth(min: 205, ideal: 235, max: 290)
        } content: {
            if model.page == .secrets {
                VStack(spacing: 0) {
                    HStack {
                        Text(model.allVaults ? "All Vaults" : "Items").font(.headline)
                        Spacer()
                        Button { model.beginCreatingItem() } label: { Image(systemName: "plus") }
                            .help("New item").disabled(model.busy || model.offline || !model.authenticated || model.itemCreationVaults.isEmpty || model.itemDraft != nil)
                    }.padding()
                    if model.authenticated {
                        List(model.displayedItems, selection: $model.selectedRow) { row in
                            HStack(spacing: 10) {
                                Image(systemName: row.item.type == .login ? "person.crop.square" : "key")
                                    .foregroundStyle(Color.accentColor).frame(width: 22)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(row.item.name).fontWeight(.medium)
                                    if model.allVaults { Text(row.vaultName).font(.caption).foregroundStyle(.secondary) }
                                }
                            }.padding(.vertical, 5).tag(row.id)
                                .contextMenu {
                                    Button("Delete…", role: .destructive) { model.itemToDelete = row }
                                        .disabled(model.offline || model.busy)
                                }
                        }.searchable(text: $model.search, prompt: "Find an item or field").disabled(model.busy)
                        if model.displayedItems.isEmpty { Text("No matching items").foregroundStyle(.secondary).padding() }
                    } else {
                        ContentUnavailableView {
                            Label("Index locked", systemImage: "lock")
                        } description: {
                            Text("Authenticate to view secret names and references.")
                        } actions: {
                            Button("Unlock") { model.unlock() }.disabled(model.busy || (!model.allVaults && model.page != .recentlyDeleted && model.vault.isEmpty))
                        }
                    }
                }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            } else if model.page == .recentlyDeleted {
                RecentlyDeletedList(model: model)
            } else {
                VStack(alignment: .leading, spacing: 16) {
                    Label("Trusted Macs", systemImage: "laptopcomputer").font(.headline)
                    Text("Approve each Mac after comparing its full fingerprint through a trusted channel.").foregroundStyle(.secondary)
                    Button("Refresh devices") { model.loadDevices() }.disabled(model.offline || model.busy || model.vault.isEmpty)
                    if model.offline { Text("Device management requires iCloud.").font(.caption) }
                    Spacer()
                }.padding()
            }
        } detail: {
            VStack(alignment: .leading, spacing: 0) {
                ScrollView {
                    if model.page == .recentlyDeleted { RecentlyDeletedDetail(model: model) }
                    else if model.page == .devices { devices }
                    else if let draft = model.itemDraft, draft.isNew, model.authenticated {
                        ItemDetailView(model: model, itemName: "").id(draft.id)
                    }
                    else if let item = model.selectedItem, model.authenticated { ItemDetailView(model: model, itemName: item).id(model.vault + ":" + item) }
                    else {
                        ContentUnavailableView {
                            Label(model.vaults.isEmpty ? "Welcome to mop" : "Your secrets, on your Mac", systemImage: "key.horizontal")
                        } description: {
                            Text(model.vaults.isEmpty ? "Create an encrypted iCloud vault, or find your existing vaults to enroll this Mac." : "Select a vault and unlock its index. Secret values stay concealed until you reveal or copy them.")
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
                }
                Divider()
                HStack(spacing: 8) {
                    if model.busy { ProgressView().controlSize(.small) }
                    Image(systemName: model.offline ? "icloud.slash" : "icloud")
                    Text(model.status + (model.busy && model.status == "Locked" ? " · submitted operation continues" : ""))
                        .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    Spacer()
                }.padding(12)
            }
        }
        .toolbar {
            ToolbarItemGroup {
                Button("Unlock / Refresh", systemImage: "arrow.clockwise") { model.unlock() }.disabled(model.busy || (!model.allVaults && model.page != .recentlyDeleted && model.vault.isEmpty))
                Button("Sync", systemImage: "icloud.and.arrow.down") { model.sync() }.disabled(model.busy || model.offline || model.vault.isEmpty || model.allVaults)
                Button("Lock", systemImage: "lock") { model.lock() }
            }
        }
        .onChange(of: model.offline) { _, _ in model.changedContext() }
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
        Menu {
            Button("Rename vault…") { vaultSheet(.renameVault, id: vault.id) }.disabled(model.offline)
            Button("Request access on this Mac…") { vaultSheet(.request, id: vault.id) }.disabled(model.offline)
            Button("Recover access…") { vaultSheet(.recover, id: vault.id) }.disabled(model.offline)
            Button("Verify vault fingerprint…") { vaultSheet(.trust, id: vault.id) }.disabled(model.offline)
            Button("Show vault fingerprint") {
                if model.prepareVaultAction(vault.id) { model.management(.fingerprint) }
            }.disabled(model.offline)
            Button("Export backup…") {
                if model.prepareVaultAction(vault.id) { model.chooseExportBackup() }
            }.disabled(!vault.supported)
            Divider()
            Button("Delete vault…", role: .destructive) { vaultSheet(.deleteVault, id: vault.id) }.disabled(model.offline)
        } label: {
            Image(systemName: "ellipsis").frame(width: 24, height: 24).contentShape(Rectangle())
        }
        .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
        .help("Actions for " + model.vaultLabel(vault))
        .accessibilityLabel("Actions for " + model.vaultLabel(vault))
        .disabled(model.busy)
    }

    private func vaultSheet(_ sheet: AppSheet, id: String) {
        if model.prepareVaultAction(id) { model.sheet = sheet }
    }

    private var devices: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Trusted Macs").font(.largeTitle).fontWeight(.semibold)
            ForEach(model.devices) { device in
                VStack(alignment: .leading, spacing: 6) {
                    Label(device.name, systemImage: "laptopcomputer").font(.headline)
                    Text(device.fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    Button("Remove Mac…", role: .destructive) { model.revoking = device; model.sheet = .revoke }
                        .disabled(model.busy || model.offline)
                }
                Divider()
            }
            if model.devices.isEmpty { Text("Refresh to authenticate and load enrolled Macs.").foregroundStyle(.secondary) }
            if !model.requests.isEmpty {
                Text("Enrollment requests").font(.headline)
                Text("Request names and fingerprints are untrusted public metadata.").font(.caption).foregroundStyle(.secondary)
                ForEach(model.requests) { request in
                    HStack {
                        Text(request.name)
                        Spacer()
                        Button("Review…") { model.enrollment = request; model.sheet = .approve }.disabled(model.busy || model.offline)
                    }
                }
            }
        }.padding(28).frame(maxWidth: .infinity, alignment: .leading)
    }
}
