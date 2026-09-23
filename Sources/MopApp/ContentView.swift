import SwiftUI
import AppKit
import MopCore

struct ContentView: View {
    @Bindable var model: AppModel
    var body: some View {
        content
            .opacity(model.isActive ? 1 : 0)
            .allowsHitTesting(model.isActive)
            .accessibilityHidden(!model.isActive)
            .overlay {
                if !model.isActive {
                    ContentUnavailableView("Locked", systemImage: "lock", description: Text("Return to mop to authenticate."))
                }
            }
    }
    private var content: some View {
        NavigationSplitView {
            VStack(alignment: .leading, spacing: 12) {
                Text("VAULT").font(.caption).foregroundStyle(.secondary)
                Picker("Vault", selection: $model.vault) {
                    Text("Select a vault").tag("")
                    ForEach(model.vaults) { vault in Text(model.vaultLabel(vault)).tag(vault.id) }
                }.labelsHidden().disabled(model.busy)
                Button("Find vaults", systemImage: "arrow.clockwise") { model.discover() }
                    .disabled(model.busy)
                Text(model.vault).font(.caption2).foregroundStyle(.secondary).textSelection(.enabled)
                List {
                    Section {
                        ForEach(AppPage.allCases, id: \.self) { page in
                            Button { model.page = page } label: {
                                Label(page.rawValue, systemImage: page == .secrets ? "key" : "laptopcomputer")
                                    .foregroundStyle(model.page == page ? Color.accentColor : Color.primary)
                            }.buttonStyle(.plain).padding(.vertical, 4)
                        }
                    }
                }.listStyle(.sidebar)
                Toggle("Offline snapshot", isOn: $model.offline).disabled(model.busy)
                Menu("Vault actions") {
                    Button("Select vault by UUID…") { model.sheet = .selectVault }
                    Button("Create vault…") { model.sheet = .createVault }.disabled(model.offline)
                    Button("Rename vault…") { model.sheet = .renameVault }.disabled(model.offline || model.vault.isEmpty)
                    Button("Request access on this Mac…") { model.sheet = .request }.disabled(model.offline || model.vault.isEmpty)
                    Button("Recover access…") { model.sheet = .recover }.disabled(model.offline || model.vault.isEmpty)
                    Button("Verify vault fingerprint…") { model.sheet = .trust }.disabled(model.offline || model.vault.isEmpty)
                    Button("Show vault fingerprint") { model.management(["vault", "fingerprint"]) }.disabled(model.offline || model.vault.isEmpty)
                    Button("Export backup…") { model.chooseExportBackup() }.disabled(!model.canExportBackup)
                    Divider()
                    Button("Delete vault…", role: .destructive) { model.sheet = .deleteVault }.disabled(model.offline || model.vault.isEmpty)
                }.disabled(model.busy)
            }.padding(16)
            .navigationSplitViewColumnWidth(min: 205, ideal: 235, max: 290)
        } content: {
            if model.page == .secrets {
                VStack(spacing: 0) {
                    HStack {
                        Text("Items").font(.headline)
                        Spacer()
                        Button { model.sheet = .createSecret } label: { Image(systemName: "plus") }
                            .help("New item").disabled(model.busy || model.offline || !model.authenticated)
                    }.padding()
                    if model.authenticated {
                        List(model.items, id: \.self, selection: $model.selectedItem) { item in
                            Text(item).fontWeight(.medium).padding(.vertical, 5).tag(item)
                        }.searchable(text: $model.search, prompt: "Find an item or field")
                        if model.items.isEmpty { Text("No matching items").foregroundStyle(.secondary).padding() }
                    } else {
                        ContentUnavailableView {
                            Label("Index locked", systemImage: "lock")
                        } description: {
                            Text("Authenticate to view secret names and references.")
                        } actions: {
                            Button("Unlock") { model.unlock() }.disabled(model.busy || model.vault.isEmpty)
                        }
                    }
                }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
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
                    if model.page == .devices { devices }
                    else if let item = model.selectedItem, model.authenticated { itemDetail(item) }
                    else {
                        ContentUnavailableView {
                            Label(model.vaults.isEmpty ? "Welcome to mop" : "Your secrets, on your Mac", systemImage: "key.horizontal")
                        } description: {
                            Text(model.vaults.isEmpty ? "Create an encrypted iCloud vault, or find your existing vaults to enroll this Mac." : "Select a vault and unlock its index. Secret values require fresh authentication.")
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
                Button("Unlock / Refresh", systemImage: "arrow.clockwise") { model.unlock() }.disabled(model.busy || model.vault.isEmpty)
                Button("Sync", systemImage: "icloud.and.arrow.down") { model.sync() }.disabled(model.busy || model.offline || model.vault.isEmpty)
                Button("Lock", systemImage: "lock") { model.lock() }
            }
        }
        .onChange(of: model.vault) { _, _ in if !model.busy { model.changedContext() } }
        .onChange(of: model.offline) { _, _ in model.changedContext() }
        .onChange(of: model.selectedItem) { _, _ in model.selected = nil; model.conceal() }
        .onChange(of: model.selected) { _, _ in model.conceal() }
        .onChange(of: model.page) { _, _ in model.conceal() }
        .sheet(item: $model.sheet) { sheet in AppSheetView(model: model, kind: sheet) }
        .alert("Operation not completed", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK") { model.error = nil }
        } message: { Text(model.error ?? "") }
        .confirmationDialog("Delete this secret?", isPresented: $model.deleteConfirmation, titleVisibility: .visible) {
            Button("Delete secret", role: .destructive) { model.delete() }
        } message: { Text("This deletes the current field after authentication. Historical encrypted copies remain.") }
        .task { model.discover() }
    }

    private func itemDetail(_ item: String) -> some View {
        VStack(alignment: .leading, spacing: 20) {
            Text(model.vaultName).font(.caption).foregroundStyle(.secondary)
            HStack {
                Text(item).font(.largeTitle).fontWeight(.semibold)
                Spacer()
                Button("Add field…") { model.sheet = .addField }.disabled(model.busy || model.offline)
            }
            ForEach(Array(Set(model.itemFields.map { $0.section ?? "" })).sorted(), id: \.self) { section in
                if !section.isEmpty { Text(section).font(.title2) }
                ForEach(model.itemFields.filter { ($0.section ?? "") == section }, id: \.self) { ref in
                    field(ref)
                }
            }
            Text("Revealing, copying, or changing a value requires authentication. Revealed values are concealed after 30 seconds.")
                .font(.caption).foregroundStyle(.secondary)
            if model.offline { Label("Read-only snapshot. Remote revocation cannot be checked.", systemImage: "icloud.slash").font(.callout).foregroundStyle(.secondary) }
        }.padding(28).frame(maxWidth: .infinity, alignment: .leading)
    }

    private func field(_ ref: SecretReference) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 16) {
                Text(ref.field).font(.headline)
                Text((model.selected == ref ? model.revealed : nil).map { String(decoding: $0, as: UTF8.self) } ?? "••••••••••••••••••••")
                    .font(.system(.body, design: .monospaced)).textSelection(.disabled).frame(maxWidth: .infinity, alignment: .leading)
                HStack {
                    Button("Copy reference") { model.selectField(ref); model.copyReference() }.buttonStyle(.borderedProminent)
                    if model.selected == ref && model.revealed != nil { Button("Conceal") { model.conceal() } }
                    else { Button("Reveal…") { model.selectField(ref); model.read(copy: false) } }
                    Button("Copy value…") { model.selectField(ref); model.read(copy: true) }
                }.disabled(model.busy)
                Text(ref.description).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                HStack {
                    Button("Replace value…") { model.selectField(ref); model.sheet = .replaceSecret }
                    Button("Delete field…", role: .destructive) { model.selectField(ref); model.deleteConfirmation = true }
                }.disabled(model.busy || model.offline)
            }.padding(12)
        }
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
