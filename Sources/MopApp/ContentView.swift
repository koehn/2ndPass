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
                Text("CLOUD VAULT").font(.caption).foregroundStyle(.secondary)
                Picker("Cloud vault", selection: $model.vault) {
                    Text("Select a vault").tag("")
                    ForEach(model.vaults, id: \.self) { id in Text(id).tag(id) }
                }.labelsHidden().disabled(model.busy)
                Button("Find vaults", systemImage: "arrow.clockwise") { model.discover() }
                    .disabled(model.offline || model.busy)
                List {
                    Section {
                        ForEach(AppPage.allCases, id: \.self) { page in
                            Button { model.page = page } label: {
                                Label(page.rawValue, systemImage: page == .secrets ? "key" : "laptopcomputer")
                                    .foregroundStyle(model.page == page ? Color.accentColor : Color.primary)
                            }.buttonStyle(.plain).padding(.vertical, 4)
                        }
                    }
                    if model.authenticated {
                        Section("Namespaces") {
                            Button("All secrets") { model.namespace = nil; model.page = .secrets }
                                .buttonStyle(.plain)
                            ForEach(model.namespaces, id: \.self) { name in
                                Button { model.namespace = name; model.page = .secrets } label: {
                                    HStack { Text(name); Spacer(); if model.namespace == name { Image(systemName: "checkmark") } }
                                }.buttonStyle(.plain)
                            }
                        }
                    }
                }.listStyle(.sidebar)
                Toggle("Offline snapshot", isOn: $model.offline).disabled(model.busy)
                Menu("Vault actions") {
                    Button("Select vault by UUID…") { model.sheet = .selectVault }
                    Button("Create vault…") { model.sheet = .createVault }.disabled(model.offline)
                    Button("Request access on this Mac…") { model.sheet = .request }.disabled(model.offline || model.vault.isEmpty)
                    Button("Recover access…") { model.sheet = .recover }.disabled(model.offline || model.vault.isEmpty)
                    Button("Verify vault fingerprint…") { model.sheet = .trust }.disabled(model.offline || model.vault.isEmpty)
                    Button("Show vault fingerprint") { model.management(["vault", "fingerprint"]) }.disabled(model.offline || model.vault.isEmpty)
                    Button("Export encrypted backup…") { exportBackup() }.disabled(model.vault.isEmpty)
                }.disabled(model.busy)
            }.padding(16)
            .navigationSplitViewColumnWidth(min: 205, ideal: 235, max: 290)
        } content: {
            if model.page == .secrets {
                VStack(spacing: 0) {
                    HStack {
                        Text(model.namespace ?? "All secrets").font(.headline)
                        Spacer()
                        Button { model.sheet = .createSecret } label: { Image(systemName: "plus") }
                            .help("New secret").disabled(model.busy || model.offline || model.vault.isEmpty)
                    }.padding()
                    if model.authenticated {
                        List(model.filtered, id: \.self, selection: $model.selected) { ref in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(ref.item).fontWeight(.medium)
                                Text([ref.section, ref.field].compactMap { $0 }.joined(separator: " / ")).font(.caption).foregroundStyle(.secondary)
                                if model.namespace == nil { Text(ref.vault).font(.caption2).foregroundStyle(.secondary) }
                            }.padding(.vertical, 5).tag(ref)
                        }.searchable(text: $model.search, prompt: "Find a secret")
                        if model.filtered.isEmpty { Text("No matching secrets").foregroundStyle(.secondary).padding() }
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
                    else if let reference = model.selected, model.authenticated { secret(reference) }
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

    private func secret(_ ref: SecretReference) -> some View {
        VStack(alignment: .leading, spacing: 20) {
            Text([ref.vault, ref.item].joined(separator: " / ")).font(.caption).foregroundStyle(.secondary)
            Text(ref.item).font(.largeTitle).fontWeight(.semibold)
            GroupBox {
                VStack(alignment: .leading, spacing: 16) {
                    Text([ref.section, ref.field].compactMap { $0 }.joined(separator: " / ")).font(.headline)
                    Text(model.revealed ?? "••••••••••••••••••••").font(.system(.body, design: .monospaced))
                        .textSelection(.disabled).frame(maxWidth: .infinity, alignment: .leading)
                    HStack {
                        Button("Copy reference") { model.copyReference() }.buttonStyle(.borderedProminent)
                        if model.revealed == nil { Button("Reveal…") { model.read(copy: false) } }
                        else { Button("Conceal") { model.conceal() } }
                        Button("Copy value…") { model.read(copy: true) }
                    }.disabled(model.busy)
                }.padding(12)
            }
            Text(ref.description).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
            Text("Revealing, copying, or changing a value requires authentication. Revealed values are concealed after 30 seconds.")
                .font(.caption).foregroundStyle(.secondary)
            Text("References resolve inside the selected cloud vault. Include its UUID when using a different CLI default.").font(.caption).foregroundStyle(.secondary)
            Divider()
            Text("Use in a command").font(.headline)
            Text("SECRET='\(ref.description)' mop run --cloud-vault \(model.vault) -- your-command")
                .font(.system(.callout, design: .monospaced)).textSelection(.enabled)
            HStack {
                Button("Replace value…") { model.sheet = .replaceSecret }
                Button("Delete…", role: .destructive) { model.deleteConfirmation = true }
            }.disabled(model.busy || model.offline)
            if model.offline { Label("Read-only snapshot. Remote revocation cannot be checked.", systemImage: "icloud.slash").font(.callout).foregroundStyle(.secondary) }
        }.padding(28).frame(maxWidth: .infinity, alignment: .leading)
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
    private func exportBackup() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "vault.mopfile"; panel.title = "Export encrypted backup"
        if panel.runModal() == .OK, let url = panel.url { model.exportBackup(to: url) }
    }
}
