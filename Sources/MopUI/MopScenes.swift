import SwiftUI
import MopCore
import MopAppSupport

public struct MopScenes: Scene {
    @State private var model: AppModel
    @MainActor private static func initialModel() -> AppModel {
        #if DEBUG && targetEnvironment(simulator)
        if ProcessInfo.processInfo.environment["MOP_UI_TESTING"] == "1" {
            return AppModel(service: UITestVaultService())
        }
        #endif
        return AppModel()
    }
    public init() {
        _ = DeveloperPreferences.shared
        _model = State(initialValue: Self.initialModel())
    }
    public var body: some Scene {
        #if os(macOS)
        Window("mop", id: "main") {
            MopRootView(model: model)
                .frame(minWidth: 820, minHeight: 540)
        }
        .defaultSize(width: 1060, height: 680)
        .commands { MopCommands(model: model) }
        #else
        WindowGroup { MopRootView(model: model) }
            .commands { MopCommands(model: model) }
        #endif
        #if os(macOS)
        Settings {
            SessionSettings(model: model)
                .onAppear { model.startMonitoringActivity() }
        }
        #endif
    }
}

private struct MopCommands: Commands {
    @Bindable var model: AppModel
    var body: some Commands {
            CommandGroup(after: .newItem) {
                Button("New Item") { model.beginCreatingItem() }
                    .keyboardShortcut("n").disabled(model.busy || model.offline || !model.authenticated || model.itemCreationVaults.isEmpty || model.itemDraft != nil || model.page != .secrets)
                Button("New Vault…") { model.sheet = .createVault }.disabled(model.busy || model.offline)
            }
            CommandMenu("Vault") {
                Button("Refresh") { model.discover(autoUnlock: true) }.keyboardShortcut("r").disabled(model.busy)
                Button("Lock") { model.lock() }.keyboardShortcut("l", modifiers: [.command, .shift])
            }
    }
}

struct SessionSettings: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var model: AppModel
    @AppStorage("developerToolsEnabled") private var developerTools = false
    @State private var vaultID = ""
    @State private var removal: VaultDeviceRecord?
    var body: some View {
        Form {

            Stepper("Lock after \(model.autoLockMinutes) minutes of inactivity", value: $model.autoLockMinutes, in: 1...60)
            Section("devices") {
                Text("Devices connected to your enrolled personal vaults.").font(.caption).foregroundStyle(.secondary)
                ForEach(model.devices) { device in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(device.name + (device.isCurrent ? " (this device)" : ""))
                            Text(device.id.uuidString).font(.caption).textSelection(.enabled)
                        }
                        Spacer()
                        Button("Remove…", role: .destructive) { removal = device }
                            .disabled(model.busy || model.offline || model.devices.count < 2)
                    }
                }
                if model.devices.isEmpty { Text("Refresh to load enrolled devices.").foregroundStyle(.secondary) }
                Button("Refresh devices") { model.loadDevices() }.disabled(model.busy || model.offline)
                Button("Add my device…") { model.sheet = .addDevice }.disabled(model.busy || model.offline)
            }
            Section("vault") {
                if model.vaults.contains(where: { $0.enrolled }) {
                    Picker("Vault", selection: Binding(get: { model.vault }, set: { _ = model.prepareVaultAction($0) })) {
                        ForEach(model.vaults.filter { $0.enrolled }) { vault in
                            Text(model.vaultLabel(vault)).tag(vault.id)
                        }
                    }.disabled(model.busy)
                    Group {
                        Button("Rename vault…") { model.sheet = .renameVault }
                        Button("Show checkpoint") { model.management(.fingerprint, keepSheet: true) }
                        Button("Export encrypted backup…") { if model.prepareVaultAction(model.vault) { model.chooseExportBackup() } }
                        Button("Verify members and devices") { model.loadMembers() }
                        ForEach(model.members) { member in
                            VStack(alignment: .leading) {
                                Text(member.id)
                                Text(member.role).font(.caption)
                            }.textSelection(.enabled)
                        }
                        Button("Share with another person…") { model.sheet = .shareAccount }
                        Button("Set up or replace hardware recovery…") { model.sheet = .setupRecovery }
                        Button("Recover using this hardware device…") { model.sheet = .recover }
                        DisclosureGroup("Advanced access management") { SharingView(model: model, setup: false) }
                        Button("Delete cloud vault…", role: .destructive) { model.sheet = .deleteVault }
                    }.disabled(model.busy || model.offline || model.selectedVaultDescriptor?.enrolled != true)
                } else {
                    Text("Connect to or create a vault to manage it here.").foregroundStyle(.secondary)
                }
            }
            if model.busy { ProgressView("Waiting for authentication or iCloud…") }
            if let notice = model.notice { Text(notice).font(.callout).textSelection(.enabled) }
            Section("Developer") {
                Toggle("Show developer tools", isOn: Binding(get: { developerTools }, set: { DeveloperPreferences.shared.set($0) }))
                Text("Include Copy Reference in field menus for scripts and configuration. Syncs across devices using your Apple Account.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            DisclosureGroup("Advanced") {
                Text("Open a vault by ID when it is missing from discovery, including a previously verified offline snapshot.")
                    .font(.caption).foregroundStyle(.secondary)
                TextField("Vault UUID", text: $vaultID).accessibilityLabel("Vault UUID")
                Button("Open vault by ID") {
                    guard let id = UUID(uuidString: vaultID.trimmingCharacters(in: .whitespacesAndNewlines))?.uuidString else { return }
                    if !model.vaults.contains(where: { $0.id == id }) {
                        model.vaults.append(VaultDescriptor(id: id, name: nil, format: "unknown", enrolled: false))
                    }
                    model.chooseVault(id)
                    dismiss()
                }.disabled(model.busy || UUID(uuidString: vaultID.trimmingCharacters(in: .whitespacesAndNewlines)) == nil)
            }
            #if os(macOS)
            Text("Activity in Mop keeps your session open. Switching apps conceals secrets. Locking your Mac, sleeping, or quitting Mop ends the session immediately.")
                .font(.caption).foregroundStyle(.secondary)
            #else
            Text("Activity in Mop resets the inactivity timer for all connected vaults. Switching apps conceals secrets and discards unsaved edits; returning before the timeout keeps the session open. Copied secrets remain available for up to 30 seconds. Temporary system prompts conceal the interface without ending authentication.").font(.caption).foregroundStyle(.secondary)
            #endif
        }
        .formStyle(.grouped)
        .mopSheetWidth(640)
        #if os(iOS)
        .safeAreaInset(edge: .top) {
            HStack {
                Text("Settings").font(.headline)
                Spacer()
                Button("Done") { dismiss() }
            }.padding().background(.regularMaterial)
        }
        #endif
        #if os(macOS)
        .frame(height: 650)
        #endif
        .onAppear {
            model.settingsVisible = true
            if model.selectedVaultDescriptor?.enrolled != true,
               let vault = model.vaults.first(where: { $0.enrolled }) {
                _ = model.prepareVaultAction(vault.id)
            }
            model.loadDevices()
        }
        .onDisappear { model.settingsVisible = false }
        .sheet(item: $model.sheet) { sheet in
            AppSheetView(model: model, kind: sheet).id(model.editorGeneration)
        }
        .documentTransfers(model: model, inSettings: true)
        .confirmationDialog("Remove this device?", isPresented: Binding(get: { removal != nil }, set: { if !$0 { removal = nil } }), titleVisibility: .visible) {
            if let device = removal {
                Button("Remove " + device.name, role: .destructive) { model.removeDevice(device.id); removal = nil }
            }
        } message: { Text("It will lose access and must explicitly reconnect with new device keys to join again.") }
        .alert("Operation not completed", isPresented: Binding(get: { model.sheet == nil && model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK") { model.error = nil }
        } message: { Text(model.error ?? "") }
    }
}
