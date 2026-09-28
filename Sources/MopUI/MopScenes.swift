import SwiftUI
import MopCore
import MopAppSupport

public struct MopScenes: Scene {
    @State private var model: AppModel
    @MainActor private static func initialModel() -> AppModel {
        #if DEBUG && (os(macOS) || targetEnvironment(simulator))
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
        Window("2ndPass", id: "main") {
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
                Button("Import…") { model.beginImport() }.disabled(model.busy || model.offline || !model.authenticated)
                Button("New Vault…") { model.presentSheet(.createVault) }.disabled(model.busy || model.offline)
            }
            CommandGroup(after: .textEditing) {
                Button("Find") { model.searchFocusRequest += 1 }.keyboardShortcut("f")
                    .disabled(!model.authenticated)
                Button("Edit Item") { model.beginItemEditing() }.keyboardShortcut("e")
                    .disabled(model.selectedTypedItem == nil || model.vaultDetailsTarget != nil || model.itemDraft != nil || model.busy || model.offline)
                Button("Move to Recently Deleted…") {
                    if let item = model.selectedTypedItem {
                        model.itemToDelete = ItemRow(id: .init(vault: model.vault, name: item.name), vaultName: model.vaultName, item: item)
                    }
                }.keyboardShortcut(.delete, modifiers: .command).disabled(model.selectedTypedItem == nil || model.vaultDetailsTarget != nil || model.itemDraft != nil || model.busy || model.offline)
                Button("Restore Item") {
                    if let row = model.selectedDeletedItem { model.restoreDeletedItem(row) }
                }.keyboardShortcut("r", modifiers: [.command, .shift]).disabled(model.page != .recentlyDeleted || model.selectedDeletedItem == nil || model.busy || model.offline)
            }
            CommandMenu("Vault") {
                Button("Refresh") { model.refresh() }.keyboardShortcut("r").disabled(model.busy)
                if model.authenticated {
                    Button("Lock") { model.lock() }.keyboardShortcut("l", modifiers: [.command, .shift])
                } else {
                    Button("Unlock 2ndPass") { model.unlock() }.disabled(!model.canUnlock)
                }
            }
    }
}

enum SettingsCategory: String, CaseIterable, Identifiable {
    case security = "Security", autoFill = "AutoFill", devices = "Devices", advanced = "Advanced"
    var id: String { rawValue }
    var symbol: String {
        switch self { case .security: "lock.shield"; case .autoFill: "key"; case .devices: "rectangle.connected.to.line.below"; case .advanced: "gearshape.2" }
    }
}

struct SessionSettings: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var model: AppModel
    @AppStorage(AttachmentDownloadSettings.key, store: AttachmentDownloadSettings.defaults) private var downloadAttachmentsDuringSync = false
    @AppStorage("developerToolsEnabled") private var developerTools = false
    @State private var vaultID = ""
    @State private var removal: VaultDeviceRecord?
    @State private var customTimeout = false
    @State private var categoryPath: [SettingsCategory] = []
    private let durations = [1, 5, 10, 15, 30, 60]
    var body: some View {
        Group {
            if !model.authenticated && model.hasConnectedVaults {
                LockedView(model: model)
                    #if os(macOS)
                    .frame(width: 620, height: 560)
                    #endif
            } else {
                #if os(macOS)
                TabView(selection: $model.settingsCategory) {
                    ForEach(SettingsCategory.allCases) { category in
                        categoryView(category).tabItem { Label(category.rawValue, systemImage: category.symbol) }.tag(category)
                    }
                }.frame(width: 620, height: 560)
                #else
                NavigationStack(path: $categoryPath) {
                    List(SettingsCategory.allCases) { category in
                        NavigationLink(value: category) { Label(category.rawValue, systemImage: category.symbol) }
                    }
                    .navigationTitle("Settings")
                    .navigationDestination(for: SettingsCategory.self) { category in
                        categoryView(category).navigationTitle(category.rawValue)
                            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
                    }
                    .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
                }
                .onAppear { categoryPath = [model.settingsCategory] }
                .onChange(of: categoryPath) { _, path in if let category = path.last { model.settingsCategory = category } }
                #endif
            }
        }
        .draftTransitionPrompt(model: model, inSettings: true)
        .onAppear { model.settingsVisible = true }
        .onDisappear { model.settingsVisible = false }
        .sheet(item: Binding<SheetRequest?>(get: { model.sheetRequest?.inSettings == true ? model.sheetRequest : nil }, set: { if model.sheetRequest?.inSettings == true { model.sheetRequest = $0 } })) { request in AppSheetView(model: model, request: request) }
        .documentTransfers(model: model, inSettings: true)
        .confirmationDialog("Remove this device?", isPresented: Binding(get: { removal != nil }, set: { if !$0 { removal = nil } }), titleVisibility: .visible) {
            if let device = removal {
                Button("Remove " + device.name, role: .destructive) { model.removeDevice(device.id); removal = nil }
            }
        } message: {
            if let device = removal {
                Text((device.isCurrent ? "This device will lose access" : device.name + " will lose access") + " to: " +
                    (device.vaultNames.isEmpty ? "your enrolled personal vaults" : device.vaultNames.values.sorted().joined(separator: ", ")) +
                    ". It must explicitly reconnect to join again. A vault’s last owner device cannot be removed.")
            }
        }
        .alert("Operation not completed", isPresented: Binding(get: { model.sheet == nil && model.error != nil }, set: { if !$0 { model.error = nil } })) {
            if model.developerDiagnosticsEnabled { Button("Copy Details") { model.copyErrorDetails() } }
            Button("OK") { model.error = nil }
        } message: { Text(model.errorMessage) }
    }
    private func categoryView(_ category: SettingsCategory) -> some View {
        Form {
            switch category {
            case .security:
                Section("Session") {
                    Picker(selection: Binding(get: { customTimeout || !durations.contains(model.autoLockMinutes) ? 0 : model.autoLockMinutes }, set: { value in
                        customTimeout = value == 0
                        if value != 0 { model.autoLockMinutes = value }
                    })) {
                        ForEach(durations, id: \.self) { Text("\($0) minute\($0 == 1 ? "" : "s")").tag($0) }
                        Text("Custom…").tag(0)
                    } label: { Text("Lock after inactivity").fixedSize() }
                    .accessibilityIdentifier("inactivity-timeout")
                    if customTimeout || !durations.contains(model.autoLockMinutes) {
                        Stepper("\(model.autoLockMinutes) minutes", value: $model.autoLockMinutes, in: 1...60)
                    }
                    Text("Activity in 2ndPass keeps your session open. Switching apps conceals secrets. Security locking clears unsaved edits immediately.").font(.callout)
                }
            case .autoFill: AutoFillSettingsView(model: model)
            case .devices:
            Section("Devices") {
                if model.removingDevice {
                    ProgressView(model.removalProgress ?? "Removing device…")
                    Text("Keep 2ndPass open while encryption is updated and the change is saved to iCloud.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Text("Devices connected to your enrolled personal vaults.").font(.caption).foregroundStyle(.secondary)
                ForEach(model.devices) { device in
                    HStack {
                        VStack(alignment: .leading) {
                            Label(device.name + (device.isCurrent ? " (this device)" : ""), systemImage: "rectangle.connected.to.line.below")
                            DisclosureGroup("Details") {
                                Text(device.id.uuidString).font(.caption).textSelection(.enabled)
                                Text("Vaults: " + device.vaultNames.values.sorted().joined(separator: ", ")).font(.caption)
                            }
                        }
                        Spacer()
                        Button("Remove…", role: .destructive) { removal = device }
                            .disabled(model.busy || model.offline || model.devices.count < 2)
                    }
                }
                if model.devices.isEmpty { Text(model.authenticated ? "Refresh to load enrolled devices." : "Unlock 2ndPass to view connected devices.").foregroundStyle(.secondary) }
                if model.authenticated {
                    Button("Refresh devices") { model.loadDevices() }.disabled(model.busy || model.offline)
                } else {
                    Button("Unlock to view devices") { model.unlock() }.disabled(!model.canUnlock)
                }
                Button("Connect Another Device…") { model.presentSheet(.addDevice, inSettings: true) }.disabled(model.busy || model.offline)
            }

            case .advanced:
                Section("Attachments on this device") {
                    Picker("Download attachments", selection: $downloadAttachmentsDuringSync) {
                        Text("On demand").tag(false)
                        Text("During sync").tag(true)
                    }
                    Text("On demand downloads files when you open or export them. During sync keeps encrypted files available offline. AutoFill never downloads attachments. Changing this setting keeps files already downloaded.")
                        .font(.callout)
                }
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
                    model.requestTransition(.vault(id)) { accepted in if accepted { dismiss() } }
                }.disabled(model.busy || UUID(uuidString: vaultID.trimmingCharacters(in: .whitespacesAndNewlines)) == nil)
            }

            }
            if let notice = model.notice { Text(notice).font(.callout).textSelection(.enabled) }
        }.formStyle(.grouped)
        .onAppear { if category == .devices && model.settingsCategory == .devices && model.authenticated { model.loadDevices() } }
        .onChange(of: model.authenticated) { _, unlocked in if unlocked && category == .devices && model.settingsCategory == .devices { model.loadDevices() } }
    }
}
