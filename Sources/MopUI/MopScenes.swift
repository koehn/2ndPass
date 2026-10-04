import SwiftUI
import MopCore
import MopSubscriptions
import MopAppSupport

public struct MopScenes: Scene {
    @State private var model: AppModel
    @MainActor private static func initialModel() -> AppModel {
        #if DEBUG && (os(macOS) || targetEnvironment(simulator))
        if ProcessInfo.processInfo.environment["MOP_UI_TESTING"] == "1" {
            let model = AppModel(breachClient: UITestBreachClient(), service: UITestVaultService())
            if ProcessInfo.processInfo.environment["MOP_UI_SECURITY_TEST"] == "1" { model.securityVisible = true }
            return model
        }
        #endif
        return AppModel()
    }
    public init() {
        _ = DeveloperPreferences.shared
        SubscriptionModel.shared.start()
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
                Button("New SSH Key…") { model.keyCreationPresented = true }.disabled(model.busy || model.offline || !model.authenticated)
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
    case security = "Security", autoFill = "AutoFill", devices = "Devices", recovery = "Recovery", advanced = "Advanced"
    var id: String { rawValue }
    var symbol: String {
        switch self { case .security: "lock.shield"; case .autoFill: "key"; case .devices: "rectangle.connected.to.line.below"; case .recovery: "key.horizontal"; case .advanced: "gearshape.2" }
    }
}

struct SessionSettings: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var model: AppModel
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
                Section("Password Health") {
                    Toggle("Check exposed passwords with HIBP", isOn: $model.breachChecksEnabled)
                    Text("HIBP receives a five-character hash prefix and your network address, not your password or account details. Checks run only on saved passwords while unlocked.").font(.caption)
                }
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
            case .recovery:
                if !model.supports(.recovery) {
                    Section("Portable Recovery") {
                        Text("Offline account recovery is not yet available for item vaults. Keep a portable backup and its separate key.")
                        Button("Restore Portable Backup…") { model.presentSheet(.restoreBackup, inSettings: true) }
                    }
                } else {
                Section("Setup and Verification") {
                    Text("Prepare an offline copy before losing your devices. Generate and verify a copy, check coverage across your owned iCloud vaults, or manage an existing key.").font(.callout)
                    if model.canPresent(.setupRecovery) { Button("Set Up or Verify Recovery…") { model.presentSheet(.setupRecovery, inSettings: true) }
                        .disabled(model.busy || model.offline)
                    }
                }
                Section("Recover Vault Access") {
                    Text("If your previously connected devices are unavailable, use your saved recovery file or code to restore vault access. You must be signed into the same Apple Account.").font(.callout)
                    if model.canPresent(.recover) { Button("Recover Vault Access…") { model.presentSheet(.recover, inSettings: true) }
                        .disabled(model.busy || model.offline)
                    }
                    Text("The recovery copy cannot restore Apple Account sign-in or missing iCloud data.").font(.caption)
                }
                }
            case .autoFill: AutoFillSettingsView(model: model)
            case .devices:
            if !model.supports(.enrollment) {
                Section("Devices") { Text("Additional-device enrollment is not yet available for item vaults.") }
            } else {
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
                        if model.supports(.deviceRemoval) {
                            Button("Remove…", role: .destructive) { removal = device }
                                .disabled(model.busy || model.offline || model.devices.count < 2)
                        }
                    }
                }
                if model.devices.isEmpty { Text(model.authenticated ? "Refresh to load enrolled devices." : "Unlock 2ndPass to view connected devices.").foregroundStyle(.secondary) }
                if model.authenticated {
                    Button("Refresh devices") { model.loadDevices() }.disabled(model.busy || model.offline)
                } else {
                    Button("Unlock to view devices") { model.unlock() }.disabled(!model.canUnlock)
                }
                Text("Devices using the same Apple Account connect automatically while an existing device is unlocked.").font(.caption).foregroundStyle(.secondary)
            }

            }
            case .advanced:
                SubscriptionSettingsView()
            Section("Developer") {
                Toggle("Show developer tools", isOn: Binding(get: { developerTools }, set: { DeveloperPreferences.shared.set($0) }))
                Text("Show additional diagnostic details. Syncs across devices using your Apple Account.")
                    .font(.caption).foregroundStyle(.secondary)
                #if os(macOS)
                Text("Install the command-line tools")
                    .font(.headline)
                Text("Install Homebrew, then run these commands in Terminal to install sp and its SSH agent:")
                    .font(.callout)
                Link("Get Homebrew", destination: URL(string: "https://brew.sh")!)
                Text("brew tap koehn/2ndpass https://github.com/koehn/2ndPass\nbrew install --cask koehn/2ndpass/secondpass-cli")
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                #endif
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
