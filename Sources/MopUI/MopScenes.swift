import SwiftUI
import MopCore

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
    var body: some View {
        Form {

            Stepper("Lock after \(model.autoLockMinutes) minutes of inactivity", value: $model.autoLockMinutes, in: 1...60)
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
            Button("Done") { dismiss() }
            Text("Activity in Mop resets the inactivity timer for all connected vaults. Switching apps conceals secrets and discards unsaved edits; returning before the timeout keeps the session open. Copied secrets remain available for up to 30 seconds. Temporary system prompts conceal the interface without ending authentication.").font(.caption).foregroundStyle(.secondary)
            #endif
        }.padding(24).mopSheetWidth(430)
    }
}
