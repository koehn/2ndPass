import SwiftUI
import AppKit

@main
struct MopApplication: App {
    @State private var model = AppModel()
    var body: some Scene {
        Window("mop", id: "main") {
            ContentView(model: model)
                .frame(minWidth: 820, minHeight: 540)
                .onAppear { model.startMonitoringActivity() }
        }
        .defaultSize(width: 1060, height: 680)
        .commands {
            CommandGroup(after: .newItem) {
                Button("New Item") { model.beginCreatingItem() }
                    .keyboardShortcut("n").disabled(model.busy || model.offline || !model.authenticated || model.itemCreationVaults.isEmpty || model.itemDraft != nil || model.page != .secrets)
                Button("New Vault…") { model.sheet = .createVault }.disabled(model.busy || model.offline)
            }
            CommandMenu("Vault") {
                Button("Unlock / Refresh") { model.unlock() }.keyboardShortcut("r").disabled(model.busy)
                Button("Lock") { model.lock() }.keyboardShortcut("l", modifiers: [.command, .shift])
                Button("Synchronize") { model.sync() }.disabled(model.busy || model.offline || model.allVaults)
            }
        }
        Settings {
            SessionSettings(model: model)
                .onAppear { model.startMonitoringActivity() }
        }
    }
}

private struct SessionSettings: View {
    @Bindable var model: AppModel
    var body: some View {
        Form {
            Stepper("Lock after \(model.autoLockMinutes) minutes of inactivity", value: $model.autoLockMinutes, in: 1...60)
            Text("Activity in Mop keeps your session open. Switching apps conceals secrets. Locking your Mac, sleeping, or quitting Mop ends the session immediately.")
                .font(.caption).foregroundStyle(.secondary)
        }.padding(24).frame(width: 430)
    }
}
