import SwiftUI
import AppKit

@main
struct MopApplication: App {
    @State private var model = AppModel()
    var body: some Scene {
        Window("mop", id: "main") {
            ContentView(model: model)
                .frame(minWidth: 820, minHeight: 540)
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                    model.deactivate()
                }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in model.activate() }
                .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.sessionDidResignActiveNotification)) { _ in model.lock() }
                .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.willSleepNotification)) { _ in model.lock() }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in model.lock() }
        }
        .defaultSize(width: 1060, height: 680)
        .commands {
            CommandGroup(after: .newItem) {
                Button("New Secret…") { model.sheet = .createSecret }
                    .keyboardShortcut("n").disabled(model.busy || model.offline || model.vault.isEmpty)
                Button("New Vault…") { model.sheet = .createVault }.disabled(model.busy || model.offline)
            }
            CommandMenu("Vault") {
                Button("Unlock / Refresh") { model.unlock() }.keyboardShortcut("r").disabled(model.busy)
                Button("Lock") { model.lock() }.keyboardShortcut("l", modifiers: [.command, .shift])
                Button("Synchronize") { model.sync() }.disabled(model.busy || model.offline)
            }
        }
    }
}
