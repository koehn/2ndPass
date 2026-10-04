import SwiftUI
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// Replaces the navigation hierarchy so locked content cannot be read by accessibility.
struct LockedView: View {
    @Bindable var model: AppModel
    @State private var confirmRepair = false
    // This is a loose SwiftPM resource, not an asset-catalog image. SwiftUI's
    // named lookup can render it blank in a packaged app's resource bundle.
    private static let icon: Image = {
        if let url = Bundle.module.url(forResource: "LockIcon", withExtension: "png") {
            #if os(macOS)
            if let image = NSImage(contentsOf: url) { return Image(nsImage: image) }
            #else
            if let image = UIImage(contentsOfFile: url.path) { return Image(uiImage: image) }
            #endif
        }
        return Image(systemName: "lock.shield")
    }()

    var body: some View {
        VStack(spacing: 24) {
            Self.icon
                .resizable().scaledToFit().frame(width: 128, height: 128)
                .accessibilityLabel("2ndPass")
            if model.isConnectingVaults {
                ProgressView("Connecting securely…")
                Text("Open and unlock 2ndPass on another device to finish connecting.")
                    .font(.callout).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                Button("Retry Connection") { model.retryVaultConnection() }
                    .disabled(model.busy)
            } else {
                Button(model.unlocking ? "Unlocking…" : "Unlock 2ndPass") {
                    if model.vaults.contains(where: { $0.supported }) { model.unlock() }
                    else { model.presentSheet(model.canPresent(.enrollDevice) ? .enrollDevice : .restoreBackup) }
                }
                .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                .disabled(model.hasConnectedVaults ? !model.canUnlock : model.busy || model.deviceRemoved)
            }
            if model.vaults.contains(where: { $0.supported && !$0.enrolled }) {
                Text("Connecting your iCloud vaults").font(.headline)
                Text("Open and unlock 2ndPass on an existing device. Key access syncs automatically.")
                    .multilineTextAlignment(.center).frame(maxWidth: 420)
                ForEach(model.vaults.filter { $0.supported && !$0.enrolled }) { vault in
                    Label(vault.name ?? "Vault \(vault.id.prefix(8))", systemImage: "icloud")
                }
            }
            if model.supports(.enrollment) && model.cloudConnectionRepairEnabled && model.sessionState == .needsRepair && !model.deviceRemoved {
                Text("This device could not open its saved vault connection. If you can open your vaults on another device, reset this device’s iCloud connection and connect again.")
                    .multilineTextAlignment(.center).frame(maxWidth: 420)
                Button("Repair iCloud Connection…") { confirmRepair = true }
                    .disabled(model.busy)
                Button("Recover with Offline Copy…") { model.presentSheet(.recover) }
                    .disabled(model.busy)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.background)
        .accessibilityIdentifier("Locked screen")
        .alert("Reset this device’s iCloud connection?", isPresented: $confirmRepair) {
            Button("Reset Connection", role: .destructive) { model.resetCloudAccess() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("First make sure you can open your vaults on another device. This removes this device’s iCloud vault keys and cached data, including any changes that have not reached iCloud. You will need to reconnect every iCloud vault. Vaults in iCloud, other devices, local-only vaults, and exported backups stay intact.")
        }
    }
}
