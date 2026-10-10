import SwiftUI
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// Replaces the navigation hierarchy so locked content cannot be read by accessibility.
struct LockedView: View {
    @Bindable var model: AppModel
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

    private func connectionThermometer(title: String) -> some View {
        VStack(spacing: 8) {
            Text(title)
            ProgressView(value: model.connectionProgress?.fraction, total: 1)
                .progressViewStyle(.linear)
                .accessibilityLabel("Vault connection progress")
                .accessibilityValue(model.connectionProgress.map { "\($0.ready) of \($0.total) vault records ready" } ?? "Waiting for approval")
            if let progress = model.connectionProgress {
                Text("\(progress.ready) of \(progress.total) vault records ready")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: 320)
        .accessibilityIdentifier("Enrollment progress")
    }

    var body: some View {
        VStack(spacing: 24) {
            Self.icon
                .resizable().scaledToFit().frame(width: 128, height: 128)
                .accessibilityLabel("2ndPass")
            if model.waitingForVaultMetadata {
                connectionThermometer(title: "Downloading vault…")
                Text("This device is connected. Waiting for vault details and secure access to finish downloading. Your vault will open automatically.")
                    .font(.callout).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center).frame(maxWidth: 420)
            } else if model.isConnectingVaults {
                connectionThermometer(title: "Connecting securely…")
                if !model.authenticated {
                    Button("Unlock to Connect") { model.authorizeVaultConnection() }.disabled(model.busy)
                }
                Text("Open and unlock 2ndPass on another device to finish connecting.")
                    .font(.callout).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            } else {
                Button(model.unlocking ? "Unlocking…" : "Unlock 2ndPass") {
                    if model.vaults.contains(where: { $0.supported }) { model.unlock() }
                    else { model.presentSheet(model.canPresent(.enrollDevice) ? .enrollDevice : .restoreBackup) }
                }
                .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                .disabled(model.hasConnectedVaults ? !model.canUnlock : model.busy || model.deviceRemoved)
            }
            if !model.waitingForVaultMetadata, model.vaults.contains(where: { $0.supported && !$0.enrolled }) {
                Text("Connecting your iCloud vaults").font(.headline)
                Text("Open and unlock 2ndPass on an existing device. Key access syncs automatically.")
                    .multilineTextAlignment(.center).frame(maxWidth: 420)
                ForEach(model.vaults.filter { $0.supported && !$0.enrolled }) { vault in
                    Label(vault.name ?? "Vault \(vault.id.prefix(8))", systemImage: "icloud")
                }
            }
            if model.supports(.recovery) && model.sessionState == .needsRepair && !model.deviceRemoved {
                Text("Use your offline recovery copy to verify access. Your saved local data remains intact.")
                    .multilineTextAlignment(.center).frame(maxWidth: 420)
                Button("Recover with Offline Copy…") { model.presentSheet(.recover) }.disabled(model.busy)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.background)
        .accessibilityIdentifier("Locked screen")
    }
}
