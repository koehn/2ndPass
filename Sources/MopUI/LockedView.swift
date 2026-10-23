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

    private var connectionStatus: some View {
        VStack(spacing: 16) {
            Text(model.connectionTitle).font(.title2)
            if !model.connectionNeedsUnlock {
                ProgressView().accessibilityLabel(model.connectionTitle)
            }
            Text(model.connectionExplanation)
                .font(.callout).foregroundStyle(.secondary)
                .multilineTextAlignment(.center).frame(maxWidth: 420)
            if model.connectionNeedsUnlock {
                Button(model.unlockQueued ? "Waiting to unlock…" : model.unlockStarting ? "Unlocking…" : "Unlock 2ndPass") {
                    model.authorizeVaultConnection()
                }.disabled(!model.canAuthorizeVaultConnection)
            }
            if let progress = model.connectionProgressText {
                Text(progress).font(.callout)
            }
            if let issue = model.syncIssue {
                Text(issue).font(.callout).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center).frame(maxWidth: 420)
            }
        }.accessibilityIdentifier("Enrollment progress")
    }

    var body: some View {
        VStack(spacing: 24) {
            Self.icon
                .resizable().scaledToFit().frame(width: 128, height: 128)
                .accessibilityLabel("2ndPass")
            if model.updateAuthenticationState != .ready {
                Text(model.updateAuthenticationMessage).multilineTextAlignment(.center)
                Button(model.updateAuthenticationButton) { model.resumeUpdates() }
                    .disabled(!model.canResumeUpdates)
                    .accessibilityIdentifier("resume-authenticated-enrollment")
                if model.updateAuthenticationState == .failed {
                    Button("Details…") { model.showUpdateAuthenticationDetails() }
                }
            }
            if model.rootPresentation == .starting {
                ProgressView("Opening 2ndPass…")
            } else if model.rootPresentation == .setup {
                Text("Welcome to 2ndPass").font(.title2)
                Button("Create a vault…") { model.presentSheet(.createVault) }
                    .buttonStyle(.borderedProminent).disabled(model.busy)
                Button("Restore a backup…") { model.presentSheet(.restoreBackup) }.disabled(model.busy)
                Button("Unlock device-local vault") { model.unlock() }.disabled(!model.canUnlock)
            } else if model.waitingForVaultMetadata || model.isConnectingVaults {
                connectionStatus
            } else if model.rootPresentation == .unlocking {
                ProgressView("Unlocking and opening your vault…")
                    .accessibilityIdentifier("Unlock in progress")
            } else {
                Button(model.unlockQueued ? "Waiting to unlock…" : model.unlockStarting ? "Unlocking…" : "Unlock 2ndPass") {
                    model.unlock()
                }
                .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                .disabled(!model.canUnlock)
            }
            if !model.waitingForVaultMetadata, model.vaults.contains(where: { $0.supported && !$0.enrolled }) {
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
