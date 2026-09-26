import SwiftUI
import MopCore
import MopAppSupport
import MopVaultNext
import UniformTypeIdentifiers

struct AppSheetView: View {
    @Bindable var model: AppModel
    let kind: AppSheet
    @State private var name = "personal"
    @State private var fingerprint = ""
    @State private var confirmation = ""
    @State private var localError: String?
    var body: some View {
        ScrollView { VStack(alignment: .leading, spacing: 18) {
            switch kind {
            case .createVault:
                Text("Create a vault").font(.title2)
                TextField("Vault name", text: $name)
                Text("Mop will create this device’s protected keys automatically. You can start saving passwords immediately and add other devices or hardware recovery later.")
                Button("Create vault") { model.createVault(name: name) }
                    .disabled((try? VaultName.validate(name)) == nil)
                Text("Until you add another device or recovery, losing this device means losing access to your vault.").font(.caption)
                Divider()
                Button("Connect to an existing vault…") { model.sheet = .enrollDevice }
                Button("Set up this device for recovery…") { model.sheet = .setupRecovery }
                Button("Recover an existing vault…") { model.sheet = .recover }
            case .enrollDevice:
                if model.deviceRemoved {
                    Text("This device was removed").font(.title2)
                    Text(model.removalCleanupPending ? "Local cleanup could not finish. Reconnect will retry cleanup before adding this device again." : "Its local account access has been cleared. Reconnect only if you want to add this device again.")
                    Button("Reconnect") { model.reconnectDevice() }
                } else {
                Text("Connect this device").font(.title2)
                Text("Mop connects automatically through your Apple Account. Keep Mop unlocked on another device until setup finishes.")
                ForEach(model.vaults.filter { !$0.enrolled }) { vault in
                    Text(vault.name ?? vault.id).font(.caption)
                }
                CloudEnrollmentView(model: model, owner: false)
                DisclosureGroup("Join another person’s shared vault") { SharingView(model: model, setup: true, flow: .connect) }
                Button("Refresh vaults") { model.sheet = nil; model.discover(autoUnlock: true) }
                Button("Create a different vault…") { model.sheet = .createVault }
                Button("No approved device? Recover…") { model.sheet = .recover }
                }
            case .addDevice:
                Text("Add my device").font(.title2)
                Text("Open Mop on your new device using the same Apple Account. Keep this device unlocked; Mop will connect the new device automatically and notify you when it joins.")
                CloudEnrollmentView(model: model, owner: true)
            case .shareAccount:
                Text("Share with another person").font(.title2)
                Text("Ask the other person to open Mop and choose Connect to an existing vault. Choose what they may do, exchange the invitation, then approve their response.")
                SharingView(model: model, setup: false, flow: .share)
            case .setupRecovery:
                Text("Optional hardware recovery").font(.title2)
                Text("On a separate device, create a recovery request. On your owner device, import that request to add recovery to existing secrets. Keep encrypted backups as well as the recovery device.")
                SharingView(model: model, setup: model.selectedVault == nil, flow: .recovery)
            case .recover:
                Text("Hardware recovery").font(.title2)
                SharingView(model: model, setup: false, recoveryMode: true)
            case .trust:
                Text("Verify current checkpoint").font(.title2)
                TextField("Independently obtained checkpoint", text: $fingerprint)
                Button("Verify") { model.management(.trust(fingerprint: fingerprint)) }.disabled(fingerprint.count != 64)
            case .renameVault:
                Text("Rename vault").font(.title2)
                Text("Update scripts and references after renaming. The old name is not retained.")
                TextField("Name", text: $name)
                Button("Rename") { model.renameVault(to: name) }.disabled((try? VaultName.validate(name)) == nil)
            case .deleteVault:
                Text("Delete cloud vault").font(.title2)
                Text("Permanently delete cloud contents and history. Existing backups and local encrypted checkpoints remain.")
                Text(model.vault).textSelection(.enabled)
                TextField("Type the vault name to confirm", text: $confirmation)
                Button("Delete", role: .destructive) {
                    if let target = model.selectedVaultDescriptor { model.deleteVault(target: target, confirmation: confirmation) }
                }.disabled(confirmation != model.vaultName)
            }
            if let notice = model.notice { Text(notice).font(.callout).textSelection(.enabled) }
            if model.busy { ProgressView("Waiting for authentication or iCloud…") }
            Button("Done") { model.sheet = nil }.disabled(model.busy)
        }.padding(24) }.mopSheetWidth(640)
        .disabled(model.busy).interactiveDismissDisabled(model.busy)
        .documentTransfers(model: model, inSheet: true)
        .onAppear { if kind == .renameVault { name = model.vaultName } }
        .alert("Operation not completed", isPresented: Binding(get: { model.error != nil || localError != nil }, set: { if !$0 { model.error = nil; localError = nil } })) {
            Button("OK") { model.error = nil; localError = nil }
        } message: { Text(localError ?? model.error ?? "") }
    }
}

private struct CloudEnrollmentView: View {
    @Bindable var model: AppModel
    let owner: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(model.enrollmentStatus).accessibilityIdentifier("enrollment-status")
            if !owner && !model.cloudEnrollments.contains(where: { $0.rejected }) {
                ProgressView("Connecting through iCloud…")
                Text("If setup is waiting, open and unlock Mop on a device that already has this vault. No approval is needed there.")
            }
            if model.cloudEnrollments.contains(where: { $0.rejected }) {
                Text("Connection cancelled. Tap Restart connection to try again.")
            }
            Button("Check iCloud now") { model.pollCloudEnrollment(owner: owner) }.disabled(model.busy)
            if !owner {
                Button("Restart connection") { model.restartCloudEnrollment() }.disabled(model.busy)
                Button("Cancel request", role: .destructive) { model.cancelCloudEnrollment() }.disabled(model.busy)
                Text("Restart tries the connection again without deleting your vault or device keys.").font(.caption)
            }
        }
        .task {
            var first = true
            while !Task.isCancelled {
                if model.isActive && !model.busy && !model.refreshing {
                    model.pollCloudEnrollment(owner: owner, automatic: !first)
                    first = false
                }
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }
}
