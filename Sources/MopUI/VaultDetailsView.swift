import SwiftUI
import MopCore

struct SheetRequest: Identifiable {
    let id = UUID()
    let kind: AppSheet
    let inSettings: Bool
    let target: VaultDescriptor?
}

struct VaultDetailsView: View {
    @Bindable var model: AppModel
    let target: VaultDescriptor
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Button(model.selectedItem == nil ? "Back to Items" : "Back to Item", systemImage: "chevron.left") { model.openVaultDetails(nil) }
            Text(target.name ?? "Unnamed vault").font(.title2).bold()
            Text(model.vaultConnectionLabel(target)).foregroundStyle(.secondary)
            if model.authenticated && target.enrolled {
                GroupBox("Vault") {
                    VStack(alignment: .leading, spacing: 12) {
                        Button("Rename Vault…") { model.presentSheet(.renameVault, target: target) }
                        Button("Export Encrypted Backup…") { model.chooseExportBackup(target: target) }
                        Button("Share with Another Person…") { model.presentSheet(.shareAccount, target: target) }
                        Button("Set Up or Replace Hardware Recovery…") { model.presentSheet(.setupRecovery, target: target) }
                        Button("Recover Using This Hardware Device…") { model.presentSheet(.recover, target: target) }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }.disabled(model.busy || model.offline)
                DisclosureGroup("Security Details") {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(target.id).textSelection(.enabled)
                        Button("Show Checkpoint") { model.management(.fingerprint, keepSheet: true, target: target) }
                        Button("Verify Members and Devices") { model.loadMembers(target: target) }
                        ForEach(model.membersVaultID == target.id ? model.members : []) { member in Text(member.id + " · " + member.role).textSelection(.enabled) }
                        SharingView(model: model, setup: false, target: target)
                    }.disabled(model.busy || model.offline)
                }
                Divider()
                Button("Delete Vault…", role: .destructive) { model.presentSheet(.deleteVault, target: target) }
                    .disabled(model.busy || model.offline)
            } else if target.enrolled {
                Button("Unlock to Manage Vault") { model.unlock() }.disabled(!model.canUnlock)
            } else {
                Button("Connect This Device…") { model.presentSheet(.enrollDevice, target: target) }
            }
            if model.lastBackupVaultID == target.id, let url = model.lastBackupURL {
                Text("Backup saved: " + url.lastPathComponent).textSelection(.enabled)
                #if os(macOS)
                Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([url]) }
                #endif
            }
        }.padding(20).frame(maxWidth: 700, alignment: .leading).frame(maxWidth: .infinity, alignment: .leading)
    }
}

@MainActor @Observable final class SheetControls {
    var revision = 0
    var title: String?
    var canSubmit = false
    var dirty = false
    var error: String?
    var submit: (() -> Void)?
}
