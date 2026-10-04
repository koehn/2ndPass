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
            Text(target.name ?? "Unnamed vault").font(.title2).bold()
            Text(model.vaultConnectionLabel(target)).foregroundStyle(.secondary)
            if model.authenticated && target.enrolled {
                GroupBox("Vault") {
                    VStack(alignment: .leading, spacing: 12) {
                        Button("Rename Vault…") { model.presentSheet(.renameVault, target: target) }
                        Button("Export Portable Backup…") { model.presentSheet(.portableBackup, target: target) }
                        Button("Restore Portable Backup…") { model.presentSheet(.restoreBackup, target: target) }
                        if model.canPresent(.shareAccount) { Button("Share with Another Person…") { model.presentSheet(.shareAccount, target: target) } }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }.disabled(model.busy || model.offline)
                Divider()
                if model.canPresent(.deleteVault) { Button("Delete Vault…", role: .destructive) { model.presentSheet(.deleteVault, target: target) }
                    .disabled(model.busy || model.offline)
                }
            } else if target.enrolled {
                Button("Unlock to Manage Vault") { model.unlock() }.disabled(!model.canUnlock)
            } else {
                if model.canPresent(.enrollDevice) { Button("Retry Connection") { model.enrollmentAction(.automaticEnrollment, vaultID: target.id) } }
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
    var secondaryTitle: String?
    var secondarySubmit: (() -> Void)?
}


struct VaultDetailsDialog: View {
    @Bindable var model: AppModel
    let target: VaultDescriptor
    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VaultDetailsView(model: model, target: model.vaultDetailsTarget ?? target)
                if let notice = model.notice {
                    Text(notice).font(.callout).textSelection(.enabled).padding()
                }
            }
            Divider()
            HStack {
                if model.busy { ProgressView().controlSize(.small) }
                Spacer()
                Button("Done") { model.openVaultDetails(nil) }
                    .keyboardShortcut(.cancelAction).disabled(model.busy)
            }.padding()
        }
        .mopSheetWidth(640)
        .frame(minHeight: 380)
        .interactiveDismissDisabled(model.busy)
        .documentTransfers(model: model, inDetails: true)
        .sheet(item: Binding(get: { model.sheetRequest?.inSettings == false ? model.sheetRequest : nil },
                             set: { if model.sheetRequest?.inSettings == false { model.sheetRequest = $0 } })) { request in
            AppSheetView(model: model, request: request)
        }
        .alert("Operation not completed", isPresented: Binding(
            get: { model.sheetRequest == nil && model.error != nil },
            set: { if !$0 { model.error = nil } })) {
                if model.developerDiagnosticsEnabled { Button("Copy Details") { model.copyErrorDetails() } }
                Button("OK") { model.error = nil }
            } message: { Text(model.errorMessage) }
    }
}
