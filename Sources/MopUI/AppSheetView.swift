import SwiftUI
import MopCore
import MopAppSupport
import MopVaultNext
import UniformTypeIdentifiers

struct AppSheetView: View {
    @Bindable var model: AppModel
    let request: SheetRequest
    private var kind: AppSheet { request.kind }
    @State private var controls = SheetControls()
    @State private var initialName = "Personal"
    @State private var confirmDiscard = false
    @State private var submitted = false
    @State private var nextSheet: AppSheet?
    @State private var name = "Personal"
    @State private var confirmation = ""
    @State private var localError: String?
    var body: some View {
        VStack(spacing: 0) { ScrollView { VStack(alignment: .leading, spacing: 18) {
            switch kind {
            case .portableBackup:
                PortableBackupView(model: model, target: request.target)
            case .restoreBackup:
                PortableBackupView(model: model, target: nil)
            case .importItems:
                PasswordImportView(model: model, controls: controls)
            case .createVault:
                Text(model.vaults.isEmpty ? "Create Your First Vault" : "Create a Vault").font(.title2)
                TextField("Vault name", text: $name)
                if (try? VaultName.validate(creationName)) == nil {
                    Text("Use letters, numbers, and hyphens for the vault name.").font(.caption).foregroundStyle(.secondary)
                }
                Text("2ndPass will create this device’s protected keys automatically.")
                Text("Export a portable backup and save its separate key. Other devices on your Apple Account connect automatically when an existing device is unlocked. Offline account recovery is not yet available for item vaults.").font(.caption)
                Divider()
                DisclosureGroup("More Options") {
                if model.canPresent(.enrollDevice) { Button("Connect to an existing vault…") { dismissOrConfirm(next: .enrollDevice) } }
                if model.canPresent(.setupRecovery) { Button("Set up an offline recovery key…") { dismissOrConfirm(next: .setupRecovery) } }
                if model.canPresent(.recover) { Button("Recover an existing vault…") { dismissOrConfirm(next: .recover) } }
                Button("Restore Portable Backup…") { dismissOrConfirm(next: .restoreBackup) }
                }
            case .enrollDevice, .addDevice:
                ItemEnrollmentView(model: model, approving: kind == .addDevice, target: request.target)
            case .shareAccount:
                Text("Sharing is not yet available for item vaults.")
            case .setupRecovery:
                OfflineRecoveryView(model: model, recovering: false)
            case .recover:
                OfflineRecoveryView(model: model, recovering: true)
            case .renameVault:
                Text("Rename vault").font(.title2)
                Text("Update scripts and references after renaming. The old name is not retained.")
                TextField("Name", text: $name)
                if (try? VaultName.validate(name)) == nil { Text("Use lowercase letters, numbers, and hyphens.").font(.caption).foregroundStyle(.secondary) }
            case .deleteVault:
                Text("Delete cloud vault").font(.title2)
                Text("Permanently delete cloud contents, history, and unsynced changes. Updated devices erase cached copies when they reconnect. Backups and older or offline clients may retain copies.")
                Text(request.target?.name ?? "Unnamed vault").font(.headline)
                Button("Export Backup First…") { model.chooseExportBackup(target: request.target) }.disabled(model.busy)
                Text(request.target?.id ?? "").font(.caption).textSelection(.enabled)
                TextField("Type the vault name to confirm", text: $confirmation)

            }
            if let error = model.error.map({ _ in model.errorMessage }) ?? controls.error ?? localError {
                Text(error).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                if model.developerDiagnosticsEnabled, model.error != nil {
                    Button("Copy Details") { model.copyErrorDetails() }
                }
            }
            if let notice = model.notice { Text(notice).font(.callout).textSelection(.enabled) }
            if model.busy { ProgressView("Waiting for authentication or iCloud…") }
        }.padding(24).disabled(model.busy) }
            Divider()
            HStack {
                if let title = controls.secondaryTitle {
                    Button(title) { controls.secondarySubmit?() }.disabled(model.busy)
                }
                Spacer()
                Button(submitted || [.enrollDevice, .addDevice, .setupRecovery, .recover, .shareAccount].contains(kind) ? "Close" : "Cancel") { dismissOrConfirm() }
                    .keyboardShortcut(.cancelAction)
                if kind == .createVault {
                    Button("Create Vault") { submitted = true; model.createVault(name: creationName) }
                        .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
                        .disabled(model.busy || (try? VaultName.validate(creationName)) == nil)
                } else if kind == .renameVault {
                    Button("Rename") { submitted = true; model.renameVault(to: name, target: request.target) }
                        .keyboardShortcut(.defaultAction).disabled(model.busy || (try? VaultName.validate(name)) == nil)
                } else if kind == .deleteVault {
                    Button("Delete Vault", role: .destructive) {
                        if let target = request.target { submitted = true; model.deleteVault(target: target, confirmation: confirmation) }
                    }.disabled(model.busy || request.target == nil || confirmation != (request.target?.name ?? request.target?.id))
                } else if let title = controls.title {
                    Button(title) { submitted = true; controls.submit?() }
                        .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent).disabled(model.busy || !controls.canSubmit)

                }
            }.padding()
        }.mopSheetWidth(640)
        .interactiveDismissDisabled(dirty && !submitted)
        .documentTransfers(model: model, inSheet: true)
        .onAppear {
            if kind == .renameVault { name = request.target?.name ?? "" }
            initialName = name
        }
        .onChange(of: controls.revision) { _, _ in if !model.busy { submitted = false } }
        .onChange(of: name) { _, _ in submitted = false }
        .onChange(of: confirmation) { _, _ in submitted = false }
        .onChange(of: controls.error) { _, error in if error != nil { submitted = false } }
        .onChange(of: model.busy) { _, busy in if !busy && (model.error != nil || controls.error != nil) { submitted = false } }
        .confirmationDialog("Discard setup changes?", isPresented: $confirmDiscard, titleVisibility: .visible) {
            Button("Discard Changes", role: .destructive) { finishDismissal() }
            Button("Keep Editing", role: .cancel) { nextSheet = nil }
        }
    }
    private var dirty: Bool { name != initialName || !confirmation.isEmpty || controls.dirty }
    private func dismissOrConfirm(next: AppSheet? = nil) {
        if kind == .createVault { model.importAfterCreation = false }
        nextSheet = next
        if dirty && !submitted { confirmDiscard = true } else { finishDismissal() }
    }
    private func finishDismissal() {
        if let nextSheet { model.presentSheet(nextSheet, target: request.target, inSettings: request.inSettings) }
        else if model.sheetRequest?.id == request.id { model.sheet = nil }
    }

    private var creationName: String { name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
    private var connectTitle: String {
        #if os(macOS)
        "Connect This Mac"
        #else
        "Connect This Device"
        #endif
    }

}
