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
            case .importItems:
                PasswordImportView(model: model, controls: controls)
            case .createVault:
                Text(model.vaults.isEmpty ? "Create Your First Vault" : "Create a Vault").font(.title2)
                TextField("Vault name", text: $name)
                if (try? VaultName.validate(creationName)) == nil {
                    Text("Use letters, numbers, and hyphens for the vault name.").font(.caption).foregroundStyle(.secondary)
                }
                Text("2ndPass will create this device’s protected keys automatically. You can start saving passwords immediately and add other devices or hardware recovery later.")
                Text("Until you add another device or recovery, losing this device means losing access to your vault.").font(.caption)
                Divider()
                DisclosureGroup("More Options") {
                Button("Connect to an existing vault…") { dismissOrConfirm(next: .enrollDevice) }
                Button("Set up this device for recovery…") { dismissOrConfirm(next: .setupRecovery) }
                Button("Recover an existing vault…") { dismissOrConfirm(next: .recover) }
                }
            case .enrollDevice:
                if model.deviceRemoved {
                    Text("This device was removed").font(.title2)
                    Text(model.removalCleanupPending ? "Local cleanup could not finish. Reconnect will retry cleanup before adding this device again." : "Its local account access has been cleared. Reconnect only if you want to add this device again.")
                    Button("Reconnect") { model.reconnectDevice() }
                } else {
                Text(connectTitle).font(.title2)
                Text("2ndPass connects automatically through your Apple Account. Keep 2ndPass unlocked on another device until setup finishes.")
                CloudEnrollmentView(model: model, owner: false)
                DisclosureGroup("More Options") {
                DisclosureGroup("Join another person’s shared vault") { SharingView(model: model, setup: true, flow: .connect, target: request.target, controls: controls) }
                Button("Refresh vaults") { model.sheet = nil; model.refresh() }
                Button("Create a different vault…") { dismissOrConfirm(next: .createVault) }
                Button("No connected device? Recover…") { dismissOrConfirm(next: .recover) }
                }
                }
            case .addDevice:
                Text("Connect Another Device").font(.title2)
                Text("Open 2ndPass on your new device using the same Apple Account. Keep this device unlocked; 2ndPass will connect the new device automatically and notify you when it joins.")
                CloudEnrollmentView(model: model, owner: true)
            case .shareAccount:
                Text("Share with another person").font(.title2)
                Text("Ask the other person to open 2ndPass and choose Connect to an existing vault. Choose what they may do, exchange the invitation, then approve their response.")
                SharingView(model: model, setup: false, flow: .share, target: request.target, controls: controls)
            case .setupRecovery:
                Text("Optional hardware recovery").font(.title2)
                Text("On a separate device, create a recovery request. On your owner device, import that request to add recovery to existing secrets. Keep encrypted backups as well as the recovery device.")
                SharingView(model: model, setup: request.target == nil, flow: .recovery, target: request.target, controls: controls)
            case .recover:
                Text("Hardware recovery").font(.title2)
                SharingView(model: model, setup: false, recoveryMode: true, target: request.target, controls: controls)
            case .renameVault:
                Text("Rename vault").font(.title2)
                Text("Update scripts and references after renaming. The old name is not retained.")
                TextField("Name", text: $name)
                if (try? VaultName.validate(name)) == nil { Text("Use lowercase letters, numbers, and hyphens.").font(.caption).foregroundStyle(.secondary) }
            case .deleteVault:
                Text("Delete cloud vault").font(.title2)
                Text("Permanently delete cloud contents and history. Existing backups and local encrypted checkpoints remain.")
                Text(request.target?.name ?? "Unnamed vault").font(.headline)
                Button("Export Backup First…") { model.chooseExportBackup(target: request.target) }.disabled(model.busy)
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
                Button(submitted || [.enrollDevice, .addDevice].contains(kind) ? "Close" : "Cancel") { dismissOrConfirm() }
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
                } else if kind == .enrollDevice && !model.deviceRemoved && model.canStartEnrollment {
                    Button("Connect") { model.startEnrollment() }
                        .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
                        .disabled(model.busy || model.enrollmentWorking)
                }
            }.padding()
        }.mopSheetWidth(640)
        .interactiveDismissDisabled(dirty && !submitted)
        .documentTransfers(model: model, inSheet: true)
        .onAppear {
            if kind == .renameVault { name = request.target?.name ?? "" }
            initialName = name
            if kind == .enrollDevice { model.prepareEnrollmentSelection() }
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

private struct CloudEnrollmentView: View {
    @Bindable var model: AppModel
    let owner: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if owner {
                Text("Connections are checked automatically while 2ndPass is unlocked.")
                if !model.enrollmentSessionActive { Button("Unlock 2ndPass") { model.unlock() }.disabled(!model.canUnlock) }
                if model.enrollmentWorking { ProgressView("Checking connections…") }
                ForEach(model.vaults.filter { $0.enrolled }) { vault in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(model.vaultLabel(vault)).font(.headline)
                        if let progress = model.ownerEnrollmentProgress[vault.id] {
                            switch progress.phase {
                            case .connected:
                                Text("Connection check completed.")
                            case .waiting:
                                Text("Connection changed during the check. Retrying automatically…")
                            default:
                                Text(progress.phase.message).textSelection(.enabled)
                            }
                            if let date = progress.lastContact {
                                Text("Last checked \(date, style: .relative) ago").font(.caption)
                            } else if let date = progress.lastAttempt {
                                Text("Last attempted \(date, style: .relative) ago").font(.caption)
                            }
                        } else {
                            Text("Waiting for the first connection check.")
                        }
                    }
                }
            } else {
                ForEach(model.vaults.filter { !$0.enrolled || model.enrollmentSelection.contains($0.id) }) { vault in
                    VStack(alignment: .leading, spacing: 8) {
                        if model.enrollmentProgress[vault.id] == nil {
                            Toggle(model.vaultLabel(vault), isOn: Binding(get: { model.enrollmentSelection.contains(vault.id) }, set: {
                                if $0 { model.enrollmentSelection.insert(vault.id) } else { model.enrollmentSelection.remove(vault.id) }
                            }))
                        } else {
                            Text(model.vaultLabel(vault)).font(.headline)
                        }
                        if let progress = model.enrollmentProgress[vault.id] {
                            Text(progress.phase.message).accessibilityIdentifier("enrollment-status")
                            if progress.phase == .contacting { ProgressView() }
                            if let date = progress.lastContact { Text("Last checked \(date, style: .relative) ago").font(.caption) }
                            switch progress.phase {
                            case .failed, .offline, .paused:
                                Button(progress.phase == .paused ? "Unlock and Retry" : "Retry") { model.retryEnrollment(vault.id) }
                                    .disabled(model.busy || model.enrollmentWorking)
                            default: EmptyView()
                            }
                            if progress.phase != .connected {
                                DisclosureGroup("Troubleshooting") {
                                    Button("Restart Connection") { model.restartCloudEnrollment(vault.id) }
                                    Button("Cancel Request", role: .destructive) { model.cancelCloudEnrollment(vault.id) }
                                    Text("Restart replaces this request without deleting your vault or device keys.").font(.caption)
                                }.disabled(model.busy || model.enrollmentWorking)
                            }
                        }
                    }.padding(.vertical, 6)
                }
                Text("Closing this window keeps submitted requests active. 2ndPass checks while unlocked; iPhone and iPad resume checks when you return to 2ndPass. Use Cancel Request to stop a connection.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}
