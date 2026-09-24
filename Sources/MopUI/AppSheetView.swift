import SwiftUI
import MopCore
import MopAppSupport
import UniformTypeIdentifiers

struct AppSheetView: View {
    @Bindable var model: AppModel
    let kind: AppSheet
    @State private var vaultName = "personal"
    @State private var name = DeviceLabel.name
    @State private var fingerprint = ""
    @State private var strict = false
    @State private var confirmed = false
    @State private var recoveryURL: URL?
    @State private var choosingRecoveryFolder = false
    @State private var importingRecovery = false
    @State private var pending: PendingVaultCreation?
    @State private var localError: String?
    @State private var discardingSetup = false
    @State private var fileRequestGeneration = 0
    @State private var deletionTarget: VaultDescriptor?
    @State private var deletionConfirmation = ""

    private var validFingerprint: Bool {
        fingerprint.count == 64 && fingerprint.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    private var title: String {
        switch kind {
        case .vaultSettings: "Vault Settings"
        case .renameVault: "Rename vault"
        case .deleteVault: "Delete vault"
        case .createVault: "Create a vault"
        case .trust: "Verify vault trust"
        case .recover: "Recover vault access"
        }
    }
    private var canSubmit: Bool {
        switch kind {
        case .vaultSettings: true
        case .createVault: (try? VaultName.validate(vaultName)) != nil && !name.isEmpty && pending?.exported == true && confirmed
        case .renameVault: (try? VaultName.validate(vaultName)) != nil
        case .deleteVault: deletionTarget != nil && !model.offline && deletionConfirmation == (deletionTarget?.name ?? deletionTarget?.id)
        case .trust: validFingerprint
        case .recover: validFingerprint && recoveryURL != nil && !name.isEmpty
        }
    }
    var body: some View {
        ScrollView { VStack(alignment: .leading, spacing: 20) {
            Text(title).font(.title2).fontWeight(.semibold)
            switch kind {
            case .vaultSettings:
                vaultSettings
            case .createVault:
                Text("Create a named encrypted vault in your private iCloud account. Vault names are visible to CloudKit; item and field names remain encrypted.")
                TextField("Vault name", text: $vaultName).disabled(pending != nil)
                Text("Your Mop identity synchronizes through iCloud Keychain. Mop authenticates locally before opening it.").font(.caption).foregroundStyle(.secondary)
                Button(pending?.exported == true ? "Export another recovery key copy…" : "Export recovery key…") {
                    do {
                        pending = try PendingVaultCreation.prepare(name: vaultName, deviceName: name, strict: strict, state: AppStorageLocation.defaultState)
                        fileRequestGeneration = model.editorGeneration
                        choosingRecoveryFolder = true
                    } catch { localError = safeMessage(error) }
                }.disabled((try? VaultName.validate(vaultName)) == nil || name.isEmpty)
                if let pending {
                    Text("Vault UUID: " + pending.id.uuidString).font(.caption).textSelection(.enabled)
                    Text(pending.exported ? "Recovery credential exported. Continue to create or reconcile this vault." : "Choose a folder outside Mop to save the recovery credential.").font(.caption)
                    if !pending.submitted {
                        Button("Discard unfinished setup…", role: .destructive) { discardingSetup = true }
                    }
                }
                Toggle("I will move the recovery key offline and retain the vault fingerprint separately.", isOn: $confirmed)
                Text("The recovery key grants full access. Keep it out of iCloud and away from encrypted backups. If creation fails after writing the key, the file is retained.").font(.caption).foregroundStyle(.secondary)
            case .deleteVault:
                if let target = deletionTarget {
                    Text(target.name ?? "Legacy or unnamed vault").font(.headline)
                    Text(target.id).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    Text("Permanently delete all cloud contents and history, and this device’s cached vault data. Backups and caches on other devices remain. This cannot be undone without a backup.")
                    if model.canExportBackup {
                        Button("Export backup…") { model.chooseExportBackup() }
                        Text("The backup is encrypted. Keep its recovery key separately.").font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text("To export a legacy vault, use an older Mop client before deleting it.").font(.caption).foregroundStyle(.secondary)
                    }
                    TextField("Type \(target.name ?? target.id) to delete", text: $deletionConfirmation)
                }
            case .renameVault:
                Text("Renaming changes references. Update scripts and configuration; the old name will no longer work.")
                TextField("New vault name", text: $vaultName)
            case .recover:
                Text("Restore vault access using an offline recovery key and a vault fingerprint obtained independently. Return the key offline afterward.")
                TextField("Vault fingerprint", text: $fingerprint)
                Button("Choose recovery key…") { fileRequestGeneration = model.editorGeneration; importingRecovery = true }
                if let recoveryURL { Text(recoveryURL.lastPathComponent).font(.caption) }
            case .trust:
                Text("Enter the full vault fingerprint obtained independently from a trusted device. Do not use a fingerprint supplied only by the cloud service.")
                TextField("Vault fingerprint", text: $fingerprint)
                    .font(.system(.body, design: .monospaced))
            }
            if kind == .deleteVault || kind == .vaultSettings, let notice = model.notice { Text(notice).font(.callout).textSelection(.enabled) }
            if model.busy { HStack { ProgressView().controlSize(.small); Text("Waiting for authentication or iCloud…").font(.caption) } }
            HStack {
                Spacer()
                Button(kind == .vaultSettings ? "Done" : "Cancel", role: .cancel) { model.sheet = nil }.keyboardShortcut(.cancelAction).disabled(model.busy)
                if kind != .vaultSettings {
                Button(kind == .deleteVault ? "Delete vault" : "Continue", role: kind == .deleteVault ? .destructive : nil) { submit() }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(model.busy || !canSubmit)
                }
            }
        }.padding(28) }.mopSheetWidth(540).disabled(model.busy)
        .interactiveDismissDisabled(model.busy)
        .confirmationDialog("Discard this unpublished vault setup?", isPresented: $discardingSetup, titleVisibility: .visible) {
            Button("Discard setup", role: .destructive) {
                do {
                    try PendingVaultCreation.discardUnsubmitted(state: AppStorageLocation.defaultState)
                    pending = nil; confirmed = false
                } catch { localError = safeMessage(error) }
            }
        } message: { Text("No vault has been submitted. Any recovery copies you exported are no longer needed for this setup.") }
        .documentTransfers(model: model, inSheet: true)
        .fileImporter(isPresented: $choosingRecoveryFolder, allowedContentTypes: [.folder]) { result in
            guard fileRequestGeneration == model.editorGeneration, model.sheet == kind else { return }
            do {
                let folder = try result.get()
                guard var intent = pending else { return }
                let url = folder.appendingPathComponent("mop-recovery-" + intent.id.uuidString + "-" + UUID().uuidString + ".key")
                try model.documents.write(to: url) { destination in
                    try intent.export(to: destination, state: AppStorageLocation.defaultState)
                }
                pending = intent
            } catch { localError = safeMessage(error) }
        }
        .fileImporter(isPresented: $importingRecovery, allowedContentTypes: [.data, .plainText]) { result in
            guard fileRequestGeneration == model.editorGeneration, model.sheet == kind else { return }
            do {
                if let recoveryURL { try? FileManager.default.removeItem(at: recoveryURL) }
                recoveryURL = try model.documents.importRecovery(result.get(), state: AppStorageLocation.defaultState)
            } catch { localError = safeMessage(error) }
        }
        .onDisappear { if let recoveryURL { try? FileManager.default.removeItem(at: recoveryURL) } }
        .onAppear {
            if kind == .createVault {
                do {
                    pending = try PendingVaultCreation.load(state: AppStorageLocation.defaultState)
                    if let pending { vaultName = pending.name; name = pending.deviceName; strict = pending.strict }
                } catch { localError = safeMessage(error) }
            }
            if kind == .renameVault { vaultName = model.vaultName }
            if kind == .deleteVault, !model.vault.isEmpty {
                deletionTarget = model.selectedVaultDescriptor ?? VaultDescriptor(id: model.vault, name: nil, format: "unknown", enrolled: false)
            }
        }
        .onChange(of: model.editorGeneration) { _, _ in fingerprint = "" }
        .alert("Operation not completed", isPresented: Binding(get: { model.error != nil || localError != nil }, set: { if !$0 { model.error = nil; localError = nil } })) {
            Button("OK") { model.error = nil; localError = nil }
        } message: { Text(localError ?? model.error ?? "") }
    }
    private func safeMessage(_ error: Error) -> String {
        (error as? MopError)?.errorDescription ?? "The document operation failed. Choose a writable folder supporting exclusive file creation, or try a different file."
    }
    private func submit() {
        switch kind {
        case .createVault:
            if let pending { model.createPreparedVault(pending) }
        case .deleteVault:
            if let deletionTarget { model.deleteVault(target: deletionTarget, confirmation: deletionConfirmation) }
        case .renameVault:
            model.renameVault(to: vaultName)
        case .trust:
            model.management(.trust(fingerprint: fingerprint))
        case .recover:
            if let recoveryURL { model.management(.recover(file: recoveryURL, name: name, fingerprint: fingerprint)) }
        case .vaultSettings: break
        }
    }

    private var vaultSettings: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text(model.vaultName).font(.headline)
            Button("Rename vault…") { model.sheet = .renameVault }.disabled(model.offline)
            Divider()
            Text("Account access").font(.headline)
            Text("Connected vaults are available on devices using your Apple Account and iCloud Keychain.")
                .foregroundStyle(.secondary)
            Button("Verify account membership") { model.loadDevices() }.disabled(model.offline)
            if !model.members.isEmpty {
                Label("Your Apple Account · Owner", systemImage: "person.crop.circle.badge.checkmark")
            }
            Divider()
            Text("Recovery and backups").font(.headline)
            Button("Export encrypted backup…") { model.chooseExportBackup() }.disabled(!model.canExportBackup)
            Button("Recover access…") { model.sheet = .recover }.disabled(model.offline)
            DisclosureGroup("Advanced security") {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Vault ID: " + model.vault).font(.caption).textSelection(.enabled)
                    Button("Show vault fingerprint") { model.management(.fingerprint, keepSheet: true) }.disabled(model.offline)
                    Button("Verify vault fingerprint…") { model.sheet = .trust }.disabled(model.offline)
                }.padding(.top, 8)
            }
            Divider()
            Button("Delete vault…", role: .destructive) { model.sheet = .deleteVault }.disabled(model.offline)
        }
    }
}
