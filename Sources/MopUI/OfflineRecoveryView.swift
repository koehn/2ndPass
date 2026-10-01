import SwiftUI
import UniformTypeIdentifiers
import MopCore
import MopAppSupport
#if os(macOS)
import AppKit
#else
import UIKit
#endif

private struct RecoveryDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.plainText, .json, .data] }
    let bytes: SecretBytes
    init(_ bytes: SecretBytes) { self.bytes = bytes }
    init(configuration: ReadConfiguration) throws { bytes = SecretBytes(copying: configuration.file.regularFileContents ?? Data()) }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: Data(bytes)) }
}

/// Secret text exists only for the visible ceremony and is discarded on lock,
/// disappearance, or backgrounding. No drafts, restoration, or clipboard writes.
struct OfflineRecoveryView: View {
    @Bindable var model: AppModel
    let recovering: Bool
    @Environment(\.scenePhase) private var scenePhase
    @State private var code = ""
    @State private var input = ""
    @State private var fingerprint = ""
    @State private var file: SecretBytes?
    @State private var imported: SecretBytes?
    @State private var exporting = false
    @State private var importing = false
    @State private var recoveryAllowed = false
    private enum ProgressLocation: Equatable {
        case generate, activate, coverage, resume, reset, revoke, eligibility, open
        case catalog(UUID), complete(UUID), read(UUID, String)
    }
    @State private var progressLocation: ProgressLocation?
    @State private var working = false
    @State private var progressMessage = ""
    @State private var progressFraction: Double?
    @State private var message = ""
    @State private var rows: [VaultDescriptor] = []
    @State private var statuses: [String] = []
    @State private var fields: [(UUID, String)] = []
    @State private var revealed = ""
    @State private var attachment: SecretBytes?
    @State private var attachmentName = "recovered-file"
    @State private var exportingAttachment = false
    @State private var completedVault = false
    @State private var recoveredVaultIDs: Set<UUID> = []
    @State private var recoveryConfirmations: [UUID: String] = [:]
    @State private var revoke = false
    @State private var resetForTesting = false
    @State private var task: Task<Void, Never>?
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(recovering ? "Recover Vault Access" : "Recovery Setup and Verification").font(.title2)
            Text("Sign into the same Apple Account first. This key restores access to your live iCloud vaults; it cannot restore Apple Account access or missing cloud data.")
            if recovering {
                if recoveryAllowed {
                    GroupBox("1. Open your vaults") {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Import the file you saved or enter your written code. This opens read-only access so you can check your data before enabling normal use on this device.").foregroundStyle(.secondary)
                            copyInput
                            actionButton("Open Read-Only Access", operation: .recoveryOpen(copy: copy), location: .open)
                                .buttonStyle(.borderedProminent).disabled(input.isEmpty && imported == nil)
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                    }
                } else {
                    actionButton("Check Access Again", operation: .recoveryEligibility, location: .eligibility)
                        .disabled(model.removalCleanupPending)
                        .help("Check whether this device can open your iCloud vaults using its existing device key.")
                }
                ForEach(rows) { row in
                    if let id = UUID(uuidString: row.id) {
                        GroupBox(row.name ?? "Unnamed vault") {
                            VStack(alignment: .leading, spacing: 10) {
                                if let confirmation = recoveryConfirmations[id] {
                                    Label(confirmation, systemImage: "checkmark.circle.fill")
                                        .fixedSize(horizontal: false, vertical: true)
                                } else if recoveredVaultIDs.contains(id) {
                                    Label("This device already has access", systemImage: "checkmark.circle.fill")
                                    Text("You can use this vault normally. Recovery is not needed.").foregroundStyle(.secondary)
                                } else {
                                    Text("Browse to confirm your data. Complete recovery to enable normal use on this device while keeping existing devices and accounts connected.").foregroundStyle(.secondary)
                                    HStack {
                                        actionButton("Browse Data", operation: .recoveryCatalog(id), location: .catalog(id), vaultID: id)
                                        actionButton("Complete Recovery", operation: .recoveryComplete(id), location: .complete(id))
                                    }
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                        }
                    }
                }
                if recoveryAllowed {
                    ForEach(Array(fields.enumerated()), id: \.offset) { _, field in
                        actionButton(field.1, operation: .recoveryRead(field.0, field.1), location: .read(field.0, field.1))
                    }
                    if attachment != nil { Button("Save " + attachmentName + "…") { exportingAttachment = true } }
                    if !revealed.isEmpty {
                        Text(revealed).textSelection(.enabled).privacySensitive()
                        Button("Conceal") { revealed = "" }
                    }
                }
            } else {
                GroupBox("1. Create and save an offline copy") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Prepare for losing your devices. Generate a recovery key, then keep a file or paper copy somewhere safe and separate from your devices and iCloud.").foregroundStyle(.secondary)
                        actionButton("Generate a New Recovery Copy", operation: .recoveryGenerate, location: .generate)
                        Text("Generating a copy does not change your current recovery key. If replacing a key, keep both copies until every vault finishes updating.").font(.caption).foregroundStyle(.secondary)
                        if !code.isEmpty {
                            Text(code).font(.system(.body, design: .monospaced)).textSelection(.enabled).privacySensitive()
                            HStack {
                                Button("Save Recovery File…") { exporting = true }.help("Save a copy to offline storage for later recovery.")
                                Button("Print Recovery Copy…") { printCopy() }.help("Print the code to keep a paper recovery copy.")
                            }
                            DisclosureGroup("Public Key Fingerprint") { Text(fingerprint).font(.caption).textSelection(.enabled) }
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
                if !code.isEmpty {
                    GroupBox("2. Verify your saved copy and activate") {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Import the file you just saved or re-enter the code from your paper copy. Verification confirms you can use that copy before enabling it for your vaults.").foregroundStyle(.secondary)
                            copyInput
                            actionButton("Verify Copy and Activate", operation: .recoveryActivate(copy: copy, fingerprint: fingerprint), location: .activate)
                                .buttonStyle(.borderedProminent).disabled(input.isEmpty && imported == nil)
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                    }
                }
                GroupBox("Check existing protection") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Check coverage to see which vaults are protected by your configured recovery key. This does not change your key or test your saved copy.").foregroundStyle(.secondary)
                        actionButton("Check Coverage", operation: .recoveryStatus, location: .coverage)
                        Text("If setup, replacement, or removal was interrupted, resume to finish applying the changes to your remaining vaults.").foregroundStyle(.secondary)
                        actionButton("Resume Incomplete Changes", operation: .recoveryResume, location: .resume)
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
                DisclosureGroup("Test recovery on this device") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Simulate losing this device without deleting your iCloud vaults. Import your saved offline copy or enter its code. We verify that it can recover every owned vault before clearing this device’s iCloud vault keys and cached iCloud data. Local-only vaults are not changed.").foregroundStyle(.secondary)
                        Text("Quit or lock 2ndPass on your other devices first. You will need your offline copy again after the reset. This cannot be undone.").font(.callout)
                        copyInput
                        if working && progressLocation == .reset { operationProgress }
                        else {
                            Button("Reset This Device for Recovery Testing…", role: .destructive) { resetForTesting = true }
                                .disabled(input.isEmpty && imported == nil)
                        }
                    }.padding(.top, 8)
                }
                DisclosureGroup("Remove offline recovery") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Revoke a lost or unwanted recovery key. Your connected devices keep access, but this key will no longer recover updated vault data once removal finishes. Previously copied data remains accessible with the old key.").foregroundStyle(.secondary)
                        if working && progressLocation == .revoke { operationProgress }
                        else { Button("Revoke Offline Key…", role: .destructive) { revoke = true } }
                    }.padding(.top, 8)
                }
            }
            Text(message).fixedSize(horizontal: false, vertical: true)
            ForEach(Array(statuses.enumerated()), id: \.offset) { _, status in Text(status).font(.caption).textSelection(.enabled) }
        }
        .onAppear {
            if recovering {
                if model.removalCleanupPending { message = "Local cleanup is incomplete. Restart 2ndPass while online before continuing recovery." }
                else { run(.recoveryEligibility) }
            }
        }
        .task(id: working) {
            guard working else { return }
            while !Task.isCancelled {
                if let update = model.service.operationProgress {
                    progressMessage = update
                    progressFraction = model.service.operationFraction
                }
                do { try await Task.sleep(for: .milliseconds(150)) } catch { return }
            }
        }
        .disabled(working || model.offline)
        .confirmationDialog("Reset this device for recovery testing?", isPresented: $resetForTesting, titleVisibility: .visible) {
            Button("Verify Copy and Reset This Device", role: .destructive) { run(.recoveryTestReset(copy: copy)) }
        } message: {
            Text("After verification, this device’s iCloud vault keys and cached iCloud data will be deleted. Local-only vaults and your vaults in iCloud stay intact. Keep your offline copy outside the app: you must enter it again to recover access. Other enrolled devices and accounts keep access when you complete recovery.")
        }
        .confirmationDialog("Revoke the offline recovery key?", isPresented: $revoke, titleVisibility: .visible) {
            Button("Revoke and rotate encryption", role: .destructive) { run(.recoveryRevoke) }
        }
        .fileExporter(isPresented: $exporting, document: file.map(RecoveryDocument.init), contentType: .plainText, defaultFilename: "2ndpass-offline-recovery-" + String(fingerprint.prefix(12))) { result in
            if case .failure = result { message = "Recovery copy was not saved. Try again before activating." }
        }
        .fileExporter(isPresented: $exportingAttachment, document: attachment.map(RecoveryDocument.init), contentType: .data, defaultFilename: attachmentName) { result in
            if case .failure = result { message = "The recovered file was not saved." }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.plainText, .json, .data]) { result in
            do {
                let url = try result.get(), access = url.startAccessingSecurityScopedResource()
                defer { if access { url.stopAccessingSecurityScopedResource() } }
                var data = try LocalFile.read(url, limit: 8192)
                defer { SecretBytes.wipe(&data) }
                imported = SecretBytes(copying: data); input = ""
            } catch { message = "Could not read the recovery copy." }
        }
        .onChange(of: input) { _, value in if !value.isEmpty { imported = nil } }
        .onChange(of: model.securityGeneration) { _, _ in clear() }
        .onChange(of: scenePhase) { _, phase in if phase == .background { clear(); model.service.lock() } }
        .onDisappear { clear(); model.service.endRecoverySession(); if completedVault { model.refresh() } }
    }
    private var operationProgress: some View {
        VStack(alignment: .leading, spacing: 6) {
            ProgressView(value: progressFraction)
                .progressViewStyle(.linear)
                .accessibilityLabel(progressMessage)
            Text(progressMessage).font(.callout).fixedSize(horizontal: false, vertical: true)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
    @ViewBuilder private func actionButton(_ title: String, operation: VaultManagement,
                                          location: ProgressLocation, vaultID: UUID? = nil) -> some View {
        if working && progressLocation == location { operationProgress }
        else { Button(title) { run(operation, vaultID: vaultID) } }
    }
    private var copyInput: some View {
        VStack(alignment: .leading, spacing: 8) {
            SecureField("Recovery code", text: $input).privacySensitive()
            Button("Import Recovery File…") { importing = true }
            if imported != nil { Label("Recovery copy loaded", systemImage: "checkmark.circle").font(.caption) }
        }
    }
    private func printCopy() {
        let text = "2ndPass offline recovery copy\n\n" + code + "\n\nPublic fingerprint: " + fingerprint + "\n\nKeep this copy offline and separate from your devices. Sign into the same Apple Account before recovering. This does not recover Apple Account access."
        #if os(macOS)
        let view = NSTextView(frame: NSRect(x: 0, y: 0, width: 480, height: 600))
        view.string = text; view.font = .monospacedSystemFont(ofSize: 14, weight: .regular)
        NSPrintOperation(view: view).run()
        view.string = ""
        #else
        let controller = UIPrintInteractionController.shared
        controller.printFormatter = UISimpleTextPrintFormatter(text: text)
        controller.present(animated: true) { controller, _, _ in controller.printFormatter = nil }
        #endif
    }
    private var copy: SecretBytes { imported ?? SecretBytes(utf8: input) }
    private func clear() {
        task?.cancel(); task = nil; code = ""; input = ""; fingerprint = ""; file = nil; imported = nil
        revealed = ""; attachment = nil; fields = []; rows = []; working = false
        recoveredVaultIDs = []; recoveryConfirmations = [:]
    }
    private func run(_ operation: VaultManagement, vaultID: UUID? = nil) {
        guard !working else { return }
        if case .recoveryComplete(let id) = operation, recoveredVaultIDs.contains(id) { return }
        progressFraction = nil
        switch operation {
        case .recoveryGenerate: progressLocation = .generate
        case .recoveryActivate: progressLocation = .activate
        case .recoveryStatus: progressLocation = .coverage
        case .recoveryResume: progressLocation = .resume
        case .recoveryTestReset: progressLocation = .reset
        case .recoveryRevoke: progressLocation = .revoke
        case .recoveryEligibility: progressLocation = .eligibility
        case .recoveryOpen: progressLocation = .open
        case .recoveryCatalog(let id): progressLocation = .catalog(id)
        case .recoveryComplete(let id): progressLocation = .complete(id)
        case .recoveryRead(let id, let path): progressLocation = .read(id, path)
        default: progressLocation = nil
        }
        switch operation {
        case .recoveryTestReset: progressMessage = "Verifying your offline copy before resetting this device…"
        case .recoveryEligibility: progressMessage = "Checking this device’s vault access…"
        case .recoveryActivate: progressMessage = "Verifying your recovery copy…"
        case .recoveryStatus: progressMessage = "Checking recovery coverage with iCloud…"
        default: progressMessage = "Working with iCloud…"
        }
        working = true; message = ""; statuses = []; revealed = ""; attachment = nil
        let generation = model.securityGeneration
        task = Task { @MainActor in
            defer { working = false }
            do {
                let result = try await model.service.execute(.manage(operation), vault: nil, offline: false)
                guard !Task.isCancelled, generation == model.securityGeneration else { return }
                if let value = result.recoveryCode { code = String(decoding: value, as: UTF8.self) }
                if let value = result.recoveryFile { file = value }
                if let value = result.recoveryFingerprint { fingerprint = value }
                if !result.vaults.isEmpty {
                    for row in result.vaults {
                        if let index = rows.firstIndex(where: { $0.id == row.id }) { rows[index] = row }
                        else { rows.append(row) }
                    }
                }
                if let catalog = result.catalog, let vaultID {
                    fields = catalog.items.flatMap { item in item.fields.map { (vaultID, SecretReference.encode(item.name) + "/" + $0.path) } }
                }
                if let value = result.recoveredAttachment { attachment = SecretBytes(copying: value.data); attachmentName = value.fileName }
                if let value = result.value { revealed = String(decoding: value, as: UTF8.self) }
                let coverage = result.recoveryVaults.isEmpty ? (result.recoveryConfiguration?.vaults ?? []) : result.recoveryVaults
                statuses = coverage.map { status in
                    let name = rows.first(where: { $0.id == status.id.uuidString })?.name
                        ?? model.vaults.first(where: { $0.id == status.id.uuidString })?.name
                        ?? "Unnamed vault"
                    let summary = status.complete
                        ? (status.fingerprint == nil ? "Offline recovery disabled" : "Complete")
                        : "Incomplete"
                    let key = !status.complete ? status.fingerprint.map { " · Recovery key: " + $0 } ?? "" : ""
                    return name + " · " + summary + (status.issue.map { " · " + $0 } ?? "") + key
                }
                message = result.message
                switch operation {
                case .recoveryEligibility:
                    rows = result.vaults
                    recoveredVaultIDs = Set(result.vaults.filter(\.enrolled).compactMap { UUID(uuidString: $0.id) })
                    recoveryAllowed = result.recoveryNeeded
                case .recoveryComplete:
                    recoveredVaultIDs.formUnion(result.recoveryVaults.filter(\.complete).map(\.id))
                    if result.recoveryVaults.contains(where: \.complete) {
                        completedVault = true
                        for status in result.recoveryVaults where status.complete {
                            recoveryConfirmations[status.id] = "Vault recovered on this device. You can use it normally. Existing devices and accounts keep access, and your offline recovery key remains enabled."
                            fields.removeAll { $0.0 == status.id }
                        }
                        message = ""; statuses = []
                        model.deviceRemoved = false; model.removalCleanupPending = false
                    }
                case .recoveryOpen: input = ""; imported = nil
                case .recoveryActivate: code = ""; input = ""; file = nil; imported = nil
                default: break
                }
            } catch {
                if case .recoveryTestReset = operation,
                   error as? MopError == .deviceRemoved || error as? MopError == .deviceRemovalPending {
                    model.showRecoveryTestReset(pending: error as? MopError == .deviceRemovalPending)
                    return
                }
                guard !Task.isCancelled, generation == model.securityGeneration else { return }
                message = (error as? MopError)?.errorDescription ?? "Recovery could not finish. Retry when iCloud and the required data are available."
            }
        }
    }
}
