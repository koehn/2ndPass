import SwiftUI
import UniformTypeIdentifiers
import MopCore
import MopAppSupport

/// Archive contents and keys are transient; the service owns authentication and
/// durable publication. This view never writes an unencrypted archive to disk.
struct PortableBackupView: View {
    @Bindable var model: AppModel
    let target: VaultDescriptor?
    @State private var picker = false
    @State private var action: Pick = .archive
    @State private var archive: Data?
    @State private var key: SecretBytes?
    @State private var sourceName = ""
    @State private var name = "restored"
    @State private var restoreID = UUID()
    @State private var archiveURL: URL?
    @State private var keySaved = false
    @State private var failure: String?
    @State private var verifiedCount: Int?
    @State private var pickerSecurityGeneration: Int?
    private enum Pick { case archive, key, exportFolder, keyFolder }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(target == nil ? "Restore Portable Backup" : "Export Portable Backup").font(.title2)
            if let target {
                Text("Export all transferable contents of \(target.name ?? "this vault"), including attachments and retained history. A new backup key unlocks this file independently of iCloud and this device.")
                Text("Device-local Secure Enclave keys cannot be exported. Keep your original vault until you have saved the separate key and tested restoration.").font(.callout)
                Button("Choose Backup Folder…") { choose(.exportFolder) }.disabled(key != nil && !keySaved)
                if let archiveURL {
                    Text("Archive verified: " + archiveURL.lastPathComponent)
                    if keySaved {
                        Label("Backup key saved separately", systemImage: "checkmark.circle")
                    } else {
                        Text("Save the backup key before closing or locking. Without it, this archive cannot be restored.").foregroundStyle(.orange)
                        Button("Save Backup Key Separately…") { choose(.keyFolder) }
                    }
                }
            } else {
                Text("Creates a new owner-only vault. Your existing vaults remain intact. Reconfigure sharing after restoration; the existing account recovery setting applies to the new vault.")
                Button("Choose Portable Archive…") { choose(.archive) }
                if !sourceName.isEmpty { Text(sourceName).font(.caption) }
                Button(key == nil ? "Choose Backup Key…" : "Choose Another Backup Key…") { choose(.key) }
                TextField("New vault name", text: $name)
                if let verifiedCount { Text("Archive authenticated: \(verifiedCount) items.") }
                Text("Restore ID: " + restoreID.uuidString).font(.caption).textSelection(.enabled)
                Button("Restore New Vault") { restore() }
                    .disabled(archive == nil || key == nil || (try? VaultName.validate(name)) == nil || model.offline)
                Text("Keep the restore ID to resume from the CLI if the app closes before completion.").font(.caption)
            }
            if let failure { Text(failure).foregroundStyle(.red) }
        }
        .fileImporter(isPresented: $picker, allowedContentTypes: folderAction ? [.folder] : [.data]) { result in
            guard pickerSecurityGeneration == model.securityGeneration else { return }
            pickerSecurityGeneration = nil
            do { try selected(result.get()) }
            catch { failure = (error as? LocalizedError)?.errorDescription ?? "The file could not be opened." }
        }
        .onChange(of: model.securityGeneration) { _, _ in clearSecrets() }
        .onDisappear { clearSecrets() }
    }

    private var folderAction: Bool { action == .exportFolder || action == .keyFolder }
    private func choose(_ next: Pick) {
        guard !model.busy else { return }
        action = next; failure = nil
        pickerSecurityGeneration = model.securityGeneration; picker = true
    }
    private func selected(_ url: URL) throws {
        switch action {
        case .archive:
            archive = try read(url, limit: PortableArchive.maximumSize)
            sourceName = url.lastPathComponent; verifiedCount = nil; restoreID = UUID()
            try verify()
        case .key:
            var bytes = try read(url, limit: 4096)
            defer { SecretBytes.wipe(&bytes) }
            key = SecretBytes(copying: bytes); verifiedCount = nil
            try verify()
        case .exportFolder:
            guard let target else { return }
            let destination = url.appendingPathComponent("2ndpass-\(UUID().uuidString).moparchive")
            model.perform { token in
                let result = try await model.service.execute(.exportPortable(destination), vault: target.id, offline: false)
                guard model.current(token) else { return }
                key = result.value; archiveURL = destination; keySaved = false
                model.notice = result.message
            }
        case .keyFolder:
            guard let key, let archiveURL else { return }
            let destination = url.appendingPathComponent(archiveURL.deletingPathExtension().lastPathComponent + ".key")
            try DocumentAccess.write(to: destination) {
                try OutputFile(url: $0, force: false, mode: 0o600, protectedFiles: [archiveURL], protectedDirectories: [AppStorageLocation.defaultState]).write(key)
            }
            keySaved = true
        }
    }
    private func verify() throws {
        guard let archive, let key else { return }
        verifiedCount = try PortableArchive.open(archive, recoveryKey: key).items.count
    }
    private func restore() {
        guard let archive, let key else { return }
        let destination = restoreID.uuidString
        model.perform { token in
            let result = try await model.service.execute(.restorePortable(document: archive, key: key, name: name), vault: destination, offline: false)
            guard model.current(token) else { return }
            try await model.completePortableRestore(result, id: destination, token: token)
        }
    }
    private func clearSecrets() {
        key = nil; archive = nil; verifiedCount = nil
        pickerSecurityGeneration = nil; picker = false
    }
    private func read(_ source: URL, limit: Int) throws -> Data {
        let access = source.startAccessingSecurityScopedResource()
        defer { if access { source.stopAccessingSecurityScopedResource() } }
        var result: Result<Data, Error>?
        var coordinatorError: NSError?
        NSFileCoordinator().coordinate(readingItemAt: source, options: [], error: &coordinatorError) { coordinatedURL in
            result = Result { try LocalFile.read(coordinatedURL, limit: limit) }
        }
        if let coordinatorError { throw coordinatorError }
        guard let result else { throw MopError.inputOutput }
        return try result.get()
    }
}
