import SwiftUI
import UniformTypeIdentifiers
import MopCore
import MopAppSupport
import MopLocalIdentity

struct KeyCredentialCreateView: View {
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var destination = ""
    @State private var name = ""
    @State private var algorithm: CredentialAlgorithm = .ed25519
    @State private var purpose: CredentialPurpose = .ssh
    @State private var importing = false
    @State private var chooseFile = false
    @State private var bytes: SecretBytes?
    @State private var fileName = ""
    @State private var passphrase = ""
    @State private var acknowledged = false
    @State private var working = false
    @State private var error: String?
    @State private var members: [VaultMemberRecord] = []
    @State private var operation: Task<Void, Never>?
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(importing ? "Import SSH Key" : "New SSH Key").font(.title2)
            Form {
                Picker("Private key", selection: $importing) {
                    Text("Generate").tag(false)
                    Text("Import").tag(true)
                }.pickerStyle(.segmented)
                    .accessibilityIdentifier("key-source")
                    .onChange(of: importing) { _, _ in destination = ""; bytes = nil; fileName = ""; passphrase = "" }
                TextField("Name", text: $name).accessibilityIdentifier("key-name")
                Picker("Use for", selection: $purpose) {
                    Text("SSH authentication").tag(CredentialPurpose.ssh)
                    Text("Git signing").tag(CredentialPurpose.gitSigning)
                }
                Picker("Save in", selection: $destination) {
                    Text("Choose storage…").tag("")
                    ForEach(model.itemCreationVaults) { Text(model.vaultLabel($0)).tag($0.id) }
                    if !importing && LocalIdentityStore.isAvailable { Text("This Device — Secure Enclave").tag(LocalVault.id) }
                }
                .accessibilityIdentifier("key-storage")
                if LocalVault.isLocal(destination) {
                    Text("P-256 · Secure Enclave · This device only")
                    Text(LocalIdentityWarning.loss).font(.callout)
                    Toggle("I understand this key cannot be recovered on another device", isOn: $acknowledged)
                } else if !destination.isEmpty {
                    Text("Encrypted and synchronized through this vault. Private keys are available to authorized software during use. Recovery requires another enrolled device or applicable configured offline recovery.").font(.callout)
                    if !members.isEmpty {
                        LabeledContent("Who has access", value: members.map { $0.id + " (" + $0.role + ")" }.joined(separator: ", "))
                    }
                    if !importing {
                        Picker("Algorithm", selection: $algorithm) {
                            Text("Ed25519").tag(CredentialAlgorithm.ed25519)
                            Text("P-256").tag(CredentialAlgorithm.p256)
                        }
                    }
                }
                if importing {
                    Button(fileName.isEmpty ? "Choose OpenSSH File…" : fileName) { chooseFile = true }
                    SecureField("File passphrase (if encrypted)", text: $passphrase)
                    Text("Ed25519, P-256, or RSA (2048–8192 bits). Encrypted files must use bcrypt and AES-256-CTR.").font(.caption)
                }
                Text("Create passkeys from a website’s registration flow and choose where to save them there.").font(.caption)
            }.disabled(working)
            if let error { Text(error).foregroundStyle(.red).textSelection(.enabled) }
            if working { ProgressView("Saving key…") }
            HStack {
                Button("Cancel") { operation?.cancel(); dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button(importing ? "Import Key" : "Create Key", action: save)
                    .accessibilityIdentifier("key-save")
                    .keyboardShortcut(.defaultAction)
                    .disabled(working || destination.isEmpty || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || (importing && bytes == nil) || (LocalVault.isLocal(destination) && !acknowledged))
            }
        }.padding(24).mopSheetWidth(540)
        .fileImporter(isPresented: $chooseFile, allowedContentTypes: [.data, .text]) { result in
            do {
                let url = try result.get(), accessed = url.startAccessingSecurityScopedResource()
                defer { if accessed { url.stopAccessingSecurityScopedResource() } }
                bytes = SecretBytes(copying: try LocalFile.read(url, limit: 1024 * 1024)); fileName = url.lastPathComponent
            } catch { self.error = error.localizedDescription }
        }
        .task(id: destination) {
            members = []
            guard !destination.isEmpty, !LocalVault.isLocal(destination) else { return }
            do { let result = try await model.service.execute(.members, vault: destination, offline: false); try Task.checkCancellation(); members = result.members }
            catch { self.error = error.localizedDescription }
        }
        .onDisappear { operation?.cancel(); bytes = nil; passphrase = "" }
    }
    private func save() {
        working = true; error = nil
        let token = model.securityGeneration
        operation = Task { @MainActor in
            defer { working = false }
            do {
                if LocalVault.isLocal(destination) {
                    guard !importing else { throw CredentialFailure.localImport }
                    let localPurpose: LocalIdentityProtocol = purpose == .ssh ? .ssh : .gitSigning
                    let auth = try await LocalAuthorization.authorizeAsync(reason: "create a device-local key", ids: [], purposes: [localPurpose], operations: [.create])
                    defer { auth.revoke() }
                    try Task.checkCancellation()
                    guard token == model.securityGeneration else { throw MopError.authentication }
                    _ = try LocalIdentityStore.open().create(name: name, protocolType: localPurpose, authorization: auth)
                    model.openLocalVault()
                } else {
                    guard !model.offline else { throw CredentialFailure.offlineCreation }
                    let service = CloudCredentialService(model.service)
                    if importing, let bytes { _ = try await service.importSSH(vault: destination, name: name, bytes: bytes, passphrase: passphrase.isEmpty ? nil : SecretBytes(utf8: passphrase), purposes: [purpose]) }
                    else { _ = try await service.createSSH(vault: destination, name: name, algorithm: algorithm, purposes: [purpose]) }
                }
                try Task.checkCancellation()
                guard token == model.securityGeneration else { throw MopError.authentication }
                model.refresh(); dismiss()
            } catch { self.error = error.localizedDescription }
        }
    }
}

struct CloudCredentialDetails: View {
    let model: AppModel
    let item: VaultItem
    var body: some View {
        if let record = try? CloudCredentialRecord(vault: model.vault, item: item) {
            CredentialDetailsView(credential: CredentialPresentation(record: record)) {
                model.clipboard.copy(SecretBytes(utf8: $0), concealed: false)
            }
        }
    }
}
