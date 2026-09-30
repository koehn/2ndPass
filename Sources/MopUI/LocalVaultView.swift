import SwiftUI
import MopCore
import MopAppSupport

/// Self-contained UI for the fixed device-local vault. Driven entirely by
/// `LocalVaultService`; it never touches the cloud `VaultService`. Identities are
/// shown by their public key only — the private half is in the Secure Enclave.
struct LocalVaultView: View {
    @Bindable var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            GroupBox {
                VStack(alignment: .leading, spacing: 6) {
                    Label("Device-only vault", systemImage: "internaldrive")
                    Text("Keys are created in this device's Secure Enclave. They cannot be exported, shared, synced, or moved to another device, and there is no backup or recovery. Only the public key is shown here.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            .tint(.secondary)

            if !model.localCreatePresented {
                Button("New Identity…") { model.beginLocalCreate() }
                    .disabled(model.localCreating || model.localLoading || model.localDeleteInProgress)
            }

            if model.localDeleteInProgress {
                ProgressView("Deleting identity…")
            } else if model.localCreating {
                ProgressView("Creating identity…")
            } else if model.localLoading {
                ProgressView("Reading identities…")
            } else if let error = model.localError {
                Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
            } else if model.localIdentities.isEmpty && !model.localCreatePresented {
                ContentUnavailableView {
                    Label("No Identities", systemImage: "key")
                } description: {
                    Text("Create a non-exportable identity to use with SSH, git signing, or key agreement.")
                }
            } else {
                List {
                    ForEach(model.localIdentities) { identity in
                        LocalIdentityRow(model: model, identity: identity)
                    }
                }
            }

            if model.localCreatePresented {
                LocalCreateForm(model: model)
            }

            Spacer()
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .confirmationDialog("Delete this identity?", isPresented: Binding(get: { model.localDeleting != nil }, set: { if !$0 { model.localDeleting = nil } }), titleVisibility: .visible) {
            if let id = model.localDeleting, let identity = model.localIdentities.first(where: { $0.id == id }) {
                Button("Delete “" + identity.name + "”", role: .destructive) { model.confirmLocalDelete() }
            }
        } message: {
            Text("The private key is in the Secure Enclave. Once deleted it cannot be recovered.")
        }
    }
}

private struct LocalIdentityRow: View {
    @Bindable var model: AppModel
    let identity: LocalIdentity

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: "key.fill").foregroundStyle(Color.accentColor)
                Text(identity.name).fontWeight(.medium)
                Spacer()
                Text(identity.protocolType.rawValue).font(.caption).foregroundStyle(.secondary)
            }
            Text(LocalIdentityCatalog.publicKeyText(for: identity))
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(3).truncationMode(.middle)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 2)
        .contextMenu {
            Button("Copy Public Key") { copyPublicKey() }
            Button("Delete…", role: .destructive) { model.requestLocalDelete(identity.id) }
        }
    }

    private func copyPublicKey() {
        let key = LocalIdentityCatalog.publicKeyText(for: identity)
        #if os(macOS)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key, forType: .string)
        #else
        UIPasteboard.general.string = key
        #endif
    }
}

/// Shown in the detail column while the device-local vault is open but no item is
/// selected. The local vault is a self-contained list; this just explains that.
struct LocalVaultDetailHint: View {
    var body: some View {
        ContentUnavailableView {
            Label("Device-local vault", systemImage: "internaldrive")
        } description: {
            Text("Identities live in the list. Their public keys are shown inline; use a row's menu to copy the key or delete the identity.")
        }
        .padding(.top, 60)
    }
}

private struct LocalCreateForm: View {
    @Bindable var model: AppModel

    var body: some View {
        GroupBox("New Identity") {
            VStack(alignment: .leading, spacing: 10) {
                TextField("Name (1-64 characters)", text: $model.localCreateName)
                    .textFieldStyle(.roundedBorder)
                Picker("Protocol", selection: $model.localCreateProtocol) {
                    ForEach(LocalIdentityProtocol.allCases, id: \.self) { protocolType in
                        Text(protocolType.rawValue).tag(protocolType)
                    }
                }
                .pickerStyle(.menu)
                HStack {
                    Spacer()
                    Button("Cancel") { model.cancelLocalCreate() }
                    Button("Create") { model.submitLocalCreate() }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.localCreating || model.localCreateName.isEmpty)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}