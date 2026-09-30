import MopLocalIdentity
import SwiftUI
import MopCore
import MopAppSupport

/// List column for the device-local vault. Selection opens a separate public-only
/// identity detail view; local identities never enter cloud item catalogs.
struct LocalVaultView: View {
    @Bindable var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            GroupBox {
                VStack(alignment: .leading, spacing: 6) {
                    Label("Device-only vault", systemImage: "internaldrive")
                    Text(LocalIdentityWarning.loss)
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            .tint(.secondary)

            if !LocalIdentityStore.isAvailable { Text("Secure Enclave is unavailable. Identity creation is disabled; no software fallback is provided.").foregroundStyle(.orange) }
            if !model.localCreatePresented {
                Button("New Identity…") { model.beginLocalCreate() }
                    .disabled(model.localCreating || model.localLoading || model.localDeleteInProgress || !LocalIdentityStore.isAvailable)
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
                    Text("Create an SSH, Git signing, or certificate identity. Create passkeys from a website’s registration flow.")
                }
            } else {
                List(model.displayedLocalIdentities, selection: $model.selectedLocalIdentityID) { identity in
                    NavigationLink(value: identity.id) {
                        HStack(spacing: 10) {
                            Image(systemName: "key.fill").foregroundStyle(Color.accentColor).frame(width: 22)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(identity.name).fontWeight(.medium)
                                Text(identity.protocolType.rawValue).font(.caption).foregroundStyle(.secondary)
                            }
                        }.padding(.vertical, 2)
                    }
                    .tag(identity.id)
                    .contextMenu {
                        Button("Copy Reference") { copyLocalPublicText(identity.reference.description) }
                        Button("Copy Public Key") { copyLocalPublicText(identity.publicKeyText) }
                        Button("Delete…", role: .destructive) { model.requestLocalDelete(identity.id) }
                    }
                }
                .onChange(of: model.selectedLocalIdentityID) { _, id in
                    if id != nil { model.cancelLocalCreate() }
                }
                if model.displayedLocalIdentities.isEmpty && !model.search.isEmpty {
                    ContentUnavailableView.search(text: model.search)
                }
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
            Text(LocalIdentityWarning.deletion)
        }
    }
}

private func copyLocalPublicText(_ text: String) {
    #if os(macOS)
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
    #else
    UIPasteboard.general.string = text
    #endif
}

struct LocalIdentityDetailView: View {
    @Bindable var model: AppModel
    let identity: LocalIdentity

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Label("local", systemImage: "internaldrive")
                Spacer()
                Button("Delete…", role: .destructive) { model.requestLocalDelete(identity.id) }
                    .disabled(model.localDeleteInProgress || model.localCreating)
            }
            Divider()
            Text(identity.name).font(.title2.weight(.semibold))
            GroupBox("Identity") {
                VStack(alignment: .leading, spacing: 10) {
                    LabeledContent("Reference", value: identity.reference.description).textSelection(.enabled)
                    LabeledContent("Type", value: identity.protocolType.rawValue)
                    LabeledContent("Algorithm", value: "P-256")
                    LabeledContent("Created", value: identity.createdAt.formatted())
                    LabeledContent("Authorization", value: identity.accessPolicy.rawValue)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            GroupBox("Device protection") {
                VStack(alignment: .leading, spacing: 10) {
                    LabeledContent("Private key", value: "Secure Enclave • Non-exportable")
                    LabeledContent("Storage", value: "This device only")
                    LabeledContent("Backup", value: "Not possible")
                    Text(LocalIdentityWarning.loss).font(.callout).foregroundStyle(.secondary)
                    Text(LocalIdentityWarning.redundancy(identity.protocolType)).font(.callout)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            GroupBox("Public key") {
                VStack(alignment: .leading, spacing: 10) {
                    Text(identity.fingerprint).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                    Text(identity.publicKeyText).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                    HStack {
                        Button("Copy Reference") { copyLocalPublicText(identity.reference.description) }
                        Button("Copy Public Key") { copyLocalPublicText(identity.publicKeyText) }
                        ShareLink("Share Public Key", item: identity.publicKeyText)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            if identity.protocolType == .gitSigning {
                GroupBox("Git signing setup") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text(identity.gitSetup).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        Button("Copy Setup Instructions") { copyLocalPublicText(identity.gitSetup) }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            if case .passkey(let data) = identity.metadata {
                GroupBox("Passkey") {
                    VStack(alignment: .leading, spacing: 10) {
                        LabeledContent("Website", value: data.relyingParty)
                        LabeledContent("User", value: data.userName)
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            if let certificates = try? identity.certificateInfo, !certificates.isEmpty {
                GroupBox("Certificates") {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(Array(certificates.enumerated()), id: \.offset) { _, cert in
                            LabeledContent("Subject", value: cert.subject)
                            LabeledContent("Issuer", value: cert.issuer)
                            LabeledContent("Valid from", value: cert.validFrom.formatted())
                            LabeledContent("Valid until", value: cert.validUntil.formatted())
                            Text(cert.expired ? "Expired" : "Attachment only; trust not validated").foregroundStyle(.secondary)
                            Text(cert.extensions).textSelection(.enabled)
                            Divider()
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }.padding().frame(maxWidth: .infinity, alignment: .topLeading)
    }
}

struct LocalVaultDetailHint: View {
    var body: some View {
        ContentUnavailableView {
            Label("Select an identity", systemImage: "key.horizontal")
        } description: {
            Text("Choose an identity to view its details and public key.")
        }
        .padding(.top, 60)
    }
}

struct LocalCreateForm: View {
    @Bindable var model: AppModel

    var body: some View {
        GroupBox("New Identity") {
            VStack(alignment: .leading, spacing: 10) {
                TextField("Name (1-64 characters)", text: $model.localCreateName)
                    .textFieldStyle(.roundedBorder)
                Picker("Protocol", selection: $model.localCreateProtocol) {
                    ForEach(LocalIdentityProtocol.creatable, id: \.self) { protocolType in
                        Text(protocolType.rawValue).tag(protocolType)
                    }
                }
                .pickerStyle(.menu)
                Text(LocalIdentityWarning.loss).font(.callout)
                Text(LocalIdentityWarning.redundancy(model.localCreateProtocol)).font(.callout)
                Toggle("I understand that device loss permanently loses this identity", isOn: $model.localCreateAcknowledged)
                HStack {
                    Spacer()
                    Button("Cancel") { model.cancelLocalCreate() }
                    Button("Create") { model.submitLocalCreate() }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.localCreating || model.localCreateName.isEmpty || !model.localCreateAcknowledged)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}