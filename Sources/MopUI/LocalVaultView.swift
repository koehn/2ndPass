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
            if !LocalIdentityStore.isAvailable { Text("Secure Enclave is unavailable. Identity creation is disabled; no software fallback is provided.").foregroundStyle(.orange) }
            if !model.localCreatePresented {
                Button("New SSH Key…") { model.keyCreationPresented = true }
                Button("New Certificate Identity…") { model.beginLocalCreate(); model.localCreateProtocol = .x509 }
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
                        let credential = CredentialPresentation(identity: identity)
                        VaultItemRowLabel(title: credential.title,
                            symbol: identity.protocolType == .x509 ? "key.fill" : credential.symbol,
                            subtitle: credential.account)
                    }
                    .tag(identity.id)
                    .contextMenu {
                        Button("Copy Reference") { copyLocalPublicText(identity.reference.description) }
                        if identity.protocolType != .webauthn {
                            Button("Copy Public Key") { model.clipboard.copy(SecretBytes(utf8: identity.publicKeyText), concealed: false) }
                        }
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
        if [.ssh, .gitSigning, .webauthn].contains(identity.protocolType) {
            let credential = CredentialPresentation(identity: identity)
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 8) {
                    Label("local", systemImage: "internaldrive").foregroundStyle(.secondary)
                    Spacer()
                    Menu {
                        Button("Copy Reference") { copy(identity.reference.description) }
                        Button("Delete", role: .destructive) { model.requestLocalDelete(identity.id) }
                            .disabled(model.localDeleteInProgress || model.localCreating)
                    } label: { Image(systemName: "ellipsis.circle").accessibilityLabel("Item actions") }
                }.font(.callout)
                Divider()
                Text(credential.title).font(.title2.weight(.semibold))
                CredentialDetailsView(credential: credential, copy: copy)
                Text("This device only · Secure Enclave").font(.caption).foregroundStyle(.secondary)
                Text("Created: " + identity.createdAt.formatted()).font(.caption).foregroundStyle(.secondary)
            }.padding().frame(maxWidth: .infinity, alignment: .topLeading)
        } else {
            LocalCertificateDetailView(model: model, identity: identity)
        }
    }

    private func copy(_ text: String) {
        model.clipboard.copy(SecretBytes(utf8: text), concealed: false)
    }
}

private struct LocalCertificateDetailView: View {
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