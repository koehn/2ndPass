import SwiftUI
import MopCore
import MopLocalIdentity

struct CredentialBackupsView: View {
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var editing: CredentialAccount?
    @State private var destination = ""
    @State private var query = ""
    private var writable: [String] { model.catalogs.keys.filter { model.catalogs[$0]?.canEdit == true && model.catalogs[$0]?.securityEnabled == true }.sorted() }
    var body: some View {
        NavigationStack {
            List {
                Text(LocalIdentityWarning.loss).font(.caption)
                if let error = model.localError { Text("Local inventory unavailable: " + error).foregroundStyle(.secondary) }
                if model.offline { Text("Local removals are reflected here; updating shared evidence requires a connection.").font(.caption) }
                TextField("Search services or accounts", text: $query)
                if writable.isEmpty { Text("Synchronized backup tracking requires an accessible, writable cloud vault upgraded from Security.") }
                else {
                    Picker("Save new account in", selection: $destination) {
                        Text("Choose a vault").tag("")
                        ForEach(writable, id: \.self) { Text(model.catalogs[$0]?.vault ?? $0).tag($0) }
                    }
                    Button("Link an Account…") { editing = CredentialAccount(service: "", account: "") }
                        .disabled(destination.isEmpty || model.offline)
                }
                ForEach(model.catalogs.keys.sorted(), id: \.self) { id in
                    Section(model.catalogs[id]?.vault ?? id) {
                        ForEach(model.credentialAccounts(in: id).filter { query.isEmpty || ($0.service + " " + $0.account).localizedCaseInsensitiveContains(query) }) { account in
                            Button { destination = id; editing = account } label: {
                                VStack(alignment: .leading, spacing: 6) {
                                    Text(account.service + " · " + account.account).font(.headline)
                                    Text(account.hasConfirmedAlternate ? "Alternate on another device confirmed by you" : "No confirmed alternate on another device")
                                    if model.offline { Text("Cached evidence; current registration cannot be established").font(.caption) }
                                }
                            }.buttonStyle(.plain)
                        }
                    }
                }
                Section("Unlinked device-local credentials") {
                    ForEach(model.localIdentities.filter { identity in
                        !model.catalogs.values.contains { $0.security?.accounts.contains { $0.registrations.contains { $0.localIdentityID == identity.id } } == true }
                    }) { identity in
                        VStack(alignment: .leading) {
                            Text(identity.name)
                            Text("Account not linked—backup status unknown").font(.caption)
                            Text(LocalIdentityWarning.redundancy(identity.protocolType)).font(.caption)
                            ForEach(passkeyMatches(identity)) { account in
                                Button("Link to " + account.service + " · " + account.account) {
                                    var linked = account; linked.registrations.append(registration(identity)); editing = linked
                                }.disabled(destination.isEmpty || model.offline || writable.isEmpty)
                            }
                            Button("Link Account…") {
                                var account = CredentialAccount(service: "", account: "")
                                if case .passkey(let metadata) = identity.metadata {
                                    account.service = metadata.relyingParty; account.account = metadata.userName
                                    account.relyingParty = metadata.relyingParty; account.userHandle = metadata.userHandle
                                }
                                account.registrations = [registration(identity)]
                                editing = account
                            }.disabled(destination.isEmpty || model.offline || writable.isEmpty)
                        }
                    }
                    if model.localIdentities.isEmpty { Text("No local identities loaded. Open the local vault to inspect device-local credentials.").font(.caption) }
                }
            }
            .navigationTitle("Credential Backups")
            .toolbar { Button("Done") { dismiss() } }
            .sheet(item: $editing) { account in
                CredentialAccountEditor(model: model, vault: destination, account: account)
            }
        }.frame(minWidth: 300, idealWidth: 650, minHeight: 420)
    }
    private func passkeyMatches(_ identity: LocalIdentity) -> [CredentialAccount] {
        guard case .passkey(let metadata) = identity.metadata else { return [] }
        return model.credentialAccounts(in: destination).filter {
            $0.relyingParty == metadata.relyingParty && $0.userHandle == metadata.userHandle
        }
    }
    private func registration(_ identity: LocalIdentity) -> CredentialRegistration {
        CredentialRegistration(protocolName: identity.protocolType.rawValue, publicIdentifier: identity.fingerprint,
            deviceID: model.catalogs[destination]?.currentDeviceID ?? "", deviceLabel: ProcessInfo.processInfo.hostName, localIdentityID: identity.id)
    }
}

private struct CredentialAccountEditor: View {
    @Bindable var model: AppModel
    let vault: String
    @State var account: CredentialAccount
    @Environment(\.dismiss) private var dismiss
    @State private var confirmation: UUID?
    @State private var capturedRevision = ""
    private var canEdit: Bool { model.catalogs[vault]?.canEdit == true && !model.offline && model.authenticated }
    var body: some View {
        NavigationStack {
            Form {
                if model.error != nil { Text(model.errorMessage).foregroundStyle(.red) }
                Text(model.catalogs[vault]?.sharingAudience ?? "Vault audience unavailable")
                TextField("Service or account security URL", text: $account.service)
                TextField("Account", text: $account.account)
                if let url = URL(string: account.service), ["https", "http"].contains(url.scheme?.lowercased() ?? ""), url.host != nil {
                    Link("Open " + account.service, destination: url)
                }
                Picker("Linked item", selection: Binding(get: { account.linkedItemID ?? "" }, set: { account.linkedItemID = $0.isEmpty ? nil : $0 })) {
                    Text("Standalone account").tag("")
                    ForEach(model.catalogs[vault]?.items ?? [], id: \.name) { item in Text(item.name).tag(item.storageID ?? "") }
                }
                Text("1. Open this account's security settings. 2. Register an independent credential on another device. 3. Test signing in or using it at the service. 4. Confirm that registration below.")
                Text("Generated keys and locally produced signatures do not prove service acceptance. Confirmations are dated statements by you, not live service checks.").font(.caption)
                ForEach($account.registrations) { $registration in
                    Section(registration.deviceLabel.isEmpty ? "Credential" : registration.deviceLabel) {
                        Picker("Protocol", selection: $registration.protocolName) {
                            ForEach(LocalIdentityProtocol.allCases, id: \.rawValue) { Text($0.rawValue).tag($0.rawValue) }
                        }.disabled(registration.localIdentityID != nil || registration.state == .confirmed)
                        TextField("Public key fingerprint or credential identifier", text: $registration.publicIdentifier)
                            .disabled(registration.localIdentityID != nil || registration.state == .confirmed)
                        TextField("Device identifier (same device = same identifier)", text: $registration.deviceID)
                            .disabled(registration.localIdentityID != nil || registration.state == .confirmed)
                        TextField("Device label", text: $registration.deviceLabel)
                        if registration.external { Text("Manually recorded external credential").font(.caption) }
                        Text(registration.state.label)
                        if let date = registration.confirmedAt { Text("Confirmed \(date.formatted())").font(.caption) }
                        if let protocolType = LocalIdentityProtocol(rawValue: registration.protocolName) { Text(LocalIdentityWarning.redundancy(protocolType)).font(.caption) }
                        Button("Confirm Registration and Successful Test…") { confirmation = registration.id }
                        Button("Mark Removed/Revoked", role: .destructive) { registration.state = .removed }
                    }
                }
                Section("Add an independent credential") {
                    Menu("Add from this device") {
                        ForEach(model.localIdentities) { identity in
                            Button(identity.name) {
                                account.registrations.append(CredentialRegistration(protocolName: identity.protocolType.rawValue,
                                    publicIdentifier: identity.fingerprint, deviceID: model.catalogs[vault]?.currentDeviceID ?? "",
                                    deviceLabel: ProcessInfo.processInfo.hostName, localIdentityID: identity.id))
                            }
                        }
                    }
                    Button("Add Other Device / External Key") {
                        account.registrations.append(CredentialRegistration(protocolName: "ssh", publicIdentifier: "", deviceID: "", deviceLabel: "", external: true))
                    }
                }
                Section("Recovery or reissuance procedure") {
                    TextField("Recovery instructions (not an alternate registration)", text: $account.recoveryMethod, axis: .vertical)
                    Text("A replacement certificate procedure does not establish an already registered alternate credential.").font(.caption)
                }
            }
            .disabled(!canEdit || model.busy)
            .navigationTitle("Account Credentials")
            .toolbar {
                Button("Cancel") { dismiss() }
                Button("Save") {
                    model.securityOperation(.saveCredentialAccount(account, revision: capturedRevision), vault: vault)
                }.disabled(!canEdit || model.busy || !valid)
            }
            .onAppear { capturedRevision = model.catalogs[vault]?.revision ?? "" }
            .onChange(of: model.catalogs[vault]?.revision) { _, revision in
                if revision != capturedRevision { dismiss() }
            }
            .onChange(of: model.authenticated) { _, active in if !active { dismiss() } }
            .confirmationDialog("Confirm registration?", isPresented: Binding(get: { confirmation != nil }, set: { if !$0 { confirmation = nil } }), titleVisibility: .visible) {
                Button("I Registered and Successfully Tested This Credential") {
                    if let index = account.registrations.firstIndex(where: { $0.id == confirmation }) {
                        account.registrations[index].state = .confirmed
                        account.registrations[index].confirmedAt = Date()
                        account.registrations[index].confirmedBy = "pending"
                    }; confirmation = nil
                }
            } message: { Text("Confirm only after the account accepted the credential and you tested it. Generating a key is not enough.") }
        }.frame(minWidth: 300, idealWidth: 650, minHeight: 450)
    }
    private var valid: Bool { (try? account.validate()) != nil }
}
