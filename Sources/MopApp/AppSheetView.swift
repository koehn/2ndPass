import SwiftUI
import AppKit
import MopCore

struct AppSheetView: View {
    @Bindable var model: AppModel
    let kind: AppSheet
    @State private var namespace = "personal"
    @State private var item = ""
    @State private var section = ""
    @State private var field = "token"
    @State private var value = ""
    @State private var name = Host.current().localizedName ?? "Mac"
    @State private var fingerprint = ""
    @State private var strict = false
    @State private var confirmed = false
    @State private var recoveryURL: URL?
    @State private var vaultID = ""

    private var reference: SecretReference? {
        if kind == .replaceSecret { return model.selected }
        return try? SecretReference(vault: namespace, item: item, section: section.isEmpty ? nil : section, field: field)
    }
    private var validFingerprint: Bool {
        fingerprint.count == 64 && fingerprint.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    private var title: String {
        switch kind {
        case .createSecret: "New secret"
        case .replaceSecret: "Replace value"
        case .createVault: "Create a vault"
        case .request: "Enroll this Mac"
        case .trust: "Verify vault trust"
        case .approve: "Approve a Mac"
        case .selectVault: "Select a vault"
        case .recover: "Recover vault access"
        case .revoke: "Remove a Mac"
        }
    }
    private var canSubmit: Bool {
        switch kind {
        case .createSecret, .replaceSecret: reference != nil
        case .createVault: !name.isEmpty && recoveryURL != nil && confirmed
        case .request: !name.isEmpty
        case .trust: validFingerprint
        case .approve: validFingerprint && confirmed && model.enrollment != nil
        case .selectVault: UUID(uuidString: vaultID) != nil
        case .recover: validFingerprint && recoveryURL != nil && !name.isEmpty
        case .revoke: confirmed && model.revoking != nil
        }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text(title).font(.title2).fontWeight(.semibold)
            switch kind {
            case .createSecret, .replaceSecret:
                if kind == .createSecret {
                    Form {
                        TextField("Namespace", text: $namespace)
                        TextField("Item", text: $item)
                        TextField("Section (optional)", text: $section)
                        TextField("Field", text: $field)
                    }
                }
                if let reference { Text(reference.description).font(.system(.caption, design: .monospaced)).textSelection(.enabled) }
                SecureField("Secret value", text: $value)
                Text("The value is sent privately to mop after you choose Save. Empty values are allowed.").font(.caption).foregroundStyle(.secondary)
            case .createVault:
                Text("Create an independent encrypted vault in your private iCloud account. Namespaces such as personal live inside this vault.")
                TextField("This Mac’s name", text: $name)
                Toggle("Require Touch ID without password fallback", isOn: $strict)
                Text("This policy applies when first creating this Mac’s key. Changing Touch ID enrollment under strict policy requires recovery.").font(.caption).foregroundStyle(.secondary)
                Button("Choose recovery key location…") {
                    let panel = NSSavePanel(); panel.nameFieldStringValue = "mop-recovery.key"
                    panel.title = "Save the offline recovery credential"
                    if panel.runModal() == .OK { recoveryURL = panel.url }
                }
                if let recoveryURL { Text(recoveryURL.path).font(.caption).textSelection(.enabled) }
                Toggle("I will move the recovery key offline and retain the vault fingerprint separately.", isOn: $confirmed)
                Text("The recovery key grants full access. Keep it out of iCloud and away from encrypted backups. If creation fails after writing the key, the file is retained.").font(.caption).foregroundStyle(.secondary)
            case .selectVault:
                Text("Enter the independent cloud vault UUID. Use this to select an existing verified snapshot while offline.")
                TextField("Cloud vault UUID", text: $vaultID)
            case .recover:
                Text("Enroll this Mac with an offline recovery key and a vault fingerprint obtained independently. Return the key offline afterward.")
                TextField("This Mac’s name", text: $name)
                TextField("Vault fingerprint", text: $fingerprint)
                Button("Choose recovery key…") {
                    let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
                    if panel.runModal() == .OK { recoveryURL = panel.url }
                }
                if let recoveryURL { Text(recoveryURL.lastPathComponent).font(.caption) }
            case .revoke:
                if let device = model.revoking {
                    Text(device.name).font(.headline)
                    Text(device.fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                }
                Text("Removing a Mac rotates every encryption key. Remaining Macs must independently verify the new vault fingerprint. Historical copies and secrets already learned remain accessible to the removed Mac. You cannot remove this Mac.")
                Toggle("Remove this Mac’s future access and rotate the keys.", isOn: $confirmed)
            case .request:
                TextField("This Mac’s name", text: $name)
                Toggle("Require Touch ID without password fallback", isOn: $strict)
                Text("Publish this Mac’s public enrollment request. On an enrolled Mac, approve it after independently comparing the full device fingerprint. Then verify that Mac’s vault fingerprint here.")
            case .trust:
                Text("Enter the full vault fingerprint obtained independently from an enrolled Mac. Do not use a fingerprint supplied only by the cloud service.")
                TextField("Vault fingerprint", text: $fingerprint)
                    .font(.system(.body, design: .monospaced))
            case .approve:
                if let request = model.enrollment {
                    Text(request.name).font(.headline)
                    Text("Request fingerprint (untrusted)").font(.caption).foregroundStyle(.secondary)
                    Text(request.fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    TextField("Fingerprint from the new Mac", text: $fingerprint)
                        .font(.system(.body, design: .monospaced))
                    Toggle("I compared this fingerprint through an independent trusted channel.", isOn: $confirmed)
                    Text("After approval, verify the vault fingerprint on the new Mac. Approval does not delete the request.").font(.caption).foregroundStyle(.secondary)
                }
            }
            if model.busy { HStack { ProgressView().controlSize(.small); Text("Waiting for authentication or iCloud…").font(.caption) } }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { value = ""; model.sheet = nil }.keyboardShortcut(.cancelAction).disabled(model.busy)
                Button(kind == .createSecret || kind == .replaceSecret ? "Save" : "Continue") { submit() }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(model.busy || !canSubmit)
            }
        }.padding(28).frame(width: 500).disabled(model.busy)
        .interactiveDismissDisabled(model.busy)
        .onAppear { namespace = model.namespace ?? "personal" }
        .onDisappear { value = "" }
        .alert("Operation not completed", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK") { model.error = nil }
        } message: { Text(model.error ?? "") }
    }
    private func submit() {
        switch kind {
        case .createSecret, .replaceSecret:
            if let reference { model.write(reference: reference, value: value, replace: kind == .replaceSecret); value = "" }
        case .createVault:
            if let recoveryURL { model.createVault(name: name, strict: strict, recovery: recoveryURL) }
        case .request:
            model.management(["device", "request", "--name", name] + (strict ? ["--strict-biometrics"] : []))
        case .trust:
            model.management(["vault", "trust", "--fingerprint", fingerprint])
        case .selectVault:
            if let id = UUID(uuidString: vaultID)?.uuidString {
                if !model.vaults.contains(id) { model.vaults.append(id) }
                model.vault = id; model.sheet = nil
            }
        case .recover:
            if let recoveryURL { model.management(["vault", "recover", "--recovery-file", recoveryURL.path, "--name", name, "--fingerprint", fingerprint]) }
        case .revoke:
            if let device = model.revoking { model.management(["device", "remove", device.fingerprint]) }
        case .approve:
            if let request = model.enrollment { model.management(["device", "add", request.request, "--fingerprint", fingerprint]) }
        }
    }
}
