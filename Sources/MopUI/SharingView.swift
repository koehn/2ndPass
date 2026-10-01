import SwiftUI
import MopCore
import MopAppSupport
import MopVaultNext
import UniformTypeIdentifiers

/// Public request/invitation documents are intentionally inspectable and portable.
/// Neither cloud acceptance nor a self-signed request substitutes for comparison.
private struct ExchangeDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    let data: Data
    init(_ data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}
enum EnrollmentFlow { case connect, share, advanced }

struct SharingView: View {
    @Bindable var model: AppModel
    let setup: Bool
    var flow: EnrollmentFlow = .advanced
    var target: VaultDescriptor? = nil
    var controls: SheetControls? = nil
    @State private var drafts: [String: FormSnapshot] = [:]
    @State private var importedName = ""
    private struct FormSnapshot: Equatable {
        var input: String; var fingerprint: String; var shareURL: String; var member: String
        var role: String; var importedName: String
    }
    private var snapshot: FormSnapshot { .init(input: input, fingerprint: fingerprint, shareURL: shareURL, member: member, role: role, importedName: importedName) }
    private var dirty: Bool { !input.isEmpty || !fingerprint.isEmpty || !member.isEmpty || !shareURL.isEmpty || role != "editor" }
    private var primaryTitle: String {
        switch action {
        case "request": return "Create Device Request"
        case "invite": return "Create Invitation"
        case "accept": return "Accept Invitation"
        case "approve": return "Approve Device"
        case "import": return "Import Checkpoint"
        case "removeMember": return "Remove Member"
        case "role": return "Change Role"
        default: return "Reconcile Permissions"
        }
    }
    private func validFingerprint(_ value: String) -> Bool { value.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    private var canSubmit: Bool {
        if ["invite", "accept", "approve", "import"].contains(action) {
            guard !input.isEmpty, validFingerprint(fingerprint) else { return false }
            if action == "accept", !shareURL.isEmpty { return URL(string: shareURL)?.scheme == "https" && URL(string: shareURL)?.host != nil }
        }
        if ["removeMember", "role"].contains(action) { return UUID(uuidString: member) != nil }
        return true
    }
    private func updateControls() {
        controls?.title = primaryTitle; controls?.canSubmit = canSubmit && !model.offline
        controls?.dirty = dirty || drafts.values.contains { !$0.input.isEmpty || !$0.fingerprint.isEmpty || !$0.member.isEmpty || !$0.shareURL.isEmpty || $0.role != "editor" }
        controls?.error = error; controls?.submit = { submit() }
    }
    private func restore(_ value: FormSnapshot) {
        input = value.input; fingerprint = value.fingerprint; shareURL = value.shareURL; member = value.member
        role = value.role; importedName = value.importedName
    }
    @State private var importingExchange = false
    @State private var exportingExchange = false
    @State private var action = "request"
    @State private var role = "editor"
    @State private var input = ""
    @State private var fingerprint = ""
    @State private var shareURL = ""
    @State private var member = ""
    @State private var error: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Devices and sharing").font(.headline)
            Group {
                Picker("Step", selection: $action) {
                    switch flow {
                    case .connect:
                        Text("1. Create this device’s request").tag("request")
                        Text("2. Accept the owner’s invitation").tag("accept")
                    case .share:
                        Text("1. Invite the new device").tag("invite")
                        Text("2. Approve its acceptance").tag("approve")
                    case .advanced:
                        Text("Import trusted checkpoint").tag("import")
                        if !setup {
                            Text("Remove member").tag("removeMember")
                            Text("Change role").tag("role")
                            Text("Reconcile cloud permissions").tag("reconcile")
                        }
                    }
                }
                if action == "request" {
                    Text("Generate the public request on the new device. The owner must compare its fingerprint, issue an invitation, and approve your acceptance.")
                }
                if ["invite", "accept", "approve", "import"].contains(action) {
                    Text(action == "accept" ? "Invitation JSON" : action == "approve" ? "Acceptance JSON" : action == "import" ? "Encrypted checkpoint JSON" : "Public device request JSON")
                    Button("Import received file…") { importingExchange = true }
                    if !input.isEmpty { Text("File loaded. Compare the verification fingerprint directly with the other device.").font(.caption) }
                    TextField((action == "accept" || action == "import") ? "Independently verified checkpoint" : "Independently verified request fingerprint", text: $fingerprint)
                }
                if action == "import" { TextField("Actual shared zone owner (blank for your own vault)", text: $shareURL) }
                if action == "accept" { TextField("iCloud share URL (other account only)", text: $shareURL) }
                if ["removeMember", "role"].contains(action) { TextField("Account or device UUID from the verified member list", text: $member) }
                if action == "invite" || action == "role" {
                    Picker("Role", selection: $role) {
                        Text("Editor").tag("editor"); Text("Viewer").tag("viewer")

                    }
                }
                if action.hasPrefix("remove") { Text("This rotates current secret keys. Copied passwords and old backups cannot be revoked.").font(.caption) }
            }
            if controls == nil { Button(primaryTitle) { submit() }.disabled(model.busy || model.offline || !canSubmit) }
            if !canSubmit { Text("Complete the required inputs and independently verified fingerprints before continuing.").font(.caption).foregroundStyle(.secondary) }
            if !importedName.isEmpty { Text("Imported: " + importedName).font(.caption) }
            if !model.exchangeOutput.isEmpty {
                Text("Save this public exchange file and send it to the other device, for example using AirDrop. No private keys are included.").font(.caption)
                Button("Save file to send…") { exportingExchange = true }
            }
            if controls == nil, let error { Text(error).foregroundStyle(.red) }
        }
        .onAppear {
            switch flow {
            case .share: action = "invite"
            case .advanced: action = "import"
            default: break
            }
            model.exchangeOutput = ""; updateControls()
        }
        .onChange(of: snapshot) { _, _ in controls?.revision += 1; updateControls() }
        .onChange(of: error) { _, _ in updateControls() }
        .onChange(of: action) { old, new in
            drafts[old] = snapshot
            if let saved = drafts[new] { restore(saved) }
            else { input = ""; fingerprint = ""; shareURL = ""; member = ""; importedName = "" }
            model.exchangeOutput = ""; model.notice = nil; error = nil; updateControls()
        }
        .fileExporter(isPresented: $exportingExchange, document: ExchangeDocument(Data(model.exchangeOutput.utf8)), contentType: .json, defaultFilename: "sp-" + action) { result in
            if case .failure(let failure) = result, (failure as NSError).code != NSUserCancelledError { error = "Could not save the exchange file." }
        }
        .fileImporter(isPresented: $importingExchange, allowedContentTypes: [.json, .data]) { result in
            do {
                let url = try result.get(), access = url.startAccessingSecurityScopedResource()
                defer { if access { url.stopAccessingSecurityScopedResource() } }
                let bytes = try LocalFile.read(url, limit: VerifiedVault.maximumBackupSize)
                _ = try JSONSerialization.jsonObject(with: bytes)
                switch action {
                case "invite": _ = try ExchangeFile.decode(DeviceRequest.self, from: bytes)
                case "accept": _ = try ExchangeFile.decode(InvitationPacket.self, from: bytes)
                case "approve": _ = try ExchangeFile.decode(AcceptancePacket.self, from: bytes)
                default: break
                }
                input = String(decoding: bytes, as: UTF8.self); importedName = url.lastPathComponent
                error = nil
            } catch { if (error as NSError).code != NSUserCancelledError { self.error = "Could not read a valid exchange file for this step." } }
        }
    }

    private func submit() {
        guard canSubmit else { error = "Complete the required inputs first."; return }
        do {
            let operation: VaultManagement
            switch action {
                case "request": operation = .deviceRequest
                case "invite":
                    operation = .inviteAccount(request: Data(input.utf8), fingerprint: fingerprint, role: MemberRole(rawValue: role)!)
                case "accept": operation = .accept(packet: Data(input.utf8), checkpoint: fingerprint, shareURL: shareURL.isEmpty ? nil : URL(string: shareURL))
                case "import":
                    _ = try VerifiedVault(checkpoint: Data(input.utf8), independentlyVerifiedDigest: fingerprint)
                    operation = .importCheckpoint(document: Data(input.utf8), fingerprint: fingerprint, sharedOwner: shareURL.isEmpty ? nil : shareURL)
                case "approve": operation = .approve(packet: Data(input.utf8), fingerprint: fingerprint)
                case "reconcile": operation = .reconcileShare
                default:
                    guard let id = UUID(uuidString: member) else { throw MopError.invalidProcess }
                    operation = action == "removeMember" ? .removeMember(id) : .role(id, MemberRole(rawValue: role)!)
            }
            error = nil; model.exchange(operation, target: target)
        } catch { self.error = (error as? MopError)?.errorDescription ?? "Invalid exchange document." }
    }
}
