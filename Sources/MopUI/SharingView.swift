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
enum EnrollmentFlow { case connect, addDevice, share, recovery, advanced }

struct SharingView: View {
    @Bindable var model: AppModel
    let setup: Bool
    var recoveryMode = false
    var flow: EnrollmentFlow = .advanced
    @State private var importingExchange = false
    @State private var exportingExchange = false
    @State private var action = "request"
    @State private var role = "editor"
    @State private var input = ""
    @State private var fingerprint = ""
    @State private var shareURL = ""
    @State private var member = ""
    @State private var backup = Data()
    @State private var ownerRequest = ""
    @State private var ownerFingerprint = ""
    @State private var nextRecoveryFingerprint = ""
    @State private var copy = false
    @State private var importingBackup = false
    @State private var error: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(recoveryMode ? "Recover on the enrolled recovery device" : "Devices and sharing").font(.headline)
            if recoveryMode {
                Text("Import an encrypted backup and independently verify its checkpoint. Paste replacement owner and recovery requests and compare both request fingerprints. Recovery removes every prior member/device. For lost account access, sign into the new account and create a new vault; the owner request must be this device’s ordinary request.")
                Button("Import encrypted backup…") { importingBackup = true }
                Text(backup.isEmpty ? "No backup selected" : "Encrypted backup loaded").font(.caption)
                TextField("Backup checkpoint", text: $fingerprint)
                Text("Replacement owner request JSON")
                TextEditor(text: $ownerRequest).frame(minHeight: 80)
                TextField("Verified owner request fingerprint", text: $ownerFingerprint)
                Text("Replacement recovery request JSON")
                TextEditor(text: $input).frame(minHeight: 80)
                TextField("Verified recovery request fingerprint", text: $nextRecoveryFingerprint)
                Toggle("Create new vault under current account; preserve source", isOn: $copy)
            } else {
                Picker("Step", selection: $action) {
                    switch flow {
                    case .connect:
                        Text("1. Create this device’s request").tag("request")
                        Text("2. Accept the owner’s invitation").tag("accept")
                    case .addDevice, .share:
                        Text("1. Invite the new device").tag("invite")
                        Text("2. Approve its acceptance").tag("approve")
                    case .recovery:
                        Text("On recovery device: create request").tag("recoveryRequest")
                        if !setup { Text("On owner device: enable recovery").tag("replaceRecovery") }
                    case .advanced:
                        Text("Enrollment request").tag("request")
                        Text("Accept invitation").tag("accept")
                        Text("Import trusted checkpoint").tag("import")
                        if !setup {
                            Text("Remove member").tag("removeMember")
                            Text("Remove device").tag("removeDevice")
                            Text("Change role").tag("role")
                            Text("Reconcile cloud permissions").tag("reconcile")
                        }
                    }
                }
                if action == "request" || action == "recoveryRequest" {
                    Text(action == "request" ? "Generate the public request on the new device. The owner must compare its fingerprint, issue an invitation, and approve your acceptance." : "Use this on the separate device you will retain for recovery. Its private keys cannot be exported or restored on another device.")
                }
                if ["invite", "accept", "approve", "replaceRecovery", "import"].contains(action) {
                    Text(action == "accept" ? "Invitation JSON" : action == "approve" ? "Acceptance JSON" : action == "import" ? "Encrypted checkpoint JSON" : "Public device request JSON")
                    Button("Import received file…") { importingExchange = true }
                    if !input.isEmpty { Text("File loaded. Compare the verification fingerprint directly with the other device.").font(.caption) }
                    TextField((action == "accept" || action == "import") ? "Independently verified checkpoint" : "Independently verified request fingerprint", text: $fingerprint)
                }
                if action == "import" { TextField("Actual shared zone owner (blank for your own vault)", text: $shareURL) }
                if action == "accept" { TextField("iCloud share URL (other account only)", text: $shareURL) }
                if ["removeMember", "removeDevice", "role"].contains(action) { TextField("Account or device UUID from the verified member list", text: $member) }
                if (action == "invite" && flow != .addDevice) || action == "role" {
                    Picker("Role", selection: $role) {
                        Text("Editor").tag("editor"); Text("Viewer").tag("viewer")

                    }
                }
                if action.hasPrefix("remove") { Text("This rotates current secret keys. Copied passwords and old backups cannot be revoked.").font(.caption) }
            }
            Button(recoveryMode ? "Recover and rotate access" : "Continue") { submit() }.disabled(model.busy || model.offline)
            if !model.exchangeOutput.isEmpty {
                Text("Save this public exchange file and send it to the other device, for example using AirDrop. No private keys are included.").font(.caption)
                Button("Save file to send…") { exportingExchange = true }
            }
            if let error { Text(error).foregroundStyle(.red) }
        }
        .onAppear {
            switch flow {
            case .addDevice, .share: action = "invite"
            case .recovery: action = setup ? "recoveryRequest" : "replaceRecovery"
            default: break
            }
            model.exchangeOutput = ""
        }
        .onChange(of: action) { _, _ in input = ""; fingerprint = ""; model.exchangeOutput = ""; model.notice = nil }
        .fileExporter(isPresented: $exportingExchange, document: ExchangeDocument(Data(model.exchangeOutput.utf8)), contentType: .json, defaultFilename: "mop-" + action) { result in
            if case .failure = result { error = "Could not save the exchange file." }
        }
        .fileImporter(isPresented: $importingExchange, allowedContentTypes: [.json, .data]) { result in
            do {
                let url = try result.get(), access = url.startAccessingSecurityScopedResource()
                defer { if access { url.stopAccessingSecurityScopedResource() } }
                input = String(decoding: try LocalFile.read(url, limit: 24 * 1024 * 1024), as: UTF8.self)
            } catch { self.error = "Could not read the exchange file." }
        }
        .fileImporter(isPresented: $importingBackup, allowedContentTypes: [.data, .json]) { result in
            do {
                let url = try result.get(), access = url.startAccessingSecurityScopedResource()
                defer { if access { url.stopAccessingSecurityScopedResource() } }
                let handle = try FileHandle(forReadingFrom: url); defer { try? handle.close() }
                backup = try handle.read(upToCount: 16 * 1024 * 1024 + 1) ?? Data()
                guard backup.count <= 16 * 1024 * 1024 else { throw MopError.invalidVault }
            } catch { self.error = "Could not load the encrypted backup." }
        }
    }
    private func submit() {
        do {
            let operation: VaultManagement
            if recoveryMode {
                let owner = Data(ownerRequest.utf8), recovery = Data(input.utf8)
                guard try ExchangeFile.decode(DeviceRequest.self, from: owner).fingerprint == ownerFingerprint,
                      try ExchangeFile.decode(DeviceRequest.self, from: recovery).fingerprint == nextRecoveryFingerprint else { throw MopError.invalidIdentity }
                operation = .recoverHardware(backup: backup, checkpoint: fingerprint, owner: owner, recovery: recovery, copy: copy)
            } else {
                switch action {
                case "request": operation = .deviceRequest(recovery: false)
                case "recoveryRequest": operation = .deviceRequest(recovery: true)
                case "invite":
                    if flow == .addDevice { operation = .inviteOwnDevice(request: Data(input.utf8), fingerprint: fingerprint) }
                    else { operation = .inviteAccount(request: Data(input.utf8), fingerprint: fingerprint, role: MemberRole(rawValue: role)!) }
                case "accept": operation = .accept(packet: Data(input.utf8), checkpoint: fingerprint, shareURL: shareURL.isEmpty ? nil : URL(string: shareURL))
                case "import": operation = .importCheckpoint(document: Data(input.utf8), fingerprint: fingerprint, sharedOwner: shareURL.isEmpty ? nil : shareURL)
                case "approve": operation = .approve(packet: Data(input.utf8), fingerprint: fingerprint)
                case "replaceRecovery": operation = .replaceRecovery(request: Data(input.utf8), fingerprint: fingerprint)
                case "reconcile": operation = .reconcileShare
                default:
                    guard let id = UUID(uuidString: member) else { throw MopError.invalidProcess }
                    operation = action == "removeMember" ? .removeMember(id) : action == "removeDevice" ? .removeDevice(id) : .role(id, MemberRole(rawValue: role)!)
                }
            }
            error = nil; model.exchange(operation)
        } catch { self.error = (error as? MopError)?.errorDescription ?? "Invalid exchange document." }
    }
}
