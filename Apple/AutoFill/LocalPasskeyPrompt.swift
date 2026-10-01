import SwiftUI
import MopCore
import MopAppSupport
import MopLocalIdentity

struct LocalPasskeyPrompt: View {
    let relyingParty: String
    let registration: Bool
    let identities: [LocalIdentity]
    let cloud: [AutoFillIdentity]
    let vaults: [VaultDescriptor]
    let busy: Bool
    let message: String?
    let perform: (String?, String) -> Void
    let cancel: () -> Void
    var resize: (CGFloat) -> Void = { _ in }
    @State private var destination = ""
    @State private var acknowledged = false

    private var deviceLocal: Bool { destination == LocalVault.id }
    private var canCreate: Bool { !destination.isEmpty && !busy && (!deviceLocal || acknowledged) }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: 24) {
                    AutoFillDialogHeader(
                        title: registration ? "Create a passkey" : "Sign in with a passkey",
                        subtitle: relyingParty)

                    if registration { storageForm } else { accounts }
                    if busy { ProgressView("Loading or authenticating…").font(.callout) }
                    if let message {
                        Label(message, systemImage: "exclamationmark.triangle")
                            .font(.callout).foregroundStyle(.orange)
                            .frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                    }
                }.padding(24).frame(maxWidth: 520)
                    .frame(maxWidth: .infinity)
                    .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { height in
                        resize(height + 88)
                    }
            }
            Divider()
            HStack(spacing: 12) {
                Button("Cancel", action: cancel).keyboardShortcut(.cancelAction)
                    .buttonStyle(.bordered)
                Spacer(minLength: 0)
                if registration {
                    Button("Create Passkey") { perform(nil, destination) }
                        .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                        .disabled(!canCreate)
                }
            }.controlSize(.large).padding(20)
        }
        .background(.background)
        .onChange(of: destination) { _, _ in acknowledged = false }
    }

    private var storageForm: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 12) {
                Picker("Save in", selection: $destination) {
                    Text("Choose storage…").tag("")
                    ForEach(vaults) { Text($0.name ?? $0.id).tag($0.id) }
                    if LocalIdentityStore.isAvailable {
                        Text("This Device — Secure Enclave").tag(LocalVault.id)
                    }
                }.disabled(busy).accessibilityIdentifier("passkey-storage")
                if !destination.isEmpty {
                    Divider()
                    Label(deviceLocal ? "Only on this device" : "Synced with your vault",
                          systemImage: deviceLocal ? "internaldrive" : "icloud")
                        .font(.subheadline.weight(.semibold))
                    Text(deviceLocal
                         ? "Protected by the Secure Enclave. This passkey cannot be shared, exported, or recovered if this device is lost or erased."
                         : "Encrypted in this vault and available to its enrolled members. Recover access using another enrolled device or configured offline recovery.")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 12))

            if deviceLocal {
                Toggle("I understand this passkey stays on this device", isOn: $acknowledged)
                    .font(.callout).disabled(busy)
                DisclosureGroup("Compatibility with websites") {
                    Text("Some Apple platforms may reject device-bound passkeys. Older local passkeys may need to be registered again after the correction to their backup status.")
                        .font(.caption).foregroundStyle(.secondary).padding(.top, 6)
                }.font(.callout)
            } else if destination.isEmpty {
                Text("Choose a cloud vault to sync your passkey, or keep it only on this device.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    private var accounts: some View {
        VStack(spacing: 10) {
            ForEach(cloud) { row in
                if let vault = AutoFillEntry.vaultID(row.recordIdentifier) {
                    accountButton(row.username, storage: "Cloud vault", symbol: "icloud") { perform(row.id, vault) }
                }
            }
            ForEach(identities) { identity in
                accountButton(identity.name, storage: "This Device", symbol: "internaldrive") {
                    perform(identity.id.uuidString, LocalVault.id)
                }
            }
            if cloud.isEmpty && identities.isEmpty && !busy {
                Text("No matching passkey is available.").foregroundStyle(.secondary)
            }
        }
    }

    private func accountButton(_ name: String, storage: String, symbol: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: "person.crop.circle").font(.title2).foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 4) {
                    Text(name).font(.body.weight(.medium))
                    Label(storage, systemImage: symbol).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.secondary)
            }.padding(14).contentShape(Rectangle())
                .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 12))
        }.buttonStyle(.plain).disabled(busy)
    }
}
