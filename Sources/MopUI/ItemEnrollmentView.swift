import SwiftUI
import MopCore
import MopAppSupport

struct ItemEnrollmentView: View {
    @Bindable var model: AppModel
    let approving: Bool
    let target: VaultDescriptor?
    @State private var vaultID = ""
    private var choices: [VaultDescriptor] { model.vaults.filter { $0.supported && !$0.enrolled } }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(approving ? "Your Devices" : "Connecting iCloud Vaults").font(.title2)
            Text("Vaults connect automatically on devices using the same Apple Account for iCloud.")
            Text("Open and unlock 2ndPass on an existing device so it can securely sync key access to this device. No access request or approval is needed.")
            if !approving {
                if choices.count > 1 {
                    Picker("Vault", selection: $vaultID) {
                        ForEach(choices) { vault in Text(vault.name ?? "Vault \(vault.id.prefix(8))").tag(vault.id) }
                    }
                }
                if model.supports(.recovery) {
                    Button("Recover with an Offline Code…") { model.presentSheet(.recover) }
                }
            }
        }
        .onAppear { vaultID = target?.id ?? choices.first?.id ?? "" }
    }
}
