import SwiftUI
import MopCore
import MopAppSupport

struct ItemEnrollmentView: View {
    @Bindable var model: AppModel
    let approving: Bool
    let target: VaultDescriptor?
    @State private var vaultID = ""
    @Environment(\.scenePhase) private var scenePhase
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
                Button("Retry Connection") { refresh() }.disabled(vaultID.isEmpty || model.busy)
            }
        }
        .onAppear { vaultID = target?.id ?? choices.first?.id ?? ""; refresh() }
        .onChange(of: scenePhase) { _, phase in if phase == .active { refresh() } }
        .onReceive(NotificationCenter.default.publisher(for: .mopCloudChanged)) { _ in refresh() }
    }
    private func refresh() {
        guard !approving, !vaultID.isEmpty, !model.busy else { return }
        model.enrollmentAction(.automaticEnrollment, vaultID: vaultID)
    }
}
