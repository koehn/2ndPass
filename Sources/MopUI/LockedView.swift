import SwiftUI

/// Replaces the navigation hierarchy so locked content cannot be read by accessibility.
struct LockedView: View {
    @Bindable var model: AppModel
    var body: some View {
        VStack(spacing: 24) {
            Image("LockIcon", bundle: .module)
                .resizable().scaledToFit().frame(width: 128, height: 128)
                .accessibilityLabel("2ndPass")
            Button(model.unlocking ? "Unlocking…" : "Unlock 2ndPass") {
                if model.hasConnectedVaults { model.unlock() }
                else { model.presentSheet(.enrollDevice) }
            }
                .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                .disabled(model.hasConnectedVaults ? !model.canUnlock : model.busy || model.deviceRemoved)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.background)
        .accessibilityIdentifier("Locked screen")
    }
}
