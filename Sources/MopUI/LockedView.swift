import SwiftUI
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// Replaces the navigation hierarchy so locked content cannot be read by accessibility.
struct LockedView: View {
    @Bindable var model: AppModel
    // This is a loose SwiftPM resource, not an asset-catalog image. SwiftUI's
    // named lookup can render it blank in a packaged app's resource bundle.
    private static let icon: Image = {
        if let url = Bundle.module.url(forResource: "LockIcon", withExtension: "png") {
            #if os(macOS)
            if let image = NSImage(contentsOf: url) { return Image(nsImage: image) }
            #else
            if let image = UIImage(contentsOfFile: url.path) { return Image(uiImage: image) }
            #endif
        }
        return Image(systemName: "lock.shield")
    }()

    var body: some View {
        VStack(spacing: 24) {
            Self.icon
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
