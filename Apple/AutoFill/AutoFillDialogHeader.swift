import SwiftUI

/// Shared branding for every app-owned AutoFill prompt, including error states.
struct AutoFillDialogHeader: View {
    let title: String
    var subtitle: String? = nil

    var body: some View {
        VStack(spacing: 10) {
            AutoFillBranding.icon
                .resizable().scaledToFit()
                .frame(width: 64, height: 64)
                .clipShape(RoundedRectangle(cornerRadius: 14))
                .accessibilityLabel("2ndPass")
            Text(title).font(.title2.bold()).multilineTextAlignment(.center)
            if let subtitle {
                Text(subtitle).font(.body).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center).textSelection(.enabled)
            }
        }.frame(maxWidth: .infinity)
    }
}

private final class AutoFillResources {}

@MainActor private enum AutoFillBranding {
    // The extension ships a loose PNG, not an asset catalog. Named SwiftUI
    // lookup can fail through CoreUI in the macOS extension host even when the
    // resource exists. Resolve and decode the file in our own bundle explicitly.
    static let icon: Image = {
        let bundle = Bundle(for: AutoFillResources.self)
        if let url = bundle.url(forResource: "Mop", withExtension: "png") {
            #if os(macOS)
            if let image = NSImage(contentsOf: url) { return Image(nsImage: image) }
            #else
            if let image = UIImage(contentsOfFile: url.path) { return Image(uiImage: image) }
            #endif
        }
        return Image(systemName: "key.fill")
    }()
}
