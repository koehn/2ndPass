import SwiftUI

/// Shared branding for every app-owned AutoFill prompt, including error states.
struct AutoFillDialogHeader: View {
    let title: String
    var subtitle: String? = nil

    var body: some View {
        VStack(spacing: 10) {
            Image("Mop", bundle: Bundle(for: AutoFillResources.self))
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
