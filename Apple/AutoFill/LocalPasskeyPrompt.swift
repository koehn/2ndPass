import SwiftUI
import MopLocalIdentity

struct LocalPasskeyPrompt: View {
    let relyingParty: String
    let registration: Bool
    let identities: [LocalIdentity]
    let busy: Bool
    let message: String?
    let perform: (UUID?) -> Void
    let cancel: () -> Void
    @State private var acknowledged = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(registration ? "Create passkey in local" : "Sign in with local").font(.headline)
            Text(relyingParty).font(.title3).textSelection(.enabled)
            if registration {
                Text(LocalIdentityWarning.loss)
                Text(LocalIdentityWarning.redundancy(.webauthn))
                Toggle("I understand that this passkey cannot be recovered on another device", isOn: $acknowledged)
                Button("Create Passkey") { perform(nil) }.disabled(!acknowledged || busy)
            } else {
                ForEach(identities) { identity in
                    Button(identity.name) { perform(identity.id) }.disabled(busy)
                }
                if identities.isEmpty { Text("No matching passkey exists in local on this device.") }
            }
            if busy { ProgressView("Authenticating…") }
            if let message { Text(message).foregroundStyle(.orange).textSelection(.enabled) }
            Button("Cancel", action: cancel).keyboardShortcut(.cancelAction)
        }.padding().frame(minWidth: 320, minHeight: 220)
    }
}
