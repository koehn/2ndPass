import SwiftUI
import MopAppSupport

/// Candidates stay local to this popover; only an explicit action enters the draft.
struct PasswordGeneratorButton: View {
    @Bindable var model: AppModel
    let use: (String) -> Void
    @State private var presented = false

    var body: some View {
        Button("Generate password", systemImage: "dice") { presented = true }
            .disabled(model.offline || model.busy || !model.authenticated)
            .popover(isPresented: $presented) {
                PasswordGeneratorView(options: $model.passwordGeneratorOptions) { password in
                    guard model.authenticated, model.isActive, !model.busy, !model.offline else { return }
                    use(password)
                    presented = false
                } cancel: { presented = false }
                .opacity(model.isActive && model.authenticated ? 1 : 0)
                .accessibilityHidden(!model.isActive || !model.authenticated)
            }
            .onChange(of: model.isActive) { _, active in if !active { presented = false } }
            .onChange(of: model.editorGeneration) { _, _ in presented = false }
            .onDisappear { presented = false }
    }
}

private struct PasswordGeneratorView: View {
    @Binding var options: PasswordOptions
    let use: (String) -> Void
    let cancel: () -> Void
    @State private var candidate = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Generate password").font(.headline)
            Stepper("Length: \(options.length)", value: $options.length, in: 8...128)
            Toggle("Pronounceable", isOn: $options.pronounceable)
            HStack {
                Toggle("Lowercase", isOn: $options.lowercase)
                Toggle("Uppercase", isOn: $options.uppercase)
            }
            HStack {
                Toggle("Numbers", isOn: $options.numbers)
                Toggle("Symbols", isOn: $options.symbols)
            }
            Toggle("Readable (exclude similar characters)", isOn: $options.readable)
            if options.pronounceable {
                Text("Alternating consonants and vowels, with optional number and symbol suffixes. Use a longer password for better strength.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Text(candidate)
                .font(.system(.body, design: .monospaced)).textSelection(.disabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityLabel("Generated password: " + candidate)
            PasswordStrengthView(password: candidate)
            if let error { Text(error).font(.caption).foregroundStyle(.red) }
            HStack {
                Button("Regenerate", action: generate)
                Spacer()
                Button("Cancel", action: cancel)
                Button("Use password") { use(candidate) }
                    .buttonStyle(.borderedProminent).disabled(candidate.isEmpty)
            }
            Text("Use password updates the input. Choose Save to store it.")
                .font(.caption).foregroundStyle(.secondary)
        }.padding(20).frame(width: 420)
        .onAppear(perform: generate)
        .onChange(of: options) { _, _ in generate() }
        .onDisappear { candidate = "" }
    }
    private func generate() {
        candidate = ""; error = nil
        do { candidate = try PasswordGenerator.generate(options) }
        catch PasswordGenerator.Failure.invalidOptions {
            error = options.pronounceable ? "Select lowercase or uppercase letters." : "Select at least one character group."
        } catch { self.error = "Secure random generation failed. Try again." }
    }
}
