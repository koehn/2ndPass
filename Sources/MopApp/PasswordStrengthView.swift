import SwiftUI
import MopCore
import MopAppSupport

struct PasswordStrengthView: View {
    var password: String? = nil
    var storedScore: PasswordQuality? = nil
    var userInputs: [String] = []
    @State private var liveScore: PasswordQuality?
    private var score: PasswordQuality? { password == nil ? storedScore : liveScore }
    private var color: Color {
        switch score {
        case .veryWeak, .weak: .red
        case .fair: .orange
        case .strong, .veryStrong: .green
        case nil: .secondary
        }
    }
    var body: some View {
        HStack(spacing: 8) {
            HStack(spacing: 3) {
                ForEach(0..<5) { segment in
                    Capsule().fill(score.map { segment <= $0.rawValue } == true ? color : Color.secondary.opacity(0.15))
                        .frame(width: 14, height: 4)
                }
            }.accessibilityHidden(true)
            Text(score?.label ?? (password == nil ? "Strength unavailable" : "Checking strength…"))
                .font(.caption).foregroundStyle(color)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Estimated password strength: \(score?.label ?? "unavailable")")
        .help("Estimated on this Mac using zxcvbn. This is not a check for leaked passwords.")
        .task(id: Evaluation(password: password, inputs: userInputs)) {
            liveScore = nil
            guard let password else { return }
            do {
                try await Task.sleep(for: .milliseconds(200))
                let result = await Task.detached { PasswordEstimator.estimate(password) }.value
                guard !Task.isCancelled else { return }
                liveScore = result
            } catch { /* Typing or leaving the editor cancels the pending estimate. */ }
        }
    }
    private struct Evaluation: Equatable { let password: String?; let inputs: [String] }
}
