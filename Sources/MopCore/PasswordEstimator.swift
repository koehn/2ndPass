import Foundation
import Synchronization
import zxcvbn

public enum PasswordEstimator {
    // The dependency has shared helpers; serialize evaluation on worker threads.
    private static let gate = Mutex(())
    public static func estimate(_ password: String, userInputs: [String] = []) -> PasswordQuality {
        guard !password.isEmpty else { return .veryWeak }
        return gate.withLock { _ in
            // Bound worst-case matching cost. A prefix score is conservative for
            // long inputs; do not infer strength from their remaining length.
            let score = zxcvbn(String(password.prefix(100)), userInputs: userInputs).score ?? 0
            return PasswordQuality(rawValue: score) ?? .veryWeak
        }
    }
}
