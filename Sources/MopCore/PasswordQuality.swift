/// An estimate, never a guarantee or a breach check.
public enum PasswordQuality: Int, Codable, Sendable, CaseIterable {
    case veryWeak, weak, fair, strong, veryStrong
    public var label: String {
        switch self {
        case .veryWeak: "Very weak"
        case .weak: "Weak"
        case .fair: "Fair"
        case .strong: "Strong"
        case .veryStrong: "Very strong"
        }
    }
}
