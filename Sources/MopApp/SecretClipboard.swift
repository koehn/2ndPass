import AppKit

/// All value copies use one device-local, expiring pasteboard entry. Explicit
/// reference copies use their separate non-value path.
@MainActor final class SecretClipboard {
    private let pasteboard: NSPasteboard
    private let lifetime: Duration
    private var change: Int?
    private var expiry: Task<Void, Never>?

    init(pasteboard: NSPasteboard = .general, lifetime: Duration = .seconds(30)) {
        self.pasteboard = pasteboard
        self.lifetime = lifetime
    }

    func copy(_ value: String) {
        expiry?.cancel()
        pasteboard.prepareForNewContents(with: [.currentHostOnly])
        // Cooperative clipboard managers can honor this marker. It is not an ACL.
        pasteboard.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        pasteboard.setString(value, forType: .string)
        change = pasteboard.changeCount
        let lifetime = lifetime
        expiry = Task { [weak self] in
            try? await Task.sleep(for: lifetime)
            guard !Task.isCancelled else { return }
            self?.clear()
        }
    }

    func clear() {
        expiry?.cancel()
        expiry = nil
        if let change, pasteboard.changeCount == change { pasteboard.clearContents() }
        change = nil
    }
}
