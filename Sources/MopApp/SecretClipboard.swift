import AppKit
import MopCore

/// Concealed values expire and clear on lock. Visible values remain on the clipboard.
@MainActor final class SecretClipboard {
    private let pasteboard: NSPasteboard
    private let lifetime: Duration
    private var change: Int?
    private var expiry: Task<Void, Never>?

    init(pasteboard: NSPasteboard = .general, lifetime: Duration = .seconds(30)) {
        self.pasteboard = pasteboard
        self.lifetime = lifetime
    }

    func copy(_ value: SecretBytes, concealed: Bool = true) {
        expiry?.cancel(); expiry = nil; change = nil
        pasteboard.prepareForNewContents(with: [.currentHostOnly])
        // Cooperative clipboard managers can honor this marker. It is not an ACL.
        if concealed {
            pasteboard.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        }
        var data = Data(value)
        defer { SecretBytes.wipe(&data) }
        pasteboard.setData(data, forType: .string)
        guard concealed else { return }
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
