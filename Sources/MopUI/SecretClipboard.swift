#if os(macOS)
import AppKit
typealias PlatformPasteboard = NSPasteboard
#else
import UIKit
import UniformTypeIdentifiers
typealias PlatformPasteboard = UIPasteboard
#endif
import MopCore

@MainActor protocol SecretClipboardAccess {
    func copy(_ value: SecretBytes, concealed: Bool)
    func clear()
}

/// Concealed values expire and clear on lock. Visible values remain on the clipboard.
@MainActor final class SecretClipboard: SecretClipboardAccess {
    private let pasteboard: PlatformPasteboard
    private let lifetime: Duration
    private var change: Int?
    private var expiry: Task<Void, Never>?

    init(pasteboard: PlatformPasteboard = .general, lifetime: Duration = .seconds(30)) {
        self.pasteboard = pasteboard
        self.lifetime = lifetime
    }

    func copy(_ value: SecretBytes, concealed: Bool = true) {
        expiry?.cancel(); expiry = nil; change = nil
        #if os(macOS)
        pasteboard.prepareForNewContents(with: [.currentHostOnly])
        // Cooperative clipboard managers can honor this marker. It is not an ACL.
        if concealed {
            pasteboard.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        }
        #endif
        var data = Data(value)
        defer { SecretBytes.wipe(&data) }
        #if os(macOS)
        pasteboard.setData(data, forType: .string)
        #else
        var options: [UIPasteboard.OptionsKey: Any] = [.localOnly: true]
        if concealed {
            let seconds = Double(lifetime.components.seconds) + Double(lifetime.components.attoseconds) / 1e18
            options[.expirationDate] = Date().addingTimeInterval(seconds)
        }
        pasteboard.setItems([[UTType.utf8PlainText.identifier: data]], options: options)
        #endif
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
        if let change, pasteboard.changeCount == change {
            #if os(macOS)
            pasteboard.clearContents()
            #else
            pasteboard.items = []
            #endif
        }
        change = nil
    }
}
