import AppKit
import Testing
@testable import MopApp

@MainActor struct SecretClipboardTests {
    @Test func valueExpiresWithoutTouchingGeneralPasteboard() async throws {
        let board = NSPasteboard.withUniqueName()
        defer { board.releaseGlobally() }
        let clipboard = SecretClipboard(pasteboard: board, lifetime: .milliseconds(50))
        clipboard.copy("fixture-secret")
        #expect(board.string(forType: .string) == "fixture-secret")
        #expect(board.types?.contains(NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")) == true)
        for _ in 0..<200 {
            if board.string(forType: .string) == nil { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(board.string(forType: .string) == nil)
    }

    @Test func expiryPreservesAnotherApplicationsNewContent() async throws {
        let board = NSPasteboard.withUniqueName()
        defer { board.releaseGlobally() }
        let clipboard = SecretClipboard(pasteboard: board, lifetime: .milliseconds(50))
        clipboard.copy("fixture-secret")
        board.clearContents()
        board.setString("new clipboard owner", forType: .string)
        try await Task.sleep(for: .milliseconds(150))
        #expect(board.string(forType: .string) == "new clipboard owner")
        clipboard.clear()
        #expect(board.string(forType: .string) == "new clipboard owner")
    }

    @Test func explicitLockClearsOwnedSecretButAppSwitchAllowsPaste() {
        let board = NSPasteboard.withUniqueName()
        defer { board.releaseGlobally() }
        let clipboard = SecretClipboard(pasteboard: board)
        let model = AppModel(clipboard: clipboard)
        clipboard.copy("fixture-secret")
        model.deactivate()
        #expect(board.string(forType: .string) == "fixture-secret")
        model.lock()
        #expect(board.string(forType: .string) == nil)
    }
}
