#if os(macOS)
import AppKit
import Testing
@testable import MopUI

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
        let model = AppModel(breachClient: TestBreachClient(), clipboard: clipboard)
        clipboard.copy("fixture-secret")
        model.deactivate()
        #expect(board.string(forType: .string) == "fixture-secret")
        model.lock()
        #expect(board.string(forType: .string) == nil)
    }
}

extension SecretClipboardTests {
    @Test func visibleValueReplacesSecretAndSurvivesExpiryAndLock() async throws {
        let board = NSPasteboard.withUniqueName()
        defer { board.releaseGlobally() }
        let clipboard = SecretClipboard(pasteboard: board, lifetime: .milliseconds(50))
        clipboard.copy("old-secret")
        clipboard.copy("alice@example.com", concealed: false)
        #expect(board.types?.contains(NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")) != true)
        try await Task.sleep(for: .milliseconds(150))
        #expect(board.string(forType: .string) == "alice@example.com")
        let model = AppModel(breachClient: TestBreachClient(), clipboard: clipboard, automaticTimer: false)
        model.lock()
        #expect(board.string(forType: .string) == "alice@example.com")
        clipboard.copy("new-secret")
        model.lock()
        #expect(board.string(forType: .string) == nil)
    }
}

#endif

#if os(iOS)
import UIKit
import Testing
@testable import MopUI

@MainActor struct MobileClipboardTests {
    @Test func secretExpiryAndReplacementOwnership() async throws {
        let name = UIPasteboard.Name("mop-test-" + UUID().uuidString)
        let board = try #require(UIPasteboard(name: name, create: true))
        defer { UIPasteboard.remove(withName: name) }
        board.string = "warmup"
        #expect(board.string == "warmup")
        let clipboard = SecretClipboard(pasteboard: board, lifetime: .seconds(2))
        clipboard.copy("secret")
        #expect(board.string == "secret")
        try await Task.sleep(for: .seconds(3))
        #expect(board.string == nil)
        clipboard.copy("secret")
        board.string = "new-owner"
        clipboard.clear()
        #expect(board.string == "new-owner")
        clipboard.copy("visible", concealed: false)
        clipboard.clear()
        #expect(board.string == "visible")
    }
}
#endif
