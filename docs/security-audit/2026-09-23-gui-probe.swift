// Copy to Tests/MopAppTests/SecurityAuditTests.swift, run the named test, then remove.
// This models the exact didResignActive handler; it does not drive the native UI.
import Foundation
import Testing
import MopCore
import MopAppSupport
@testable import MopApp

@MainActor struct SecurityAuditTests {
    @Test func backgroundUnlockRetainsIndex() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-gui-audit-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let executable = root.appendingPathComponent("mop")
        try Data("#!/bin/sh\nsleep 0.2\nprintf '[\"mop://fixture/private/name\"]'\n".utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let model = AppModel(client: CLIClient(executable: executable))
        model.vault = UUID().uuidString
        model.unlock()
        #expect(model.busy)
        // MopApplication's inactive notification skips lock while a command runs.
        model.conceal()
        if !model.busy { model.lock(clearClipboard: false) }
        for _ in 0..<500 {
            if !model.busy { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(!model.busy)
        #expect(model.authenticated)
        #expect(model.references.map(\.description) == ["mop://fixture/private/name"])
        print("CONFIRMED: inactive-handler path permits delayed unlock to publish the private index.")
    }
}
