import Foundation
import Testing
import MopCore
import MopAppSupport
@testable import MopApp

@MainActor struct AppModelTests {
    private func fixture(_ script: String) throws -> (AppModel, URL) {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-model-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let executable = directory.appendingPathComponent("mop")
        try Data(("#!/bin/sh\n" + script).utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let model = AppModel(client: CLIClient(executable: executable))
        model.vault = UUID().uuidString
        return (model, directory)
    }
    private func finish(_ model: AppModel) async throws {
        for _ in 0..<500 {
            if !model.busy { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        Issue.record("Operation did not finish")
    }
    @Test func lockDiscardsPendingAuthenticatedIndex() async throws {
        let (model, directory) = try fixture("sleep 0.1\nprintf '[\"mop://personal/github/token\"]'\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        model.unlock()
        model.lock()
        try await finish(model)
        #expect(model.references.isEmpty)
        #expect(!model.authenticated)
        #expect(model.status == "Locked")
    }
    @Test func failedRefreshHidesPreviousIndex() async throws {
        let (model, directory) = try fixture("exit 3\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        model.references = [try SecretReference("mop://personal/github/token")]
        model.authenticated = true
        model.unlock()
        #expect(!model.authenticated)
        #expect(model.references.isEmpty)
        try await finish(model)
        #expect(model.error?.contains("Authentication") == true)
    }
    @Test func successfulIndexContainsNoValuesAndFiltersNamespaces() async throws {
        let (model, directory) = try fixture("printf '[\"mop://personal/github/token\",\"mop://work/db/password\"]'\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        model.unlock(); try await finish(model)
        #expect(model.authenticated)
        #expect(model.revealed == nil)
        #expect(model.namespaces == ["personal", "work"])
        model.namespace = "work"
        #expect(model.filtered.map(\.field) == ["password"])
        model.search = "github"
        #expect(model.filtered.isEmpty)
    }
    @Test func uncertainCreationRetainsReconciliationIDButNotOldIndex() async throws {
        let (model, directory) = try fixture("exit 22\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        let previous = model.vault
        model.references = [try SecretReference("mop://personal/github/token")]
        model.authenticated = true
        model.createVault(name: "Test Mac", strict: false, recovery: directory.appendingPathComponent("unused.key"))
        try await finish(model)
        #expect(model.vault != previous)
        #expect(model.vaults.contains(model.vault))
        #expect(!model.authenticated)
        #expect(model.references.isEmpty)
        #expect(model.error?.contains("uncertain") == true)
    }
}
