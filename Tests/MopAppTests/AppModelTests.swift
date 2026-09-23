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
    @Test func backgroundCompletionLocksAndDiscardsIndex() async throws {
        let (model, directory) = try fixture("sleep 0.1\nprintf '[\"mop://personal/github/token\"]'\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        model.unlock()
        model.deactivate()
        #expect(!model.isActive)
        try await finish(model)
        #expect(model.references.isEmpty)
        #expect(!model.authenticated)
        model.activate()
        #expect(model.status == "Locked")
        #expect(model.references.isEmpty)
    }
    @Test func authenticationFocusReturnAllowsPendingResult() async throws {
        let (model, directory) = try fixture("sleep 0.1\nprintf '[\"mop://personal/github/token\"]'\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        model.unlock()
        model.deactivate()
        model.activate()
        try await finish(model)
        #expect(model.authenticated)
        #expect(model.references.count == 1)
    }
    @Test func backgroundMutationFinishesButDoesNotRestoreVisibleState() async throws {
        let (model, directory) = try fixture("sleep 0.1\ncat > /dev/null\ntouch \"$(dirname \"$0\")/committed\"\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        model.references = [try SecretReference("mop://personal/github/token")]
        model.authenticated = true
        model.write(reference: model.references[0], value: "fixture", replace: true)
        model.deactivate()
        try await finish(model)
        #expect(FileManager.default.fileExists(atPath: directory.appendingPathComponent("committed").path))
        #expect(!model.authenticated)
        #expect(model.references.isEmpty)
        #expect(model.notice == nil)
    }
    @Test func successfulIndexContainsNoValuesAndGroupsItems() async throws {
        let (model, directory) = try fixture("printf '[\"mop://personal/github/token\",\"mop://personal/github/password\"]'\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        model.unlock(); try await finish(model)
        #expect(model.authenticated)
        #expect(model.revealed == nil)
        #expect(model.items == ["github"])
        model.selectedItem = "github"
        #expect(model.itemFields.map(\.field) == ["password", "token"])
        model.search = "missing"
        #expect(model.filtered.isEmpty)
    }
    @Test func uncertainCreationRetainsReconciliationIDButNotOldIndex() async throws {
        let (model, directory) = try fixture("exit 22\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        let previous = model.vault
        model.references = [try SecretReference("mop://personal/github/token")]
        model.authenticated = true
        model.createVault(name: "personal", deviceName: "Test Mac", strict: false, recovery: directory.appendingPathComponent("unused.key"))
        try await finish(model)
        #expect(model.vault != previous)
        #expect(model.vaults.contains { $0.id == model.vault })
        #expect(!model.authenticated)
        #expect(model.references.isEmpty)
        #expect(model.error?.contains("uncertain") == true)
    }
}

extension AppModelTests {
    @Test func fieldActionsKeepOneItemAndRemoveItAfterLastDelete() async throws {
        let (model, directory) = try fixture("cat > /dev/null\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        let first = try SecretReference("mop://personal/mycloud/sshd")
        let second = try SecretReference("mop://personal/mycloud/admin/password")
        model.write(reference: first, value: "one", replace: false); try await finish(model)
        model.write(reference: second, value: "two", replace: false); try await finish(model)
        #expect(model.items == ["mycloud"])
        #expect(model.itemFields.count == 2)
        model.revealed = "two"
        model.selectField(first)
        #expect(model.revealed == nil)
        model.delete(); try await finish(model)
        #expect(model.items == ["mycloud"] && model.selectedItem == "mycloud")
        model.selectField(second)
        model.delete(); try await finish(model)
        #expect(model.items.isEmpty && model.selectedItem == nil)
    }

    @Test func renameKeepsUUIDAndLocksOldReferences() async throws {
        let (model, directory) = try fixture("printf '%s\\n' \"$@\" > \"$(dirname \"$0\")/arguments\"\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        let id = model.vault
        model.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-vault-v4", enrolled: true)]
        model.references = [try SecretReference("mop://personal/mycloud/sshd")]
        model.authenticated = true
        model.renameVault(to: "private"); try await finish(model)
        #expect(model.vault == id && model.vaultName == "private")
        #expect(!model.authenticated && model.references.isEmpty)
        let args = try String(contentsOf: directory.appendingPathComponent("arguments"), encoding: .utf8)
        #expect(args == "vault\nrename\n\(id)\nprivate\n--vault\n\(id)\n")
    }

    @Test func contextChangeDiscardsPendingRenameDisplay() async throws {
        let (model, directory) = try fixture("sleep 0.1\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        model.vaults = [VaultDescriptor(id: model.vault, name: "personal", format: "mop-vault-v4", enrolled: true)]
        model.renameVault(to: "private")
        model.changedContext()
        try await finish(model)
        #expect(model.vaults.first?.name == "personal")
        #expect(model.notice == nil)
    }
}

extension AppModelTests {
    @Test func deleteRequiresTypedConfirmationAndUsesFixedUUID() async throws {
        let (model, directory) = try fixture("printf '%s\\n' \"$@\" > \"$(dirname \"$0\")/arguments\"\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        let id = model.vault
        let target = VaultDescriptor(id: id, name: "personal", format: "mop-vault-v4", enrolled: true)
        let other = VaultDescriptor(id: UUID().uuidString, name: "work", format: "mop-vault-v4", enrolled: true)
        model.vaults = [target, other]
        model.deleteVault(target: target, confirmation: "wrong")
        #expect(!model.busy && !FileManager.default.fileExists(atPath: directory.appendingPathComponent("arguments").path))
        model.offline = true
        model.deleteVault(target: target, confirmation: "personal")
        #expect(!model.busy)
        model.offline = false
        model.references = [try SecretReference("mop://personal/item/field")]
        model.authenticated = true; model.revealed = "hidden"
        model.deleteVault(target: target, confirmation: "personal")
        #expect(model.revealed == nil && model.references.isEmpty)
        try await finish(model)
        #expect(model.vault.isEmpty && model.vaults == [other])
        #expect(try String(contentsOf: directory.appendingPathComponent("arguments"), encoding: .utf8) == "vault\ndelete\n\(id)\n--yes\n--vault\n\(id)\n")
    }

    @Test func legacyDeletionAndUncertainFailureKeepRetryTarget() async throws {
        let (model, directory) = try fixture("exit 27\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = VaultDescriptor(id: model.vault, name: nil, format: "mop-vault-v3", enrolled: false)
        model.vaults = [target]
        #expect(!model.canExportBackup)
        model.deleteVault(target: target, confirmation: "legacy")
        #expect(!model.busy)
        model.deleteVault(target: target, confirmation: target.id)
        try await finish(model)
        #expect(model.vault == target.id && model.vaults == [target])
        #expect(model.error?.contains("could not be confirmed") == true)
    }

    @Test func pendingDeleteDoesNotReplaceChangedContext() async throws {
        let (model, directory) = try fixture("sleep 0.1\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = VaultDescriptor(id: model.vault, name: "personal", format: "mop-vault-v4", enrolled: true)
        model.vaults = [target]
        model.deleteVault(target: target, confirmation: "personal")
        let other = UUID().uuidString
        model.vault = other; model.changedContext()
        try await finish(model)
        #expect(model.vault == other && model.notice == nil)
    }

    @Test func exportFromDeleteSheetUsesSelectedVaultAndOfflineFlag() async throws {
        let (model, directory) = try fixture("printf '%s\\n' \"$@\" > \"$(dirname \"$0\")/arguments\"\nprintf encrypted-fixture > \"$4\"\n")
        defer { try? FileManager.default.removeItem(at: directory) }
        let id = model.vault
        model.vaults = [VaultDescriptor(id: id, name: "personal", format: "mop-vault-v4", enrolled: true)]
        model.sheet = .deleteVault; model.offline = true
        let backup = directory.appendingPathComponent("backup.mopfile")
        model.exportBackup(to: backup); try await finish(model)
        #expect(try String(contentsOf: backup, encoding: .utf8) == "encrypted-fixture")
        #expect(try String(contentsOf: directory.appendingPathComponent("arguments"), encoding: .utf8) == "vault\nexport\n--out-file\n\(backup.path)\n--vault\n\(id)\n--offline\n")
        #expect(model.sheet == .deleteVault && model.notice?.contains("backup exported") == true)
    }
}
