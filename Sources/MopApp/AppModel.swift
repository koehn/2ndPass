import AppKit
import SwiftUI
import MopCore
import MopAppSupport

struct MacRecord: Decodable, Identifiable {
    let name: String
    let fingerprint: String
    var id: String { fingerprint }
}
struct Enrollment: Decodable, Identifiable {
    let request: String
    let name: String
    let fingerprint: String
    var id: String { request }
}

enum AppPage: String, CaseIterable { case secrets = "Secrets", devices = "Trusted Macs" }
enum AppSheet: String, Identifiable { case createSecret, addField, replaceSecret, createVault, renameVault, deleteVault, request, trust, approve, selectVault, recover, revoke
    var id: String { rawValue }
}

@MainActor @Observable
final class AppModel {
    let client: CLIClient
    let clipboard: SecretClipboard
    var isActive = true
    var vaults: [VaultDescriptor] = []
    var vault = ""
    var page = AppPage.secrets
    var selectedItem: String?
    var references: [SecretReference] = []
    var selected: SecretReference?
    var search = ""
    var devices: [MacRecord] = []
    var requests: [Enrollment] = []
    var enrollment: Enrollment?
    var revoking: MacRecord?
    var offline = false
    var authenticated = false
    var revealed: SecretBytes?
    var busy = false
    var error: String?
    var notice: String?
    var status = "Select a vault to begin"
    var sheet: AppSheet?
    var deleteConfirmation = false
    private var generation = 0
    private var concealTask: Task<Void, Never>?

    init(client: CLIClient? = nil, clipboard: SecretClipboard? = nil) {
        let executable = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("mop")
            ?? URL(fileURLWithPath: "/nonexistent/mop")
        self.client = client ?? CLIClient(executable: executable)
        self.clipboard = clipboard ?? SecretClipboard()
    }
    var selectedVaultDescriptor: VaultDescriptor? { vaults.first { $0.id == vault } }
    var canExportBackup: Bool { !vault.isEmpty && (selectedVaultDescriptor?.supported == true || authenticated) }
    var vaultName: String { references.first?.vault ?? vaults.first { $0.id == vault }?.name ?? "" }
    var filtered: [SecretReference] {
        references.filter { search.isEmpty || $0.description.localizedCaseInsensitiveContains(search) }
    }
    var items: [String] { Array(Set(filtered.map(\.item))).sorted() }
    var itemFields: [SecretReference] { references.filter { $0.item == selectedItem }.sorted() }
    func selectField(_ reference: SecretReference) { if selected != reference { conceal() }; selected = reference }
    func vaultLabel(_ descriptor: VaultDescriptor) -> String {
        guard let name = descriptor.name else { return "Legacy · " + descriptor.id }
        return vaults.filter { $0.name == name }.count > 1 ? name + " · " + descriptor.id : name
    }
    var selectedVault: String? { vault.isEmpty ? nil : vault }

    func conceal() { revealed = nil; concealTask?.cancel() }
    func clearClipboard() { clipboard.clear() }
    func deactivate() {
        isActive = false
        conceal()
        // The view hides all metadata immediately. A temporary authentication
        // dialog may return focus before the command completes.
        if !busy { lock(clearClipboard: false) }
    }
    func activate() { isActive = true }
    func lock(clearClipboard: Bool = true) {
        generation += 1
        conceal(); if clearClipboard { self.clearClipboard() }; references = []; selected = nil; devices = []; requests = []
        enrollment = nil; revoking = nil; selectedItem = nil; authenticated = false; sheet = nil; notice = nil
        status = "Locked"
    }
    func changedContext() { lock(); status = offline ? "Offline mode · unlock a verified snapshot" : "Ready to authenticate" }

    func perform(_ action: @escaping @MainActor (Int) async throws -> Void) {
        guard !busy else { return }
        busy = true; error = nil; notice = nil
        let token = generation
        Task {
            defer {
                busy = false
                if !isActive { lock(clearClipboard: false) }
            }
            do { try await action(token) }
            catch {
                if token == generation { if case CLIError.failed(let code) = error, [8, 10, 13, 16, 18].contains(code) { self.lock() }
                    self.error = (error as? LocalizedError)?.errorDescription ?? "The operation could not be completed." }
            }
        }
    }
    func current(_ token: Int) -> Bool { token == generation && isActive }

    func discover() {
        perform { token in
            let result = try await self.client.run(["vault", "list", "--json"], offline: self.offline)
            let rows = try result.decode([VaultDescriptor].self)
            let ids = rows.map(\.id)
            guard self.current(token) else { return }
            self.vaults = rows
            // Use the repository's account-scoped default, never an arbitrary vault.
            if self.vault.isEmpty {
                if let result = try? await self.client.run(["vault", "status"]),
                   let status = try? result.decode([String: String].self),
                   let id = status["vault"], ids.contains(id), self.current(token) { self.vault = id }
            } else if !ids.contains(self.vault) { self.vault = ""; self.lock() }
            self.status = ids.isEmpty ? "Create your first vault" : "Choose a vault, then unlock its index"
        }
    }
    func unlock() {
        guard !busy else { return }
        conceal(); references = []; authenticated = false
        perform { token in
            let result = try await self.client.run(["list", "--json"], vault: self.selectedVault, offline: self.offline)
            let refs = try result.decode([String].self).map { try SecretReference($0) }.sorted()
            guard self.current(token) else { return }
            self.references = refs; self.authenticated = true
            if let name = refs.first?.vault {
                self.vaults.removeAll { $0.id == self.vault }
                self.vaults.append(VaultDescriptor(id: self.vault, name: name, format: "mop-vault-v4", enrolled: true))
            } else if self.vaultName.isEmpty {
                let discovery = try await self.client.run(["vault", "list", "--json"], offline: self.offline)
                let rows = try discovery.decode([VaultDescriptor].self)
                guard self.current(token) else { return }
                self.vaults = rows
            }
            if let item = self.selectedItem, !refs.contains(where: { $0.item == item }) { self.selectedItem = nil }
            if let selected = self.selected, !refs.contains(selected) { self.selected = nil }
            self.status = self.offline ? "Read only · verified cache from \(result.offlineDate ?? "unknown time")" : "Index authenticated · values concealed"
        }
    }
    func copyReference() {
        guard let selected else { return }
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(selected.description, forType: .string)
        notice = "Reference copied."
    }
    func read(copy: Bool) {
        guard let selected else { return }
        conceal()
        perform { token in
            let result = try await self.client.run(["read", "--no-newline", selected.description], vault: self.selectedVault, offline: self.offline)
            guard self.current(token), self.selected == selected, NSApplication.shared.isActive else { return }
            if copy {
                self.clipboard.copy(result.output)
                self.notice = "Value copied. Mop clears its clipboard entry after 30 seconds."
            } else {
                self.revealed = result.output
                self.concealTask = Task { [weak self = self] in
                    try? await Task.sleep(for: .seconds(30))
                    guard !Task.isCancelled else { return }; self?.conceal()
                }
            }
            if self.offline { self.status = "Read only · verified cache from \(result.offlineDate ?? "unknown time")" }
        }
    }
    func write(reference: SecretReference, value: String, replace: Bool) {
        guard !offline else { return }
        let value = SecretBytes(utf8: value)
        perform { token in
            _ = try await self.client.run(["write", reference.description] + (replace ? ["--replace"] : []), vault: self.selectedVault, input: value)
            guard self.current(token) else { return }
            if !self.references.contains(reference) { self.references.append(reference); self.references.sort() }
            self.selected = reference; self.selectedItem = reference.item; self.authenticated = true
            self.sheet = nil; self.conceal(); self.notice = "Secret saved to iCloud."
        }
    }
    func delete() {
        guard let selected, !offline else { return }
        perform { token in
            _ = try await self.client.run(["delete", selected.description], vault: self.selectedVault)
            guard self.current(token) else { return }
            self.references.removeAll { $0 == selected }; self.selected = nil; self.conceal()
            if self.itemFields.isEmpty { self.selectedItem = nil }
            self.notice = "Secret deleted. Historical encrypted copies remain."
        }
    }
    func loadDevices() {
        guard !offline else { return }
        perform { token in
            let result = try await self.client.run(["device", "list"], vault: self.selectedVault)
            let devices = try result.decode([MacRecord].self)
            guard self.current(token) else { return }
            self.devices = devices
            let pending = try await self.client.run(["device", "requests"], vault: self.selectedVault)
            guard self.current(token) else { return }
            self.requests = try pending.decode([Enrollment].self).filter { request in !devices.contains { $0.fingerprint == request.fingerprint } }
            self.status = "Device list authenticated"
        }
    }
    func management(_ command: [String], input: String? = nil) {
        guard !offline else { return }
        perform { token in
            let result = try await self.client.run(command, vault: self.selectedVault, input: input.map { SecretBytes(utf8: $0) })
            guard self.current(token) else { return }
            self.sheet = nil; self.notice = result.text
            self.requests = []; self.devices = []
        }
    }
    func sync() {
        guard !offline else { return }
        perform { token in
            _ = try await self.client.run(["vault", "sync"], vault: self.selectedVault)
            guard self.current(token) else { return }
            self.status = "Ciphertext synchronized · unlock to verify the offline snapshot"
        }
    }
    func createVault(name: String, deviceName: String, strict: Bool, recovery: URL) {
        guard !offline, !busy else { return }
        conceal(); references = []; selected = nil; devices = []; requests = []; authenticated = false
        let id = UUID().uuidString
        perform { token in
            // Retain this UUID even on a failed/uncertain initialization for reconciliation.
            self.vault = id; self.vaults.append(VaultDescriptor(id: id, name: name, format: "mop-vault-v4", enrolled: true))
            self.status = "Creating vault \(id) · retain any recovery file written"
            let result = try await self.client.run(["vault", "init", name, "--device-name", deviceName, "--recovery-file", recovery.path] + (strict ? ["--strict-biometrics"] : []), vault: id)
            guard self.current(token) else { return }
            self.references = []; self.selected = nil; self.authenticated = true; self.sheet = nil
            self.notice = result.text; self.status = "Vault created · move the recovery credential offline"
        }
    }
    func renameVault(to name: String) {
        guard !offline, !vault.isEmpty else { return }
        let id = vault
        perform { token in
            _ = try await self.client.run(["vault", "rename", id, name], vault: id)
            guard self.current(token), self.vault == id else { return }
            self.lock()
            if let index = self.vaults.firstIndex(where: { $0.id == id }) {
                let old = self.vaults[index]
                self.vaults[index] = VaultDescriptor(id: id, name: name, format: old.format, enrolled: old.enrolled)
            }
            self.notice = "Vault renamed. Update existing references; unlock to refresh items."
        }
    }
    func deleteVault(target: VaultDescriptor, confirmation: String) {
        guard !offline, !busy, vault == target.id, confirmation == (target.name ?? target.id) else { return }
        conceal(); clearClipboard(); references = []; selected = nil; selectedItem = nil; authenticated = false
        perform { token in
            _ = try await self.client.run(["vault", "delete", target.id, "--yes"], vault: target.id)
            guard self.current(token), self.vault == target.id else { return }
            self.lock()
            self.vaults.removeAll { $0.id == target.id }
            self.vault = ""
            self.notice = "Vault deleted. Backups and caches on other Macs remain."
            self.status = "Vault deleted"
        }
    }

    func chooseExportBackup() {
        guard canExportBackup, !busy else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = (vaultName.isEmpty ? "vault" : vaultName) + ".mopfile"
        panel.title = "Export encrypted backup"
        if panel.runModal() == .OK, let url = panel.url { exportBackup(to: url) }
    }
    func exportBackup(to url: URL) {
        guard canExportBackup, !busy else { return }
        let id = vault
        perform { token in
            _ = try await self.client.run(["vault", "export", "--out-file", url.path], vault: id, offline: self.offline)
            guard self.current(token) else { return }; self.notice = "Encrypted backup exported. Keep your recovery key separately."
        }
    }
}
