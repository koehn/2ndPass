import SwiftUI
import MopCore

struct SecretHistoryView: View {
    @Bindable var model: AppModel
    let selection: HistorySelection
    @Environment(\.dismiss) private var dismiss
    @State private var revealed: SecretBytes?
    @State private var revealedID: String?
    @State private var restore: String?
    @State private var clear = false
    private var catalog: ItemCatalog? { model.catalogs[selection.vault] }
    private var history: SecretFieldHistory? {
        guard let item = catalog?.items.first(where: { $0.name == selection.item }) else { return nil }
        return catalog?.security?.histories.first { $0.itemID == item.storageID && $0.path == selection.path }
    }
    var body: some View {
        NavigationStack {
            List {
                if model.error != nil { Text(model.errorMessage).foregroundStyle(.red) }
                Text(selection.item + " · " + selection.path).font(.headline)
                Text("The last 20 previous values are retained. Restoring here does not change a password or reactivate a revoked credential at its service.").font(.caption)
                if catalog?.securityEnabled != true { Text("Upgrade this vault from Security to start collecting history.") }
                else if history?.entries.isEmpty != false { Text("No previous values recorded") }
                ForEach(history?.entries ?? []) { entry in
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Replaced \(entry.replacedAt.formatted())")
                        Text(model.isActive && model.authenticated && revealedID == entry.id ? revealed.map { String(decoding: $0, as: UTF8.self) } ?? "••••••••" : "••••••••")
                            .font(.system(.body, design: .monospaced)).privacySensitive()
                        HStack {
                            Button(revealedID == entry.id ? "Conceal" : "Reveal") {
                                if revealedID == entry.id { revealed = nil; revealedID = nil } else { read(entry.id, copy: false) }
                            }
                            Button("Copy") { read(entry.id, copy: true) }
                            Button("Restore…") { restore = entry.id }.disabled(catalog?.canEdit != true || model.offline)
                        }.buttonStyle(.borderless)
                    }
                }
                if let history, !history.entries.isEmpty, catalog?.canEdit == true {
                    Button("Clear History…", role: .destructive) { clear = true }.disabled(model.offline)
                }
            }
            .disabled(model.busy || !model.authenticated)
            .navigationTitle("Secret History")
            .toolbar { Button("Done") { dismiss() } }
            .confirmationDialog("Restore this stored value?", isPresented: Binding(get: { restore != nil }, set: { if !$0 { restore = nil } }), titleVisibility: .visible) {
                Button("Restore Value") {
                    if let entry = restore, let revision = catalog?.revision {
                        revealed = nil; revealedID = nil
                        model.securityOperation(.restoreHistory(entry: entry, revision: revision), vault: selection.vault)
                    }; restore = nil
                }
            } message: { Text("The current value will be added to history. The service's credential will not change.") }
            .confirmationDialog("Clear this field’s history?", isPresented: $clear, titleVisibility: .visible) {
                Button("Clear History", role: .destructive) {
                    if let field = history?.id, let revision = catalog?.revision {
                        revealed = nil; revealedID = nil
                        model.securityOperation(.clearHistory(field: field, revision: revision), vault: selection.vault)
                    }
                }
            } message: { Text("Removes previous values from the current vault and future backups. Earlier revisions, backups, and other copies may retain them.") }
            .task(id: revealedID) {
                guard revealedID != nil else { return }
                do { try await Task.sleep(for: .seconds(30)); revealed = nil; revealedID = nil } catch { }
            }
            .onChange(of: model.isActive) { _, active in if !active { revealed = nil; revealedID = nil } }
            .onChange(of: catalog?.revision) { _, _ in revealed = nil; revealedID = nil }
            .onDisappear { revealed = nil; revealedID = nil }
        }.frame(minWidth: 300, idealWidth: 560, minHeight: 350)
    }
    private func read(_ entry: String, copy: Bool) {
        guard let revision = catalog?.revision else { return }
        let visibility = model.visibilityGeneration
        model.perform { token in
            let result = try await model.service.execute(.readHistory(entry: entry, revision: revision), vault: selection.vault, offline: model.offline)
            guard model.current(token), model.isActive, model.visibilityGeneration == visibility,
                  model.historySelection?.id == selection.id, catalog?.revision == revision, let value = result.value else { return }
            if copy { model.clipboard.copy(value, concealed: true) }
            else { revealed = value; revealedID = entry }
        }
    }
}
