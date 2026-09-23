import SwiftUI

struct RecentlyDeletedList: View {
    @Bindable var model: AppModel
    var body: some View {
        VStack(spacing: 0) {
            HStack { Text("Recently Deleted").font(.headline); Spacer() }.padding()
            if model.authenticated {
                List(model.deletedRows, selection: $model.selectedDeleted) { row in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(row.item.deletion?.originalName ?? row.item.name).fontWeight(.medium)
                        Text(row.vaultName).font(.caption).foregroundStyle(.secondary)
                    }.padding(.vertical, 5).tag(row.id)
                        .contextMenu {
                            Button("Restore") { model.restoreDeletedItem(row) }.disabled(model.offline || model.busy)
                        }
                }.searchable(text: $model.search, prompt: "Find deleted items").disabled(model.busy)
                if model.deletedRows.isEmpty { Text("No recently deleted items").foregroundStyle(.secondary).padding() }
            } else {
                ContentUnavailableView {
                    Label("Recently Deleted is locked", systemImage: "lock")
                } description: { Text("Unlock to view deleted items from your enrolled vaults.") }
                actions: { Button("Unlock") { model.unlock() }.disabled(model.busy) }
            }
        }
    }
}

struct RecentlyDeletedDetail: View {
    @Bindable var model: AppModel
    var body: some View {
        if model.authenticated, let row = model.selectedDeletedItem, let deletion = row.item.deletion {
            VStack(alignment: .leading, spacing: 16) {
                Label(row.vaultName + " › Recently Deleted", systemImage: "trash").foregroundStyle(.secondary)
                Text(deletion.originalName).font(.largeTitle).fontWeight(.semibold)
                Text("Deleted " + deletion.deletedAt.formatted(date: .abbreviated, time: .shortened))
                Text("Expires " + deletion.expiresAt.formatted(date: .abbreviated, time: .shortened))
                    .foregroundStyle(.secondary)
                ForEach(row.item.fields, id: \.path) { field in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(field.path.removingPercentEncoding ?? field.path).font(.caption).foregroundStyle(.secondary)
                        Text(field.type.concealed ? "••••••••" : (field.value ?? ""))
                    }
                }
                Button("Restore item") { model.restoreDeletedItem(row) }
                    .buttonStyle(.borderedProminent).disabled(model.busy || model.offline)
                Text("Restore to the original vault to edit or reveal values. An existing item with the same name must be renamed first.")
                    .font(.caption).foregroundStyle(.secondary)
                if model.offline { Text("Restoring requires iCloud.").font(.caption) }
            }.padding(28).frame(maxWidth: .infinity, alignment: .leading)
        } else {
            ContentUnavailableView("Recently Deleted", systemImage: "trash",
                description: Text("Deleted items can be restored for 30 days. Expired items are removed when Mop is unlocked and online."))
                .padding(.top, 60)
        }
    }
}
