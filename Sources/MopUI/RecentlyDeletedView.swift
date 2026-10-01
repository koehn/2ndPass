import SwiftUI

struct RecentlyDeletedList: View {
    @Bindable var model: AppModel
    var body: some View {
        VStack(spacing: 0) {
            ItemSearchBar(model: model)
            SearchSummary(model: model)
            if model.authenticated {
                List(model.deletedRows, selection: $model.deletedListSelection) { row in
                    NavigationLink(value: row.id) { VStack(alignment: .leading, spacing: 4) {
                        Text(row.item.deletion?.originalName ?? row.item.name).fontWeight(.medium)
                        Text(row.vaultName).font(.caption).foregroundStyle(.secondary)
                    }.padding(.vertical, 5) }.tag(row.id)
                        .listRowBackground(model.searchIsFocused && !model.search.isEmpty && model.searchHighlighted == row.id ? Color.accentColor.opacity(0.12) : nil)
                        .contextMenu {
                            Button("Restore") { model.restoreDeletedItem(row) }.disabled(model.offline || model.busy)
                        }
                }.disabled(model.busy)
                if model.deletedRows.isEmpty && !model.search.isEmpty { Button("Clear Search") { model.search = "" } }
                if model.deletedRows.isEmpty { Text(model.search.isEmpty ? "No recently deleted items" : "No Search Results").foregroundStyle(.secondary).padding() }
            } else {
                ContentUnavailableView {
                    Label("Recently Deleted is locked", systemImage: "lock")
                } description: { Text("Unlock 2ndPass to view recently deleted items.") }
                actions: { Button("Unlock 2ndPass") { model.unlock() }.disabled(!model.canUnlock) }
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
                Text(deletion.originalName).font(.title2).fontWeight(.semibold)
                ItemDatesView(item: row.item, lastUsed: model.lastUsedDate(for: row.item, vaultID: row.id.vault))
                Text("Deleted " + deletion.deletedAt.formatted(date: .abbreviated, time: .shortened))
                Text("Expires " + deletion.expiresAt.formatted(date: .abbreviated, time: .shortened))
                    .foregroundStyle(.secondary)
                if let tags = row.item.metadata?.tags, !tags.isEmpty { TagBadges(tags: tags) }
                ForEach(row.item.fields, id: \.path) { field in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(field.path.removingPercentEncoding ?? field.path).font(.caption).foregroundStyle(.secondary)
                        if field.type.concealed { Text("••••••••") }
                        else { Text(field.value ?? "").textSelection(.enabled) }
                    }
                }
                Button("Restore item") { model.restoreDeletedItem(row) }
                    .buttonStyle(.borderedProminent).disabled(model.busy || model.offline)
                Text("Restore to the original vault to edit or reveal values. An existing item with the same name must be renamed first.")
                    .font(.caption).foregroundStyle(.secondary)
                if model.offline { Text("Restoring requires iCloud.").font(.caption) }
            }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
        } else {
            ContentUnavailableView("Recently Deleted", systemImage: "trash",
                description: Text("Deleted items can be restored for 30 days. Expired items are removed when 2ndPass is unlocked and online."))
                .padding(.top, 60)
        }
    }
}
