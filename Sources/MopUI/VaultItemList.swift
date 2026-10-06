import SwiftUI
import MopCore

private struct ItemListReveal: Equatable {
    let selection: ItemRow.ID?
    let generation: Int
}

/// Keep the row builder independent of ContentView's detail/selection state.
/// ForEach's implicit row identity also serves as the scroll target: wrapping
/// every row in IDView makes macOS traverse the dynamic rows while diffing.
struct VaultItemList: View {
    @Bindable var model: AppModel
    @State private var directSelection: ItemRow.ID?

    var body: some View {
        ScrollViewReader { proxy in
            List(model.displayedItems, selection: Binding(get: { model.listSelection }, set: { selection in
                model.listSelection = selection
                if model.listSelection == selection { directSelection = selection }
            })) { [model] row in
                VaultItemListRow(model: model, row: row).tag(row.id)
            }
            .disabled(model.busy)
            .id(model.selectionGeneration)
            .task(id: ItemListReveal(selection: model.listSelection, generation: model.selectionGeneration)) {
                if let selection = model.listSelection, selection == directSelection {
                    directSelection = nil
                    return
                }
                await Task.yield()
                guard !Task.isCancelled, let selection = model.listSelection else { return }
                proxy.scrollTo(selection)
            }
            .safeAreaInset(edge: .trailing, spacing: 0) {
                if !model.collection.isRecent {
                    AlphabetIndex(targets: model.alphabetTargets) { id in
                        proxy.scrollTo(id, anchor: .top)
                    }
                    .disabled(model.busy)
                }
            }
        }
    }
}

private struct VaultItemListRow: View {
    @Bindable var model: AppModel
    let row: ItemRow

    var body: some View {
        NavigationLink(value: row.id) {
            if model.conflictItems.contains(row.id) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .accessibilityLabel("Sync conflict — review both versions")
            }
            VaultItemRowLabel(title: row.item.displayTitle, symbol: row.item.type.symbol,
                subtitle: row.subtitle, vaultName: model.allVaults ? row.vaultName : nil,
                recentDate: row.recentDate, searchDetail: row.searchDetail)
        }
        .listRowBackground(model.searchIsFocused && !model.search.isEmpty && model.searchHighlighted == row.id
                           ? Color.accentColor.opacity(0.12) : nil)
        .contextMenu {
            if let identity = row.localIdentity {
                Button("Delete…", role: .destructive) { model.requestLocalDelete(identity.id) }
                    .disabled(model.localDeleteInProgress || model.localCreating)
            } else {
                Button("Delete", role: .destructive) { model.itemToDelete = row }
                    .disabled(model.offline || model.busy)
            }
        }
    }
}
