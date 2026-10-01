import SwiftUI

struct ItemSearchBar: View {
    @Bindable var model: AppModel
    @FocusState private var focused: Bool
    private var rows: [ItemRow] { model.page == .recentlyDeleted ? model.deletedRows : model.displayedItems }
    var body: some View {
        HStack {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField("Search " + model.searchScope, text: Binding(get: { model.search }, set: {
                ItemSearchIndex.noteInput()
                model.search = $0
            }))
                .textFieldStyle(.plain)
                .focused($focused)
                .accessibilityLabel("Search " + model.searchScope).accessibilityIdentifier("Item search")
            if !model.search.isEmpty {
                Button("Clear Search", systemImage: "xmark.circle.fill") { model.search = "" }
                    .labelStyle(.iconOnly).buttonStyle(.plain).help("Clear Search")
            }
        }
        .padding(8).background(.quaternary, in: RoundedRectangle(cornerRadius: 8)).padding(10)
        .onChange(of: model.searchFocusRequest) { _, _ in focused = true }
        .onChange(of: model.collection) { _, _ in focused = false }
        .onChange(of: focused) { _, value in model.searchIsFocused = value }
        .onDisappear { model.searchIsFocused = false }
        .onChange(of: model.search) { _, _ in model.searchHighlighted = rows.first?.id }
        .onChange(of: model.selectedRow) { _, _ in focused = false }
        .onChange(of: model.selectedDeleted) { _, _ in focused = false }
        .onSubmit { openHighlighted() }
        .onKeyPress(.downArrow) { guard focused else { return .ignored }; move(1); return .handled }
        .onKeyPress(.upArrow) { guard focused else { return .ignored }; move(-1); return .handled }
        .onKeyPress(.escape) {
            guard focused else { return .ignored }
            if model.search.isEmpty { focused = false } else { model.search = "" }
            return .handled
        }
    }
    private func move(_ offset: Int) {
        guard !rows.isEmpty else { return }
        let current = rows.firstIndex { $0.id == model.searchHighlighted } ?? (offset > 0 ? -1 : rows.count)
        model.searchHighlighted = rows[min(rows.count - 1, max(0, current + offset))].id
    }
    private func openHighlighted() {
        guard let row = rows.first(where: { $0.id == model.searchHighlighted }) ?? rows.first else { return }
        if model.page == .recentlyDeleted { model.selectedDeleted = row.id }
        else { model.selectedRow = row.id }
        focused = false
    }
}

struct SearchSummary: View {
    let model: AppModel
    var body: some View {
        HStack {
            Text(model.searchScope)
            Spacer()
            let count = model.isLocalVaultSelected ? model.displayedLocalIdentities.count : model.page == .recentlyDeleted ? model.deletedRows.count : model.displayedItems.count
            Text("\(count) \(count == 1 ? "result" : "results")")
        }.font(.caption).foregroundStyle(.secondary).padding(.horizontal, 12).padding(.vertical, 6)
    }
}
