import SwiftUI

extension View {
    func mopSearch(model: AppModel) -> some View { modifier(ItemSearchModifier(model: model)) }
}
private struct ItemSearchModifier: ViewModifier {
    @Bindable var model: AppModel
    @FocusState private var focused: Bool
    @State private var presented = false
    private var rows: [ItemRow] { model.page == .recentlyDeleted ? model.deletedRows : model.displayedItems }
    func body(content: Content) -> some View {
        content
            .searchable(text: $model.search, isPresented: $presented, placement: .toolbar, prompt: "Search " + model.searchScope)
            .searchFocused($focused)
            .onChange(of: model.searchFocusRequest) { _, _ in presented = true; focused = true }
            .onChange(of: focused) { _, value in model.searchIsFocused = value }
            .onChange(of: model.search) { _, _ in model.searchHighlighted = rows.first?.id }
            .onChange(of: model.selectedRow) { _, _ in focused = false }
            .onChange(of: model.selectedDeleted) { _, _ in focused = false }
            .onSubmit(of: .search) { openHighlighted() }
            .onKeyPress(.downArrow) { guard focused else { return .ignored }; move(1); return .handled }
            .onKeyPress(.upArrow) { guard focused else { return .ignored }; move(-1); return .handled }
            .onKeyPress(.escape) {
                guard focused else { return .ignored }
                if model.search.isEmpty { focused = false; presented = false } else { model.search = "" }
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
            let count = model.page == .recentlyDeleted ? model.deletedRows.count : model.displayedItems.count
            Text("\(count) \(count == 1 ? "result" : "results")")
        }.font(.caption).foregroundStyle(.secondary).padding(.horizontal, 12).padding(.vertical, 6)
    }
}
