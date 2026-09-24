import SwiftUI

struct ItemSearchView: View {
    @Bindable var model: AppModel
    let selected: () -> Void
    @FocusState private var focused: Bool
    @State private var highlighted = 0
    private var results: [ItemSearchResult] { model.searchResults }
    private var showing: Bool { focused && !model.search.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField("Find an item or field", text: $model.search)
                .textFieldStyle(.plain).focused($focused)
                .accessibilityLabel("Search items")
                .onSubmit { if results.indices.contains(highlighted) { choose(results[highlighted]) } }
                .onKeyPress(.downArrow) {
                    guard showing, !results.isEmpty else { return .ignored }
                    highlighted = min(highlighted + 1, results.count - 1); return .handled
                }
                .onKeyPress(.upArrow) {
                    guard showing else { return .ignored }
                    highlighted = max(0, highlighted - 1); return .handled
                }
                .onKeyPress(.escape) { focused = false; return .handled }
            if !model.search.isEmpty {
                Button { model.search = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain).foregroundStyle(.secondary).accessibilityLabel("Clear search")
            }
        }
        .padding(.horizontal, 10).frame(height: 36)
        .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
        .overlay(alignment: .topLeading) {
            if showing {
                ScrollViewReader { reader in
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            if results.isEmpty {
                                Text("No matching items").foregroundStyle(.secondary).padding()
                            }
                            ForEach(Array(results.enumerated()), id: \.element.id) { index, result in
                                Button { choose(result) } label: {
                                    HStack(spacing: 10) {
                                        Image(systemName: result.row.item.type.symbol)
                                            .foregroundStyle(Color.accentColor).frame(width: 24)
                                        VStack(alignment: .leading, spacing: 3) {
                                            Text(result.row.item.name).fontWeight(.medium).lineLimit(1)
                                            Text(result.detail).font(.caption).foregroundStyle(Color.secondary).lineLimit(2)
                                            if model.allVaults, result.field != nil {
                                                Text(result.row.vaultName).font(.caption2).foregroundStyle(Color.secondary)
                                            }
                                        }
                                        Spacer(minLength: 0)
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading).padding(10)
                                    .background(highlighted == index ? Color.accentColor.opacity(0.12) : Color.clear)
                                    .contentShape(Rectangle())
                                }
                                // Positions change while typing; keep scroll identity tied to the item.
                                .buttonStyle(.plain).id(result.id)
                                .accessibilityIdentifier("search-result-" + result.row.id.vault + ":" + result.row.id.name)
                            }
                        }
                    }
                    .frame(height: min(300, max(56, CGFloat(results.count) * 82)))
                    .onChange(of: highlighted) { _, index in
                        if results.indices.contains(index) { reader.scrollTo(results[index].id) }
                    }
                }
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.primary.opacity(0.12)))
                .shadow(color: .black.opacity(0.15), radius: 8, y: 4)
                .padding(.top, 42)
            }
        }
        .onChange(of: model.search) { _, _ in highlighted = 0 }
        .onChange(of: model.selectedRow) { _, _ in focused = false }
        .disabled(model.busy)
    }
    private func choose(_ result: ItemSearchResult) {
        model.selectedRow = result.id
        model.search = ""; focused = false
        selected()
    }
}
