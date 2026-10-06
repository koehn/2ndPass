import Foundation
import SwiftUI

/// Targets are taken from the displayed order, so filtering and localized sorting
/// stay in agreement with the index. Index navigation never changes selection.
struct AlphabetTarget<ID: Hashable>: Identifiable {
    let letter: String
    let row: ID
    var id: String { letter }

    static func build<Row>(_ rows: [Row], locale: Locale = .current,
                           title: (Row) -> String, id: (Row) -> ID) -> [Self] {
        var seen = Set<String>()
        return rows.compactMap { row in
            let initial = title(row).trimmingCharacters(in: .whitespacesAndNewlines).first
            let letter = initial.map { $0.isLetter ? String($0).uppercased(with: locale) : "#" } ?? "#"
            guard seen.insert(letter).inserted else { return nil }
            return Self(letter: letter, row: id(row))
        }
    }
}

struct AlphabetIndex<ID: Hashable>: View {
    let targets: [AlphabetTarget<ID>]
    let jump: (ID) -> Void

    var body: some View {
        if !targets.isEmpty {
            GeometryReader { geometry in
                ScrollView(.vertical) {
                    VStack(spacing: 0) {
                        ForEach(targets) { target in
                            Button { jump(target.row) } label: {
                                Text(target.letter)
                                    .font(.system(size: 11, weight: .semibold))
                                    .frame(width: 28, height: 22)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(.tint)
                            .accessibilityLabel("Jump to \(target.letter)")
                            .help("Jump to \(target.letter)")
                        }
                    }
                }
                .scrollIndicators(.hidden)
                .frame(height: min(geometry.size.height, CGFloat(targets.count) * 22))
                .frame(maxHeight: .infinity)
            }
            .frame(width: 28)
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Alphabet index")
        }
    }
}
