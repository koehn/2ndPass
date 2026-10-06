import Foundation
import Testing
@testable import MopUI

struct AlphabetIndexTests {
    private struct Row {
        let id: Int
        let title: String
    }

    @Test func targetsFirstMatchingRowInDisplayedOrder() {
        let rows = [Row(id: 1, title: "apple"), Row(id: 2, title: "Apricot"),
                    Row(id: 3, title: "Banana"), Row(id: 4, title: "Zulu")]
        let targets = AlphabetTarget.build(rows, title: { $0.title }, id: { $0.id })
        #expect(targets.map(\.letter) == ["A", "B", "Z"])
        #expect(targets.map(\.row) == [1, 3, 4])
        let filtered = AlphabetTarget.build(Array(rows.dropFirst()), title: { $0.title }, id: { $0.id })
        #expect(filtered.first?.row == 2)
    }

    @Test func supportsLocaleSpecificLettersAndNonalphabeticTitles() {
        let rows = [Row(id: 1, title: "123"), Row(id: 2, title: ""),
                    Row(id: 3, title: "  istanbul"), Row(id: 4, title: "ızmir"),
                    Row(id: 5, title: "東京")]
        let targets = AlphabetTarget.build(rows, locale: Locale(identifier: "tr_TR"),
                                          title: { $0.title }, id: { $0.id })
        #expect(targets.map(\.letter) == ["#", "İ", "I", "東"])
        #expect(targets.map(\.row) == [1, 3, 4, 5])
        #expect(AlphabetTarget<Int>.build([Row](), title: { $0.title }, id: { $0.id }).isEmpty)
    }
}

extension AlphabetIndexTests {
    @MainActor @Test func cachedTargetsFollowSearchAndCatalogReplacement() {
        func index(_ names: [String]) -> ItemSearchIndex {
            ItemSearchIndex(rows: names.map {
                ItemRow(id: .init(vault: "vault", name: $0), vaultName: "Vault",
                        item: .init(name: $0, fields: []))
            })
        }
        let first = index(["Apple", "Apricot", "Banana"])
        #expect(first.alphabetTargets("").map(\.row.name) == ["Apple", "Banana"])
        #expect(first.alphabetTargets("apricot").map(\.row.name) == ["Apricot"])
        #expect(first.alphabetTargets("missing").isEmpty)
        #expect(first.alphabetTargets("").map(\.row.name) == ["Apple", "Banana"])
        let replaced = index(["Apricot", "Cherry"])
        #expect(replaced.alphabetTargets("").map(\.row.name) == ["Apricot", "Cherry"])
    }

    @MainActor @Test func repeatedAlphabetReadsStayFastForLargeVault() {
        let index = ItemSearchIndex(rows: (0..<5_000).map {
            let name = "Account \($0)"
            return ItemRow(id: .init(vault: "vault", name: name), vaultName: "Vault",
                           item: .init(name: name, fields: []))
        })
        _ = index.alphabetTargets("")
        let elapsed = ContinuousClock().measure {
            for _ in 0..<500 {
                #expect(index.alphabetTargets("").first?.row.name == "Account 0")
            }
        }
        print("Alphabet index: 500 cached reads over 5,000 items: \(elapsed)")
        #expect(elapsed < .seconds(1))
    }
}
