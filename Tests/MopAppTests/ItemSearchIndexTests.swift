import Foundation
import Testing
import MopCore
@testable import MopUI

@MainActor struct ItemSearchIndexTests {
    private var row: ItemRow {
        var item = VaultItem(name: "Account", fields: [
            ItemField(path: "username", type: .username, value: "alice"),
            ItemField(path: "password", type: .password, value: "concealed-marker")
        ])
        item.metadata = ItemMetadata(tags: ["Team"])
        return ItemRow(id: .init(vault: "vault", name: item.name), vaultName: "Personal", item: item)
    }

    @Test func rowsAndQueriesWorkBeforeAndAfterBackgroundPreparation() async throws {
        let index = ItemSearchIndex(rows: [row])
        // Completion cannot publish until this main-actor turn yields.
        #expect(index.isPreparing)
        #expect(index.search("").rows.count == 1)
        #expect(index.search("ALICE").results.first?.detail == "username: alice")
        #expect(index.search("concealed-marker").rows.isEmpty)
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while index.isPreparing && ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(1))
        }
        #expect(!index.isPreparing)
        #expect(index.search("team").rows.count == 1)
        #expect(index.search("alice").results.first?.detail == "username: alice")
        #expect(index.search("concealed-marker").rows.isEmpty)
    }

    @Test func backgroundPreparationDoesNotRetainDiscardedIndex() {
        var index: ItemSearchIndex? = ItemSearchIndex(rows: Array(repeating: row, count: 5_000))
        weak var discarded = index
        #expect(index?.isPreparing == true)
        index = nil
        #expect(discarded == nil)
    }
}
