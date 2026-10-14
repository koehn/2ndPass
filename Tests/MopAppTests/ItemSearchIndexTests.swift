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
    @Test func reusePreservesFreshRowsAndInvalidatesChangedText() async throws {
        let original = ItemSearchIndex(rows: [row])
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while original.isPreparing && ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(1))
        }
        #expect(!original.isPreparing)
        var latest = row
        latest.recentDate = Date()
        let reused = ItemSearchIndex(rows: [latest], reusing: original)
        while reused.isPreparing && ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(1))
        }
        #expect(reused.reusableEntryCount == 1)
        #expect(reused.search("alice").rows.first?.recentDate == latest.recentDate)
        var changed = row.item
        changed.fields = [ItemField(path: "username", type: .username, value: "bob")]
        let replacement = ItemRow(id: row.id, vaultName: row.vaultName, item: changed)
        let updated = ItemSearchIndex(rows: [replacement], reusing: original)
        while updated.isPreparing && ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(1))
        }
        #expect(!updated.isPreparing)
        #expect(updated.reusableEntryCount == 0)
        #expect(updated.search("alice").rows.isEmpty)
        #expect(updated.search("bob").rows.count == 1)
        let renamed = ItemSearchIndex(rows: [ItemRow(id: row.id, vaultName: "Work", item: row.item)], reusing: original)
        #expect(renamed.reusableEntryCount == 0)
        #expect(renamed.search("personal").rows.isEmpty)
        #expect(ItemSearchIndex(rows: [row], deleted: true, reusing: original).reusableEntryCount == 0)
        #expect(ItemSearchIndex(rows: [], reusing: original).search("alice").rows.isEmpty)
    }

}
