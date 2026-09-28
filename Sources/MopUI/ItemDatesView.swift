import SwiftUI
import MopCore

struct ItemDatesView: View {
    let item: VaultItem
    let lastUsed: Date?
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let date = item.metadata?.createdAt { row("Created", date) }
            if let date = item.metadata?.addedAt { row("Added to 2ndPass", date) }
            if let date = item.metadata?.updatedAt { row("Changed", date) }
            if let lastUsed { row("Last Used on This Device", lastUsed) }
        }.font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
    }
    private func row(_ label: String, _ date: Date) -> some View {
        Text(label + ": " + date.formatted(date: .abbreviated, time: .standard))
    }
}
