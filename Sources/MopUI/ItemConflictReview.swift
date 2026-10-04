import SwiftUI
import MopCore
import MopAppSupport

struct ItemConflictInbox: View {
    let model: AppModel
    var body: some View {
        if !model.conflictPreviews.isEmpty {
            Button { model.reviewConflict() } label: {
                Label("Review \(model.conflictPreviews.count) sync conflicts", systemImage: "exclamationmark.arrow.triangle.2.circlepath")
                    .foregroundStyle(.orange)
            }.padding(8)
        }
        if let failure = model.conflictFailure {
            Text(failure).font(.caption).foregroundStyle(.orange)
            Button("Retry conflict check") { model.refreshConflicts() }
        }
    }
}

struct ItemConflictBanner: View {
    let model: AppModel
    let item: ItemRow.ID
    var body: some View {
        if model.conflictItems.contains(item) {
            VStack(alignment: .leading, spacing: 8) {
                Label("Sync conflict", systemImage: "exclamationmark.triangle.fill")
                    .font(.headline).foregroundStyle(.orange)
                Text("This item has conflicting changes. Both versions are preserved. Other items continue syncing.")
                Button("Review conflict") { model.reviewConflict(item) }
            }
            .padding().frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
            .accessibilityIdentifier("item-sync-conflict")
        } else if let failure = model.conflictFailure {
            Text(failure).font(.caption).foregroundStyle(.orange)
            Button("Retry conflict check") { model.refreshConflicts() }
        }
    }
}

struct ItemConflictReview: View {
    @Bindable var model: AppModel
    private var previews: [ItemVaultConflictPreview] {
        guard let item = model.conflictReviewItem else { return model.conflictPreviews }
        return model.conflictPreviews.filter {
            $0.conflict.local.scope.vaultID.uuidString == item.vault && $0.local.item.name == item.name
        }
    }
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Text("The version you choose will sync to your other devices.").font(.subheadline).foregroundStyle(.secondary)
                    ForEach(previews, id: \.conflict.id) { preview in
                        ItemConflictEditor(service: model.service, preview: preview,
                            refresh: { model.refreshConflicts() },
                            resolved: {
                                model.conflictReviewPresented = false
                                model.conflictReviewItem = nil
                                model.refreshConflicts()
                            })
                            .id(preview.conflict.local.versionID.uuidString + preview.conflict.remote.versionID.uuidString + preview.conflict.serverSystemFields.base64EncodedString())
                    }
                    if previews.isEmpty { Text("No conflicts to review.") }
                    if let failure = model.conflictFailure { Text(failure).foregroundStyle(.orange) }
                }.padding()
            }
            .navigationTitle("Sync Conflicts")
            .toolbar {
                Button("Cancel") {
                    model.conflictReviewPresented = false
                    model.conflictReviewItem = nil
                }.keyboardShortcut(.cancelAction)
            }
        }.frame(minWidth: 320, idealWidth: 640, minHeight: 400)
    }
}

private struct ItemConflictEditor: View {
    let service: any VaultService
    let preview: ItemVaultConflictPreview
    let refresh: () async -> Void
    let resolved: () -> Void
    @State private var busy = false
    @State private var failure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(preview.local.item.name).font(.title2.bold())
            Text("Which version do you want to keep?")
            version(name: preview.localDeviceName, date: preview.localUpdatedAt,
                    deleted: preview.local.item.deletion != nil, choice: .local)
            version(name: preview.remoteDeviceName, date: preview.remoteUpdatedAt,
                    deleted: preview.remote.item.deletion != nil, choice: .remote)
            if let failure { Text(failure).foregroundStyle(.red) }
            if busy { ProgressView("Saving your choice…") }
        }
        .disabled(busy)
    }

    private func version(name: String, date: Date?, deleted: Bool, choice: ItemConflictChoice) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                Text(name).font(.headline)
                if let date {
                    Text("Updated " + date.formatted(date: .abbreviated, time: .standard))
                        .foregroundStyle(.secondary)
                } else {
                    Text("Update time unavailable").foregroundStyle(.secondary)
                }
                if deleted { Label("Deleted on this device", systemImage: "trash") }
                Button("Keep this version") { resolve(choice) }
                    .buttonStyle(.borderedProminent)
                    .accessibilityLabel("Keep version from " + name)
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func resolve(_ choice: ItemConflictChoice) {
        busy = true; failure = nil
        // A successful save can remove this row through observation before the
        // service returns. Let the completion close the dialog in that case.
        Task {
            do { try await service.resolve(preview, choice: choice); resolved() }
            catch { failure = "Could not save your choice. Both versions are still preserved. Please try again."; await refresh() }
            busy = false
        }
    }
}
