import SwiftUI
import MopSync
import MopAppSupport
#if os(iOS)
import UIKit
#endif

struct SyncDiagnosticsView: View {
    private let service: any VaultService
    init(model: AppModel) { service = model.service }
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @State private var previousIdleTimerDisabled: Bool?

    @State private var operations: [SyncOperationDiagnostic] = []
    @State private var discardDay = Calendar.current.date(from: DateComponents(year: 2026, month: 10, day: 16)) ?? Date()
    @State private var summary = ""
    @State private var discardResult: String?
    @State private var report = ""
    @State private var page = 0
    @State private var busy = false
    @State private var failure: String?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("Items can be available while background operations remain unresolved. Retrying preserves local changes and verifies dependencies again.")
                    if !summary.isEmpty { Text(summary) }
                    if let discardResult { Text(discardResult) }
                    if busy { ProgressView("Checking sync operations…") }
                    if let failure { Text(failure).foregroundStyle(.red) }
                    if !busy && operations.isEmpty { Text("No unresolved operations or retained cleanup records.") }
                }
                Section {
                    Text("Showing page \(page + 1) of \(max(1, (operations.count + 24) / 25)) · \(operations.count) operations")
                    HStack {
                        Button("Previous") { page -= 1 }.disabled(page == 0)
                        Spacer()
                        Button("Next") { page += 1 }.disabled((page + 1) * 25 >= operations.count)
                    }
                    Button("Refresh Diagnostics") { Task { await load(retry: false) } }.disabled(busy)
                }
                Section("Discard old work") {
                    DatePicker("Date", selection: $discardDay, displayedComponents: .date)
                    Text("Discards pending work created on this date, including unsent edits. Encrypted recovery records are retained; newer work is preserved.")
                    Button("Discard Work on Selected Date", role: .destructive) {
                        Task {
                            busy = true
                            do {
                                let count = try await service.discardSynchronizationWork(on: discardDay)
                                discardResult = "Discarded \(count) operations. Encrypted recovery records retained."
                                await load(retry: false)
                            } catch { failure = "Could not discard work. Unlock the app and try again." }
                            busy = false
                        }
                    }.disabled(busy)
                }
                ForEach(Self.visibleOperations(operations, page: page)) { operation in
                    Section(operation.resolution == nil ? "Unresolved · \(operation.kind.rawValue)" : "Resolved · \(operation.kind.rawValue)") {
                        LabeledContent("Operation", value: operation.id.uuidString)
                        if let vault = operation.vault { LabeledContent("Vault", value: vault.uuidString) }
                        if let item = operation.item { LabeledContent("Item", value: item.uuidString) }
                        LabeledContent("State", value: operation.state.rawValue)
                        LabeledContent("Created", value: operation.createdAt.formatted())
                        LabeledContent("Attempts", value: String(operation.attempts))
                        if let reason = operation.resolution {
                            Text(resolution(reason))
                            if let date = operation.completedAt { LabeledContent("Resolved", value: date.formatted()) }
                        } else {
                            Text(action(operation))
                            if let next = operation.nextAttempt { LabeledContent("Next attempt", value: next.formatted()) }
                            if let failure = operation.failure { LabeledContent("Failure", value: failure.rawValue) }
                        }
                        if let transport = operation.transport {
                            Text("\(transport.category) (CloudKit \(transport.code))")
                            LabeledContent("Last cloud error", value: transport.occurredAt.formatted())
                        } else if operation.failure == .transport {
                            Text("The earlier app did not retain the underlying cloud error. Retry to collect current diagnostics.")
                        }
                        if let membership = operation.membership { LabeledContent("Required membership", value: membership) }
                        ForEach(operation.records, id: \.self) { Text("Required record: " + $0).font(.caption) }
                        ForEach(operation.dependencies, id: \.self) { Text("Dependency: " + $0).font(.caption) }
                    }.textSelection(.enabled)
                }
            }
            .navigationTitle("Sync Diagnostics")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { ShareLink("Share Diagnostics", item: report) }
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
                ToolbarItem(placement: .primaryAction) { Button("Recheck and Retry") { Task { await load(retry: true) } }.disabled(busy) }
            }
            .task { await load(retry: false) }
        }
        .frame(minWidth: 300, minHeight: 350)
        .onAppear { updateKeepAwake(active: scenePhase == .active) }
        .onChange(of: scenePhase) { _, phase in updateKeepAwake(active: phase == .active) }
        .onDisappear { updateKeepAwake(active: false) }
    }
    private func updateKeepAwake(active: Bool) {
        #if os(iOS)
        if active {
            if previousIdleTimerDisabled == nil {
                previousIdleTimerDisabled = UIApplication.shared.isIdleTimerDisabled
            }
            UIApplication.shared.isIdleTimerDisabled = true
        } else if let previous = previousIdleTimerDisabled {
            UIApplication.shared.isIdleTimerDisabled = previous
            previousIdleTimerDisabled = nil
        }
        #endif
    }
    nonisolated static func visibleOperations(_ operations: [SyncOperationDiagnostic], page: Int) -> [SyncOperationDiagnostic] {
        Array(operations.dropFirst(max(0, page) * 25).prefix(25))
    }
    nonisolated static func diagnosticReport(_ operations: [SyncOperationDiagnostic]) -> String {
        var sections = ["Sync diagnostics · " + Date().ISO8601Format()]
        for operation in operations {
            var lines: [String] = []
            lines.append("Operation: " + operation.id.uuidString)
            lines.append("Kind: " + operation.kind.rawValue + " · State: " + operation.state.rawValue)
            lines.append("Vault: " + (operation.vault?.uuidString ?? "—"))
            lines.append("Created: " + operation.createdAt.ISO8601Format())
            lines.append("Attempts: " + String(operation.attempts))
            lines.append("Next attempt: " + (operation.nextAttempt?.ISO8601Format() ?? "none"))
            lines.append("Failure: " + (operation.failure?.rawValue ?? "none"))
            lines.append("Resolution: " + (operation.resolution?.rawValue ?? "unresolved"))
            lines.append("Records: " + operation.records.joined(separator: ", "))
            lines.append("Dependencies: " + operation.dependencies.joined(separator: ", "))
            if let error = operation.transport {
                lines.append("Cloud error: " + error.category + " (" + String(error.code) + ")")
                lines.append("Last cloud error: " + error.occurredAt.ISO8601Format())
            } else { lines.append("Cloud error: not recorded") }
            sections.append(lines.joined(separator: "\n"))
        }
        return sections.joined(separator: "\n\n")
    }
    private func load(retry: Bool) async {
        busy = true; failure = nil
        defer { busy = false }
        do {
            if retry { try await service.requestSynchronization(refreshPrerequisites: true) }
            let snapshot = try await service.synchronizationDiagnostics()
            let exported = await Task.detached(priority: .utility) { Self.diagnosticReport(snapshot) }.value
            try Task.checkCancellation()
            operations = snapshot
            let pending = snapshot.filter { $0.state != .completed }.count
            summary = "\(pending) pending · \(snapshot.count - pending) resolved or discarded"
            report = exported
            page = min(page, max(0, (snapshot.count - 1) / 25))
        } catch { failure = "Could not check sync operations. Unlock the app and try again." }
    }
    private func resolution(_ reason: SyncResolution) -> String {
        switch reason {
        case .discardedByUser: "Discarded at your request. Encrypted recovery records were retained; this does not confirm cloud delivery."
        case .verifiedMembershipAvailable: "The exact requested membership is already verified locally. Its dependent work remains queued for normal checks."
        case .verifiedContentAvailable: "The exact requested content version is already verified locally. No upload was marked delivered."
        case .unneededGrantSource: "An unused grant and its missing-source request were archived. Verified current content has replacement access. No cloud delivery was assumed."
        case .obsoleteGrantGeneration: "Verified successor content supersedes the requested key generation. The obsolete request was retired without issuing access or claiming delivery."
        case .obsoleteGrantRequester: "The trusted membership history proves this grant requester was removed. The obsolete request was retired."
        }
    }
    private func action(_ operation: SyncOperationDiagnostic) -> String {
        if operation.state == .needsAttention && operation.failure == .transport {
            return "Required cloud data was unavailable. Keep an authorized device online, then recheck and retry. If it remains missing, retain these details for targeted recovery; do not reset the vault."
        }
        if operation.dependencies.contains(where: { $0.hasPrefix("trustedContentZone:") }) {
            return "Waiting for independently verified access to this vault. Network retries are paused; approving or recovering the vault can resume this operation."
        }
        if operation.failure == .authorization { return "Unlock an authorized device to continue." }
        if operation.failure == .invalidAuthority { return "Verification failed. The record remains preserved for investigation." }
        if !operation.dependencies.isEmpty { return "Waiting for verified dependencies. Recheck to resolve satisfied work; unresolved work is preserved." }
        return "This operation remains pending. Automatic retry timing and cloud throttling are preserved."
    }
}
