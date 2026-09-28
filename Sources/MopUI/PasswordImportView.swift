import SwiftUI
import UniformTypeIdentifiers
import MopCore
import MopAppSupport

struct PasswordImportView: View {
    @Bindable var model: AppModel
    let controls: SheetControls
    @State private var format = ImportFormat.auto
    @State private var destination = ""
    @State private var choosingFile = false
    @State private var document: ImportDocument?
    @State private var preview: ImportPreview?
    @State private var selected = Set<Int>()
    @State private var reviewed = Set<Int>()
    @State private var localError: String?
    @State private var epoch = UUID()
    @State private var reading = false
    @State private var working = false
    @State private var readTask: Task<Void, Never>?
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Import Passwords and Items").font(.title2)
            Text("Choose an unencrypted password-manager export. Existing entries will be kept. Update 2ndPass on connected devices before importing new item types or metadata.").font(.callout)
            Picker("Source", selection: $format) {
                ForEach(ImportFormat.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }.disabled(document != nil || reading)
            Picker("Destination vault", selection: $destination) {
                Text("Choose a vault").tag("")
                ForEach(model.itemCreationVaults) { vault in Text(model.vaultLabel(vault)).tag(vault.id) }
            }.disabled(document != nil || reading)
            Button(document == nil ? "Choose File…" : "Choose Another File…") { clear(); choosingFile = true }
                .disabled(destination.isEmpty || reading)
            if reading { ProgressView("Reading export…") }
            if let preview {
                Text(preview.report.summary).font(.headline)
                rows(preview.report, selectable: true)
                Text("Warnings identify data or behaviors that cannot be migrated. Import proceeds only with the supported data shown above.").font(.caption)
            }
            if let localError { Text(localError).foregroundStyle(.red) }
        }
        .fileImporter(isPresented: $choosingFile, allowedContentTypes: [.commaSeparatedText, .json, .zip, .data]) { result in
            guard case .success(let url) = result else { return }
            let token = epoch, chosenFormat = format
            reading = true
            readTask = Task {
                do {
                    let task = Task.detached { try PasswordImport.read(url, format: chosenFormat) }
                    let parsed = try await withTaskCancellationHandler(operation: { try await task.value }, onCancel: { task.cancel() })
                    guard !Task.isCancelled, epoch == token, model.authenticated, model.isActive else { return }
                    document = parsed; selected = Set(parsed.records.map(\.id)); reading = false; review()
                } catch {
                    guard epoch == token else { return }
                    reading = false; localError = (error as? ImportFailure)?.errorDescription ?? "Could not read the export."
                }
            }
        }
        .onAppear { destination = model.itemCreationVaults.first(where: { $0.id == model.vault })?.id ?? model.itemCreationVaults.first?.id ?? "" }
        .onChange(of: selected) { _, _ in updateControls() }
        .onDisappear { clear() }
        .onChange(of: model.authenticated) { _, value in if !value { clear() } }
        .onChange(of: model.isActive) { _, value in if !value { clear() } }
    }
    private func rows(_ report: ImportReport, selectable: Bool) -> some View {
        LazyVStack(alignment: .leading, spacing: 10) {
            ForEach(report.rows) { row in
                VStack(alignment: .leading) {
                    if selectable && [.ready, .excluded].contains(row.disposition) {
                        Toggle(isOn: Binding(get: { selected.contains(row.id) }, set: { value in
                            if value { selected.insert(row.id) } else { selected.remove(row.id) }
                        })) { Text(row.name + " — " + (row.type?.label ?? "Unknown")) }
                    } else { Text(row.name + " — " + row.disposition.rawValue) }
                    ForEach(Array(row.warnings.enumerated()), id: \.offset) { _, warning in Text(warning).font(.caption).foregroundStyle(.secondary) }
                }
            }
        }
    }
    private func review() {
        guard let document else { return }
        let token = epoch, ids = selected, vault = destination
        working = true
        model.perform { generation in
            defer { if epoch == token { working = false } }
            let result = try await model.service.execute(.previewImport(document, selected: ids), vault: vault, offline: model.offline)
            guard model.current(generation), epoch == token else { return }
            preview = result.importPreview; reviewed = ids; updateControls()
        }
    }
    private func updateControls() {
        guard let preview else {
            controls.title = nil; controls.submit = nil
            controls.secondaryTitle = nil; controls.secondarySubmit = nil
            return
        }
        let needsReview = selected != reviewed
        controls.title = needsReview ? "Review Selection" : "Import \(preview.report.ready) Items"
        controls.canSubmit = needsReview || preview.report.ready > 0
        controls.submit = needsReview ? { review() } : { commit() }
        controls.secondaryTitle = "Refresh Preview"
        controls.secondarySubmit = { review() }
    }
    private func commit() {
        guard let document, let preview, selected == reviewed, !model.busy else { return }
        // Ownership moves to the app model before the sheet clears its source data.
        model.commitImport(document, preview: preview, selected: selected, destination: destination)
    }
    private func clear() {
        if working { model.cancelImportOperation() }; working = false
        epoch = UUID(); readTask?.cancel(); readTask = nil; reading = false
        document = nil; preview = nil; selected = []; reviewed = []; localError = nil
        updateControls()
    }
}
