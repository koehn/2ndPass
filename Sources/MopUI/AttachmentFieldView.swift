import SwiftUI
import UniformTypeIdentifiers
import MopCore
import MopAppSupport

private struct AttachmentDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    var attachment: Attachment
    init(_ attachment: Attachment) { self.attachment = attachment }
    init(configuration: ReadConfiguration) throws {
        guard let data = configuration.file.regularFileContents else { throw AttachmentFailure.invalid }
        attachment = try Attachment(fileName: configuration.file.preferredFilename ?? "attachment", data: data)
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        let wrapper = FileWrapper(regularFileWithContents: attachment.data)
        wrapper.preferredFilename = attachment.fileName
        return wrapper
    }
}

struct AttachmentFieldView: View {
    let model: AppModel
    let editing: Bool
    let existing: Bool
    let reference: SecretReference?
    @Binding var value: String?
    @State private var choosing = false
    @State private var exporting = false
    @State private var document: AttachmentDocument?
    @State private var error: String?
    @State private var generation = UUID()
    private var active: Bool { model.authenticated && model.isActive }
    private var attachment: Attachment? { value.flatMap { try? Attachment.decode($0) } }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let attachment {
                Label(attachment.fileName, systemImage: "paperclip")
                Text(ByteCountFormatter.string(fromByteCount: Int64(attachment.data.count), countStyle: .file)).font(.caption)
            } else {
                Label(existing ? "Encrypted attachment" : "Choose a file to attach", systemImage: "paperclip")
            }
            HStack {
                if editing {
                    Button(value == nil && existing ? "Replace File…" : "Choose File…") { choosing = true }
                }
                if attachment != nil || (existing && reference != nil) {
                    Button("Save File…") { export() }
                }
            }.disabled(!active || model.busy)
            if editing { Text("Up to 8 MiB per file; attachments count toward vault capacity.").font(.caption).foregroundStyle(.secondary) }
            if let error { Text(error).font(.caption).foregroundStyle(.red) }
        }
        .fileImporter(isPresented: $choosing, allowedContentTypes: [.data]) { result in
            guard active, editing, case .success(let url) = result else { return }
            do { value = try AttachmentFiles.read(url).encodedValue(); error = nil; model.activity() }
            catch { self.error = (error as? AttachmentFailure)?.errorDescription ?? "Could not read the selected file." }
        }
        .fileExporter(isPresented: $exporting, document: document, contentType: .data, defaultFilename: document?.attachment.fileName ?? "attachment") { result in
            document = nil
            if case .failure = result { error = "Could not save the attachment." }
        }
        .onChange(of: active) { _, active in if !active { clear() } }
        .onDisappear { clear() }
    }
    private func export() {
        guard active else { return }
        error = nil
        if let attachment { document = AttachmentDocument(attachment); exporting = true }
        else if let reference {
            let token = generation
            model.loadAttachment(reference) { attachment in
                guard token == generation, active else { return }
                document = AttachmentDocument(attachment); exporting = true
            }
        }
    }
    private func clear() {
        generation = UUID(); document = nil; choosing = false; exporting = false; error = nil
    }
}
