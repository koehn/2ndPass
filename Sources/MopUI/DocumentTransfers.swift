import SwiftUI
import UniformTypeIdentifiers
import MopCore
import MopAppSupport

struct DocumentRequest: Identifiable {
    let id = UUID()
    let vault: String
    let generation: Int
}

extension View {
    func documentTransfers(model: AppModel, inSheet: Bool = false, inSettings: Bool = false) -> some View {
        modifier(DocumentTransfers(model: model, inSheet: inSheet, inSettings: inSettings))
    }
}

private struct DocumentTransfers: ViewModifier {
    @Bindable var model: AppModel
    let inSheet: Bool
    let inSettings: Bool
    @State private var pending: DocumentRequest?
    private var presented: Binding<Bool> {
        Binding(get: { model.documentRequest != nil && (model.sheet != nil) == inSheet && (inSheet || model.settingsVisible == inSettings) },
                set: { if !$0 { model.documentRequest = nil } })
    }
    func body(content: Content) -> some View {
        content.fileImporter(isPresented: presented, allowedContentTypes: [.folder]) { result in
            // A folder picker plus an exclusive writer preserves the Mac's no-overwrite
            // rule. File exporters can offer replacement of an existing credential.
            guard let request = pending,
                  model.editorGeneration == request.generation, model.vault == request.vault else { return }
            model.documentRequest = nil
            pending = nil
            switch result {
            case .success(let folder):
                model.completeBackupSelection(folder: folder, request: request)
            case .failure:
                model.error = "The folder could not be opened. Choose a writable folder in Files."
            }
        }.onChange(of: model.documentRequest?.id) { _, _ in
            if let request = model.documentRequest { pending = request }
        }
    }
}
