import SwiftUI

extension View {
    func draftTransitionPrompt(model: AppModel, inSettings: Bool) -> some View {
        modifier(DraftTransitionPrompt(model: model, inSettings: inSettings))
    }
}

private struct DraftTransitionPrompt: ViewModifier {
    @Bindable var model: AppModel
    let inSettings: Bool
    func body(content: Content) -> some View {
        content.alert("Save changes?", isPresented: Binding(
            get: { model.showsUnsavedChanges && model.settingsVisible == inSettings },
            set: { model.showsUnsavedChanges = $0 }
        )) {
            Button("Save Changes") { model.saveAndContinue() }
                .disabled(model.draftSaveUnavailableReason != nil || model.busy)
            Button("Discard Changes", role: .destructive) { model.discardAndContinue() }
            Button("Cancel", role: .cancel) { model.cancelPendingTransition() }
        } message: {
            Text(model.draftSaveUnavailableReason ?? "Save your edits before continuing, or discard them. Cancel keeps this item open.")
        }
    }
}
