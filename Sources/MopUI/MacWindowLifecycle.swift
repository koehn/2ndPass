#if os(macOS)
import AppKit
import SwiftUI

/// Intercept normal window closure while preserving SwiftUI's other delegate behavior.
struct MacWindowLifecycle: NSViewRepresentable {
    let model: AppModel
    // Observe draft lifetime so SwiftUI delegate changes are reconciled before closing an editor.
    let hasDraft: Bool
    func makeNSView(context: Context) -> WindowObserver {
        let view = WindowObserver()
        view.model = model
        return view
    }
    func updateNSView(_ view: WindowObserver, context: Context) {
        view.model = model
        view.attach()
    }

    final class WindowObserver: NSView {
        var model: AppModel?
        private var proxy: CloseDelegate?
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            attach()
            Task { @MainActor [weak self] in self?.attach() }
        }
        func attach() {
            guard let window, let model else { return }
            MopApplicationDelegate.editingModel = model
            if let proxy, window.delegate === proxy { return }
            let delegate = CloseDelegate(model: model, window: window)
            proxy = delegate
            window.delegate = delegate
        }
    }

    final class CloseDelegate: NSObject, NSWindowDelegate {
        weak var window: NSWindow?
        let original: (any NSWindowDelegate)?
        let model: AppModel
        private var closing = false
        init(model: AppModel, window: NSWindow) {
            self.model = model; self.window = window; original = window.delegate
        }
        override func responds(to selector: Selector!) -> Bool {
            super.responds(to: selector) || original?.responds(to: selector) == true
        }
        override func forwardingTarget(for selector: Selector!) -> Any? {
            original?.responds(to: selector) == true ? original : super.forwardingTarget(for: selector)
        }
        func windowShouldClose(_ sender: NSWindow) -> Bool {
            if closing { return original?.windowShouldClose?(sender) ?? true }
            guard !model.busy else { return false }
            guard model.hasUnsavedChanges else {
                model.cancelItemEditing()
                return original?.windowShouldClose?(sender) ?? true
            }
            model.requestTransition(.closeWindow) { [weak self, weak sender] accepted in
                guard accepted, let self, let sender else { return }
                self.closing = true
                sender.performClose(nil)
                self.closing = false
            }
            return false
        }
    }
}
#endif
