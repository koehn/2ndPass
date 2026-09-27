import SwiftUI
#if os(iOS)
import UIKit
#endif

extension View {
    @ViewBuilder func mopMenuStyle() -> some View {
        #if os(macOS)
        self.menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
        #else
        self.buttonStyle(.borderless)
        #endif
    }

    @ViewBuilder func mopControlTarget() -> some View {
        #if os(iOS)
        self.frame(minWidth: 44, minHeight: 44).contentShape(Rectangle())
        #else
        self
        #endif
    }

    @ViewBuilder func mopSheetWidth(_ width: CGFloat) -> some View {
        #if os(macOS)
        self.frame(width: width)
        #else
        self.frame(maxWidth: width)
        #endif
    }
}

struct SessionToolbar: ToolbarContent {
    @Bindable var model: AppModel
    @Binding var settings: Bool
    var body: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            Menu {
                Button("New Item") { model.beginCreatingItem() }
                    .disabled(model.busy || model.offline || !model.authenticated || model.itemCreationVaults.isEmpty || model.itemDraft != nil || model.page != .secrets)
                Button("Import…") { model.beginImport() }.disabled(model.busy || model.offline || !model.authenticated)
                Button("New Vault…") { model.presentSheet(.createVault) }.disabled(model.busy || model.offline)
            } label: { Label("New", systemImage: "plus") }
            if let target = model.selectedVaultDescriptor {
                Button("Vault Details", systemImage: "info.circle") { model.openVaultDetails(target) }
                    .disabled(model.busy)
            }
            Button("Refresh", systemImage: "arrow.clockwise") { model.refresh() }
                .accessibilityLabel("Refresh").keyboardShortcut("r")
                .disabled(model.busy)
            if model.authenticated {
                Button("Lock", systemImage: "lock") { model.lock() }
                    .accessibilityLabel("Lock").keyboardShortcut("l", modifiers: [.command, .shift])
            } else {
                Button("Unlock", systemImage: "lock.open") { model.unlock() }
                    .accessibilityLabel("Unlock").disabled(!model.canUnlock)
            }
            #if os(iOS)
            Button("Settings", systemImage: "gear") { settings = true }.accessibilityLabel("Settings")
            #endif
        }
    }
}

extension View {
    @ViewBuilder func mobileSessionToolbar(model: AppModel, settings: Binding<Bool>, compact: Bool, isDetail: Bool = false) -> some View {
        #if os(iOS)
        self.modifier(MobileToolbarModifier(model: model, settings: settings, compact: compact, isDetail: isDetail))
        #else
        self
        #endif
    }
}

#if os(iOS)
private struct MobileToolbarModifier: ViewModifier {
    let model: AppModel
    @Binding var settings: Bool
    let compact: Bool
    let isDetail: Bool
    func body(content: Content) -> some View {
        content.toolbar {
            if compact || isDetail { SessionToolbar(model: model, settings: $settings) }
        }
    }
}
#endif

struct MopRootView: View {
    @Bindable var model: AppModel
    var body: some View {
        ContentView(model: model)
            .onAppear { model.startMonitoringActivity() }
            .draftTransitionPrompt(model: model, inSettings: false)
            #if os(macOS)
            .background(MacWindowLifecycle(model: model, hasDraft: model.itemDraft != nil))
            #endif
            #if os(iOS)
            .background(ActivityBridge())
            .privacySensitive()
            #endif
    }
}

#if os(iOS)
extension Notification.Name {
    static let mopUserActivity = Notification.Name("MopUserActivity")
}

/// Observes touches without consuming gestures. Accessibility/keyboard edits are
/// also reported by the shared root's state-change handlers.
private struct ActivityBridge: UIViewRepresentable {
    func makeUIView(context: Context) -> ActivityView { ActivityView() }
    func updateUIView(_ uiView: ActivityView, context: Context) {}
    final class ActivityView: UIView, UIGestureRecognizerDelegate {
        private weak var installedWindow: UIWindow?
        private var observer: UIGestureRecognizer?
        private var shield: UIView?
        override init(frame: CGRect) {
            super.init(frame: frame)
            NotificationCenter.default.addObserver(self, selector: #selector(concealWindow), name: UIApplication.willResignActiveNotification, object: nil)
            NotificationCenter.default.addObserver(self, selector: #selector(revealWindow), name: UIApplication.didBecomeActiveNotification, object: nil)
        }
        required init?(coder: NSCoder) { fatalError("init(coder:) is unavailable") }
        @objc private func concealWindow() {
            guard shield == nil, let window = installedWindow else { return }
            let cover = UIView(frame: window.bounds)
            cover.backgroundColor = .systemBackground
            cover.autoresizingMask = [.flexibleWidth, .flexibleHeight]
            cover.isAccessibilityElement = true
            cover.accessibilityLabel = "Mop is concealed"
            cover.accessibilityViewIsModal = true
            window.addSubview(cover)
            shield = cover
        }
        @objc private func revealWindow() { shield?.removeFromSuperview(); shield = nil }
        deinit { NotificationCenter.default.removeObserver(self) }
        override func didMoveToWindow() {
            super.didMoveToWindow()
            if let observer { installedWindow?.removeGestureRecognizer(observer) }
            guard let window else { return }
            installedWindow = window
            let gesture = ActivityGesture(target: nil, action: nil)
            gesture.cancelsTouchesInView = false
            gesture.delaysTouchesBegan = false
            gesture.delaysTouchesEnded = false
            gesture.delegate = self
            window.addGestureRecognizer(gesture)
            observer = gesture
        }
        func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer, shouldRecognizeSimultaneouslyWith otherGestureRecognizer: UIGestureRecognizer) -> Bool { true }
    }
    final class ActivityGesture: UIGestureRecognizer {
        override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
            NotificationCenter.default.post(name: .mopUserActivity, object: nil)
        }
        override func touchesMoved(_ touches: Set<UITouch>, with event: UIEvent) {
            NotificationCenter.default.post(name: .mopUserActivity, object: nil)
        }
        override func touchesEnded(_ touches: Set<UITouch>, with event: UIEvent) { state = .failed }
        override func touchesCancelled(_ touches: Set<UITouch>, with event: UIEvent) { state = .failed }
        override func pressesBegan(_ presses: Set<UIPress>, with event: UIPressesEvent) {
            NotificationCenter.default.post(name: .mopUserActivity, object: nil)
        }
        override func pressesEnded(_ presses: Set<UIPress>, with event: UIPressesEvent) { state = .failed }
    }
}
#endif
