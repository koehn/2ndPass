@preconcurrency import CloudKit
import Foundation
import MopAppSupport
import MopSync
#if os(macOS)
import AppKit
#else
import UIKit
#endif

extension Notification.Name {
    static let mopCloudChanged = Notification.Name("MopCloudChanged")
}

/// Notifications are hints only. The service fetches and authenticates the head
/// before publishing contents, rather than trusting notification payloads.
@MainActor public final class MopApplicationDelegate: NSObject {
    static weak var editingModel: AppModel?
    private var accountObserver: NSObjectProtocol?

    private func start() {
        #if DEBUG && (os(macOS) || targetEnvironment(simulator))
        if ProcessInfo.processInfo.environment["MOP_UI_TESTING"] == "1" { return }
        #endif
        #if os(macOS)
        NSApplication.shared.registerForRemoteNotifications()
        #else
        UIApplication.shared.registerForRemoteNotifications()
        #endif
        accountObserver = NotificationCenter.default.addObserver(forName: .CKAccountChanged, object: nil, queue: .main) { _ in
            Task { @MainActor in await AutoFillStorage.invalidate() }
        }
        // CKSyncEngine owns subscription creation and its transport retries.
    }
    private func received(_ userInfo: [AnyHashable: Any]) -> Bool {
        guard let notification = CKNotification(fromRemoteNotificationDictionary: userInfo),
              notification.subscriptionID == SyncStoreLayout.contentSubscriptionID else { return false }
        NotificationCenter.default.post(name: .mopCloudChanged, object: nil)
        return true
    }
}
#if os(macOS)
extension MopApplicationDelegate: NSApplicationDelegate {
    public func applicationDidFinishLaunching(_ notification: Notification) { start() }
    public func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let model = Self.editingModel else { return .terminateNow }
        guard !model.busy, model.pendingTransition == nil else { return .terminateCancel }
        guard model.hasUnsavedChanges else { return .terminateNow }
        model.requestTransition(.quit) { accepted in
            sender.reply(toApplicationShouldTerminate: accepted)
        }
        return .terminateLater
    }
    public func application(_ application: NSApplication, didReceiveRemoteNotification userInfo: [String: Any]) {
        guard received(userInfo), !application.isActive else { return }
        Task { try? await CloudBackgroundRefresh.request() }
    }
}
#else
extension MopApplicationDelegate: UIApplicationDelegate {
    public func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        start(); return true
    }
    public func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any], fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
        guard received(userInfo) else { completionHandler(.noData); return }
        guard application.applicationState != .active else { completionHandler(.noData); return }
        Task {
            do { try await CloudBackgroundRefresh.request(); completionHandler(.noData) }
            catch { completionHandler(.failed) }
        }
    }
}
#endif
