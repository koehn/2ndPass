@preconcurrency import CloudKit
import Foundation
import MopAppSupport
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
    private var subscriptionTask: Task<Void, Never>?
    private var accountObserver: NSObjectProtocol?
    private var networkObserver: NSObjectProtocol?

    private func start() {
        #if DEBUG && (os(macOS) || targetEnvironment(simulator))
        if ProcessInfo.processInfo.environment["MOP_UI_TESTING"] == "1" { return }
        #endif
        #if os(macOS)
        NSApplication.shared.registerForRemoteNotifications()
        #else
        UIApplication.shared.registerForRemoteNotifications()
        #endif
        accountObserver = NotificationCenter.default.addObserver(forName: .CKAccountChanged, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in await AutoFillStorage.invalidate(); self?.subscribe() }
        }
        networkObserver = NotificationCenter.default.addObserver(forName: NetworkAvailability.changed, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.subscribe() }
        }
        subscribe()
    }
    private func subscribe() {
        subscriptionTask?.cancel()
        subscriptionTask = Task {
            guard NetworkAvailability.shared.isOnline,
                  let config = try? DefaultVaultPlatformConfiguration().cloudConfiguration() else { return }
            let container = CKContainer(identifier: config.container)
            let databases = [(container.privateCloudDatabase, "mop-private-database-v6"), (container.sharedCloudDatabase, "mop-shared-database-v6")]
            for (database, subscriptionID) in databases {
            let subscription = CKDatabaseSubscription(subscriptionID: subscriptionID)
            let info = CKSubscription.NotificationInfo()
            info.shouldSendContentAvailable = true
            subscription.notificationInfo = info
            // Retry transient subscription failures without prompting for secret access.
            while !Task.isCancelled {
                do { _ = try await database.save(subscription); break }
                catch {
                    do { try await Task.sleep(for: .seconds(60)) }
                    catch { return }
                }
            }
        }
        }
    }
    private func received(_ userInfo: [AnyHashable: Any]) -> Bool {
        guard let notification = CKNotification(fromRemoteNotificationDictionary: userInfo),
              ["mop-private-database-v6", "mop-shared-database-v6"].contains(notification.subscriptionID ?? "") else { return false }
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
        Task { try? await CloudBackgroundRefresh.download() }
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
            do { try await CloudBackgroundRefresh.download(); completionHandler(.newData) }
            catch { completionHandler(.failed) }
        }
    }
}
#endif
