import Foundation

/// Mirrors the account preference into UserDefaults so AppStorage updates all views.
@MainActor final class DeveloperPreferences {
    static let key = "developerToolsEnabled"
    static let shared = DeveloperPreferences()
    private let defaults: UserDefaults
    private let readCloud: () -> Bool?
    private let writeCloud: (Bool) -> Void
    nonisolated(unsafe) private var observer: NSObjectProtocol?

    convenience init() {
        let cloud = NSUbiquitousKeyValueStore.default
        self.init(defaults: .standard,
                  readCloud: { cloud.object(forKey: Self.key) as? Bool },
                  writeCloud: { cloud.set($0, forKey: Self.key); cloud.synchronize() })
        observer = NotificationCenter.default.addObserver(forName: NSUbiquitousKeyValueStore.didChangeExternallyNotification,
                                                          object: cloud, queue: .main) { [weak self] notification in
            let reason = notification.userInfo?[NSUbiquitousKeyValueStoreChangeReasonKey] as? Int
            MainActor.assumeIsolated {
                guard reason != NSUbiquitousKeyValueStoreQuotaViolationChange else { return }
                self?.receive(accountChanged: reason == NSUbiquitousKeyValueStoreAccountChange,
                              initialSync: reason == NSUbiquitousKeyValueStoreInitialSyncChange)
            }
        }
        cloud.synchronize()
    }
    init(defaults: UserDefaults, readCloud: @escaping () -> Bool?, writeCloud: @escaping (Bool) -> Void) {
        self.defaults = defaults; self.readCloud = readCloud; self.writeCloud = writeCloud
        // Don't upload a device's default before the account's initial download.
        if let value = readCloud() { defaults.set(value, forKey: Self.key) }
    }
    func set(_ value: Bool) {
        defaults.set(value, forKey: Self.key)
        writeCloud(value)
    }
    func receive(accountChanged: Bool = false, initialSync: Bool = false) {
        if let value = readCloud() { defaults.set(value, forKey: Self.key) }
        else if accountChanged { defaults.set(false, forKey: Self.key) }
        else if initialSync, let value = defaults.object(forKey: Self.key) as? Bool {
            // Migrate a saved local choice only after confirming no account value exists.
            writeCloud(value)
        }
    }
    deinit { if let observer { NotificationCenter.default.removeObserver(observer) } }
}
