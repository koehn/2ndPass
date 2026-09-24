import Foundation
import MopAppSupport
import CloudKit
#if os(macOS)
import AppKit
#else
import UIKit
#endif

enum AppLifecycleEvent: Sendable { case cloudChanged, active, inactive, background, lock, accountChanged, terminate, activity }

@MainActor protocol AppLifecycleMonitoring {
    func start(_ receive: @escaping @MainActor (AppLifecycleEvent) -> Void)
    func stop()
}

@MainActor final class SystemAppLifecycleMonitor: AppLifecycleMonitoring {
    private var observers: [(NotificationCenter, NSObjectProtocol)] = []
    private var activityMonitor: Any?
    func start(_ receive: @escaping @MainActor (AppLifecycleEvent) -> Void) {
        guard observers.isEmpty else { return }
        func observe(_ center: NotificationCenter, _ name: Notification.Name, _ event: AppLifecycleEvent) {
            let observer = center.addObserver(forName: name, object: nil, queue: .main) { _ in
                MainActor.assumeIsolated { receive(event) }
            }
            observers.append((center, observer))
        }
        observe(.default, .CKAccountChanged, .accountChanged)
        observe(.default, .mopCloudChanged, .cloudChanged)
        observe(.default, NetworkAvailability.changed, .cloudChanged)
        _ = NetworkAvailability.shared
        #if os(macOS)
        observe(.default, NSApplication.didResignActiveNotification, .inactive)
        observe(.default, NSApplication.didBecomeActiveNotification, .active)
        observe(.default, NSApplication.willTerminateNotification, .terminate)
        observe(NSWorkspace.shared.notificationCenter, NSWorkspace.sessionDidResignActiveNotification, .lock)
        observe(NSWorkspace.shared.notificationCenter, NSWorkspace.willSleepNotification, .lock)
        observe(DistributedNotificationCenter.default(), Notification.Name("com.apple.screenIsLocked"), .lock)
        activityMonitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown, .rightMouseDown, .otherMouseDown, .mouseMoved, .leftMouseDragged, .rightMouseDragged, .scrollWheel]) { event in
            MainActor.assumeIsolated { receive(.activity) }
            return event
        }
        #else
        observe(.default, UIApplication.willResignActiveNotification, .inactive)
        observe(.default, UIApplication.didBecomeActiveNotification, .active)
        observe(.default, UIApplication.didEnterBackgroundNotification, .background)
        observe(.default, UIApplication.protectedDataWillBecomeUnavailableNotification, .lock)
        observe(.default, .mopUserActivity, .activity)
        #endif
    }
    func stop() {
        for (center, observer) in observers { center.removeObserver(observer) }
        observers.removeAll()
        #if os(macOS)
        if let activityMonitor { NSEvent.removeMonitor(activityMonitor); self.activityMonitor = nil }
        #endif
    }
}
