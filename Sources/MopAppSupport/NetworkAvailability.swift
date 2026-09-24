import Foundation
import Network
import Synchronization

/// Shared reachability hint; CloudKit errors remain authoritative.
public final class NetworkAvailability: Sendable {
    public static let shared = NetworkAvailability()
    public static let changed = Notification.Name("MopNetworkAvailabilityChanged")
    private let online = Mutex(true)
    private let monitor = NWPathMonitor()
    public var isOnline: Bool { online.withLock { $0 } }
    private init() {
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let value = path.status == .satisfied
            let changed = self.online.withLock { old in
                defer { old = value }
                return old != value
            }
            if changed {
                DispatchQueue.main.async { NotificationCenter.default.post(name: Self.changed, object: nil) }
            }
        }
        monitor.start(queue: DispatchQueue(label: "mop.network"))
    }
}
