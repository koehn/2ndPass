@preconcurrency import CloudKit
import Foundation
import MopSync

final class ContentRuntimeObservers: @unchecked Sendable {
    private let tokens: [NSObjectProtocol]
    let lease: SynchronizationLeaseObserver
    init(leaseURL: URL, wake: @escaping @Sendable (SyncWakeReason) -> Void, retire: @escaping @Sendable () -> Void) throws {
        _ = NetworkAvailability.shared.isOnline
        lease = try SynchronizationLeaseObserver(url: leaseURL) { wake(.ownerReleased) }
        tokens = [
            NotificationCenter.default.addObserver(forName: NetworkAvailability.changed, object: nil, queue: nil) { _ in
                if NetworkAvailability.shared.isOnline { wake(.networkRestored) }
            },
            NotificationCenter.default.addObserver(forName: .CKAccountChanged, object: nil, queue: nil) { _ in retire() }
        ]
    }
    deinit { tokens.forEach(NotificationCenter.default.removeObserver) }
}
