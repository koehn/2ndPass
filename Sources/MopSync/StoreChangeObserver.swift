@preconcurrency import CoreData
import Foundation

/// NotificationCenter serializes access to the immutable observer token. Removal
/// is automatic when the repository releases its observer; callbacks hold it weakly.
final class StoreChangeObserver: @unchecked Sendable {
    private let token: NSObjectProtocol

    init(coordinator: NSPersistentStoreCoordinator, changed: @escaping @Sendable () -> Void) {
        token = NotificationCenter.default.addObserver(forName: .NSPersistentStoreRemoteChange,
            object: coordinator, queue: nil) { _ in changed() }
    }

    deinit { NotificationCenter.default.removeObserver(token) }
}
