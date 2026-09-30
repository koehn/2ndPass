import Foundation
import LocalAuthentication
import MopAuth
import MopCore
#if os(macOS)
import AppKit
#endif

public enum LocalKeyOperation: Hashable, Sendable { case create, delete, sign, csr, certificate, keyAgreement, passkey }

/// Unforgeable outside this module. No serialization; holds only the authorized
/// context, exact scope, and revocation state. Key handles remain operation-local.
public final class LocalAuthorization: @unchecked Sendable {
    private let lock = NSLock()
    private var active = true
    private var used = false
    private let ids: Set<UUID>
    private let purposes: Set<LocalIdentityProtocol>
    private let operations: Set<LocalKeyOperation>
    private let expires: Date
    private let oneShot: Bool
    let context: LAContext
    init(context: LAContext, ids: Set<UUID>, purposes: Set<LocalIdentityProtocol>, operations: Set<LocalKeyOperation>, expires: Date = .distantFuture, oneShot: Bool = false) {
        self.context = context; self.ids = ids; self.purposes = purposes; self.operations = operations
        self.expires = expires; self.oneShot = oneShot
    }
    public static func authorize(reason: String, ids: Set<UUID>, purposes: Set<LocalIdentityProtocol>, operations: Set<LocalKeyOperation>, oneShot: Bool = true, lifetime: TimeInterval? = nil, contextCreated: (LAContext) throws -> Void = { _ in }) throws -> LocalAuthorization {
        if let lifetime { guard lifetime.isFinite, lifetime > 0, lifetime <= 43200 else { throw MopError.authentication } }
        let value = LocalAuthorization(context: try Authentication.authorize(reason: reason, contextCreated: contextCreated), ids: ids, purposes: purposes, operations: operations, expires: Date().addingTimeInterval(lifetime ?? (oneShot ? 60 : 43200)), oneShot: oneShot)
        value.watchDeviceState(); return value
    }
    public static func authorizeAsync(reason: String, ids: Set<UUID>, purposes: Set<LocalIdentityProtocol>, operations: Set<LocalKeyOperation>, oneShot: Bool = true) async throws -> LocalAuthorization {
        let value = LocalAuthorization(context: try await Authentication.authorizeAsync(reason: reason), ids: ids, purposes: purposes, operations: operations, expires: Date().addingTimeInterval(oneShot ? 60 : 43200), oneShot: oneShot)
        value.watchDeviceState(); return value
    }
    func watchDeviceState() {
        // A dedicated run loop also receives lock notifications while the CLI waits
        // for a foreground ssh/git child. No key handle is retained by this thread.
        let ready = DispatchSemaphore(value: 0)
        Thread.detachNewThread { [self] in
            var observations: [(NotificationCenter, NSObjectProtocol)] = []
            func observe(_ center: NotificationCenter, _ name: Notification.Name) {
                observations.append((center, center.addObserver(forName: name, object: nil, queue: nil) { [weak self] _ in self?.revoke() }))
            }
            #if os(macOS)
            observe(DistributedNotificationCenter.default(), Notification.Name("com.apple.screenIsLocked"))
            observe(NSWorkspace.shared.notificationCenter, NSWorkspace.willSleepNotification)
            observe(NSWorkspace.shared.notificationCenter, NSWorkspace.sessionDidResignActiveNotification)
            #else
            observe(.default, Notification.Name("UIApplicationProtectedDataWillBecomeUnavailable"))
            observe(.default, Notification.Name("UIApplicationDidEnterBackgroundNotification"))
            #endif
            let timer = Timer(timeInterval: 0.25, repeats: true) { _ in }
            RunLoop.current.add(timer, forMode: .default)
            ready.signal()
            while isActive { RunLoop.current.run(until: Date().addingTimeInterval(0.25)) }
            timer.invalidate()
            for (center, token) in observations { center.removeObserver(token) }
            revoke()
        }
        ready.wait()
    }
    public func revoke() { lock.withLock { active = false; context.invalidate() } }
    public var isActive: Bool { lock.withLock { active && Date() < expires } }
    func begin(id: UUID?, purpose: LocalIdentityProtocol, operation: LocalKeyOperation) throws {
        try lock.withLock {
            guard active, Date() < expires, !oneShot || !used,
                  oneShot || ([.ssh, .gitSigning].contains(purpose) && operation == .sign),
                  purposes.contains(purpose), operations.contains(operation),
                  id.map({ ids.contains($0) }) ?? (operation == .create) else { throw MopError.authentication }
            used = true
        }
    }
    func check() throws { guard isActive else { throw MopError.authentication } }
    deinit { context.invalidate() }
}
