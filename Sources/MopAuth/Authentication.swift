import Foundation
import LocalAuthentication
import MopCore
import Synchronization

public enum Authentication {
    /// Secure Enclave operations can outlive the reusable LA authorization.
    /// Recognize the observed native interaction-required failure without
    /// treating unrelated storage or network failures as authentication failures.
    public static func requiresRenewal(_ error: any Error) -> Bool {
        let native = error as NSError
        return native.domain == LAError.errorDomain
            || (native.domain == "com.apple.LocalAuthentication" && native.code == -1004)
    }

    /// GUI and extension callers must suspend while the system authenticates,
    /// rather than occupying a Swift concurrency worker with a semaphore wait.
    public static func authorizeAsync(reason: String, contextCreated: (LAContext) throws -> Void = { _ in }) async throws -> LAContext {
        let context = LAContext()
        do {
            try contextCreated(context)
            try Task.checkCancellation()
            context.touchIDAuthenticationAllowableReuseDuration = 0
            context.localizedReason = reason
            guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) else { throw MopError.authentication }
            guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) else { throw MopError.authentication }
            try Task.checkCancellation()
            context.interactionNotAllowed = true
            return context
        } catch {
            context.invalidate()
            throw MopError.authentication
        }
    }

    public static func authorize(reason: String = "access secrets for this sp command", contextCreated: (LAContext) throws -> Void = { _ in }) throws -> LAContext {
        let context = LAContext()
        do { try contextCreated(context) } catch { context.invalidate(); throw error }
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedReason = reason
        let policy: LAPolicy = .deviceOwnerAuthentication
        guard context.canEvaluatePolicy(policy, error: nil) else {
            context.invalidate()
            throw MopError.authentication
        }
        let result = Mutex(false)
        let completion = DispatchSemaphore(value: 0)
        context.evaluatePolicy(policy, localizedReason: context.localizedReason) { success, _ in
            result.withLock { $0 = success }
            completion.signal()
        }
        completion.wait()
        guard result.withLock({ $0 }) else {
            context.invalidate()
            throw MopError.authentication
        }
        // Reuse only this explicit authorization. Fail closed if a Keychain operation
        // would require another prompt rather than silently creating a new session.
        context.interactionNotAllowed = true
        return context
    }
}
