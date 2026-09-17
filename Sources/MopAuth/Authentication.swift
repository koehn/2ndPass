import Foundation
import LocalAuthentication
import MopCore
import Synchronization

public enum Authentication {
    public static func authorize(strictBiometrics: Bool = false) throws -> LAContext {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedReason = "access secrets for this mop command"
        let policy: LAPolicy = strictBiometrics ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication
        if strictBiometrics { context.localizedFallbackTitle = "" }
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
