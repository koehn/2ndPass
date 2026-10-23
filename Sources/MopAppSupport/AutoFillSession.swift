import AuthenticationServices
import Foundation
import MopCore

public enum AutoFillSessionError: Error, Equatable, Sendable { case expired, ended }

/// One fresh authentication may authorize one fill, never a later request.
@MainActor public final class AutoFillRequestSession {
    private let service: any VaultService
    private let usageStore: any ItemUsageStoring
    private var preparedUsage: ItemUsageIdentity?
    private let now: () -> TimeInterval
    private let deadline: TimeInterval
    private var ended = false
    public init(service: any VaultService = ItemVaultService(allowsAttachments: false), usageStore: any ItemUsageStoring = ItemUsageStore(), now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.usageStore = usageStore
        self.service = service; self.now = now; deadline = now() + 60
        service.lock()
    }
    deinit { service.lock() }
    public func end() { ended = true; service.lock() }
    public func check() throws {
        guard !ended else { throw AutoFillSessionError.ended }
        guard now() < deadline else { end(); throw AutoFillSessionError.expired }
        try Task.checkCancellation()
    }
    public func password(_ identity: AutoFillIdentity, remembering hosts: Set<String> = []) async throws -> ASPasswordCredential {
        defer { end() }
        try check()
        try await remember(hosts, for: identity)
        let (entry, secret) = try await AutoFillAccess.resolve(recordIdentifier: identity.recordIdentifier, kind: .password, service: service)
        try check()
        guard let bytes = secret.value else { throw MopError.notFound }
        preparedUsage = secret.usageIdentity
        return ASPasswordCredential(user: entry.username, password: String(decoding: bytes, as: UTF8.self))
    }
    public func code(_ identity: AutoFillIdentity, remembering hosts: Set<String> = []) async throws -> (credential: ASOneTimeCodeCredential, expiresAt: Date) {
        defer { end() }
        try check()
        try await remember(hosts, for: identity)
        let (_, secret) = try await AutoFillAccess.resolve(recordIdentifier: identity.recordIdentifier, kind: .oneTimeCode, service: service)
        try check()
        guard let bytes = secret.value, let expiry = secret.otpExpiresAt, expiry > Date(),
              let period = secret.otpPeriod, period > 0 else { throw MopError.invalidOTP }
        preparedUsage = secret.usageIdentity
        return (ASOneTimeCodeCredential(code: String(decoding: bytes, as: UTF8.self)), expiry)
    }
    private func remember(_ hosts: Set<String>, for identity: AutoFillIdentity) async throws {
        guard !hosts.isEmpty else { return }
        try check()
        try await AutoFillRememberWebsite.save(hosts, for: identity, service: service)
        try check()
    }

    /// Called only by the controller when handing the validated credential to the OS.
    /// Merely constructing a credential or listing choices is not usage.
    public func recordDeliveredUsage() async {
        guard !Task.isCancelled, now() < deadline, let identity = preparedUsage else { return }
        preparedUsage = nil
        await ItemUsageLogging.record([identity], store: usageStore)
    }

}
