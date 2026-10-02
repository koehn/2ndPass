import Foundation

public struct SubscriptionReader: Sendable {
    public struct Remote: Sendable {
        public let account: String
        public let evidence: [SubscriptionEvidence]
        public init(account: String, evidence: [SubscriptionEvidence]) { self.account = account; self.evidence = evidence }
    }
    private let configuration: SubscriptionConfiguration
    private let verifier: any SubscriptionEvidenceVerifying
    private let cache: SubscriptionCache
    private let fingerprint: @Sendable () -> String?
    private let fetch: @Sendable () async throws -> Remote
    private let now: @Sendable () -> Date
    private let timeout: Double
    public init(configuration: SubscriptionConfiguration, verifier: any SubscriptionEvidenceVerifying, cache: SubscriptionCache = .standard,
                fingerprint: @escaping @Sendable () -> String? = { SubscriptionRuntime.localAccountFingerprint },
                now: @escaping @Sendable () -> Date = { Date() }, timeout: Double = 2,
                fetch: @escaping @Sendable () async throws -> Remote) {
        self.configuration = configuration; self.verifier = verifier; self.cache = cache
        self.fingerprint = fingerprint; self.fetch = fetch; self.now = now; self.timeout = timeout
    }
    public func status(offline: Bool) async -> SubscriptionStatus {
        if configuration.environment == "Development" { return SubscriptionStatus(.developmentExempt) }
        guard configuration.publicationEnabled else { return SubscriptionStatus(.unavailable) }
        let started = ProcessInfo.processInfo.systemUptime
        let local = fingerprint()
        let entry = cache.read(configuration, fingerprint: local)
        let date = now()
        let cached = if let entry { try? await subscriptionDeadline(seconds: timeout) { try await verifier.verify(entry.evidence, token: configuration.accountToken(entry.account), now: date) } } else { nil as SubscriptionClaims? }
        guard fingerprint() == local else { cache.remove(configuration); return SubscriptionStatus(.unavailable) }
        if offline {
            return cached?.status(at: date, verifiedAt: entry!.verifiedAt, source: .cache) ?? SubscriptionStatus(.unavailable)
        }
        do {
            let (remote, claims) = try await subscriptionDeadline(seconds: max(0, timeout - (ProcessInfo.processInfo.systemUptime - started))) {
                let remote = try await fetch()
                var claims: [SubscriptionClaims] = []
                for evidence in remote.evidence {
                    try Task.checkCancellation()
                    if let claim = try? await verifier.verify(evidence, token: configuration.accountToken(remote.account), now: date) { claims.append(claim) }
                }
                guard remote.evidence.isEmpty || !claims.isEmpty else { throw SubscriptionFailure.invalidEvidence }
                if let cached, entry?.account == remote.account { claims.append(cached) }
                return (remote, SubscriptionClaims.latest(claims))
            }
            guard fingerprint() == local else { cache.remove(configuration); return SubscriptionStatus(.unavailable) }
            guard let claims else {
                cache.remove(configuration)
                return SubscriptionStatus(.missing, lastVerified: date, source: .cloud)
            }
            if let local {
                try? cache.write(.init(account: remote.account, fingerprint: local, evidence: claims.evidence, verifiedAt: date), configuration: configuration)
            }
            let fromCache = remote.evidence.isEmpty && cached != nil
            return claims.status(at: date, verifiedAt: fromCache ? entry!.verifiedAt : date, source: fromCache ? .cache : .cloud)
        } catch {
            guard fingerprint() == local else { cache.remove(configuration); return SubscriptionStatus(.unavailable) }
            return cached?.status(at: date, verifiedAt: entry!.verifiedAt, source: .cache) ?? SubscriptionStatus(.unavailable)
        }
    }
}
