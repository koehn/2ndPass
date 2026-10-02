import Foundation
import Testing
import Synchronization
@testable import MopSubscriptions
import MopSubscriptionVerification

private let time = Date(timeIntervalSince1970: 1_800_000_000)
private let account = "fixture-account"
private func config(_ environment: String = "Production", enabled: Bool = true) throws -> SubscriptionConfiguration {
    try .init(container: "iCloud.com.koehn.mop", environment: environment, appAppleID: 123, publicationEnabled: enabled)
}
private func jws(_ payload: [String: Any]) throws -> String {
    "e30." + (try JSONSerialization.data(withJSONObject: payload)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") + ".fixture"
}
private func evidence(expires: Double = 3600, signed: Double = -10, revoked: Bool = false, grace: Double? = nil, overrides: [String: Any] = [:]) throws -> SubscriptionEvidence {
    var data: [String: Any] = ["bundleId": SubscriptionConfiguration.hostBundleID, "productId": SubscriptionConfiguration.productID,
        "environment": "Production", "originalTransactionId": "original", "transactionId": "transaction",
        "appAccountToken": try config().accountToken(account).uuidString,
        "purchaseDate": time.addingTimeInterval(-7200).timeIntervalSince1970 * 1000,
        "signedDate": time.addingTimeInterval(signed).timeIntervalSince1970 * 1000,
        "expiresDate": time.addingTimeInterval(expires).timeIntervalSince1970 * 1000, "inAppOwnershipType": "PURCHASED"]
    if revoked { data["revocationDate"] = time.addingTimeInterval(-1).timeIntervalSince1970 * 1000 }
    data.merge(overrides) { _, b in b }
    let renewal = try grace.map { grace in try jws(["environment": "Production", "originalTransactionId": "original", "productId": SubscriptionConfiguration.productID,
        "signedDate": time.addingTimeInterval(-1).timeIntervalSince1970 * 1000, "isInBillingRetryPeriod": true,
        "gracePeriodExpiresDate": time.addingTimeInterval(grace).timeIntervalSince1970 * 1000]) }
    return try .init(transaction: jws(data), renewal: renewal)
}
private func claims(_ evidence: SubscriptionEvidence, now: Date = time) throws -> SubscriptionClaims {
    try .init(verified: evidence, token: config().accountToken(account), now: now)
}
private struct FixtureVerifier: SubscriptionEvidenceVerifying {
    let accepted: Set<String>
    func verify(_ evidence: SubscriptionEvidence, token: UUID, now: Date) async throws -> SubscriptionClaims {
        guard accepted.contains(evidence.digest) else { throw SubscriptionFailure.invalidEvidence }
        return try SubscriptionClaims(verified: evidence, token: token, now: now)
    }
}
private func cache() -> (SubscriptionCache, URL) {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    return (SubscriptionCache(directory: url), url)
}

@Test func subscriptionStatesAndGraceDeadlines() throws {
    #expect(try claims(evidence()).status(at: time, verifiedAt: time, source: .cloud).status == .active)
    #expect(try claims(evidence(expires: -1)).status(at: time, verifiedAt: time, source: .cloud).status == .expired)
    #expect(try claims(evidence(expires: -1, grace: 600)).status(at: time, verifiedAt: time, source: .cloud).status == .billingGrace)
    #expect(try claims(evidence(expires: -600, grace: -1)).status(at: time, verifiedAt: time, source: .cloud).status == .expired)
    #expect(try claims(evidence(revoked: true)).status(at: time, verifiedAt: time, source: .cloud).status == .revoked)
}
@Test func rejectWrongScopeOwnershipAndRenewal() throws {
    for (key, value) in [("bundleId", "other"), ("productId", "other"), ("environment", "Sandbox"), ("appAccountToken", UUID().uuidString), ("inAppOwnershipType", "FAMILY_SHARED")] {
        #expect(throws: (any Error).self) { try claims(evidence(overrides: [key: value])) }
    }
    let e = try evidence()
    let wrong = try jws(["environment": "Production", "originalTransactionId": "other", "productId": SubscriptionConfiguration.productID, "signedDate": time.timeIntervalSince1970 * 1000])
    #expect(throws: (any Error).self) { try claims(.init(transaction: e.transaction, renewal: wrong)) }
    #expect(throws: (any Error).self) { try claims(evidence(signed: 600)) }
    #expect(throws: (any Error).self) { try SubscriptionConfiguration(container: "iCloud.com.koehn.mop", environment: "Production", appAppleID: nil, publicationEnabled: true) }
}
@Test func stalePublicationCannotUndoRevocationOrRenewal() throws {
    let old = try claims(evidence(signed: -100))
    let revoked = try claims(evidence(signed: -1, revoked: true))
    #expect(SubscriptionClaims.latest([revoked, old])?.revoked != nil)
    #expect(SubscriptionClaims.latest([old, revoked])?.revoked != nil)
    let renewed = try claims(evidence(overrides: ["transactionId": "new", "purchaseDate": time.addingTimeInterval(-100).timeIntervalSince1970 * 1000]))
    #expect(SubscriptionClaims.latest([renewed, revoked, old])?.transactionID == "new")
}
@Test func cacheOfflineExpiryAndAccountSwitch() async throws {
    let (cache, root) = cache(); defer { try? FileManager.default.removeItem(at: root) }
    let e = try evidence(); let config = try config()
    try cache.write(.init(account: account, fingerprint: "local", evidence: e, verifiedAt: time), configuration: config)
    let calls = Mutex(0)
    let reader = SubscriptionReader(configuration: config, verifier: FixtureVerifier(accepted: [e.digest]), cache: cache,
        fingerprint: { "local" }, now: { time.addingTimeInterval(3601) }) { calls.withLock { $0 += 1 }; throw SubscriptionFailure.unavailable }
    #expect(await reader.status(offline: true).status == .expired)
    #expect(calls.withLock { $0 } == 0)
    #expect(await reader.status(offline: false).source == .cache)
    #expect(cache.read(config, fingerprint: "other") == nil)
    #expect(await reader.status(offline: true).status == .unavailable)
}
@Test func remoteValidationTimeoutAndNoLateCacheWrite() async throws {
    let (cache, root) = cache(); defer { try? FileManager.default.removeItem(at: root) }
    let e = try evidence(); let config = try config()
    let valid = FixtureVerifier(accepted: [e.digest])
    let reader = SubscriptionReader(configuration: config, verifier: valid, cache: cache, fingerprint: { "local" }, now: { time }) {
        .init(account: account, evidence: [e])
    }
    #expect(await reader.status(offline: false).status == .active)
    cache.remove(config)
    let slow = SubscriptionReader(configuration: config, verifier: valid, cache: cache, fingerprint: { "local" }, now: { time }, timeout: 0.01) {
        // Deliberately ignore task cancellation like a late callback.
        try? await Task.sleep(for: .milliseconds(100))
        return .init(account: account, evidence: [e])
    }
    #expect(await slow.status(offline: false).status == .unavailable)
    try await Task.sleep(for: .milliseconds(150))
    #expect(cache.read(config, fingerprint: "local") == nil)
    let invalid = SubscriptionReader(configuration: config, verifier: FixtureVerifier(accepted: []), cache: cache, fingerprint: { "local" }, now: { time }) { .init(account: account, evidence: [e]) }
    #expect(await invalid.status(offline: false).status == .unavailable)
}
@Test func developmentNeverFetchesOrPretendsPurchased() async throws {
    let reader = SubscriptionReader(configuration: try config("Development"), verifier: FixtureVerifier(accepted: []), fingerprint: { nil }) {
        Issue.record("Development attempted a remote lookup"); throw SubscriptionFailure.unavailable
    }
    #expect(await reader.status(offline: false).status == .developmentExempt)
}
@Test func realVerifierRejectsUnsignedEvidence() async throws {
    let verifier = try AppleSubscriptionVerifier(appAppleID: 123)
    await #expect(throws: (any Error).self) { try await verifier.verify(evidence(), token: config().accountToken(account), now: time) }
}

@MainActor private final class FakePurchaser: SubscriptionPurchasing {
    var outcome = SubscriptionPurchaseOutcome.purchased
    var snapshot: [SubscriptionClaims] = []
    var shouldFail = false
    var purchases = 0
    var restores = 0
    func price() async throws -> String { if shouldFail { throw SubscriptionFailure.unavailable }; return "$10.00" }
    func purchase(token: UUID) async throws -> SubscriptionPurchaseOutcome { purchases += 1; if shouldFail { throw SubscriptionFailure.unavailable }; return outcome }
    func restore() async throws { restores += 1 }
    func evidence(token: UUID, now: Date) async throws -> [SubscriptionClaims] { if shouldFail { throw SubscriptionFailure.unavailable }; return snapshot }
}
@Test @MainActor func purchasePendingCancelledRestoreAndPublicationRetry() async throws {
    let purchaser = FakePurchaser(); purchaser.snapshot = [try claims(evidence())]
    let (cache, root) = cache(); defer { try? FileManager.default.removeItem(at: root) }
    let configuration = try config()
    let published = Mutex(0); let fail = Mutex(true)
    let model = SubscriptionModel(purchaser: purchaser, cache: cache, configuration: { configuration }, fingerprint: { "local" }, enabled: { true }, account: { _ in account }) { _, _, _ in
        published.withLock { $0 += 1 }
        if fail.withLock({ $0 }) { throw SubscriptionFailure.unavailable }
    }
    purchaser.outcome = .pending; await model.purchase()
    #expect(model.purchaseMessage == "Purchase pending approval")
    #expect(published.withLock { $0 } == 0)
    purchaser.outcome = .cancelled; await model.purchase()
    #expect(model.purchaseMessage == "Purchase cancelled")
    purchaser.outcome = .purchased; await model.purchase()
    #expect(model.status.status == .active)
    #expect(cache.read(configuration, fingerprint: "local", pending: true) != nil)
    fail.withLock { $0 = false }; purchaser.shouldFail = true
    await model.refresh() // Publish prior verified evidence even though StoreKit is unavailable.
    #expect(published.withLock { $0 } == 2)
    #expect(cache.read(configuration, fingerprint: "local", pending: true) == nil)
    #expect(model.status.status == .active)
    purchaser.shouldFail = false; await model.restore()
    #expect(purchaser.restores == 1)
    #expect(model.publicationMessage == "Published to iCloud")
}
@Test @MainActor func sandboxPurchaseNeverPublishesIntoProduction() async throws {
    let purchaser = FakePurchaser()
    let e = try evidence(overrides: ["environment": "Sandbox"])
    purchaser.snapshot = [try SubscriptionClaims(verified: e, token: config().accountToken(account), now: time, environment: "Sandbox")]
    let configuration = try config()
    let model = SubscriptionModel(purchaser: purchaser, configuration: { configuration }, fingerprint: { "local" }, enabled: { true }, account: { _ in account }) { _, _, _ in
        Issue.record("Sandbox evidence published to production")
    }
    await model.purchase()
    #expect(model.publicationMessage == "Testing: production evidence publication disabled")
}

@Test func renewalFreshnessIsIndependentOfTransactionSigning() throws {
    let newerTransaction = try claims(evidence(expires: -1, signed: 0))
    let newerRenewal = try claims(evidence(expires: -1, signed: -100, grace: 600))
    let selected = try #require(SubscriptionClaims.latest([newerRenewal, newerTransaction]))
    #expect(selected.status(at: time, verifiedAt: time, source: .cloud).status == .billingGrace)
    #expect(selected.signed == newerTransaction.signed)
    // The combined pair must still pass the claim binding checks on the next cache read.
    #expect(try claims(selected.evidence).graceExpires == newerRenewal.graceExpires)
}

@Test @MainActor func failedPurchaseRetainsPriorEvidence() async throws {
    let purchaser = FakePurchaser(); purchaser.snapshot = [try claims(evidence())]
    let configuration = try config(enabled: false)
    let model = SubscriptionModel(purchaser: purchaser, configuration: { configuration }, fingerprint: { "local" }, enabled: { true }, account: { _ in account }) { _, _, _ in
        Issue.record("Publication disabled")
    }
    await model.refresh()
    purchaser.shouldFail = true
    await model.purchase()
    #expect(model.status.status == .active)
    #expect(model.purchaseMessage == "Could not complete purchase verification. Try again.")
}

@Test @MainActor func accountSwitchDuringLookupPreventsPurchase() async throws {
    let purchaser = FakePurchaser()
    let configuration = try config()
    let fingerprint = Mutex("first")
    let (cache, root) = cache(); defer { try? FileManager.default.removeItem(at: root) }
    let model = SubscriptionModel(purchaser: purchaser, cache: cache, configuration: { configuration },
        fingerprint: { fingerprint.withLock { $0 } }, enabled: { true }, account: { _ in
            fingerprint.withLock { $0 = "second" }; return account
        }) { _, _, _ in Issue.record("Published across an account change") }
    await model.purchase()
    #expect(purchaser.purchases == 0)
    #expect(model.status.status == .unavailable)
}

@Test @MainActor func restartReverifiesDurablePendingEvidence() async throws {
    let purchaser = FakePurchaser(); purchaser.snapshot = [try claims(evidence())]
    let configuration = try config()
    let (cache, root) = cache(); defer { try? FileManager.default.removeItem(at: root) }
    let first = SubscriptionModel(purchaser: purchaser, cache: cache, configuration: { configuration }, fingerprint: { "local" }, enabled: { true }, account: { _ in account }) { _, _, _ in throw SubscriptionFailure.unavailable }
    await first.refresh()
    #expect(cache.read(configuration, fingerprint: "local", pending: true) != nil)
    let published = Mutex(0)
    let restarted = SubscriptionModel(purchaser: purchaser, cache: cache, configuration: { configuration }, fingerprint: { "local" }, enabled: { true }, account: { _ in account }) { _, _, _ in published.withLock { $0 += 1 } }
    purchaser.shouldFail = true
    await restarted.refresh()
    #expect(published.withLock { $0 } == 0)
    #expect(cache.read(configuration, fingerprint: "local", pending: true) != nil)
    purchaser.shouldFail = false
    await restarted.refresh()
    #expect(published.withLock { $0 } == 1)
    #expect(cache.read(configuration, fingerprint: "local", pending: true) == nil)
}

@Test func unavailableJSONIncludesUnknownDates() throws {
    let bytes = try JSONEncoder().encode(SubscriptionStatus(.unavailable))
    let json = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
    #expect(json["expiration"] is NSNull)
    #expect(json["lastVerified"] is NSNull)
}
