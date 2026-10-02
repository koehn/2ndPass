import Foundation
import StoreKit
import Observation
import CloudKit

public enum SubscriptionPurchaseOutcome: Sendable { case purchased, pending, cancelled }
@MainActor public protocol SubscriptionPurchasing {
    func price() async throws -> String
    func purchase(token: UUID) async throws -> SubscriptionPurchaseOutcome
    func restore() async throws
    func evidence(token: UUID, now: Date) async throws -> [SubscriptionClaims]
}

@MainActor public final class StoreKitSubscriptionPurchaser: SubscriptionPurchasing {
    public init() {}
    private func product() async throws -> Product {
        guard let product = try await Product.products(for: [SubscriptionConfiguration.productID]).first else { throw SubscriptionFailure.unavailable }
        return product
    }
    public func price() async throws -> String { try await product().displayPrice }
    public func purchase(token: UUID) async throws -> SubscriptionPurchaseOutcome {
        switch try await product().purchase(options: [.appAccountToken(token)]) {
        case .success(let verification):
            guard case .verified(let transaction) = verification else { throw SubscriptionFailure.invalidEvidence }
            await transaction.finish()
            return .purchased
        case .pending: return .pending
        case .userCancelled: return .cancelled
        @unknown default: throw SubscriptionFailure.unavailable
        }
    }
    public func restore() async throws { try await AppStore.sync() }
    public func evidence(token: UUID, now: Date) async throws -> [SubscriptionClaims] {
        guard let subscription = try await product().subscription else { throw SubscriptionFailure.configuration }
        var claims: [SubscriptionClaims] = []
        for status in try await subscription.status {
            guard case .verified(let transaction) = status.transaction,
                  case .verified = status.renewalInfo else { throw SubscriptionFailure.invalidEvidence }
            guard transaction.productID == SubscriptionConfiguration.productID else { continue }
            let evidence = SubscriptionEvidence(transaction: status.transaction.jwsRepresentation, renewal: status.renewalInfo.jwsRepresentation)
            let environment = transaction.environment == .production ? "Production" : transaction.environment == .sandbox ? "Sandbox" : "Xcode"
            claims.append(try SubscriptionClaims(verified: evidence, token: token, now: now, environment: environment))
        }
        return claims
    }
}

@MainActor @Observable public final class SubscriptionModel {
    public static let shared = SubscriptionModel()
    public private(set) var status = SubscriptionStatus(.unavailable)
    public private(set) var price: String?
    public private(set) var purchaseMessage = ""
    public private(set) var publicationMessage = "Not published"
    public private(set) var busy = false
    public private(set) var canPurchase = false
    public private(set) var availabilityMessage = "Subscription configuration is unavailable."
    private let purchaser: any SubscriptionPurchasing
    private let cache: SubscriptionCache
    @ObservationIgnored nonisolated(unsafe) private var updates: Task<Void, Never>?
    @ObservationIgnored nonisolated(unsafe) private var retry: Task<Void, Never>?
    private var started = false
    private var generation = 0
    private var lastClaims: SubscriptionClaims?
    private var pending: (SubscriptionConfiguration, SubscriptionClaims, String, String)?
    private let configuration: @Sendable () throws -> SubscriptionConfiguration
    private let fingerprint: @Sendable () -> String?
    private let enabled: @MainActor () async -> Bool
    private let account: @Sendable (SubscriptionConfiguration) async throws -> String
    private let publish: @Sendable (SubscriptionConfiguration, SubscriptionClaims, String) async throws -> Void
    public init(purchaser: any SubscriptionPurchasing = StoreKitSubscriptionPurchaser(), cache: SubscriptionCache = .standard,
                configuration: @escaping @Sendable () throws -> SubscriptionConfiguration = { try SubscriptionRuntime.configuration() },
                fingerprint: @escaping @Sendable () -> String? = { SubscriptionRuntime.localAccountFingerprint },
                enabled: @escaping @MainActor () async -> Bool = {
                    guard SubscriptionRuntime.purchasesEnabled else { return false }
                    return await SubscriptionModel.storeKitAvailable
                },
                account: @escaping @Sendable (SubscriptionConfiguration) async throws -> String = { try await SubscriptionCloud(container: $0.container).account() },
                publish: @escaping @Sendable (SubscriptionConfiguration, SubscriptionClaims, String) async throws -> Void = { try await SubscriptionCloud(container: $0.container).publish($1, account: $2) }) {
        self.purchaser = purchaser; self.cache = cache; self.configuration = configuration
        self.fingerprint = fingerprint; self.enabled = enabled; self.account = account; self.publish = publish
    }
    public func start() {
        guard !started else { return }; started = true
        updates = Task { [weak self] in
            for await result in Transaction.updates {
                guard !Task.isCancelled else { return }
                if case .verified(let transaction) = result, transaction.productID == SubscriptionConfiguration.productID {
                    await self?.refresh()
                    await transaction.finish()
                }
            }
        }
        Task { await refresh() }
    }
    public func accountChanged() {
        generation += 1; lastClaims = nil; pending = nil; status = SubscriptionStatus(.unavailable); publicationMessage = "Account changed; refresh required"
        if let config = try? configuration() { cache.remove(config); cache.remove(config, pending: true) }
        Task { await refresh() }
    }
    public func refresh() async { await perform(purchase: false, restore: false) }
    public func purchase() async { await perform(purchase: true, restore: false) }
    public func restore() async { await perform(purchase: false, restore: true) }
    private func perform(purchase: Bool, restore: Bool) async {
        guard !busy else { return }; busy = true
        let currentGeneration = generation
        var purchaseCompleted = false
        defer {
            busy = false
            if generation != currentGeneration { Task { await refresh() } }
        }
        do {
            let config = try configuration()
            canPurchase = await enabled()
            availabilityMessage = canPurchase ? "Annual Pro subscription. This preview reports status only; all features remain available." : "Purchase and restore require the App Store version with subscriptions enabled."
            if config.environment == "Development" && !canPurchase {
                status = SubscriptionStatus(.developmentExempt); publicationMessage = "Development: production publication disabled"; return
            }
            var canRefresh = canPurchase
            if !canRefresh && config.publicationEnabled && !purchase && !restore {
                canRefresh = await Self.storeKitAvailable
            }
            guard canRefresh else { publicationMessage = "Publication inactive"; return }
            if pending == nil, cache.read(config, fingerprint: fingerprint(), pending: true) != nil {
                // Reacquire Apple-verified evidence before replaying a durable outbox after restart.
                publicationMessage = "Saved evidence awaiting StoreKit re-verification"
            }
            // Retry already verified in-memory evidence even if StoreKit is temporarily unavailable.
            if let (pendingConfig, claim, pendingAccount, local) = pending, local == fingerprint() {
                let publish = self.publish
                try await subscriptionDeadline(seconds: 15) { try await publish(pendingConfig, claim, pendingAccount) }
                guard generation == currentGeneration, local == fingerprint() else { throw SubscriptionFailure.account }
                cache.remove(pendingConfig, pending: true); pending = nil
                publicationMessage = "Published to iCloud"
            }
            // Pricing failure must not prevent evidence recovery after a restart.
            price = try? await purchaser.price()
            let accountFingerprint = self.fingerprint()
            let readAccount = self.account
            let account = try await subscriptionDeadline(seconds: 10) { try await readAccount(config) }
            let fingerprint = self.fingerprint()
            guard accountFingerprint == fingerprint, generation == currentGeneration else { throw SubscriptionFailure.account }
            let token = config.accountToken(account)
            if purchase {
                switch try await purchaser.purchase(token: token) {
                case .pending: purchaseMessage = "Purchase pending approval"; return
                case .cancelled: purchaseMessage = "Purchase cancelled"; return
                case .purchased: purchaseMessage = "Purchase verified"; purchaseCompleted = true
                }
            }
            if restore { try await purchaser.restore(); purchaseMessage = "Purchases restored"; purchaseCompleted = true }
            let claims = try await purchaser.evidence(token: token, now: Date())
            guard generation == currentGeneration, fingerprint == self.fingerprint() else { throw SubscriptionFailure.account }
            guard let latest = SubscriptionClaims.latest(claims) else {
                // Absence is not a signed revocation. Never erase cached/pending evidence here.
                if let lastClaims { status = lastClaims.status(at: Date(), verifiedAt: status.lastVerified ?? Date(), source: .storeKit) }
                else { status = SubscriptionStatus(.missing) }
                publicationMessage = "No new verified subscription evidence"; return
            }
            lastClaims = latest
            status = latest.status(at: Date(), verifiedAt: Date(), source: .storeKit)
            // Independently inspect the environment only AFTER StoreKit verification.
            struct Environment: Decodable { let environment: String }
            let signedEnvironment = try SubscriptionClaims.payload(latest.evidence.transaction, as: Environment.self).environment
            guard config.environment == "Production", signedEnvironment == "Production", config.publicationEnabled else {
                publicationMessage = "Testing: production evidence publication disabled"; return
            }
            guard let fingerprint else { throw SubscriptionFailure.account }
            let entry = SubscriptionCache.Entry(account: account, fingerprint: fingerprint, evidence: latest.evidence, verifiedAt: Date())
            try cache.write(entry, configuration: config, pending: true)
            pending = (config, latest, account, fingerprint)
            publicationMessage = "Publishing to iCloud…"
            let publish = self.publish
            try await subscriptionDeadline(seconds: 15) { try await publish(config, latest, account) }
            guard generation == currentGeneration, fingerprint == self.fingerprint() else { throw SubscriptionFailure.account }
            cache.remove(config, pending: true); pending = nil; publicationMessage = "Published to iCloud"; retry?.cancel(); retry = nil
        } catch {
            if case SubscriptionFailure.account = error {
                lastClaims = nil; pending = nil; status = SubscriptionStatus(.unavailable)
                if let config = try? configuration() { cache.remove(config); cache.remove(config, pending: true) }
            }
            if let lastClaims { status = lastClaims.status(at: Date(), verifiedAt: status.lastVerified ?? Date(), source: .storeKit) }
            // Keep known purchase state separate from network/publication failure.
            if (purchase || restore) && !purchaseCompleted { purchaseMessage = "Could not complete purchase verification. Try again." }
            publicationMessage = "Could not refresh or publish; previous evidence retained. Will retry."
            retry?.cancel()
            retry = Task { [weak self] in
                do { try await Task.sleep(for: .seconds(60)); await self?.refresh() } catch { }
            }
        }
    }
    deinit { updates?.cancel(); retry?.cancel() }
    public static var storeKitAvailable: Bool {
        get async {
            #if DEBUG
            return true // Test purchase UI still requires the sealed build setting.
            #else
            guard let result = try? await AppTransaction.shared,
                  case .verified(let transaction) = result else { return false }
            return transaction.bundleID == SubscriptionConfiguration.hostBundleID
                && (transaction.environment == .production || transaction.environment == .sandbox)
            #endif
        }
    }
}
