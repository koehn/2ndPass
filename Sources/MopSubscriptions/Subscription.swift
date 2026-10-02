import Foundation
import CryptoKit

public enum SubscriptionFailure: Error { case configuration, invalidEvidence, account, unavailable, timeout }
public enum SubscriptionState: String, Codable, Sendable { case active, billingGrace, expired, revoked, missing, unavailable, developmentExempt }
public enum SubscriptionSource: String, Codable, Sendable { case cloud, cache, storeKit, none }
public struct SubscriptionStatus: Codable, Equatable, Sendable {
    public var status: SubscriptionState
    public var expiration: Date?
    public var lastVerified: Date?
    public var source: SubscriptionSource
    public init(_ status: SubscriptionState, expiration: Date? = nil, lastVerified: Date? = nil, source: SubscriptionSource = .none) {
        self.status = status; self.expiration = expiration; self.lastVerified = lastVerified; self.source = source
    }
    private enum CodingKeys: String, CodingKey { case status, expiration, lastVerified, source }
    public func encode(to encoder: any Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(status, forKey: .status)
        try values.encode(expiration, forKey: .expiration)
        try values.encode(lastVerified, forKey: .lastVerified)
        try values.encode(source, forKey: .source)
    }
    public var diagnostic: String {
        switch status {
        case .active: "Pro subscription active"
        case .billingGrace: "Pro subscription in billing grace period"
        case .expired: "Pro subscription expired; open 2ndPass to refresh or renew"
        case .revoked: "Pro subscription revoked"
        case .missing: "No Pro subscription evidence; open 2ndPass to purchase or restore"
        case .unavailable: "Subscription status unavailable"
        case .developmentExempt: "Subscription check skipped (development exempt)"
        }
    }
}

public struct SubscriptionEvidence: Codable, Equatable, Sendable {
    public let transaction: String
    public let renewal: String?
    public init(transaction: String, renewal: String? = nil) { self.transaction = transaction; self.renewal = renewal }
    public var digest: String { Self.hash(transaction + "\n" + (renewal ?? "")) }
    public static func hash(_ value: String) -> String { SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined() }
    public func validateSize() throws {
        guard !transaction.isEmpty, transaction.utf8.count <= 64 * 1024, (renewal?.utf8.count ?? 0) <= 64 * 1024 else { throw SubscriptionFailure.invalidEvidence }
    }
}

public struct SubscriptionConfiguration: Sendable {
    public static let productID = "com.koehn.mop.pro.yearly"
    public static let hostBundleID = "com.koehn.mop"
    public let container: String
    public let environment: String
    public let appAppleID: Int64?
    public let publicationEnabled: Bool
    public init(container: String, environment: String, appAppleID: Int64?, publicationEnabled: Bool) throws {
        guard container == "iCloud.com.koehn.mop", ["Development", "Production"].contains(environment),
              !publicationEnabled || (appAppleID ?? 0) > 0 else { throw SubscriptionFailure.configuration }
        self.container = container; self.environment = environment; self.appAppleID = appAppleID; self.publicationEnabled = publicationEnabled
    }
    /// Domain-separated, deterministic account binding. Neither email nor a raw account ID is sent to StoreKit.
    public func accountToken(_ account: String) -> UUID {
        var bytes = Array(SHA256.hash(data: Data(("2ndPass.subscription.v1\n" + container + "\n" + account).utf8)).prefix(16))
        bytes[6] = (bytes[6] & 0x0f) | 0x80; bytes[8] = (bytes[8] & 0x3f) | 0x80
        return UUID(uuid: (bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5],bytes[6],bytes[7],bytes[8],bytes[9],bytes[10],bytes[11],bytes[12],bytes[13],bytes[14],bytes[15]))
    }
}

/// Claims are used only after StoreKit or Apple's SignedDataVerifier verifies the corresponding JWS.
public struct SubscriptionClaims: Sendable {
    public let originalID: String
    public let transactionID: String
    public let purchased: Date
    public let signed: Date
    public let renewalSigned: Date?
    public let expires: Date
    public let graceExpires: Date?
    public let revoked: Date?
    public let evidence: SubscriptionEvidence

    private struct TransactionPayload: Decodable {
        let bundleId: String; let productId: String; let environment: String
        let originalTransactionId: String; let transactionId: String
        let appAccountToken: UUID; let purchaseDate: Date; let signedDate: Date; let expiresDate: Date
        let revocationDate: Date?; let isUpgraded: Bool?; let inAppOwnershipType: String?
    }
    private struct RenewalPayload: Decodable {
        let environment: String; let originalTransactionId: String; let productId: String
        let signedDate: Date; let gracePeriodExpiresDate: Date?; let isInBillingRetryPeriod: Bool?
        let appAccountToken: UUID?
    }
    public static func payload<T: Decodable>(_ jws: String, as: T.Type) throws -> T {
        let parts = jws.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, jws.utf8.count <= 64 * 1024 else { throw SubscriptionFailure.invalidEvidence }
        var encoded = String(parts[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        encoded += String(repeating: "=", count: (4 - encoded.count % 4) % 4)
        guard let data = Data(base64Encoded: encoded) else { throw SubscriptionFailure.invalidEvidence }
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .millisecondsSince1970
        return try decoder.decode(T.self, from: data)
    }
    public init(verified evidence: SubscriptionEvidence, token: UUID, now: Date, environment: String = "Production") throws {
        try evidence.validateSize()
        let t = try Self.payload(evidence.transaction, as: TransactionPayload.self)
        guard t.bundleId == SubscriptionConfiguration.hostBundleID, t.productId == SubscriptionConfiguration.productID,
              t.environment == environment, t.appAccountToken == token, t.isUpgraded != true,
              t.inAppOwnershipType == "PURCHASED", !t.originalTransactionId.isEmpty, !t.transactionId.isEmpty,
              t.signedDate <= now.addingTimeInterval(300), t.expiresDate >= t.purchaseDate else { throw SubscriptionFailure.invalidEvidence }
        let r = try evidence.renewal.map { try Self.payload($0, as: RenewalPayload.self) }
        if let r {
            guard r.environment == environment, r.originalTransactionId == t.originalTransactionId,
                  r.productId == t.productId, r.appAccountToken == nil || r.appAccountToken == token,
                  r.signedDate <= now.addingTimeInterval(300), r.signedDate >= t.purchaseDate else { throw SubscriptionFailure.invalidEvidence }
        }
        originalID = t.originalTransactionId; transactionID = t.transactionId; purchased = t.purchaseDate
        signed = t.signedDate; renewalSigned = r?.signedDate; expires = t.expiresDate
        graceExpires = r?.isInBillingRetryPeriod == true ? r?.gracePeriodExpiresDate : nil
        revoked = t.revocationDate; self.evidence = evidence
    }
    public func status(at now: Date, verifiedAt: Date, source: SubscriptionSource) -> SubscriptionStatus {
        let deadline = max(expires, graceExpires ?? expires)
        let state: SubscriptionState = revoked != nil ? .revoked : now < expires ? .active : now < deadline ? .billingGrace : .expired
        return SubscriptionStatus(state, expiration: deadline, lastVerified: verifiedAt, source: source)
    }
    private init(transaction: Self, renewal: Self) {
        originalID = transaction.originalID; transactionID = transaction.transactionID
        purchased = transaction.purchased; signed = transaction.signed; expires = transaction.expires
        revoked = transaction.revoked; renewalSigned = renewal.renewalSigned; graceExpires = renewal.graceExpires
        evidence = SubscriptionEvidence(transaction: transaction.evidence.transaction, renewal: renewal.evidence.renewal)
    }
    public static func latest(_ claims: [Self]) -> Self? {
        // First collapse each transaction: a newer revocation must beat an older valid copy.
        let transactions = Dictionary(grouping: claims, by: \.transactionID).compactMap { _, copies in
            guard let transaction = copies.max(by: { a, b in
                if a.signed != b.signed { return a.signed < b.signed }
                if (a.revoked != nil) != (b.revoked != nil) { return a.revoked == nil }
                return (a.renewalSigned ?? .distantPast) < (b.renewalSigned ?? .distantPast)
            }) else { return nil as Self? }
            // Renewal status can change without the transaction being re-signed.
            let renewal = copies.max { ($0.renewalSigned ?? .distantPast) < ($1.renewalSigned ?? .distantPast) }!
            return Self(transaction: transaction, renewal: renewal)
        }
        return transactions.max { a, b in a.purchased == b.purchased ? a.signed < b.signed : a.purchased < b.purchased }
    }
}

public protocol SubscriptionEvidenceVerifying: Sendable {
    func verify(_ evidence: SubscriptionEvidence, token: UUID, now: Date) async throws -> SubscriptionClaims
}
