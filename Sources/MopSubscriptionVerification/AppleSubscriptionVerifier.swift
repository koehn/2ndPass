#if os(macOS)
import Foundation
import AppStoreServerLibrary
import MopSubscriptions

public struct AppleSubscriptionVerifier: SubscriptionEvidenceVerifying {
    private let verifier: SignedDataVerifier
    public init(appAppleID: Int64) throws {
        guard appAppleID > 0 else { throw SubscriptionFailure.configuration }
        let roots = try ["AppleRootCA-G2", "AppleRootCA-G3"].map { name in
            guard let url = Bundle.module.url(forResource: name, withExtension: "cer", subdirectory: "Resources") else { throw SubscriptionFailure.configuration }
            return try Data(contentsOf: url)
        }
        // Offline verification validates the certificate chain at Apple's signed date.
        // Purchase revocations come from refreshed transaction evidence, not certificate OCSP.
        verifier = try SignedDataVerifier(rootCertificates: roots, bundleId: SubscriptionConfiguration.hostBundleID,
            appAppleId: appAppleID, environment: .production, enableOnlineChecks: false)
    }
    public func verify(_ evidence: SubscriptionEvidence, token: UUID, now: Date) async throws -> SubscriptionClaims {
        try evidence.validateSize()
        guard case .valid = await verifier.verifyAndDecodeTransaction(signedTransaction: evidence.transaction) else { throw SubscriptionFailure.invalidEvidence }
        if let renewal = evidence.renewal {
            guard case .valid = await verifier.verifyAndDecodeRenewalInfo(signedRenewalInfo: renewal) else { throw SubscriptionFailure.invalidEvidence }
        }
        return try SubscriptionClaims(verified: evidence, token: token, now: now)
    }
}
#endif
