@preconcurrency import CloudKit
import Foundation
import Synchronization
import MopKeychain

public enum SubscriptionRuntime {
    public static func configuration() throws -> SubscriptionConfiguration {
        let cloud = try SigningIdentity.cloudConfiguration()
        let settings = SigningIdentity.subscriptionSettings()
        if settings.purchasesEnabled && (settings.appAppleID ?? 0) <= 0 { throw SubscriptionFailure.configuration }
        return try SubscriptionConfiguration(container: cloud.container, environment: cloud.environment,
            appAppleID: settings.appAppleID, publicationEnabled: settings.publicationEnabled)
    }
    public static var purchasesEnabled: Bool { SigningIdentity.subscriptionSettings().purchasesEnabled }
    public static var localAccountFingerprint: String? {
        guard let token = FileManager.default.ubiquityIdentityToken,
              let data = try? NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: false) else { return nil }
        return SubscriptionEvidence.hash(data.base64EncodedString())
    }
}

/// Private, append-only evidence. No CKShare and no dependency on vault enrollment or keys.
public actor SubscriptionCloud {
    private let cloud: CKContainer
    private let zone = CKRecordZone.ID(zoneName: "mop-subscription-v1", ownerName: CKCurrentUserDefaultName)
    public init(container: String) { cloud = CKContainer(identifier: container) }
    public func account() async throws -> String {
        guard try await cloud.accountStatus() == .available else { throw SubscriptionFailure.account }
        return try await cloud.userRecordID().recordName
    }
    public func fetch(account expected: String) async throws -> [SubscriptionEvidence] {
        guard try await account() == expected else { throw SubscriptionFailure.account }
        var evidence: [SubscriptionEvidence] = []
        do {
            var page = try await cloud.privateCloudDatabase.records(matching: CKQuery(recordType: "MopSubscriptionEvidence", predicate: NSPredicate(value: true)), inZoneWith: zone)
            while true {
                for (_, result) in page.matchResults {
                    let record = try result.get()
                    guard let bytes = record["payload"] as? Data, bytes.count <= 140 * 1024 else { throw SubscriptionFailure.invalidEvidence }
                    let item = try JSONDecoder().decode(SubscriptionEvidence.self, from: bytes)
                    try item.validateSize(); evidence.append(item)
                }
                try Task.checkCancellation()
                guard let cursor = page.queryCursor else { break }
                page = try await cloud.privateCloudDatabase.records(continuingMatchFrom: cursor)
            }
        } catch let error as CKError where error.code == .zoneNotFound || error.code == .unknownItem { return [] }
        guard try await account() == expected else { throw SubscriptionFailure.account }
        return evidence
    }
    public func publish(_ claims: SubscriptionClaims, account expected: String) async throws {
        guard try await account() == expected else { throw SubscriptionFailure.account }
        _ = try await cloud.privateCloudDatabase.save(CKRecordZone(zoneID: zone))
        guard try await account() == expected else { throw SubscriptionFailure.account }
        let record = CKRecord(recordType: "MopSubscriptionEvidence", recordID: CKRecord.ID(recordName: claims.evidence.digest, zoneID: zone))
        record["payload"] = try JSONEncoder().encode(claims.evidence) as CKRecordValue
        record["expiration"] = max(claims.expires, claims.graceExpires ?? claims.expires) as CKRecordValue
        record["signedAt"] = claims.signed as CKRecordValue
        record["status"] = claims.status(at: Date(), verifiedAt: Date(), source: .storeKit).status.rawValue as CKRecordValue
        do { _ = try await cloud.privateCloudDatabase.save(record) }
        catch let error as CKError where error.code == .serverRecordChanged {
            // Same content-addressed record already exists. Never overwrite it.
            let saved = try await cloud.privateCloudDatabase.record(for: record.recordID)
            guard saved["payload"] as? Data == record["payload"] as? Data else { throw SubscriptionFailure.invalidEvidence }
        }
        guard try await account() == expected else { throw SubscriptionFailure.account }
    }
}

/// A deadline that does not wait for an uncooperative network callback. Late results cannot update caches.
public func subscriptionDeadline<T: Sendable>(seconds: Double, operation: @escaping @Sendable () async throws -> T) async throws -> T {
    let gate = Mutex<CheckedContinuation<T, Error>?>(nil)
    return try await withCheckedThrowingContinuation { continuation in
        gate.withLock { $0 = continuation }
        let worker = Task {
            let result: Result<T, Error>
            do { result = .success(try await operation()) } catch { result = .failure(error) }
            gate.withLock { value in let c = value; value = nil; return c }?.resume(with: result)
        }
        Task {
            try? await Task.sleep(for: .seconds(seconds))
            if let c = gate.withLock({ value in let c = value; value = nil; return c }) {
                worker.cancel(); c.resume(throwing: SubscriptionFailure.timeout)
            }
        }
    }
}
