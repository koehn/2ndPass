import Foundation

public struct SubscriptionCache: Sendable {
    public struct Entry: Codable, Sendable {
        public let account: String
        public let fingerprint: String
        public let evidence: SubscriptionEvidence
        public let verifiedAt: Date
        public init(account: String, fingerprint: String, evidence: SubscriptionEvidence, verifiedAt: Date) {
            self.account = account; self.fingerprint = fingerprint; self.evidence = evidence; self.verifiedAt = verifiedAt
        }
    }
    private let directory: URL
    public init(directory: URL) { self.directory = directory }
    private func url(_ configuration: SubscriptionConfiguration, pending: Bool) -> URL {
        directory.appendingPathComponent(SubscriptionEvidence.hash(configuration.container + configuration.environment) + (pending ? "-pending.json" : ".json"))
    }
    public func read(_ configuration: SubscriptionConfiguration, fingerprint: String?, pending: Bool = false) -> Entry? {
        let file = url(configuration, pending: pending)
        guard let fingerprint else { try? FileManager.default.removeItem(at: file); return nil }
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: file.path),
              (attributes[.size] as? NSNumber)?.intValue ?? Int.max <= 150 * 1024,
              let bytes = try? Data(contentsOf: file), let entry = try? JSONDecoder().decode(Entry.self, from: bytes),
              entry.fingerprint == fingerprint else { try? FileManager.default.removeItem(at: file); return nil }
        return entry
    }
    public func write(_ entry: Entry, configuration: SubscriptionConfiguration, pending: Bool = false) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let file = url(configuration, pending: pending)
        try JSONEncoder().encode(entry).write(to: file, options: [.atomic, .completeFileProtection])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }
    public func remove(_ configuration: SubscriptionConfiguration, pending: Bool = false) { try? FileManager.default.removeItem(at: url(configuration, pending: pending)) }
    public static var standard: Self {
        let root = SigningStorage.root
        return Self(directory: root.appendingPathComponent("SubscriptionV1", isDirectory: true))
    }
}

import MopKeychain
private enum SigningStorage {
    static var root: URL {
        if let group = SigningIdentity.appGroupIdentifier, let root = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) { return root }
        return URL.applicationSupportDirectory.appendingPathComponent("2ndPass", isDirectory: true)
    }
}
