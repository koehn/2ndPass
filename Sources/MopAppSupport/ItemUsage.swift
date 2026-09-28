import Foundation
import OSLog
import MopCore

public struct ItemUsageIdentity: Codable, Hashable, Sendable {
    public let account: String
    public let vault: String
    public let item: String
    public init(account: String, vault: String, item: String) {
        self.account = account; self.vault = vault; self.item = item
    }
}

public protocol ItemUsageStoring: Sendable {
    func load(accounts: Set<String>) async throws -> [ItemUsageIdentity: Date]
    func record(_ identities: Set<ItemUsageIdentity>, at date: Date) async throws
    func prune(account: String, vault: String, keeping items: Set<String>, before date: Date) async throws
}

public extension ItemCatalog {
    func usageIdentity(for item: VaultItem, vaultID: String) -> ItemUsageIdentity? {
        guard let usageScope, let id = item.storageID else { return nil }
        return ItemUsageIdentity(account: usageScope, vault: vaultID, item: id)
    }
}

/// Device-only metadata, with no names, field values, or cloud writes. The account
/// directory lock is also used by account removal, preventing late writes after removal.
public struct ItemUsageStore: ItemUsageStoring {
    public let state: URL
    public init(state: URL = AppStorageLocation.defaultState) { self.state = state }
    private struct Record: Codable { let identity: ItemUsageIdentity; var date: Date }
    private func directory(_ account: String) throws -> LocalDirectory {
        guard UUID(uuidString: account) != nil else { throw MopError.invalidIdentity }
        return try LocalDirectory(directory: state.appendingPathComponent("v7").appendingPathComponent(account))
    }
    private func read(_ directory: LocalDirectory) throws -> [Record] {
        let marker = directory.directory.appendingPathComponent("removed.json")
        if FileManager.default.fileExists(atPath: marker.path),
           try JSONDecoder().decode(Bool.self, from: LocalFile.read(marker, privateFile: true)) { return [] }
        let file = directory.directory.appendingPathComponent("usage.json")
        guard FileManager.default.fileExists(atPath: file.path) else { return [] }
        let records = try JSONDecoder().decode([Record].self, from: LocalFile.read(file, privateFile: true, limit: 16 * 1024 * 1024))
        guard records.allSatisfy({ UUID(uuidString: $0.identity.account) != nil &&
            UUID(uuidString: $0.identity.vault) != nil && UUID(uuidString: $0.identity.item) != nil &&
            $0.date.timeIntervalSince1970.isFinite }) else { throw MopError.invalidVault }
        return records
    }
    private func write(_ records: [Record], in directory: LocalDirectory) throws {
        let marker = directory.directory.appendingPathComponent("removed.json")
        if FileManager.default.fileExists(atPath: marker.path),
           try JSONDecoder().decode(Bool.self, from: LocalFile.read(marker, privateFile: true)) { throw MopError.deviceRemoved }
        var file = directory.directory.appendingPathComponent("usage.json")
        let sorted = records.sorted { ($0.identity.vault, $0.identity.item) < ($1.identity.vault, $1.identity.item) }
        try LocalFile.write(JSONEncoder().encode(sorted), to: file, replace: FileManager.default.fileExists(atPath: file.path))
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        try file.setResourceValues(values)
    }
    public func load(accounts: Set<String>) async throws -> [ItemUsageIdentity: Date] {
        try await Task.detached {
            var result: [ItemUsageIdentity: Date] = [:]
            for account in accounts {
                let directory = try directory(account)
                let records = try directory.locked { try read(directory) }
                for record in records where record.identity.account == account {
                    result[record.identity] = max(result[record.identity] ?? .distantPast, record.date)
                }
            }
            return result
        }.value
    }
    public func record(_ identities: Set<ItemUsageIdentity>, at date: Date) async throws {
        guard date.timeIntervalSince1970.isFinite,
              identities.allSatisfy({ UUID(uuidString: $0.vault) != nil && UUID(uuidString: $0.item) != nil }) else { throw MopError.invalidIdentity }
        try await Task.detached {
            for account in Set(identities.map(\.account)) {
                let directory = try directory(account)
                try directory.locked {
                    var records = try read(directory)
                    for identity in identities where identity.account == account {
                        if let index = records.firstIndex(where: { $0.identity == identity }) {
                            records[index].date = max(records[index].date, date)
                        } else { records.append(Record(identity: identity, date: date)) }
                    }
                    try write(records, in: directory)
                }
            }
        }.value
    }
    public func prune(account: String, vault: String, keeping items: Set<String>, before date: Date) async throws {
        try await Task.detached {
            let directory = try directory(account)
            try directory.locked {
                let records = try read(directory)
                let kept = records.filter { $0.identity.vault != vault || items.contains($0.identity.item) || $0.date > date }
                if kept.count != records.count { try write(kept, in: directory) }
            }
        }.value
    }
}

public enum ItemUsageLogging {
    private static let logger = Logger(subsystem: "com.koehn.mop", category: "Usage")
    public static func failure(_ error: Error) {
        let error = error as NSError
        logger.error("Local usage metadata failed: \(error.domain, privacy: .public) (\(error.code))")
    }
    public static func record(_ identities: Set<ItemUsageIdentity>, at date: Date = Date(),
                              store: any ItemUsageStoring) async {
        guard !identities.isEmpty else { return }
        do { try await store.record(identities, at: date) }
        catch { failure(error) }
    }
}
