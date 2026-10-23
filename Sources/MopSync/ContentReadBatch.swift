@preconcurrency import CoreData
import Foundation

/// Readiness hints only. Workers must revalidate authority and content at commit.
public struct ContentReadinessQuery: Sendable {
    public let scope: ItemScope
    public let observedVersion: UUID?
    public let recipient: String?
    public let keyGeneration: UUID?
    public let missingVersion: UUID?
    public init(scope: ItemScope, observedVersion: UUID?, recipient: String?, keyGeneration: UUID?, missingVersion: UUID?) {
        self.scope = scope; self.observedVersion = observedVersion; self.recipient = recipient
        self.keyGeneration = keyGeneration; self.missingVersion = missingVersion
    }
}

public struct ContentMigrationRead: Sendable {
    public let versions: [PreparedContentVersion]
    public let grants: [PreparedContentGrant]
}

extension EncryptedItemRepository {
    /// Three fetches for at most 64 waits, in one consistent database transaction.
    public func contentReadiness(_ queries: [ContentReadinessQuery]) throws -> [Bool] {
        guard queries.count <= 64 else { throw ContentStoreError.invalidRecord }
        guard !queries.isEmpty else { return [] }
        return try transaction {
            let keys = Array(Set(queries.map { $0.scope.storageKey }))
            let stateRequest = NSFetchRequest<NSManagedObject>(entityName: "ContentKeyState")
            stateRequest.predicate = NSPredicate(format: "key IN %@", keys)
            var states: [String: ContentKeyState] = [:]
            for row in try context.fetch(stateRequest) {
                guard let key = row.value(forKey: "key") as? String else { throw ItemRepositoryError.corruptStore }
                states[key] = try contentValue(row)
            }
            let grantRequest = NSFetchRequest<NSManagedObject>(entityName: "ContentGrant")
            grantRequest.predicate = NSCompoundPredicate(orPredicateWithSubpredicates: queries.compactMap { query in
                guard let recipient = query.recipient, let generation = query.keyGeneration else { return nil }
                return NSPredicate(format: "scopeKey == %@ AND keyGeneration == %@ AND recipient == %@", query.scope.storageKey, generation as NSUUID, recipient)
            })
            var grants = Set<String>()
            if queries.contains(where: { $0.recipient != nil && $0.keyGeneration != nil }) {
                for row in try context.fetch(grantRequest) {
                    guard let scope = row.value(forKey: "scopeKey") as? String,
                          let generation = row.value(forKey: "keyGeneration") as? UUID,
                          let recipient = row.value(forKey: "recipient") as? String else { throw ItemRepositoryError.corruptStore }
                    grants.insert(scope + ":" + generation.uuidString + ":" + recipient)
                }
            }
            let versionKeys = queries.compactMap { query in query.missingVersion.map { query.scope.storageKey + ":" + $0.uuidString } }
            var versions = Set<String>()
            if !versionKeys.isEmpty {
                let request = NSFetchRequest<NSManagedObject>(entityName: "ContentVersion")
                request.predicate = NSPredicate(format: "key IN %@", versionKeys)
                for row in try context.fetch(request) {
                    guard let key = row.value(forKey: "key") as? String else { throw ItemRepositoryError.corruptStore }
                    versions.insert(key)
                }
            }
            return queries.map { query in
                let key = query.scope.storageKey
                if states[key]?.versionID != query.observedVersion { return true }
                if let recipient = query.recipient, let generation = query.keyGeneration,
                   grants.contains(key + ":" + generation.uuidString + ":" + recipient) { return true }
                if let version = query.missingVersion { return versions.contains(key + ":" + version.uuidString) }
                return false
            }
        }
    }

    /// Bounded inventory read; every prepared grant still uses the normal CAS commit.
    public func contentMigrationReads(scopes: [ItemScope], recipients: Set<String>) throws -> [ItemScope: ContentMigrationRead] {
        guard scopes.count <= 16 else { throw ContentStoreError.invalidRecord }
        guard !scopes.isEmpty else { return [:] }
        return try transaction {
            let keys = Array(Set(scopes.map(\.storageKey)))
            let versionsRequest = NSFetchRequest<NSManagedObject>(entityName: "ContentVersion")
            versionsRequest.predicate = NSPredicate(format: "scopeKey IN %@", keys)
            let versions: [PreparedContentVersion] = try context.fetch(versionsRequest).map { try contentValue($0) }
            let grantsRequest = NSFetchRequest<NSManagedObject>(entityName: "ContentGrant")
            grantsRequest.predicate = NSPredicate(format: "scopeKey IN %@ AND recipient IN %@", keys, Array(recipients))
            let grants: [PreparedContentGrant] = try context.fetch(grantsRequest).map { try contentValue($0) }
            let groupedVersions = Dictionary(grouping: versions, by: { $0.version.scope })
            let groupedGrants = Dictionary(grouping: grants, by: \.scope)
            return Dictionary(uniqueKeysWithValues: Set(scopes).map { scope in
                (scope, ContentMigrationRead(versions: groupedVersions[scope] ?? [], grants: groupedGrants[scope] ?? []))
            })
        }
    }
}
