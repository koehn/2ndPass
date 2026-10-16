import Foundation

/// A recipient-bound reference to encrypted, authenticated history. Never stores
/// plaintext or an unwrapped key. The crypto/session boundary verifies the pair.
public struct ReadableContentReference: Codable, Equatable, Sendable {
    public let version: UUID
    public let keyGeneration: UUID
    public let grant: String
    public let recipient: String
    public init(version: UUID, keyGeneration: UUID, grant: String, recipient: String) {
        self.version = version; self.keyGeneration = keyGeneration
        self.grant = grant; self.recipient = recipient
    }
}

extension EncryptedItemRepository {
    private func readableKey(_ scope: ItemScope, _ recipient: String) -> String {
        "readable-content:" + scope.storageKey + ":" + recipient
    }
    public func readableContent(scope: ItemScope, recipient: String) throws -> ReadableContentReference? {
        try transaction { try journalValue("StateBlob", key: readableKey(scope, recipient)) }
    }
    /// Local bootstrap progress only; never evidence of authorization or cloud coverage.
    public func readableVersionsInitialized(scope: VaultScope) throws -> Bool {
        try transaction {
            let complete: Bool? = try journalValue("StateBlob", key: "readable-initialized:" + scope.storageKey)
            return complete == true
        }
    }

    public func finishReadableVersionInitialization(scope: VaultScope, permit: any RepositoryWritePermit) throws {
        try Task.checkCancellation()
        try permit.withWritePermission {
            try transaction(publishLocalChanges: false) {
                try touchVaultBoundary(scope)
                try writeJournal(true, entity: "StateBlob", key: "readable-initialized:" + scope.storageKey)
            }
        }
    }

    public func rememberReadableContent(scope: ItemScope, reference: ReadableContentReference,
                                        expectedHead: UUID, onlyIfAbsent: Bool = false, permit: any RepositoryWritePermit) throws {
        try permit.withWritePermission {
            try transaction {
                if onlyIfAbsent, try fetchOne("StateBlob", key: readableKey(scope, reference.recipient)) != nil { return }
                guard
                      let head = try fetchOne("Item", key: scope.storageKey),
                      try decodeVersion(head).versionID == expectedHead,
                      let row = try fetchOne("ContentVersion", key: scope.storageKey + ":" + reference.version.uuidString),
                      let data = row.value(forKey: "value") as? Data else { throw ItemRepositoryError.staleLocalVersion }
                let content = try JSONDecoder().decode(PreparedContentVersion.self, from: data)
                guard content.version.scope == scope, content.version.versionID == reference.version,
                      content.keyGeneration == reference.keyGeneration else { throw ContentStoreError.invalidRecord }
                // A readable reference must belong to the current head's chain,
                // not an unrelated archived conflict branch. Close races with
                // concurrent promotion and explicit conflict resolutions.
                var cursor = try decodeVersion(head)
                while cursor.versionID != reference.version {
                    guard let parent = cursor.baseVersionID,
                          let row = try fetchOne("ContentVersion", key: scope.storageKey + ":" + parent.uuidString),
                          let bytes = row.value(forKey: "value") as? Data else { throw ItemRepositoryError.staleLocalVersion }
                    let previous = try JSONDecoder().decode(PreparedContentVersion.self, from: bytes).version
                    guard previous.versionID == parent, previous.scope == scope,
                          previous.generation < cursor.generation, cursor.generation - previous.generation == 1 else { throw ContentStoreError.invalidRecord }
                    cursor = previous
                }
                if reference.version != expectedHead,
                   let old: ReadableContentReference = try journalValue("StateBlob", key: readableKey(scope, reference.recipient)),
                   let oldRow = try fetchOne("ContentVersion", key: scope.storageKey + ":" + old.version.uuidString),
                   let oldData = oldRow.value(forKey: "value") as? Data {
                    let previous = try JSONDecoder().decode(PreparedContentVersion.self, from: oldData)
                    if previous.version.generation > content.version.generation { return }
                }
                let grants = try contentRows("ContentGrant", field: "scopeKey", equals: scope.storageKey)
                guard try grants.contains(where: { row in
                    guard let bytes = row.value(forKey: "value") as? Data else { throw ItemRepositoryError.corruptStore }
                    let grant = try JSONDecoder().decode(PreparedContentGrant.self, from: bytes)
                    return grant.scope == scope && grant.identifier == reference.grant && grant.recipient == reference.recipient && grant.keyGeneration == reference.keyGeneration
                }) else { throw ContentStoreError.invalidRecord }
                try touchVaultBoundary(VaultScope(scope))
                try writeJournal(reference, entity: "StateBlob", key: readableKey(scope, reference.recipient))
            }
        }
    }
}
