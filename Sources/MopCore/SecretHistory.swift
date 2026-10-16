import Foundation

public struct SecretHistoryEntry: Codable, Equatable, Sendable, Identifiable {
    public var id: String
    public var replacedAt: Date
    public init(id: String, replacedAt: Date) { self.id = id; self.replacedAt = replacedAt }
}

/// Public metadata only; values are separately encrypted vault records.
public struct SecretFieldHistory: Codable, Equatable, Sendable, Identifiable {
    public var id: UUID
    public var itemID: String
    public var path: String
    public var entries: [SecretHistoryEntry]
    public init(itemID: String, path: String, entries: [SecretHistoryEntry] = []) {
        id = UUID(); self.itemID = itemID; self.path = path; self.entries = entries
    }
}

/// Logical history plus transient device-local health projections.
/// Only history is serialized into content or portable archives.
public struct VaultSecurityMetadata: Codable, Equatable, Sendable {
    public var histories: [SecretFieldHistory] = []
    public var passwordChecks: [CachedPasswordCheck]? = nil
    public init() {}
    private enum CodingKeys: String, CodingKey { case histories, accounts, passwordChecks }
    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        histories = try values.decodeIfPresent([SecretFieldHistory].self, forKey: .histories) ?? []
        for key in [CodingKeys.accounts, .passwordChecks] where values.contains(key) {
            if try values.decodeNil(forKey: key) { continue }
            let removed = try values.nestedUnkeyedContainer(forKey: key)
            guard removed.isAtEnd else { throw MopError.invalidVault }
        }
    }
    public func encode(to encoder: any Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(histories, forKey: .histories)
    }
}

/// Encrypted derived results, bound to an immutable secret record and scan scope.
/// Contains no password, password hash, or session fingerprint.
public struct CachedPasswordCheck: Codable, Equatable, Sendable {
    public var record: String
    public var context: [String]
    public var weak: Bool
    public var exposed: Bool
    public var checkedAt: Date
    public var breachCheckedAt: Date?
    public var reuseGroup: UUID?
    public var scope: String
    public var evaluator: Int = 1
    public var batch: UUID
    // Independently valid results; flat fields are the report projection.
    public var strengthResult: CachedStrengthResult? = nil
    public var breachResult: CachedBreachResult? = nil
    public var reuseResult: CachedReuseResult? = nil
    public init(record: String, context: [String], weak: Bool, exposed: Bool, checkedAt: Date,
                breachCheckedAt: Date?, reuseGroup: UUID?, scope: String, batch: UUID) {
        self.record = record; self.context = context; self.weak = weak; self.exposed = exposed
        self.checkedAt = checkedAt; self.breachCheckedAt = breachCheckedAt
        self.reuseGroup = reuseGroup; self.scope = scope; self.batch = batch
        strengthResult = CachedStrengthResult(weak: weak, checkedAt: checkedAt, context: context)
        breachResult = breachCheckedAt.map { CachedBreachResult(exposed: exposed, checkedAt: $0) }
        reuseResult = CachedReuseResult(group: reuseGroup, scope: scope, batch: batch, checkedAt: checkedAt)
    }
}

public struct CachedStrengthResult: Codable, Equatable, Sendable {
    public var quality: PasswordQuality? = nil
    public var weak: Bool
    public var checkedAt: Date
    public var context: [String]
    public var evaluator: Int
    public init(weak: Bool, checkedAt: Date, context: [String], evaluator: Int = 1, quality: PasswordQuality? = nil) {
        self.quality = quality
        self.weak = weak; self.checkedAt = checkedAt; self.context = context; self.evaluator = evaluator
    }
}
public struct CachedBreachResult: Codable, Equatable, Sendable {
    public var exposed: Bool
    public var checkedAt: Date
    public init(exposed: Bool, checkedAt: Date) { self.exposed = exposed; self.checkedAt = checkedAt }
}
public struct CachedReuseResult: Codable, Equatable, Sendable {
    public var group: UUID?
    public var scope: String
    public var batch: UUID
    public var checkedAt: Date
    public init(group: UUID?, scope: String, batch: UUID, checkedAt: Date) {
        self.group = group; self.scope = scope; self.batch = batch; self.checkedAt = checkedAt
    }
}

extension CachedPasswordCheck {
    /// A delayed writer must not shorten a successful check's lifetime.
    public func retainingNewerResults(from other: Self) -> Self {
        guard record == other.record else { return self }
        var result = self
        if let value = other.strengthResult, value.checkedAt > (strengthResult?.checkedAt ?? .distantPast) { result.strengthResult = value }
        if let value = other.breachResult, value.checkedAt > (breachResult?.checkedAt ?? .distantPast) { result.breachResult = value }
        if let value = other.reuseResult, value.checkedAt > (reuseResult?.checkedAt ?? .distantPast) { result.reuseResult = value }
        if let value = result.strengthResult { result.weak = value.weak; result.checkedAt = value.checkedAt; result.context = value.context; result.evaluator = value.evaluator }
        if let value = result.breachResult { result.exposed = value.exposed; result.breachCheckedAt = value.checkedAt }
        if let value = result.reuseResult { result.reuseGroup = value.group; result.scope = value.scope; result.batch = value.batch }
        return result
    }

    public func validate() throws {
        let dates = [checkedAt, breachCheckedAt, strengthResult?.checkedAt, breachResult?.checkedAt, reuseResult?.checkedAt].compactMap { $0 }
        let inputs = context + (strengthResult?.context ?? [])
        guard UUID(uuidString: record) != nil, context.count == 2, strengthResult.map({ $0.context.count == 2 }) ?? true,
              inputs.allSatisfy({ $0.utf8.count <= 16384 }), dates.allSatisfy({ $0.timeIntervalSince1970.isFinite }),
              scope.count == 64, reuseResult.map({ $0.scope.count == 64 }) ?? true else { throw MopError.invalidVault }
    }
}
