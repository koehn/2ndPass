import Foundation

/// Deterministic routing only. Authorization still comes from signed membership
/// and grants, bound to the independently pinned account/vault.
public struct RecipientGrantZone: Equatable, Sendable {
    public let vault: UUID
    public let recipient: String
    public var name: String { "MopGrants4-" + vault.uuidString + "-" + recipient }
    public init(vault: UUID, recipient: String) throws {
        guard recipient.utf8.count == 64,
              recipient.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw ContentStoreError.invalidRecord }
        self.vault = vault; self.recipient = recipient
    }
    public init(name: String) throws {
        let prefix = "MopGrants4-"
        guard name.hasPrefix(prefix), name.count == prefix.count + 36 + 1 + 64 else { throw ContentStoreError.invalidRecord }
        let rest = String(name.dropFirst(prefix.count))
        guard let vault = UUID(uuidString: String(rest.prefix(36))) else { throw ContentStoreError.invalidRecord }
        try self.init(vault: vault, recipient: String(rest.suffix(64)))
        guard self.name == name else { throw ContentStoreError.invalidRecord }
    }
}

extension RecipientGrantZone {
    /// Membership supplies eligibility; locally enrolled identity and explicit
    /// recovery-key presentation select subscriptions. Publisher destinations
    /// are intentionally absent from this function.
    public static func downloads(vault: UUID, devices: Set<String>, local: String?,
                                 recovery: String?, presentedRecovery: String?) throws -> [String] {
        var recipients = Set<String>()
        if let local, devices.contains(local) { recipients.insert(local) }
        if let recovery, recovery == presentedRecovery { recipients.insert(recovery) }
        return try recipients.sorted().map { try RecipientGrantZone(vault: vault, recipient: $0).name }
    }
}
