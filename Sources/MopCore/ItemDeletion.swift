import Foundation

/// Encrypted item metadata used to identify a deleted item and its retention window.
public struct ItemDeletion: Codable, Equatable, Sendable {
    public static let retention: TimeInterval = 30 * 24 * 60 * 60
    public let id: UUID
    public let originalName: String
    public let deletedAt: Date
    public var expiresAt: Date { deletedAt.addingTimeInterval(Self.retention) }
    public func isExpired(at date: Date) -> Bool { date >= expiresAt }

    public init(id: UUID = UUID(), originalName: String, deletedAt: Date) {
        self.id = id; self.originalName = originalName; self.deletedAt = deletedAt
    }
}
