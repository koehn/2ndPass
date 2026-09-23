import Foundation
import Testing
import MopCore

@Test func deletionExpiresAtThirtyDaysAndRoundTrips() throws {
    let deletedAt = Date(timeIntervalSince1970: 1_000_000)
    let deletion = ItemDeletion(originalName: "Login", deletedAt: deletedAt)
    #expect(!deletion.isExpired(at: deletion.expiresAt.addingTimeInterval(-1)))
    #expect(deletion.isExpired(at: deletion.expiresAt))
    #expect(deletion.expiresAt.timeIntervalSince(deletedAt) == 2_592_000)
    let decoded = try JSONDecoder().decode(ItemDeletion.self, from: JSONEncoder().encode(deletion))
    #expect(decoded == deletion)
}
