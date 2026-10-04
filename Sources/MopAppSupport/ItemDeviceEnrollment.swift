import Foundation
import MopCore

/// Display data for enrollment through the authenticated same-account iCloud channel.
public struct ItemEnrollmentRequestView: Sendable, Identifiable {
    public let id: UUID
    public let deviceID: UUID
    public let expiresAt: Date
    public init(id: UUID, deviceID: UUID, expiresAt: Date) {
        self.id = id; self.deviceID = deviceID; self.expiresAt = expiresAt
    }
}
public struct ItemEnrollmentView: Sendable {
    public var request: ItemEnrollmentRequestView?
    public var inbox: [ItemEnrollmentRequestView] = []
    public var approvalAvailable = false
    public init() {}
}
public struct ItemVaultDiscovery: Sendable {
    public let vaults: [VaultDescriptor]
    public let complete: Bool
    public init(vaults: [VaultDescriptor], complete: Bool) { self.vaults = vaults; self.complete = complete }
}
