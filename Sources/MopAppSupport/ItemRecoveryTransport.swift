@preconcurrency import CloudKit
import Foundation
import MopCore
import MopSync
import MopVaultNext

/// Native implementations must authenticate the private CloudKit account before
/// returning a bootstrap history. Test transports model that same boundary.
protocol ItemRecoveryAccount: Sendable {
    var containerIdentifier: String { get }
    var environment: String { get }
    var accountNamespace: String { get }
    var memberID: UUID { get }
    var directory: URL { get }
    var recoveryScope: RecoveryScope { get }
    func setupScope(vaultID: UUID) throws -> ItemVaultSetupScope
}
extension NativeItemCloudAccount: ItemRecoveryAccount {}

protocol ItemRecoveryTransport: Sendable {
    func check() async throws
    func discover() async throws -> [VaultDescriptor]
    func history(_ vault: UUID) async throws -> (TrustedMembershipHistory, ProvisioningCloudRecord)
    func publish(_ successor: MembershipEnvelope, expected: ProvisioningCloudRecord) async throws
    func records(_ vault: UUID) async throws -> [(EncryptedItemVersion, Data)]
    @discardableResult func save(_ version: EncryptedItemVersion, expected: Data) async throws -> Data
    func configuration() async throws -> (RecoveryConfiguration, CKRecord?)
    func saveConfiguration(_ value: RecoveryConfiguration, expected: CKRecord?) async throws
}
extension NativeItemRecoveryTransport: ItemRecoveryTransport {
    func discover() async throws -> [VaultDescriptor] { try await NativeItemEnrollmentTransport(account: account).discover() }
}
