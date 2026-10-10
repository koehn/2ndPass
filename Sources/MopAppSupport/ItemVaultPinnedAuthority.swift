import Foundation
import MopCore
import MopSync
import MopVaultNext

public protocol ItemVaultInventoryStore: ItemVaultTrustStore {
    func records(container: String, environment: String, account: String) throws -> [ItemVaultSetupRecord]
}
