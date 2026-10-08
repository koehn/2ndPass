import Foundation
import CryptoKit
import MopCore
import MopSync
import MopVaultNext

enum ItemVaultDeletionCleanup {
    static func perform(_ state: VaultDeletionState, account: NativeItemCloudAccount) async throws {
        guard state.phase == .cloudDeleted, state.scope.account == account.accountNamespace else { throw VaultDeletionFailure.staleState }
        try account.withWritePermission {}
        let scope = try account.setupScope(vaultID: state.scope.vaultID)
        try removeAssets(directory: account.leaseURL(database: "private").deletingLastPathComponent(), account: state.scope.account, vaultID: state.scope.vaultID, assetVersions: state.assetVersions)
        try await NativeItemEnrollmentTransport(account: account).purgeDeletedVault(state.scope.vaultID)
        try ItemEnrollmentRequestStore(directory: account.directory, scope: EnrollmentScope(container: account.containerIdentifier,
            environment: account.environment, account: account.accountNamespace, vault: state.scope.vaultID, member: account.memberID)).purge()
        try await AutoFillPublisher().remove(vaultID: state.scope.vaultID.uuidString)
        try await ItemUsageStore().prune(account: account.memberID.uuidString, vault: state.scope.vaultID.uuidString, keeping: [], before: .distantFuture)
        try account.withWritePermission {
            let keyScope = account.containerIdentifier + "/" + account.environment + "/items/" + account.accountNamespace + "/" + state.scope.vaultID.uuidString
            try DeviceKeychain.remove(scope: keyScope, member: account.memberID)
            try KeychainItemVaultTrustStore().removeDeletedVault(scope: scope)
        }
    }
    static func removeAssets(directory: URL, account: String, vaultID: UUID, assetVersions: [UUID]) throws {
        let assets = directory.appendingPathComponent("EncryptedAssets", isDirectory: true)
        let accountDirectory = SHA256.hash(data: Data(account.utf8)).map { String(format: "%02x", $0) }.joined()
        let scoped = assets.appendingPathComponent(accountDirectory, isDirectory: true).appendingPathComponent(vaultID.uuidString, isDirectory: true)
        if FileManager.default.fileExists(atPath: scoped.path) { try FileManager.default.removeItem(at: scoped) }
        // Historical mutation receipts retain every uploaded version, including
        // superseded/acknowledged mutations. Use those exact IDs for the old flat
        // cache; UUID alone cannot distinguish equal vault IDs in other accounts.
        if FileManager.default.fileExists(atPath: assets.path) {
            let versions = Set(assetVersions.map(\.uuidString))
            for file in try FileManager.default.contentsOfDirectory(at: assets, includingPropertiesForKeys: nil)
                where file.pathExtension == "ciphertext" && versions.contains(String(file.lastPathComponent.prefix(36))) {
                try FileManager.default.removeItem(at: file)
            }
        }
    }
}
