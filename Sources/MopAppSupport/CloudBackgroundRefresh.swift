import Foundation
import MopSync

/// A background notification records a durable wake-up for the shared engine
/// owner, or takes the same lease for this OS-granted execution opportunity.
/// It never opens device keys; secret-dependent work stays durably deferred.
public enum CloudBackgroundRefresh {
    public static func request() async throws {
        let account = try await NativeItemCloudAccount.connect(offline: true)
        let repository = try EncryptedItemRepository(storeURL: SyncStoreLayout.contentPreviewURL(in: account.directory), layout: .contentPreview3)
        _ = try await repository.requestSync(account: account.accountNamespace, database: "private", reason: .foreground)
        let runtime = try ItemVaultSyncRuntime(account: account, repository: repository)
        await withTaskCancellationHandler {
            try? await runtime.runAvailableWork()
            await runtime.stop()
        } onCancel: { runtime.invalidate() }
    }
}
