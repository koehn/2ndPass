import Foundation
import MopSync

/// A background notification records a durable wake-up for the shared engine
/// owner. It never opens device keys, creates a second engine or claims a fetch
/// completed. If no owner can run, the next authorized foreground session drains it.
public enum CloudBackgroundRefresh {
    public static func request() async throws {
        let account = try await NativeItemCloudAccount.connect(offline: true)
        let repository = try EncryptedItemRepository(storeURL: account.directory.appendingPathComponent("Items.sqlite"))
        _ = try await repository.requestSync(account: account.accountNamespace, database: "private", reason: .foreground)
    }
}
