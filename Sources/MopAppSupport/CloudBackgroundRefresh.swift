import Foundation
import MopCloudKit

/// Refresh ciphertext without opening a Keychain identity or authenticating the
/// user. Downloaded revisions become offline snapshots only after verification
/// by the normal authenticated vault service.
public enum CloudBackgroundRefresh {
    public static func download() async throws {
        guard NetworkAvailability.shared.isOnline else { return }
        let configuration = DefaultVaultPlatformConfiguration()
        let cloud = try configuration.cloudConfiguration()
        let transport = AppleCloudTransport(container: cloud.container, environment: cloud.environment)
        let repository = try await CloudRepository.open(transport: transport, state: configuration.stateDirectory)
        for id in try await repository.list() {
            try Task.checkCancellation()
            _ = try await repository.vault(id).sync()
        }
    }
}
