import Foundation
import MopVaultNext

/// Only signed descendants of locally trusted roots become cached checkpoints.
/// Background refresh neither opens keys nor invents trust for discovered zones.
public enum CloudBackgroundRefresh {
    public static func download() async throws {
        guard NetworkAvailability.shared.isOnline else { return }
        let configuration = DefaultVaultPlatformConfiguration(), config = try configuration.cloudConfiguration()
        let transport = try CloudRevisionTransport(container: config.container, environment: config.environment)
        let account = try await transport.account()
        let registry = try NextRegistry(state: configuration.stateDirectory, container: config.container, environment: config.environment, account: account)
        guard try !registry.removed() else { return }
        for var entry in try registry.entries() where entry.ready {
            try Task.checkCancellation()
            let storage = try registry.storage(entry)
            let root = try VerifiedVault(checkpoint: entry.checkpoint, independentlyVerifiedDigest: entry.digest)
            let coordinator = try PublicationCoordinator(address: entry.address, checkpoint: root, transport: transport, storage: storage)
            _ = try await coordinator.refresh()
            let current = await coordinator.offlineSnapshot().0
            if AttachmentDownloadSettings.duringSync {
                _ = try await AttachmentDownloads(state: configuration.stateDirectory, address: entry.address)
                    .load(current, digests: current.attachmentDigests, transport: transport, offline: false)
            }
            entry.name = current.name; try registry.put(entry)
        }
    }
}
