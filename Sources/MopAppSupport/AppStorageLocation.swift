import Foundation
import CryptoKit
import MopCore
import MopKeychain

public protocol VaultPlatformConfiguration: Sendable {
    var stateDirectory: URL { get }
    func cloudConfiguration() throws -> (container: String, environment: String)
}

public struct DefaultVaultPlatformConfiguration: VaultPlatformConfiguration {
    public init() {}
    public var stateDirectory: URL { AppStorageLocation.defaultState }
    public func cloudConfiguration() throws -> (container: String, environment: String) {
        try SigningIdentity.cloudConfiguration()
    }
}

public enum AppStorageLocation {
    /// The item backend must share its store with the CLI and extensions. A
    /// missing entitlement must not silently create an isolated client store.
    /// Tests inject their own directory when constructing the repository.
    public static func sharedItemSyncDirectory(container: String, environment: String) throws -> URL {
        guard let group = SigningIdentity.appGroupIdentifier,
              let root = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) else {
            throw MopError.signing
        }
        return try itemSyncDirectory(root: root, container: container, environment: environment)
    }

    /// CloudKit record identifiers are only unique inside their container and
    /// environment. Keep their stores, trust journals and engine state separate.
    static func itemSyncDirectory(root: URL, container: String, environment: String) throws -> URL {
        guard !container.isEmpty, ["Development", "Production"].contains(environment) else {
            throw MopError.signing
        }
        let namespace = try JSONEncoder().encode([container, environment])
        let digest = SHA256.hash(data: namespace).map { String(format: "%02x", $0) }.joined()
        return root.appendingPathComponent("MopItems", isDirectory: true)
            .appendingPathComponent(digest, isDirectory: true)
    }

    /// Uses an opaque namespace so neither account identifiers nor caller input
    /// become filesystem path components. Each account/database owns one lease.
    public static func itemSyncLease(directory: URL, account: String, database: String) throws -> URL {
        guard !account.isEmpty, ["private", "shared"].contains(database) else { throw MopError.invalidVault }
        let binding = try JSONEncoder().encode([account, database])
        let digest = SHA256.hash(data: binding).map { String(format: "%02x", $0) }.joined()
        return directory.appendingPathComponent("Leases", isDirectory: true).appendingPathComponent(digest + ".lock")
    }

    public static var defaultState: URL {
        #if os(macOS)
        if let override = ProcessInfo.processInfo.environment["MOP_STATE_DIRECTORY"] { return URL(fileURLWithPath: override, isDirectory: true) }
        #endif
        if let group = SigningIdentity.appGroupIdentifier,
           let root = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) {
            return root.appendingPathComponent("MopV7", isDirectory: true)
        }
        return URL.applicationSupportDirectory.appendingPathComponent("MopV7", isDirectory: true)
    }
}
