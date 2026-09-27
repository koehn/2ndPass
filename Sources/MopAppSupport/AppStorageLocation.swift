import Foundation
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
    public static var defaultState: URL {
        #if os(macOS)
        if let override = ProcessInfo.processInfo.environment["MOP_STATE_DIRECTORY"] { return URL(fileURLWithPath: override, isDirectory: true) }
        #endif
        if let group = SigningIdentity.appGroupIdentifier,
           let root = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) {
            return root.appendingPathComponent("MopV6", isDirectory: true)
        }
        return URL.applicationSupportDirectory.appendingPathComponent("Mop", isDirectory: true)
    }
}
