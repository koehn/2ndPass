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
        URL(fileURLWithPath: ProcessInfo.processInfo.environment["MOP_STATE_DIRECTORY"]
            ?? URL.applicationSupportDirectory.appendingPathComponent("Mop", isDirectory: true).path, isDirectory: true)
        #else
        URL.applicationSupportDirectory.appendingPathComponent("Mop", isDirectory: true)
        #endif
    }
}
