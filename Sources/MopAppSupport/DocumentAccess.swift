import Foundation
import MopCore

public protocol DocumentAccessing: Sendable {
    func importRecovery(_ source: URL, state: URL) throws -> URL
    func write<T>(to destination: URL, _ action: (URL) throws -> T) throws -> T
}

public struct SystemDocumentAccess: DocumentAccessing {
    public init() {}
    public func importRecovery(_ source: URL, state: URL) throws -> URL {
        try DocumentAccess.importRecovery(source, state: state)
    }
    public func write<T>(to destination: URL, _ action: (URL) throws -> T) throws -> T {
        try DocumentAccess.write(to: destination, action)
    }
}

public enum DocumentAccess {
    /// The old device-request/recovery document route was removed at item cutover.
    public static func importRecovery(_ source: URL, state: URL = AppStorageLocation.defaultState) throws -> URL {
        throw ItemVaultServiceFailure.unavailable
    }

    public static func write<T>(to destination: URL, _ action: (URL) throws -> T) throws -> T {
        let folder = destination.deletingLastPathComponent()
        let access = folder.startAccessingSecurityScopedResource()
        defer { if access { folder.stopAccessingSecurityScopedResource() } }
        var outcome: Result<T, Error>?
        var coordinatorError: NSError?
        NSFileCoordinator().coordinate(writingItemAt: destination, options: [], error: &coordinatorError) { url in
            outcome = Result { try action(url) }
        }
        if let coordinatorError { throw coordinatorError }
        guard let outcome else { throw MopError.inputOutput }
        return try outcome.get()
    }
}
