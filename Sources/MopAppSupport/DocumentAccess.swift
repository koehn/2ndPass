import Foundation
import MopCore
import MopVaultNext

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
    /// File providers may not expose private POSIX modes. Stage a bounded copy in
    /// the protected sandbox, then apply the normal strict recovery parser.
    public static func importRecovery(_ source: URL, state: URL = AppStorageLocation.defaultState) throws -> URL {
        let access = source.startAccessingSecurityScopedResource()
        defer { if access { source.stopAccessingSecurityScopedResource() } }
        let directory = state.appendingPathComponent("imports", isDirectory: true)
        try LocalFile.privateDirectory(directory)
        let target = directory.appendingPathComponent(UUID().uuidString + ".key")
        var failure: Error?
        var coordinatorError: NSError?
        NSFileCoordinator().coordinate(readingItemAt: source, options: [], error: &coordinatorError) { url in
            do {
                var bytes = try LocalFile.read(url, limit: 64 * 1024)
                defer { SecretBytes.wipe(&bytes) }
                try LocalFile.write(bytes, to: target)
                try ExchangeFile.decode(DeviceRequest.self, from: bytes).validate()
            } catch { failure = error }
        }
        if let error = failure ?? coordinatorError {
            try? FileManager.default.removeItem(at: target)
            throw error
        }
        return target
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
