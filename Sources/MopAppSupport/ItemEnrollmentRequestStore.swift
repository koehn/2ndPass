import Foundation
import MopCore
import MopVaultNext

/// The request is public and signed; private keys remain in the device Keychain.
/// Saving before publication makes retry/relaunch reuse the same enrollment ID.
struct ItemEnrollmentRequestStore: Sendable {
    let directory: URL
    let scope: EnrollmentScope
    private var location: URL {
        directory.appendingPathComponent("Enrollment").appendingPathComponent(setupHash(Data((scope.account + "/" + scope.vault.uuidString).utf8)))
    }
    func load() throws -> DeviceEnrollmentRequest? {
        let directory = try LocalDirectory(directory: location)
        return try directory.locked {
            let file = location.appendingPathComponent("request.json")
            guard FileManager.default.fileExists(atPath: file.path) else { return nil }
            let request = try DeviceEnrollmentRequest.decode(LocalFile.read(file, privateFile: true, limit: 65_536))
            guard request.scope == scope else { throw DeviceEnrollmentFailure.invalidRequest }
            return request
        }
    }
    func reserve(_ request: DeviceEnrollmentRequest) throws -> DeviceEnrollmentRequest {
        guard request.scope == scope else { throw DeviceEnrollmentFailure.invalidRequest }
        let directory = try LocalDirectory(directory: location)
        return try directory.locked {
            let file = location.appendingPathComponent("request.json")
            if FileManager.default.fileExists(atPath: file.path) {
                let previous = try DeviceEnrollmentRequest.decode(LocalFile.read(file, privateFile: true, limit: 65_536))
                guard previous.scope == scope else { throw DeviceEnrollmentFailure.invalidRequest }
                return previous
            }
            try LocalFile.write(request.encoded(), to: file, replace: false)
            return request
        }
    }
    /// Preserve canceled transcripts: an owner may have approved concurrently
    /// with cancellation, and that durable grant must remain recoverable.
    func history() throws -> [DeviceEnrollmentRequest] {
        let directory = try LocalDirectory(directory: location)
        return try directory.locked {
            let files = try FileManager.default.contentsOfDirectory(at: location, includingPropertiesForKeys: nil)
                .filter { $0.pathExtension == "json" && $0.lastPathComponent != "request.json" }
            guard files.count <= 128 else { throw MopError.invalidVault }
            return try files.map { file in
                let request = try DeviceEnrollmentRequest.decode(LocalFile.read(file, privateFile: true, limit: 65_536))
                guard request.scope == scope, file.lastPathComponent == request.id.uuidString + ".json" else { throw DeviceEnrollmentFailure.invalidRequest }
                return request
            }
        }
    }
    func clear() throws {
        let directory = try LocalDirectory(directory: location)
        try directory.locked {
            let file = location.appendingPathComponent("request.json")
            if FileManager.default.fileExists(atPath: file.path) {
                let bytes = try LocalFile.read(file, privateFile: true, limit: 65_536)
                let request = try DeviceEnrollmentRequest.decode(bytes)
                guard request.scope == scope else { throw DeviceEnrollmentFailure.invalidRequest }
                let archive = location.appendingPathComponent(request.id.uuidString + ".json")
                if !FileManager.default.fileExists(atPath: archive.path) { try LocalFile.write(bytes, to: archive, replace: false) }
                try FileManager.default.removeItem(at: file)
            }
        }
    }
}
