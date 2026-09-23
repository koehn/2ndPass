// Disposable fake transport; no Apple account, Keychain, or real vault access.
import Foundation
import CryptoKit
import MopCore
import MopVault
import MopCloudKit

private actor AuditCloud: CloudTransport {
    nonisolated let container = "iCloud.security-audit"
    nonisolated let environment = "Development"
    var objects: [String: CloudObject] = [:]
    func account() -> String { "fixture-account" }
    func zones() -> [UUID] { [] }
    func createZone(_ vault: UUID) {}
    func fetch(_ id: String, vault: UUID) -> CloudObject? { objects[id] }
    func save(_ id: String, kind: CloudKind, data: Data, vault: UUID, expected: Data?) throws -> CloudObject {
        throw MopError.cloudUnavailable
    }
    func requests(vault: UUID) -> [String] { [] }
    func set(_ id: String, _ data: Data) { objects[id] = CloudObject(data: data, version: Data()) }
}

@main struct CloudAuditProbe {
    static func main() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-cloud-audit-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let device = P256.KeyAgreement.PrivateKey()
        let bytes = try VaultSession.createSnapshot(
            device: DeviceRequest(name: "Fixture", publicKey: device.publicKey.x963Representation), recovery: RecoveryKey())
        let document = try VaultDocument.decode(bytes)
        let parts = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        let cloud = AuditCloud()
        let vault = CloudVault(id: document.header.vaultID, cache: try CloudCache(directory: root),
                               transport: cloud, accountID: "fixture-account")
        let revision = String(repeating: "0", count: 64)
        await cloud.set("head", try JSONSerialization.data(withJSONObject: ["revision": revision, "root": revision]))
        for attempt in 0..<3 {
            // A hash is not authentication: the service chooses both bytes and hash.
            let invalid = Data(repeating: UInt8(65 + attempt), count: 65_536)
            let hash = VaultCoding.digest(invalid)
            let manifest: [String: Any] = ["format": "mop-cloud-manifest-v1", "header": parts["header"]!,
                                           "sealed": parts["sealed"]!, "records": [UUID().uuidString: hash]]
            await cloud.set("m-" + revision, try JSONSerialization.data(withJSONObject: manifest))
            await cloud.set("s-" + hash, invalid)
            do {
                _ = try await vault.sync()
                fatalError("Expected malformed record rejection")
            } catch MopError.invalidVault {}
            let cached = root.appendingPathComponent(hash + ".blob")
            let persisted = try Data(contentsOf: cached)
            precondition(persisted == invalid)
        }
        let files = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "blob" }
        let retained = try files.reduce(0) { try $0 + Data(contentsOf: $1).count }
        precondition(files.count == 3 && retained == 196_608)
        print("CONFIRMED: three rejected syncs retained \(files.count) malformed blobs, \(retained) bytes, without authentication.")
    }
}
