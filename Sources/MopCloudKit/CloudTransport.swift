import Foundation
import MopCore
import MopVault

public enum CloudKind: String, Sendable { case blob = "MopBlob", head = "MopHead", request = "MopRequest" }

public struct CloudObject: Sendable {
    public let data: Data
    /// Opaque server record system fields. Never synthesize a change tag.
    public let version: Data
    public init(data: Data, version: Data) { self.data = data; self.version = version }
}

/// All addresses are scoped to this transport's container/environment/account.
public protocol CloudTransport: Sendable {
    var container: String { get }
    var environment: String { get }
    func account() async throws -> String
    func validateOfflineAccount() async throws
    func zones() async throws -> [UUID]
    func createZone(_ vault: UUID) async throws
    func fetch(_ id: String, vault: UUID) async throws -> CloudObject?
    func save(_ id: String, kind: CloudKind, data: Data, vault: UUID, expected: Data?) async throws -> CloudObject
    func requests(vault: UUID) async throws -> [String]
}

struct CloudHead: Codable, Sendable {
    let revision: String
    let root: String
}

struct CloudManifest: Codable, Sendable {
    let format: String
    let header: VaultHeader
    let sealed: Data
    let records: [String: String]

    init(document: VaultDocument) throws {
        format = "mop-cloud-manifest-v1"
        header = document.header
        sealed = document.sealed
        records = try document.records.mapValues { VaultCoding.digest(try VaultCoding.encode($0)) }
    }

    func document(records values: [String: VaultRecord]) throws -> VaultDocument {
        guard format == "mop-cloud-manifest-v1", Set(records.keys) == Set(values.keys) else { throw MopError.invalidVault }
        // Decode through the existing v3 validator, including its size limit.
        struct Parts: Encodable { let header: VaultHeader; let sealed: Data; let records: [String: VaultRecord] }
        return try VaultDocument.decode(VaultCoding.encode(Parts(header: header, sealed: sealed, records: values)))
    }
}

func decodeCloud<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
    guard data.count <= VaultCoding.maximumFileSize else { throw MopError.invalidVault }
    do { return try JSONDecoder().decode(type, from: data) }
    catch { throw MopError.invalidVault }
}

public extension CloudTransport {
    func validateOfflineAccount() async throws {}
}
