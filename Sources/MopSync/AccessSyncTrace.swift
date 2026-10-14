import CryptoKit
import Foundation
import OSLog

/// Diagnostic correlation only: never pass payloads, names, keys or error descriptions.
/// Stable hashes let logs from separate devices identify the same routing IDs.
public enum AccessSyncTrace {
    private static let logger = Logger(subsystem: "com.koehn.mop", category: "CloudSync")

    public static func token(_ identifier: String) -> String {
        SHA256.hash(data: Data(identifier.utf8)).prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    public static func event(_ stage: String, operation: UUID? = nil, item: UUID? = nil,
                             generation: UUID? = nil, recipient: String? = nil, record: String? = nil,
                             detail: String = "") {
        let op = operation.map { token($0.uuidString) } ?? "-"
        let item = item.map { token($0.uuidString) } ?? "-"
        let generation = generation.map { token($0.uuidString) } ?? "-"
        let recipient = recipient.map(token) ?? "-"
        let record = record.map(token) ?? "-"
        logger.notice("Access trace: \(stage, privacy: .public) op=\(op, privacy: .public) item=\(item, privacy: .public) generation=\(generation, privacy: .public) recipient=\(recipient, privacy: .public) record=\(record, privacy: .public) \(detail, privacy: .public)")
    }

    public static func failure(_ stage: String, operation: UUID, error: any Error) {
        let native = error as NSError
        event(stage, operation: operation,
              detail: "type=\(String(reflecting: type(of: error))) code=\(native.code)")
    }
}
