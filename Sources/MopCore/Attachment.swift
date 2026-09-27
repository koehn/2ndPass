import Foundation

public enum AttachmentFailure: Error, LocalizedError, Sendable {
    case tooLarge, capacity, invalid, unavailable
    public var errorDescription: String? {
        switch self {
        case .unavailable: "This attachment is not downloaded on this device. Connect to download it."
        case .tooLarge: "Attachments may contain up to 8 MiB."
        case .capacity: "The vault metadata would exceed its 16 MiB revision capacity."
        case .invalid: "The attachment is missing or has an invalid filename or content."
        }
    }
}

/// The complete envelope is a concealed field value, encrypted by the normal
/// record lifecycle. No file bytes or filenames need to be stored outside it.
public struct Attachment: Codable, Equatable, Sendable {
    public static let maximumBytes = 8 * 1024 * 1024
    public let fileName: String
    public var data: Data
    public init(fileName: String, data: Data) throws {
        self.fileName = fileName; self.data = data
        try validate()
    }
    public func validate() throws {
        guard !fileName.isEmpty, ![".", ".."].contains(fileName),
              !fileName.contains("/"), !fileName.contains("\\"), !fileName.contains("\0"),
              fileName.utf8.count <= 255 else { throw AttachmentFailure.invalid }
        guard data.count <= Self.maximumBytes else { throw AttachmentFailure.tooLarge }
    }
    public func encodedValue() throws -> String {
        try validate()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return String(decoding: try encoder.encode(self), as: UTF8.self)
    }
    public static func decode(_ value: String) throws -> Self {
        guard value.utf8.count <= maximumBytes * 4 / 3 + 4096 else { throw AttachmentFailure.tooLarge }
        guard let attachment = try? JSONDecoder().decode(Self.self, from: Data(value.utf8)) else { throw AttachmentFailure.invalid }
        try attachment.validate()
        return attachment
    }
}
