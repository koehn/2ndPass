import Foundation
import Testing
@testable import MopCore

@Suite struct AttachmentTests {
    @Test func binaryEnvelopeRoundTripsAndRejectsUnsafeNames() throws {
        let attachment = try Attachment(fileName: "proof.bin", data: Data([0, 255, 128, 42]))
        #expect(try Attachment.decode(attachment.encodedValue()) == attachment)
        for name in ["", ".", "..", "../proof", "a/b", "a\\b", "a\0b"] {
            #expect(throws: AttachmentFailure.invalid) { try Attachment(fileName: name, data: Data()) }
        }
        #expect(throws: AttachmentFailure.tooLarge) { try Attachment(fileName: "big", data: Data(repeating: 0, count: Attachment.maximumBytes + 1)) }
        #expect(throws: AttachmentFailure.invalid) { try Attachment.decode("not an attachment") }
    }
}
