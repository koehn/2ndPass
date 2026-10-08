import Foundation
import Testing
import MopCore
@testable import MopVaultNext

@Test func verifiedHealthOpeningRetainsBindingSignatureAndRecipientChecks() throws {
    let owner = try TestDevice(), authority = try testAuthority(owner: owner), item = UUID()
    let digest = try MembershipEnvelope.genesis(vault: authority.id, membership: authority.membership, owner: owner).digest()
    let envelope = try ItemHealthEnvelope.seal([], vault: authority.id, item: item, generation: 1,
        membership: authority.membership, membershipStateDigest: digest, signer: owner)
    let bytes = try envelope.encoded()
    let verified = try ItemHealthEnvelope.decodeVerified(bytes, vault: authority.id, item: item,
        membership: authority.membership, membershipStateDigest: digest)
    #expect(try verified.open(device: owner).isEmpty)
    let stranger = try TestDevice()
    #expect(throws: MopError.self) { try verified.open(device: stranger) }
    #expect(throws: MopError.self) {
        try ItemHealthEnvelope.decodeVerified(bytes, vault: UUID(), item: item,
            membership: authority.membership, membershipStateDigest: digest)
    }
    #expect(throws: MopError.self) {
        try ItemHealthEnvelope.decodeVerified(bytes, vault: authority.id, item: UUID(),
            membership: authority.membership, membershipStateDigest: digest)
    }
    #expect(throws: MopError.self) {
        try ItemHealthEnvelope.decodeVerified(bytes, vault: authority.id, item: item,
            membership: authority.membership, membershipStateDigest: String(repeating: "0", count: 64))
    }
    let corrupted = ItemHealthEnvelope(header: envelope.header, ciphertext: envelope.ciphertext,
        envelopes: envelope.envelopes, signature: Data(repeating: 0, count: 64))
    #expect(throws: MopError.self) {
        try ItemHealthEnvelope.decodeVerified(corrupted.encoded(), vault: authority.id, item: item,
            membership: authority.membership, membershipStateDigest: digest)
    }
    owner.close()
    #expect(throws: MopError.self) { try verified.open(device: owner) }
}
