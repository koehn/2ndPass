import CryptoKit
import Foundation
import Testing
import MopCore
@testable import MopVault

struct PairingTests {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    func invite() -> PairingInvitation { PairingInvitation(vault: UUID(), container: "iCloud.test", environment: "Development", now: now) }
    func request() throws -> PairingRequest { PairingRequest(device: try DeviceRequest(name: "Phone", publicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation)) }
    @Test func roundTripAndCode() throws {
        let invitation = invite(), request = try request()
        let parsed = try PairingInvitation.parse(invitation.qr(now: now), now: now)
        let bytes = try invitation.seal(request, direction: .request, now: now)
        #expect(try parsed.open(PairingRequest.self, bytes: bytes, direction: .request, now: now) == request)
        #expect(try parsed.confirmation(request, now: now) == invitation.confirmation(request, now: now))
        #expect(try parsed.confirmation(request, now: now).count == 6)
        #expect(try invitation.seal(request, direction: .request, now: now) != bytes)
    }
    @Test func tamperingAndContextSeparation() throws {
        let invitation = invite(), request = try request()
        let bytes = try invitation.seal(request, direction: .request, now: now)
        var corrupt = bytes; corrupt[corrupt.count - 1] ^= 1
        #expect(throws: PairingError.self) { try invitation.open(PairingRequest.self, bytes: corrupt, direction: .request, now: now) }
        #expect(throws: PairingError.self) { try invite().open(PairingRequest.self, bytes: bytes, direction: .request, now: now) }
        #expect(throws: PairingError.self) { try invitation.open(PairingRequest.self, bytes: bytes, direction: .response, now: now) }
        let qr = try invitation.qr(now: now)
        let data = try #require(Data(base64Encoded: String(qr.dropFirst(11))))
        var json = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        for field in ["vault", "session", "container", "environment", "expires"] {
            var changed = json
            switch field {
            case "vault", "session": changed[field] = UUID().uuidString
            case "environment": changed[field] = "Production"
            case "expires": changed[field] = invitation.expires - 1
            default: changed[field] = "iCloud.other"
            }
            let other = try JSONDecoder().decode(PairingInvitation.self, from: JSONSerialization.data(withJSONObject: changed))
            #expect(throws: PairingError.self) { try other.open(PairingRequest.self, bytes: bytes, direction: .request, now: now) }
        }
        json["version"] = 2
        let unsupported = "mop-pair:1:" + (try JSONSerialization.data(withJSONObject: json)).base64EncodedString()
        #expect(throws: PairingError.self) { try PairingInvitation.parse(unsupported, now: now) }
    }
    @Test func malformedExpiredAndOversized() throws {
        let invitation = invite(), qr = try invitation.qr(now: now)
        for text in ["", "https://example.com", "mop-pair:1:not base64", String(repeating: "x", count: 2049)] {
            #expect(throws: PairingError.self) { try PairingInvitation.parse(text, now: now) }
        }
        #expect(throws: PairingError.self) { try PairingInvitation.parse(qr, now: now.addingTimeInterval(300)) }
        #expect(throws: PairingError.self) { try PairingInvitation.parse(qr, now: now.addingTimeInterval(-60)) }
        #expect(throws: PairingError.self) { try invitation.seal(String(repeating: "x", count: 8192), direction: .request, now: now) }
        #expect(throws: PairingError.self) { try invitation.open(PairingRequest.self, bytes: Data(count: 8193), direction: .request, now: now) }
    }
    @Test func receiptBindsEntireRequest() throws {
        let request = try request()
        let receipt = try PairingReceipt(request: request, vaultFingerprint: String(repeating: "a", count: 64), revision: String(repeating: "b", count: 64))
        try receipt.validate(request: request)
        #expect(throws: PairingError.self) { try receipt.validate(request: PairingRequest(device: request.device)) }
        let renamed = try DeviceRequest(name: "Impostor", publicKey: request.device.publicKey)
        #expect(throws: PairingError.self) { try receipt.validate(request: PairingRequest(device: renamed)) }
    }
}
