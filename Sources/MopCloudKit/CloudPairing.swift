import Foundation
import MopCore
import MopVault

public extension CloudRepository {
    private func pairingVault(_ invitation: PairingInvitation) async throws -> CloudVault {
        try invitation.validate()
        guard invitation.container == transport.container, invitation.environment == transport.environment else { throw PairingError.invalid }
        try await online()
        let target = try vault(invitation.vault)
        _ = try await target.head() // A pairing never creates or resurrects a zone.
        try Task.checkCancellation()
        return target
    }
    func pairingMessage(_ invitation: PairingInvitation, direction: PairingInvitation.Direction) async throws -> Data? {
        let target = try await pairingVault(invitation)
        let object = try await transport.fetch("p-\(invitation.session.uuidString)-\(direction.rawValue)", vault: target.id)
        try await online(); try invitation.validate(); try Task.checkCancellation()
        guard let object else { return nil }
        guard object.data.count <= PairingInvitation.maximumPayload else { throw PairingError.invalid }
        return object.data
    }
    /// Immutable, create-only messages. Identical retry bytes reconcile a lost response.
    func publishPairing(_ bytes: Data, invitation: PairingInvitation, direction: PairingInvitation.Direction) async throws {
        guard bytes.count <= PairingInvitation.maximumPayload else { throw PairingError.invalid }
        let target = try await pairingVault(invitation)
        let id = "p-\(invitation.session.uuidString)-\(direction.rawValue)"
        if let prior = try await transport.fetch(id, vault: target.id) {
            guard prior.data == bytes else { throw PairingError.occupied }; return
        }
        try invitation.validate(); try Task.checkCancellation()
        do { _ = try await transport.save(id, kind: .blob, data: bytes, vault: target.id, expected: nil) }
        catch {
            let original = error
            if let prior = try await transport.fetch(id, vault: target.id) {
                guard prior.data == bytes else { throw PairingError.occupied }
            } else { throw original }
        }
        try await online(); try Task.checkCancellation()
    }
}
