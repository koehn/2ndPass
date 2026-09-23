import Foundation
import MopCore
import MopVault

public final class CloudSecretStore: AsyncSecretStore {
    public let vault: CloudVault
    private let session: VaultSession
    private let offline: Bool
    public var snapshot: Data { session.snapshot }

    public init(vault: CloudVault, snapshot: Data, opener: any VaultKeyOpener, offline: Bool = false,
                onClose: @escaping () -> Void = {}) throws {
        self.vault = vault; self.offline = offline
        session = try vault.authenticatedSession(snapshot: snapshot, opener: opener, offline: offline, onClose: onClose)
    }
    public func read(_ reference: SecretReference) throws -> String { try session.read(reference) }
    public func list(vault: String?) throws -> [SecretReference] { try session.list(vault: vault) }
    public func fingerprint() throws -> String { try session.fingerprint() }
    public func recipients() throws -> [DeviceRequest] { try session.recipients() }

    private func mutate(rotation: Bool = false, _ body: () throws -> Void) async throws {
        guard !offline else { throw MopError.offlineWrite }
        let expected = session.snapshot
        do {
            try body()
            try await vault.commit(expected: expected, replacement: session.snapshot,
                                   rotationFingerprint: rotation ? session.fingerprint() : nil)
            try vault.finishCommittedSession(session, rotation: rotation)
        } catch { close(); throw error }
    }
    public func write(_ reference: SecretReference, value: String, replace: Bool) async throws {
        try await mutate { try session.write(reference, value: value, replace: replace) }
    }
    public func delete(_ reference: SecretReference) async throws { try await mutate { try session.delete(reference) } }
    public func enroll(_ request: DeviceRequest, fingerprint: String) async throws {
        try await mutate { try session.enroll(request, expectedFingerprint: fingerprint) }
    }
    public func revoke(_ fingerprint: String, currentDevice: Data) async throws {
        try await mutate(rotation: true) { try session.revoke(fingerprint, currentDevice: currentDevice) }
    }
    public func restore(_ revision: String) async throws {
        guard !offline else { throw MopError.offlineWrite }
        guard try await vault.revisions().contains(revision) else { throw MopError.invalidVault }
        let bytes = try await vault.revision(revision)
        try await mutate { try session.restore(bytes) }
    }
    public func close() { session.close() }
    deinit { close() }
}

