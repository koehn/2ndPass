import AuthenticationServices
import Foundation
import MopCore

/// Encrypted labels are held only in a presented, authenticated request.
public struct AutoFillChoice: Identifiable, Equatable, Sendable {
    public var id: String { identity.recordIdentifier }
    public let identity: AutoFillIdentity
    public let itemName: String
    public let vaultName: String
    public init(identity: AutoFillIdentity, itemName: String, vaultName: String) {
        self.identity = identity; self.itemName = itemName; self.vaultName = vaultName
    }
}

public enum AutoFillSessionError: Error, Equatable, Sendable { case expired, ended }

/// One fresh authentication may authorize one fill, never a later request.
@MainActor public final class AutoFillRequestSession {
    private let service: any VaultService
    private let now: () -> TimeInterval
    private let deadline: TimeInterval
    private var ended = false
    public private(set) var unavailableVaults = 0
    public init(service: any VaultService = NativeVaultService(allowsAttachments: false), now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.service = service; self.now = now; deadline = now() + 60
        service.lock()
    }
    deinit { service.lock() }
    public func end() { ended = true; service.lock() }
    public func check() throws {
        guard !ended else { throw AutoFillSessionError.ended }
        guard now() < deadline else { end(); throw AutoFillSessionError.expired }
        try Task.checkCancellation()
    }
    public func choices(for identities: [AutoFillIdentity]) async throws -> [AutoFillChoice] {
        try check()
        var choices: [AutoFillChoice] = []
        var firstFailure: (any Error)?
        unavailableVaults = 0
        let ids = Set(identities.compactMap { AutoFillEntry.vaultID($0.recordIdentifier) }).sorted()
        for id in ids {
            do {
                let result = try await service.execute(.catalog, vault: id, offline: true)
                try check()
                let catalog = try result.requireCatalog()
                let resolved = AutoFillEntry.entries(catalog: catalog, vaultID: id)
                for identity in identities where AutoFillEntry.vaultID(identity.recordIdentifier) == id {
                    guard let entry = resolved.first(where: { $0.recordIdentifier == identity.recordIdentifier && $0.kind == identity.kind }) else { continue }
                    choices.append(AutoFillChoice(identity: AutoFillIdentity(entry: entry), itemName: entry.reference.item, vaultName: catalog.vault))
                }
            } catch {
                try check()
                if let failure = error as? MopError, [.authentication, .deviceRemoved, .deviceRemovalPending, .cloudAccount].contains(failure) { end(); throw error }
                if firstFailure == nil { firstFailure = error }
                unavailableVaults += 1
            }
        }
        if choices.isEmpty, let firstFailure { end(); throw firstFailure }
        return choices
    }
    public func password(_ identity: AutoFillIdentity) async throws -> ASPasswordCredential {
        defer { end() }
        try check()
        let (entry, secret) = try await AutoFillAccess.resolve(recordIdentifier: identity.recordIdentifier, kind: .password, service: service)
        try check()
        guard let bytes = secret.value else { throw MopError.notFound }
        return ASPasswordCredential(user: entry.username, password: String(decoding: bytes, as: UTF8.self))
    }
    public func code(_ identity: AutoFillIdentity) async throws -> (credential: ASOneTimeCodeCredential, expiresAt: Date) {
        defer { end() }
        try check()
        let (_, secret) = try await AutoFillAccess.resolve(recordIdentifier: identity.recordIdentifier, kind: .oneTimeCode, service: service)
        try check()
        guard let bytes = secret.value, let expiry = secret.otpExpiresAt, expiry > Date(),
              let period = secret.otpPeriod, period > 0 else { throw MopError.invalidOTP }
        return (ASOneTimeCodeCredential(code: String(decoding: bytes, as: UTF8.self)), expiry)
    }
}
