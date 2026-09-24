import Foundation
import Synchronization
import Testing
import MopCore
import MopVault
@testable import MopAppSupport

private final class PairingTestService: VaultService, Sendable {
    let operations = Mutex<[PairingOperation]>([])
    let handler: @Sendable (PairingOperation) async throws -> PairingProgress?
    init(_ handler: @escaping @Sendable (PairingOperation) async throws -> PairingProgress?) { self.handler = handler }
    var authenticatedAt: TimeInterval? { 0 }
    func lock() {}
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult {
        guard case .pairing(let action) = operation else { throw MopError.invalidProcess }
        operations.withLock { $0.append(action) }
        var result = VaultResult(); result.pairing = try await handler(action); return result
    }
}
@MainActor struct PairingCoordinatorTests {
    func waitUntil(_ predicate: () -> Bool) async throws {
        for _ in 0..<600 {
            if predicate() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        Issue.record("Pairing coordinator did not reach expected state")
    }
    @Test func macApprovalRequiresExplicitAction() async throws {
        let id = UUID(), vault = UUID(), expires = Date().addingTimeInterval(60)
        let approved = Mutex(false)
        let acknowledged = Mutex(false)
        let service = PairingTestService { action in
            let phase: PairingProgress.Phase
            switch action {
            case .start: phase = .displaying
            case .poll: phase = approved.withLock { $0 } ? (acknowledged.withLock { $0 } ? .complete : .awaitingTrust) : .comparing
            case .approve: approved.withLock { $0 = true }; phase = .awaitingTrust
            default: return nil
            }
            return PairingProgress(session: id, vault: vault, expires: expires, phase: phase,
                                   qr: phase == .displaying ? "sensitive qr" : nil, code: phase == .displaying ? nil : "123456")
        }
        let coordinator = PairingCoordinator(service: service)
        coordinator.start(vault: vault.uuidString)
        try await waitUntil { coordinator.progress?.phase == .comparing }
        #expect(coordinator.progress?.qr == nil)
        #expect(!service.operations.withLock { $0.contains { if case .approve = $0 { true } else { false } } })
        coordinator.approve()
        try await waitUntil { coordinator.progress?.phase == .awaitingTrust }
        #expect(!coordinator.finished)
        acknowledged.withLock { $0 = true }
        try await waitUntil { coordinator.finished }
        #expect(coordinator.progress?.phase == .complete)
        #expect(coordinator.submitted)
        coordinator.cancel()
    }
    @Test func duplicateScanIgnoredAndExpiryClearsSecrets() async throws {
        let service = PairingTestService { _ in nil }
        let now = Date()
        let invitation = PairingInvitation(vault: UUID(), container: "iCloud.test", environment: "Development", now: now.addingTimeInterval(-298))
        let coordinator = PairingCoordinator(service: service)
        coordinator.scan(try invitation.qr())
        #expect(coordinator.scanned)
        coordinator.scan("not a QR")
        #expect(coordinator.error == nil)
        try await waitUntil { coordinator.finished }
        #expect(coordinator.progress == nil)
        #expect(coordinator.error == PairingError.expired.errorDescription)
        coordinator.join(name: "Phone", strict: false)
        #expect(service.operations.withLock { $0.isEmpty })
    }
    @Test func cancelSuppressesLateCompletion() async throws {
        let id = UUID(), vault = UUID()
        let service = PairingTestService { _ in
            // Deliberately ignore cancellation to exercise late-result suppression.
            try? await Task.sleep(for: .seconds(2))
            return PairingProgress(session: id, vault: vault, expires: Date().addingTimeInterval(60), phase: .displaying, qr: "secret")
        }
        let coordinator = PairingCoordinator(service: service)
        coordinator.start(vault: vault.uuidString)
        try await waitUntil { service.operations.withLock { !$0.isEmpty } }
        coordinator.cancel()
        try await Task.sleep(for: .milliseconds(50))
        #expect(coordinator.finished)
        #expect(coordinator.progress == nil)
        #expect(!coordinator.busy)
    }
    @Test func invalidScanDoesNotCallService() {
        let service = PairingTestService { _ in nil }
        let coordinator = PairingCoordinator(service: service)
        coordinator.scan("https://example.com")
        #expect(!coordinator.scanned)
        #expect(coordinator.error != nil)
        #expect(service.operations.withLock { $0.isEmpty })
        coordinator.cancel()
    }
}
