import Foundation
import Synchronization
import Testing
import MopCore
import MopVaultNext
@testable import MopAppSupport

private final class EnrollmentAuthorizationBackend: ItemVaultServiceBackend, Sendable {
    struct State {
        var authorizedAt: TimeInterval?
        var prompts = 0
        var syncs = 0
    }
    let state = Mutex(State())
    var enrollmentAuthorizedAt: TimeInterval? { state.withLock { $0.authorizedAt } }
    func inventory() async throws -> [VaultDescriptor] { [] }
    func enrollment(_ action: VaultManagement, vaultID: UUID) async throws -> VaultResult {
        state.withLock {
            if $0.authorizedAt == nil { $0.authorizedAt = 42; $0.prompts += 1 }
        }
        return VaultResult()
    }
    func open(_ vaultID: UUID) async throws -> ItemVaultSession { throw MopError.vaultMissing }
    func create(name: String, id: UUID, archiveData: Data?, recoveryKey: SecretBytes?) async throws -> ItemVaultSession {
        throw MopError.invalidVault
    }
    func requestSync() async throws { state.withLock { $0.syncs += 1 } }
    func lock() { state.withLock { $0.authorizedAt = nil } }
}

@Test func enrollmentAuthorizationSurvivesDiscoveryWithoutOpeningVaultAndEndsOnLock() async throws {
    let backend = EnrollmentAuthorizationBackend()
    let service = ItemVaultService(backend: backend)
    let vault = UUID().uuidString
    try await service.requestSynchronization()
    #expect(backend.state.withLock { $0.syncs } == 0)
    _ = try await service.execute(.manage(.automaticEnrollment), vault: vault, offline: false)
    _ = try await service.execute(.discover, vault: nil, offline: false)
    #expect(service.enrollmentAuthorizedAt == 42)
    #expect(!service.isAuthenticated)
    _ = try await service.execute(.manage(.automaticEnrollment), vault: vault, offline: false)
    #expect(backend.state.withLock { $0.prompts } == 1)
    try await service.requestSynchronization()
    #expect(backend.state.withLock { $0.syncs } == 1)
    service.lock()
    #expect(service.enrollmentAuthorizedAt == nil && !service.isAuthenticated)
    try await service.requestSynchronization()
    #expect(backend.state.withLock { $0.syncs } == 1)
}
