import Foundation
import Testing
import MopCore
import MopSync
@testable import MopVaultNext
@testable import MopAppSupport

private struct JoinedDisplayBackend: ItemVaultServiceBackend {
    let session: ItemVaultSession
    func inventory() async throws -> [VaultDescriptor] {
        [VaultDescriptor(id: session.binding.vaultID.uuidString, name: "existing", format: "mop-content-v3", enrolled: true)]
    }
    func open(_ vaultID: UUID) async throws -> ItemVaultSession { session }
    func create(name: String, id: UUID, archiveData: Data?, recoveryKey: SecretBytes?) async throws -> ItemVaultSession { throw MopError.invalidVault }
    func requestSync() async throws {}
    func lock() { session.lock() }
}

@Test func enrollmentRequestSurvivesRestartAndRetainsIdentityAcrossRetry() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mop-enrollment-request-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let device = try SessionDevice()
    let scope = EnrollmentScope(container: "iCloud.test", environment: "Development", account: "account", vault: UUID(), member: device.identity.member)
    let original = try DeviceEnrollmentRequest.create(scope: scope, device: device)
    let store = ItemEnrollmentRequestStore(directory: directory, scope: scope)
    #expect(try store.reserve(original) == original)
    let reopened = ItemEnrollmentRequestStore(directory: directory, scope: scope)
    #expect(try reopened.load() == original)
    let retry = try DeviceEnrollmentRequest.create(scope: scope, device: device)
    #expect(retry.id != original.id)
    #expect(try reopened.reserve(retry) == original)
    let foreignScope = EnrollmentScope(container: scope.container, environment: "Production", account: scope.account, vault: scope.vault, member: scope.member)
    #expect(throws: DeviceEnrollmentFailure.invalidRequest) {
        try ItemEnrollmentRequestStore(directory: directory, scope: foreignScope).load()
    }
    let otherAccount = EnrollmentScope(container: scope.container, environment: scope.environment, account: "other", vault: scope.vault, member: scope.member)
    #expect(try ItemEnrollmentRequestStore(directory: directory, scope: otherAccount).load() == nil)
    try reopened.clear()
    #expect(try reopened.load() == nil)
}
