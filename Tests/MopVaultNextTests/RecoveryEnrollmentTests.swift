import Foundation
import Testing
import MopCore
@testable import MopVaultNext

private func recoveryEnrollmentFixture() throws -> (TestDevice, TestDevice, OfflineRecoveryKey, TrustedMembershipHistory, EnrollmentScope) {
    let scope = try RecoveryScope(container: "iCloud.test", environment: "Development", account: "account")
    let recovery = try OfflineRecoveryKey(scope: scope), owner = try TestDevice(member: scope.member), joining = try TestDevice(member: scope.member)
    let membership = try Membership(accounts: [.init(id: scope.member, role: .owner, devices: [owner.identity])], offlineRecovery: recovery.identity)
    let genesis = try MembershipEnvelope.genesis(membership: membership, owner: owner)
    let history = try TrustedMembershipHistory(genesis: genesis, vault: genesis.header.vault, pinnedDigest: genesis.digest())
    return (owner, joining, recovery, history, EnrollmentScope(container: scope.container, environment: scope.environment, account: scope.account, vault: history.vault, member: scope.member))
}

@Test func recoveryEnrollsNewDeviceWithoutAnAvailableOwnerAndPreservesRecipients() throws {
    let (owner, joining, recovery, history, scope) = try recoveryEnrollmentFixture()
    let document = try portableDocument(items: [VaultItem(name: "login", type: .login,
        fields: [.init(path: "password", type: .password, value: "secret")])])
    let original = try ItemEnvelope.seal(document, vault: scope.vault, generation: 1,
        membership: history.current.membership, membershipStateDigest: history.current.digest(), signer: owner)
    let request = try DeviceEnrollmentRequest.create(scope: scope, device: joining)
    let approval = try DeviceEnrollmentApproval.create(request: request, history: history, owner: recovery)
    let accepted = try DeviceEnrollmentApproval.decode(approval.encoded()).acceptFromAuthenticatedPrivateCloudKit(request: request, scope: scope)
    let repaired = try original.repairingMembership(history: accepted, decryptor: recovery, signer: joining)
    #expect(accepted.current.membership.devices.contains(owner.identity))
    #expect(accepted.current.membership.offlineRecovery == recovery.identity)
    #expect(repaired.encryptedRecords == original.encryptedRecords)
    #expect(repaired.header.keyGeneration == original.header.keyGeneration)
    for device: any DeviceOperations in [owner, joining, recovery] {
        for (id, record) in document.records {
            #expect(try repaired.read(record: id, device: device, membership: accepted.current.membership,
                membershipStateDigest: accepted.current.digest()) == record.bytes)
        }
    }
    #expect(throws: (any Error).self) {
        try ItemEnvelope.seal(document, vault: scope.vault, generation: 1,
            membership: accepted.current.membership, membershipStateDigest: accepted.current.digest(), signer: recovery)
    }
}

@Test func recoverySignerCannotReplaceRecoveryOrRemoveDevices() throws {
    let (owner, joining, recovery, history, _) = try recoveryEnrollmentFixture()
    let added = try Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])], offlineRecovery: recovery.identity)
    #expect(throws: (any Error).self) {
        try MembershipEnvelope.successor(of: history.current, membership: added, owner: recovery)
    }
    let removed = try Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [joining.identity])],
        offlineRecovery: recovery.identity, removedDevices: [owner.identity.device])
    #expect(throws: (any Error).self) { try MembershipEnvelope.successor(of: history.current, membership: removed, owner: recovery) }
    let revoked = try Membership(accounts: history.current.membership.accounts)
    #expect(throws: (any Error).self) { try MembershipEnvelope.successor(of: history.current, membership: revoked, owner: recovery) }
    let valid = try MembershipEnvelope.successor(of: history.current, membership: revoked, owner: owner)
    try valid.verifyAccountTransition(of: history.current)
    let foreign = try OfflineRecoveryKey(scope: recovery.scope)
    let request = try DeviceEnrollmentRequest.create(scope: EnrollmentScope(container: "iCloud.test", environment: "Development", account: "account", vault: history.vault, member: owner.identity.member), device: joining)
    #expect(throws: (any Error).self) { try DeviceEnrollmentApproval.create(request: request, history: history, owner: foreign) }
}

@Test func envelopeRepairRequestIsBoundAndDeduplicatedWithoutGrantingAuthority() throws {
    let (owner, joining, _, history, scope) = try recoveryEnrollmentFixture()
    let record = UUID(), version = UUID()
    let first = try EnvelopeRepairRequest.create(scope: scope, record: record, version: version, history: history, device: owner)
    let retry = try EnvelopeRepairRequest.create(scope: scope, record: record, version: version, history: history, device: owner)
    #expect(try first.identifier == retry.identifier)
    try EnvelopeRepairRequest.decode(first.encoded()).verify(scope: scope, history: history)
    #expect(throws: (any Error).self) { try EnvelopeRepairRequest.create(scope: scope, record: record, version: version, history: history, device: joining) }
    let otherScope = EnrollmentScope(container: scope.container, environment: scope.environment, account: "other", vault: scope.vault, member: scope.member)
    #expect(throws: (any Error).self) { try first.verify(scope: otherScope, history: history) }
}
