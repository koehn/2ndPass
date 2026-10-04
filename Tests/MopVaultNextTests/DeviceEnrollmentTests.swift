import Foundation
import Testing
import MopCore
@testable import MopVaultNext

private func enrollmentFixture() throws -> (TestDevice, TestDevice, EnrollmentScope, TrustedMembershipHistory) {
    let owner = try TestDevice(), joining = try TestDevice(member: owner.identity.member), vault = UUID()
    let membership = try Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity])])
    let genesis = try MembershipEnvelope.genesis(vault: vault, membership: membership, owner: owner)
    return (owner, joining, EnrollmentScope(container: "iCloud.test", environment: "Development", account: "account", vault: vault, member: owner.identity.member),
            try TrustedMembershipHistory(genesis: genesis, vault: vault, pinnedDigest: genesis.digest()))
}

@Test func deviceEnrollmentBindsGrantToAuthenticatedPrivateAccountRequest() throws {
    let (owner, joining, scope, history) = try enrollmentFixture(), now = Date()
    let request = try DeviceEnrollmentRequest.create(scope: scope, device: joining, now: now)
    let approval = try DeviceEnrollmentApproval.create(request: request, history: history, owner: owner, now: now)
    let transported = try DeviceEnrollmentApproval.decode(approval.encoded())
    let accepted = try transported.acceptFromAuthenticatedPrivateCloudKit(request: request, scope: scope, now: now)
    #expect(accepted.current.membership.devices.count == 2)
    #expect(accepted.current.membership.role(of: joining.identity) == .owner)
    #expect(accepted.current.membership.owner == history.current.membership.owner)
    #expect(owner.unwrappedContexts.isEmpty && joining.unwrappedContexts.isEmpty)
    let another = try DeviceEnrollmentRequest.create(scope: scope, device: joining, now: now)
    #expect(throws: (any Error).self) {
        try approval.acceptFromAuthenticatedPrivateCloudKit(request: another, scope: scope, now: now)
    }
    let foreign = EnrollmentScope(container: scope.container, environment: scope.environment, account: "other-account", vault: scope.vault, member: scope.member)
    #expect(throws: (any Error).self) {
        try approval.acceptFromAuthenticatedPrivateCloudKit(request: request, scope: foreign, now: now)
    }
}

@Test func deviceEnrollmentRejectsExpiredAndDifferentAccountMembers() throws {
    let (owner, joining, scope, history) = try enrollmentFixture(), now = Date()
    #expect(throws: DeviceEnrollmentFailure.invalidRequest) {
        try DeviceEnrollmentRequest.create(scope: scope, device: TestDevice(), now: now)
    }
    let request = try DeviceEnrollmentRequest.create(scope: scope, device: joining, now: now)
    #expect(throws: DeviceEnrollmentFailure.expired) { try request.verify(now: now.addingTimeInterval(901)) }
    let approval = try DeviceEnrollmentApproval.create(request: request, history: history, owner: owner, now: now)
    let delayed = try approval.acceptFromAuthenticatedPrivateCloudKit(request: request, scope: scope, now: now.addingTimeInterval(86400))
    #expect(delayed.current.membership.devices.contains(joining.identity))
    #expect(throws: DeviceEnrollmentFailure.expired) {
        try DeviceEnrollmentApproval.create(request: request, history: history, owner: owner, now: now.addingTimeInterval(901))
    }
    var changed = try #require(JSONSerialization.jsonObject(with: request.encoded()) as? [String: Any])
    var address = try #require(changed["scope"] as? [String: Any]); address["account"] = "other-account"; changed["scope"] = address
    let substituted = try JSONSerialization.data(withJSONObject: changed, options: [.sortedKeys])
    #expect(throws: (any Error).self) { try DeviceEnrollmentRequest.decode(substituted) }
}

@Test func admittedDeviceReadsExistingSecretAndAttachmentWithoutResealingTheirCiphertext() throws {
    let (owner, joining, scope, history) = try enrollmentFixture()
    let attachment = try Attachment(fileName: "existing.bin", data: Data([0, 1, 255, 42]))
    let document = try portableDocument(items: [VaultItem(name: "Login", type: .login, fields: [
        ItemField(path: "password", type: .password, value: "existing-secret"),
        ItemField(path: "attachment", type: .attachment, value: try attachment.encodedValue())])])
    let original = try ItemEnvelope.seal(document, vault: scope.vault, generation: 1, membership: history.current.membership,
        membershipStateDigest: history.current.digest(), signer: owner)
    let request = try DeviceEnrollmentRequest.create(scope: scope, device: joining)
    let approval = try DeviceEnrollmentApproval.create(request: request, history: history, owner: owner)
    let admitted = try original.admittingDevice(joining.identity, previous: history.current, successor: approval.successor, signer: owner)
    #expect(admitted.encryptedRecords == original.encryptedRecords)
    #expect(admitted.header.keyGeneration == original.header.keyGeneration)
    #expect(admitted.header.base == original.header.version && admitted.header.generation == 2)
    let trusted = try approval.acceptFromAuthenticatedPrivateCloudKit(request: request, scope: scope)
    for (record, value) in document.records {
        #expect(try admitted.read(record: record, device: joining, membership: trusted.current.membership,
            membershipStateDigest: trusted.current.digest()) == value.bytes)
    }
    #expect(throws: (any Error).self) {
        try original.catalog(device: joining, membership: history.current.membership, membershipStateDigest: history.current.digest())
    }
}

@Test func deviceAdditionCannotSmuggleAnotherRecipientOrReplacePinnedAuthority() throws {
    let (owner, joining, scope, history) = try enrollmentFixture()
    let extra = try TestDevice(member: owner.identity.member)
    let expanded = try Membership(accounts: [.init(id: owner.identity.member, role: .owner,
        devices: [owner.identity, joining.identity, extra.identity])])
    let successor = try MembershipEnvelope.successor(of: history.current, membership: expanded, owner: owner)
    #expect(throws: (any Error).self) { try successor.verifyDeviceAddition(of: history.current, device: joining.identity) }
    let otherRoot = try MembershipEnvelope.genesis(vault: scope.vault, membership: history.current.membership, owner: owner)
    // A different signed root at the same vault cannot replace an existing pin.
    let foreignOwner = try TestDevice(member: owner.identity.member)
    let foreignMembership = try Membership(accounts: [.init(id: foreignOwner.identity.member, role: .owner, devices: [foreignOwner.identity])])
    let foreignRoot = try MembershipEnvelope.genesis(vault: scope.vault, membership: foreignMembership, owner: foreignOwner)
    #expect(throws: (any Error).self) {
        try TrustedMembershipHistory(genesis: foreignRoot, vault: scope.vault, pinnedDigest: otherRoot.digest())
    }
}

@Test func offlineContentAdoptsMultipleAdditiveAdmissionsWithoutDecryptingFields() throws {
    let (owner, joining, scope, initial) = try enrollmentFixture()
    let document = try portableDocument(items: [VaultItem(name: "Login", type: .login,
        fields: [ItemField(path: "password", type: .password, value: "offline-secret")])])
    let original = try ItemEnvelope.seal(document, vault: scope.vault, generation: 1,
        membership: initial.current.membership, membershipStateDigest: initial.current.digest(), signer: owner)
    let request = try DeviceEnrollmentRequest.create(scope: scope, device: joining)
    let first = try DeviceEnrollmentApproval.create(request: request, history: initial, owner: owner)
    var current = try first.acceptFromAuthenticatedPrivateCloudKit(request: request, scope: scope)
    let third = try TestDevice(member: owner.identity.member)
    let secondRequest = try DeviceEnrollmentRequest.create(scope: scope, device: third)
    let second = try DeviceEnrollmentApproval.create(request: secondRequest, history: current, owner: owner)
    try current.append(second.successor)
    let adopted = try original.adoptingMembership(history: current, signer: owner)
    #expect(adopted.encryptedRecords == original.encryptedRecords)
    #expect(adopted.header.keyGeneration == original.header.keyGeneration)
    #expect(adopted.header.base == original.header.version)
    for (id, value) in document.records {
        #expect(try adopted.read(record: id, device: third, membership: current.current.membership,
            membershipStateDigest: current.current.digest()) == value.bytes)
    }
    let revokedMembership = try Membership(accounts: [.init(id: owner.identity.member, role: .owner,
        devices: [owner.identity, third.identity])], removedDevices: [joining.identity.device])
    let revoked = try MembershipEnvelope.successor(of: current.current, membership: revokedMembership, owner: owner)
    try current.append(revoked)
    #expect(throws: (any Error).self) { try original.adoptingMembership(history: current, signer: owner) }
}

@Test func reconnectReusesMembershipAndBindsExactRequest() throws {
    let (owner, joining, scope, original) = try enrollmentFixture(), now = Date()
    let first = try DeviceEnrollmentRequest.create(scope: scope, device: joining, now: now)
    let admission = try DeviceEnrollmentApproval.create(request: first, history: original, owner: owner, now: now)
    let history = try admission.acceptFromAuthenticatedPrivateCloudKit(request: first, scope: scope, now: now)
    let request = try DeviceEnrollmentRequest.create(scope: scope, device: joining, now: now)
    let approval = try DeviceEnrollmentApproval.reconnect(request: request, history: history, owner: owner, now: now)
    let decoded = try DeviceEnrollmentApproval.decode(approval.encoded())
    #expect(decoded.isReconnect)
    let impostor = try TestDevice(member: joining.identity.member, deviceID: joining.identity.device)
    let wrongKeys = try DeviceEnrollmentRequest.create(scope: scope, device: impostor, now: now)
    #expect(throws: DeviceEnrollmentFailure.invalidApproval) {
        try DeviceEnrollmentApproval.reconnect(request: wrongKeys, history: history, owner: owner, now: now)
    }
    let accepted = try decoded.acceptFromAuthenticatedPrivateCloudKit(request: request, scope: scope, now: now)
    #expect(accepted.orderedStates == history.orderedStates)
    #expect(throws: (any Error).self) {
        try decoded.acceptFromAuthenticatedPrivateCloudKit(request: first, scope: scope, now: now)
    }
    #expect(throws: (any Error).self) {
        try DeviceEnrollmentApproval.reconnect(request: request, history: original, owner: owner, now: now)
    }
    #expect(throws: DeviceEnrollmentFailure.expired) {
        try DeviceEnrollmentApproval.reconnect(request: request, history: history, owner: owner, now: now.addingTimeInterval(901))
    }
    // Switching grant mode or membership invalidates the owner's signature.
    var object = try #require(JSONSerialization.jsonObject(with: approval.encoded()) as? [String: Any])
    object["successor"] = try JSONSerialization.jsonObject(with: original.current.encoded())
    let tampered = try JSONSerialization.data(withJSONObject: object)
    #expect(throws: (any Error).self) { try DeviceEnrollmentApproval.decode(tampered) }
}
