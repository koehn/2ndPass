import Foundation
import Testing
import MopCore
@testable import MopVaultNext

@Suite struct ContentEnvelopeTests: Sendable {
    private func contentFixture() throws -> (TestDevice, TestDevice, TrustedMembershipHistory) {
        let owner = try TestDevice(), joining = try TestDevice(member: owner.identity.member)
        let membership = try Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity])])
        let genesis = try MembershipEnvelope.genesis(membership: membership, owner: owner)
        return (owner, joining, try TrustedMembershipHistory(genesis: genesis, vault: genesis.header.vault, pinnedDigest: genesis.digest()))
    }

    @Test func coordinationDomainBindsAccountPurposeAndPinnedOwner() throws {
        let (owner, joining, history) = try contentFixture()
        let scope = EnrollmentScope(container: "iCloud.test", environment: "Development", account: "account", vault: history.vault, member: owner.identity.member)
        let request = try DeviceEnrollmentRequest.create(scope: scope, device: joining)
        let wrapper = try CoordinationEnvelope.sign(kind: .enrollmentRequest, scope: scope, identity: request.id, payload: request.encoded(), device: joining)
        #expect(try CoordinationEnvelope.decode(wrapper.encoded(), scope: scope) == wrapper)
        #expect(throws: (any Error).self) { try wrapper.verifyAuthority(history: history) }
        let wrongScope = EnrollmentScope(container: scope.container, environment: scope.environment, account: "different", vault: scope.vault, member: scope.member)
        #expect(throws: (any Error).self) { try CoordinationEnvelope.decode(wrapper.encoded(), scope: wrongScope) }
        var json = try #require(try JSONSerialization.jsonObject(with: wrapper.encoded()) as? [String: Any])
        json["kind"] = "enrollmentApproval"
        let tampered = try JSONDecoder().decode(CoordinationEnvelope.self, from: JSONSerialization.data(withJSONObject: json))
        #expect(throws: (any Error).self) { try tampered.verifySignature(scope: scope) }
        #expect(throws: (any Error).self) {
            try CoordinationEnvelope.sign(kind: .discovery, scope: scope, identity: scope.vault, payload: Data([1]), history: history, device: joining)
        }
        let hint = try CoordinationEnvelope.sign(kind: .discovery, scope: scope, identity: scope.vault, payload: Data([1]), history: history, device: owner)
        try hint.verifyAuthority(history: history)
    }

    @Test func separateGrantAddsAccessWithoutChangingContentOrStorageVersion() throws {
        let (owner, joining, originalHistory) = try contentFixture()
        var history = originalHistory
        let publication = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: UUID(), history: history, signer: owner)
        let before = try publication.content.encoded()
        let membership = try Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])])
        try history.append(MembershipEnvelope.successor(of: history.current, membership: membership, owner: owner))
        let ownerGrant = try #require(publication.grants.first)
        let joiningGrant = try ContentKeyGrant.extendingAccess(to: joining.identity, content: publication.content,
            existingGrant: ownerGrant, history: history, decryptor: owner, signer: owner)
        #expect(try publication.content.encoded() == before)
        try publication.content.verifyForPublication(history: history)
        #expect(try publication.content.open(component: "password", grant: joiningGrant, history: history, device: joining) == "secret")
        #expect(try ContentKeyGrant.decode(joiningGrant.encoded(), content: publication.content, history: history) == joiningGrant)
        #expect(throws: (any Error).self) {
            try publication.content.open(component: "password", grant: ownerGrant, history: history, device: joining)
        }
    }

    @Test func contentGrantsCannotCrossItemsKeyGenerationsOrRecipients() throws {
        let (owner, joining, history) = try contentFixture()
        let item = UUID()
        let first = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: item, history: history, signer: owner)
        let second = try ContentEnvelope.seal(["password": "changed"], vault: history.vault, item: item,
            generation: 2, base: first.content.header.version, history: history, signer: owner)
        let grant = try #require(first.grants.first)
        #expect(second.content.header.contentRevision != first.content.header.contentRevision)
        #expect(throws: (any Error).self) { try grant.verify(content: second.content, history: history) }
        #expect(throws: (any Error).self) {
            try ContentKeyGrant.extendingAccess(to: joining.identity, content: first.content, existingGrant: grant,
                history: history, decryptor: owner, signer: owner)
        }
        var json = try #require(try JSONSerialization.jsonObject(with: grant.encoded()) as? [String: Any])
        json["recipient"] = joining.identity.fingerprint
        let altered = try JSONDecoder().decode(ContentKeyGrant.self, from: JSONSerialization.data(withJSONObject: json))
        #expect(throws: (any Error).self) { try altered.verify(content: first.content, history: history) }
    }

    @Test func contentKeyRotationPreservesLogicalRevisionAndReplacesStorageAndKeys() throws {
        let (owner, _, history) = try contentFixture()
        let first = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: UUID(), history: history, signer: owner)
        let grant = try #require(first.grants.first)
        let rotated = try first.content.rotateKey(grant: grant, history: history, decryptor: owner, signer: owner)
        #expect(rotated.content.header.contentRevision == first.content.header.contentRevision)
        #expect(rotated.content.header.keyGeneration != first.content.header.keyGeneration)
        #expect(rotated.content.header.base == first.content.header.version)
        #expect(rotated.content.header.generation == 2)
        let nextGrant = try #require(rotated.grants.first)
        #expect(try rotated.content.open(component: "password", grant: nextGrant, history: history, device: owner) == "secret")
        #expect(throws: (any Error).self) { try grant.verify(content: rotated.content, history: history) }
    }

    @Test func contentComponentIdentityAndSignaturePreventSubstitution() throws {
        let (owner, _, history) = try contentFixture()
        let publication = try ContentEnvelope.seal(["password": "secret", "username": "person"],
            vault: history.vault, item: UUID(), history: history, signer: owner)
        let content = try ContentEnvelope.decode(publication.content.encoded(), history: history, item: publication.content.header.item)
        #expect(content == publication.content)
        #expect(throws: (any Error).self) { try content.verify(history: history, item: UUID()) }
        var json = try #require(try JSONSerialization.jsonObject(with: content.encoded()) as? [String: Any])
        var components = try #require(json["components"] as? [String: Any])
        components["password"] = components["username"]; json["components"] = components
        let changed = try JSONDecoder().decode(ContentEnvelope.self, from: JSONSerialization.data(withJSONObject: json))
        #expect(throws: (any Error).self) { try changed.verify(history: history, item: content.header.item) }
    }
    @Test func editsReuseGrantsAcrossAdditiveEnrollmentAndDifferentAuthors() throws {
        let (owner, joining, originalHistory) = try contentFixture()
        var history = originalHistory
        let first = try ContentEnvelope.seal(["password": "before"], vault: history.vault, item: UUID(), history: history, signer: owner)
        let ownerGrant = try #require(first.grants.first)
        let membership = try Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])])
        try history.append(MembershipEnvelope.successor(of: history.current, membership: membership, owner: owner))
        let joiningGrant = try ContentKeyGrant.extendingAccess(to: joining.identity, content: first.content,
            existingGrant: ownerGrant, history: history, decryptor: owner, signer: owner)
        let edited = try first.content.editing(["password": "after"], grant: joiningGrant, history: history, device: joining)
        #expect(edited.header.keyGeneration == first.content.header.keyGeneration)
        #expect(edited.header.contentRevision != first.content.header.contentRevision)
        #expect(edited.header.author == joining.identity.fingerprint)
        #expect(try edited.open(component: "password", grant: ownerGrant, history: history, device: owner) == "after")
        #expect(try edited.open(component: "password", grant: joiningGrant, history: history, device: joining) == "after")
    }

    @Test func identicalConcurrentEditsSupersedeButDifferentEditsSurvive() throws {
        let (owner, _, history) = try contentFixture()
        let first = try ContentEnvelope.seal(["password": "before"], vault: history.vault, item: UUID(), history: history, signer: owner)
        let grant = try #require(first.grants.first)
        let local = try first.content.editing(["password": "after"], grant: grant, history: history, device: owner)
        let same = try first.content.editing(["password": "after"], grant: grant, history: history, device: owner)
        let different = try first.content.editing(["password": "other"], grant: grant, history: history, device: owner)
        #expect(local.components != same.components)
        #expect(try ContentReconciliation.inspect(local: local, remote: local, ancestors: [], history: history) == .acknowledgeDuplicate)
        #expect(try ContentReconciliation.inspect(local: local, remote: first.content, ancestors: [], history: history) == .keepLocal)
        #expect(try ContentReconciliation.inspect(local: first.content, remote: local, ancestors: [], history: history) == .acceptRemote)
        #expect(try ContentReconciliation.inspect(local: local, remote: same, ancestors: [], history: history) == .preserveBranches)
        #expect(try ContentReconciliation.inspect(local: local, remote: same, ancestors: [first.content], history: history) == .compareContents)
        #expect(try ContentReconciliation.reconcile(local: local, remote: same, ancestors: [first.content],
            localGrant: grant, remoteGrant: grant, history: history, device: owner) == .acceptRemoteSupersedingLocal)
        #expect(try ContentReconciliation.reconcile(local: local, remote: different, ancestors: [first.content],
            localGrant: grant, remoteGrant: grant, history: history, device: owner) == .preserveBranches)
    }

    @Test func rotationRequiresNewGrantsAndRejectsOldKeyEditsAfterRevocation() throws {
        let (owner, joining, originalHistory) = try contentFixture()
        var history = originalHistory
        let added = try Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])])
        try history.append(MembershipEnvelope.successor(of: history.current, membership: added, owner: owner))
        let first = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: UUID(), history: history, signer: owner)
        let grant = try #require(first.grants.first { $0.recipient == owner.identity.fingerprint })
        let removed = try Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity])],
            removedDevices: [joining.identity.device])
        try history.append(MembershipEnvelope.successor(of: history.current, membership: removed, owner: owner))
        #expect(throws: (any Error).self) { try first.content.verifyForPublication(history: history) }
        #expect(throws: (any Error).self) { try grant.verifyForPublication(content: first.content, history: history) }
        #expect(throws: (any Error).self) { try first.content.editing(["password": "new"], grant: grant, history: history, device: owner) }
        let rotated = try first.content.rotateKey(grant: grant, history: history, decryptor: owner, signer: owner)
        try rotated.content.verifyForPublication(history: history)
        #expect(rotated.grants.count == 1)
        #expect(rotated.content.header.contentRevision == first.content.header.contentRevision)
        let newGrant = try #require(rotated.grants.first)
        #expect(try first.content.hasIdenticalContents(to: rotated.content, grant: grant, otherGrant: newGrant,
            history: history, device: owner))
    }

    @Test func offlineEditRebasesOnlyOverVerifiedAccessOnlyRotation() throws {
        let (owner, _, history) = try contentFixture()
        let first = try ContentEnvelope.seal(["password": "before"], vault: history.vault, item: UUID(), history: history, signer: owner)
        let grant = try #require(first.grants.first)
        let edited = try first.content.editing(["password": "offline edit"], grant: grant, history: history, device: owner)
        let rotated = try first.content.rotateKey(grant: grant, history: history, decryptor: owner, signer: owner)
        let newGrant = try #require(rotated.grants.first)
        let rebased = try edited.rebasingEdit(onto: rotated.content, commonBase: first.content,
            grant: grant, baseGrant: grant, rotatedGrant: newGrant, history: history, device: owner)
        #expect(rebased.header.keyGeneration == rotated.content.header.keyGeneration)
        #expect(rebased.header.contentRevision == edited.header.contentRevision)
        #expect(rebased.header.base == rotated.content.header.version)
        #expect(try rebased.open(component: "password", grant: newGrant, history: history, device: owner) == "offline edit")
        let competing = try first.content.editing(["password": "competing"], grant: grant, history: history, device: owner)
        #expect(throws: (any Error).self) {
            try edited.rebasingEdit(onto: competing, commonBase: first.content,
                grant: grant, baseGrant: grant, rotatedGrant: grant, history: history, device: owner)
        }
        #expect(throws: (any Error).self) {
            try rebased.open(component: "password", grant: grant, history: history, device: owner)
        }
    }

    @Test func recoveryAdmissionRequiresRotationBeforeNewGrantsOrPublication() throws {
        let scope = try RecoveryScope(container: "iCloud.test", environment: "Development", account: "account")
        let recovery = try OfflineRecoveryKey(scope: scope)
        let owner = try TestDevice(member: scope.member), joining = try TestDevice(member: scope.member)
        let membership = try Membership(accounts: [.init(id: scope.member, role: .owner, devices: [owner.identity])],
            offlineRecovery: recovery.identity)
        let genesis = try MembershipEnvelope.genesis(membership: membership, owner: owner)
        let history = try TrustedMembershipHistory(genesis: genesis, vault: genesis.header.vault, pinnedDigest: genesis.digest())
        let first = try ContentEnvelope.seal(["password": "secret"], vault: history.vault, item: UUID(), history: history, signer: owner)
        let enrollmentScope = EnrollmentScope(container: scope.container, environment: scope.environment, account: scope.account,
            vault: history.vault, member: scope.member)
        let request = try DeviceEnrollmentRequest.create(scope: enrollmentScope, device: joining)
        let approval = try DeviceEnrollmentApproval.create(request: request, history: history, owner: recovery)
        let accepted = try approval.acceptFromAuthenticatedPrivateCloudKit(request: request, scope: enrollmentScope)
        let recoveryGrant = try #require(first.grants.first { $0.recipient == recovery.identity.fingerprint })
        #expect(throws: (any Error).self) { try first.content.verifyForPublication(history: accepted) }
        #expect(throws: (any Error).self) {
            try ContentKeyGrant.extendingAccess(to: joining.identity, content: first.content, existingGrant: recoveryGrant,
                history: accepted, decryptor: recovery, signer: joining)
        }
        let rotated = try first.content.rotateKey(grant: recoveryGrant, history: accepted, decryptor: recovery, signer: joining)
        try rotated.content.verifyForPublication(history: accepted)
        let joiningGrant = try #require(rotated.grants.first { $0.recipient == joining.identity.fingerprint })
        #expect(try rotated.content.open(component: "password", grant: joiningGrant, history: accepted, device: joining) == "secret")
    }

    @Test func concurrentDeletionAndEditingKeepBothBranches() throws {
        let (owner, _, history) = try contentFixture()
        let first = try ContentEnvelope.seal(["password": "before"], vault: history.vault, item: UUID(), history: history, signer: owner)
        let grant = try #require(first.grants.first)
        let deleted = try first.content.deleting(grant: grant, history: history, device: owner)
        let edited = try first.content.editing(["password": "after"], grant: grant, history: history, device: owner)
        #expect(deleted.header.isTombstone)
        #expect(deleted.components.isEmpty)
        #expect(try ContentReconciliation.inspect(local: deleted, remote: edited, ancestors: [first.content], history: history) == .preserveBranches)
        #expect(try ContentReconciliation.inspect(local: first.content, remote: deleted, ancestors: [], history: history) == .acceptRemote)
        #expect(throws: (any Error).self) { try deleted.editing(["password": "resurrected"], grant: grant, history: history, device: owner) }
        let rotated = try deleted.rotateKey(grant: grant, history: history, decryptor: owner, signer: owner)
        #expect(rotated.content.header.isTombstone)
        #expect(rotated.content.header.contentRevision == deleted.header.contentRevision)
        try rotated.content.verifyForPublication(history: history)
    }

    @Test func knownCommonAncestorDoesNotRequireDownloadingUnrelatedOlderHistory() throws {
        let (owner, _, history) = try contentFixture()
        let first = try ContentEnvelope.seal(["password": "before"], vault: history.vault, item: UUID(), history: history, signer: owner)
        let grant = try #require(first.grants.first)
        let base = try first.content.editing(["password": "base"], grant: grant, history: history, device: owner)
        let local = try base.editing(["password": "after"], grant: grant, history: history, device: owner)
        let remote = try base.editing(["password": "after"], grant: grant, history: history, device: owner)
        #expect(try ContentReconciliation.reconcile(local: local, remote: remote, ancestors: [base],
            localGrant: grant, remoteGrant: grant, history: history, device: owner) == .acceptRemoteSupersedingLocal)
    }

    @Test func originalEditorGrantSurvivesAnOwnerContentEdit() throws {
        let owner = try TestDevice(), editor = try TestDevice()
        let membership = try Membership(accounts: [
            .init(id: owner.identity.member, role: .owner, devices: [owner.identity]),
            .init(id: editor.identity.member, role: .editor, devices: [editor.identity])])
        let genesis = try MembershipEnvelope.genesis(membership: membership, owner: owner)
        let history = try TrustedMembershipHistory(genesis: genesis, vault: genesis.header.vault, pinnedDigest: genesis.digest())
        let first = try ContentEnvelope.seal(["password": "before"], vault: history.vault, item: UUID(), history: history, signer: editor)
        let ownerGrant = try #require(first.grants.first { $0.recipient == owner.identity.fingerprint })
        let editorGrant = try #require(first.grants.first { $0.recipient == editor.identity.fingerprint })
        let edited = try first.content.editing(["password": "owner edit"], grant: ownerGrant, history: history, device: owner)
        #expect(edited.header.keyAuthor == editor.identity.fingerprint)
        #expect(edited.header.author == owner.identity.fingerprint)
        try ownerGrant.verifyForPublication(content: edited, history: history)
        #expect(try edited.open(component: "password", grant: editorGrant, history: history, device: editor) == "owner edit")
    }

}
