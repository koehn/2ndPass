import Foundation
import Testing
import MopCore
@testable import MopVaultNext

@Test func membershipEnvelopeRequiresIndependentPinAndOwnerAuthorizedSuccessors() throws {
    let owner = try TestDevice(), viewer = try TestDevice()
    var vault = try testAuthority(owner: owner)
    let genesis = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
    try genesis.verifyGenesis(vault: vault.id, pinnedDigest: genesis.digest())
    #expect(try MembershipEnvelope.decode(genesis.encoded()) == genesis)
    #expect(throws: (any Error).self) { try genesis.verifyGenesis(vault: UUID(), pinnedDigest: genesis.digest()) }
    #expect(throws: (any Error).self) { try genesis.verifyGenesis(vault: vault.id, pinnedDigest: String(repeating: "0", count: 64)) }
    vault.membership = try Membership(accounts: vault.membership.accounts + [AccountMember(id: viewer.identity.member, role: .viewer, devices: [viewer.identity])])
    let added = try MembershipEnvelope.successor(of: genesis, membership: vault.membership, owner: owner)
    try added.verifySuccessor(of: genesis)
    #expect(added.header.parent == (try genesis.digest()))
    #expect(throws: MopError.cloudPermission) { try MembershipEnvelope.successor(of: added, membership: vault.membership, owner: viewer) }
    #expect(throws: MopError.cloudPermission) { try MembershipEnvelope.genesis(membership: vault.membership, owner: viewer) }
    var corrupted = try added.encoded()
    corrupted[corrupted.count / 2] ^= 1
    #expect(throws: (any Error).self) {
        try MembershipEnvelope.decode(corrupted).verifySuccessor(of: genesis)
    }
}

@Test func membershipEnvelopePreventsRetiredDeviceResurrection() throws {
    let owner = try TestDevice(), editor = try TestDevice()
    var vault = try testAuthority(owner: owner)
    vault.membership = try Membership(accounts: vault.membership.accounts + [AccountMember(id: editor.identity.member, role: .editor, devices: [editor.identity])])
    let before = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
    #expect(throws: MopError.cloudPermission) { try MembershipEnvelope.successor(of: before, membership: vault.membership, owner: editor) }
    let removedMembership = try Membership(accounts: vault.membership.accounts.filter { $0.id != editor.identity.member }, removedDevices: [editor.identity.device])
    let removed = try MembershipEnvelope.successor(of: before, membership: removedMembership, owner: owner)
    try removed.verifySuccessor(of: before)
    #expect(throws: (any Error).self) { try MembershipEnvelope.successor(of: removed, membership: vault.membership, owner: owner) }
    let forgotRemoval = try Membership(accounts: removed.membership.accounts, offlineRecovery: removed.membership.offlineRecovery, removedDevices: [])
    #expect(throws: (any Error).self) { try MembershipEnvelope.successor(of: removed, membership: forgotRemoval, owner: owner) }
}

@Test func trustedMembershipHistoryRejectsUnpinnedRootForkAndSkippedSuccessors() throws {
    let owner = try TestDevice(), peer = try TestDevice()
    let vault = try testAuthority(owner: owner)
    let root = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
    #expect(throws: (any Error).self) {
        try TrustedMembershipHistory(genesis: root, vault: vault.id, pinnedDigest: String(repeating: "0", count: 64))
    }
    var trusted = try TrustedMembershipHistory(genesis: root, vault: vault.id, pinnedDigest: root.digest())
    let viewerRoster = try Membership(accounts: vault.membership.accounts + [AccountMember(id: peer.identity.member, role: .viewer, devices: [peer.identity])])
    let editorRoster = try Membership(accounts: vault.membership.accounts + [AccountMember(id: peer.identity.member, role: .editor, devices: [peer.identity])])
    let accepted = try MembershipEnvelope.successor(of: root, membership: viewerRoster, owner: owner)
    let fork = try MembershipEnvelope.successor(of: root, membership: editorRoster, owner: owner)
    let higherFork = try MembershipEnvelope.successor(of: fork, membership: editorRoster, owner: owner)
    try trusted.append(accepted)
    #expect(throws: (any Error).self) { try trusted.append(fork) }
    #expect(throws: (any Error).self) { try trusted.append(higherFork) }
    #expect(trusted.current == accepted)
    #expect(trusted.count == 2)
    #expect(try trusted.state(forDigest: root.digest()) == root)
    #expect(throws: (any Error).self) { try trusted.state(forDigest: fork.digest()) }
    try trusted.append(root)
    #expect(trusted.current == accepted)
}
