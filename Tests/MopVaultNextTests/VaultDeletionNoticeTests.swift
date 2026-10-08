import Foundation
import Testing
import MopCore
@testable import MopVaultNext

@Test func deletionNoticeAuthenticatesOwnerAndFullBinding() throws {
    let owner = try TestDevice(), outsider = try TestDevice()
    let vault = try testAuthority(owner: owner)
    let root = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
    let history = try TrustedMembershipHistory(genesis: root, vault: vault.id, pinnedDigest: root.digest())
    let binding = VaultDeletionNotice.Binding(container: "iCloud.test", environment: "Development", account: "account",
        vault: vault.id, database: "private", zone: "MopItems-" + vault.id.uuidString, owner: "__defaultOwner__", genesis: try root.digest())
    let notice = try VaultDeletionNotice.create(binding: binding, history: history, owner: owner)
    try VaultDeletionNotice.decode(notice.encoded()).verify(binding: binding, trusted: history)
    #expect(throws: MopError.cloudPermission) { try VaultDeletionNotice.create(binding: binding, history: history, owner: outsider) }
    for field in ["container", "environment", "account", "vault", "database", "zone", "owner", "genesis"] {
        var object = try #require(JSONSerialization.jsonObject(with: notice.encoded()) as? [String: Any])
        var altered = try #require(object["binding"] as? [String: Any])
        altered[field] = field == "vault" ? UUID().uuidString : "different"
        object["binding"] = altered
        let forged = try JSONDecoder().decode(VaultDeletionNotice.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(throws: (any Error).self) { try forged.verify(binding: binding, trusted: history) }
    }
    var object = try #require(JSONSerialization.jsonObject(with: notice.encoded()) as? [String: Any])
    object["signature"] = Data(repeating: 0, count: 64).base64EncodedString()
    let forged = try JSONDecoder().decode(VaultDeletionNotice.self, from: JSONSerialization.data(withJSONObject: object))
    #expect(throws: (any Error).self) { try forged.verify(binding: binding, trusted: history) }
}

@Test func deletionNoticeAcceptsRacingAdditionWithoutReplacingPinnedMembership() throws {
    let owner = try TestDevice(), peer = try TestDevice(member: owner.identity.member)
    let vault = try testAuthority(owner: owner)
    let root = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
    let old = try TrustedMembershipHistory(genesis: root, vault: vault.id, pinnedDigest: root.digest())
    var next = old
    let membership = try Membership(accounts: [AccountMember(id: owner.identity.member, role: .owner, devices: [owner.identity, peer.identity])])
    try next.append(MembershipEnvelope.successor(of: root, membership: membership, owner: owner))
    let binding = VaultDeletionNotice.Binding(container: "iCloud.test", environment: "Development", account: "account",
        vault: vault.id, database: "private", zone: "MopItems-" + vault.id.uuidString, owner: "__defaultOwner__", genesis: try root.digest())
    let current = try VaultDeletionNotice.create(binding: binding, history: next, owner: peer)
    try current.verify(binding: binding, trusted: old)
    let stale = try VaultDeletionNotice.create(binding: binding, history: old, owner: owner)
    try stale.verify(binding: binding, trusted: next)
    #expect(next.count == 2)
    let removed = try Membership(accounts: [AccountMember(id: owner.identity.member, role: .owner, devices: [peer.identity])],
        removedDevices: [owner.identity.device])
    try next.append(MembershipEnvelope.successor(of: next.current, membership: removed, owner: owner))
    #expect(throws: MopError.vaultUntrusted) { try stale.verify(binding: binding, trusted: next) }
    // The remaining owner can still authorize deletion from the shared branch.
    try current.verify(binding: binding, trusted: next)
}
