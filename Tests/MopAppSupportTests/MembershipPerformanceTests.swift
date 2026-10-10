import Foundation
import Testing
import MopCore
import MopSync
import MopVaultNext
@testable import MopAppSupport

@Suite struct MembershipPerformanceTests {
    @Test func repeatedMembershipQueriesReuseVerifiedInputsAndInvalidateOnAppend() throws {
        let cache = ItemVaultMembershipAuthority.Cache()
        let owner = try SessionDevice(), joining = try SessionDevice(member: owner.identity.member)
        let vault = try sessionAuthority(owner: owner)
        let genesis = try MembershipEnvelope.genesis(vault: vault.id, membership: vault.membership, owner: owner)
        let scope = ItemVaultSetupScope(container: "iCloud.test", environment: "Development",
            binding: ItemVaultBinding(account: "a", database: "private", zoneOwner: "owner", vaultID: vault.id))
        let record = try ItemVaultSetupRecord(scope: scope, sourceDigest: "source", name: "test", genesis: genesis.encoded(), pinnedDigest: genesis.digest())
        let addition = try MembershipEnvelope.successor(of: genesis,
            membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity, joining.identity])]), owner: owner)
        let successors = try [addition.encoded()]
        let history = try ItemVaultMembershipAuthority.history(record: record, successors: successors, cache: cache)
        let policy = try GrantBackedContentStorage.recipientPolicy(history: history)
        let clock = ContinuousClock(), start = clock.now
        for _ in 0..<1000 {
            let reused = try ItemVaultMembershipAuthority.history(record: record, successors: successors, cache: cache)
            #expect(reused.cacheIdentity == history.cacheIdentity)
            #expect(try GrantBackedContentStorage.recipientPolicy(history: reused) == policy)
            #expect(try GrantBackedContentStorage.keyAuthority(history: reused, at: addition.digest()) == genesis.digest())
        }
        let warm = start.duration(to: clock.now)
        let baselineStart = clock.now
        for _ in 0..<1000 {
            var rebuilt = try TrustedMembershipHistory(genesis: MembershipEnvelope.decode(record.genesis), vault: vault.id, pinnedDigest: record.pinnedDigest)
            try addition.verifyAccountTransition(of: rebuilt.current)
            try rebuilt.append(MembershipEnvelope.decode(successors[0]))
            #expect(try GrantBackedContentStorage.recipientPolicy(history: rebuilt) == policy)
        }
        print("Membership benchmark: 1,000 repeated history/policy queries; cached=\(warm); rebuild=\(baselineStart.duration(to: clock.now))")
        // Copies retain their old policy; only a successful append changes identity.
        var revoked = history
        let removal = try MembershipEnvelope.successor(of: addition,
            membership: Membership(accounts: [.init(id: owner.identity.member, role: .owner, devices: [owner.identity])], removedDevices: [joining.identity.device]), owner: owner)
        try revoked.append(removal)
        #expect(revoked.cacheIdentity != history.cacheIdentity)
        let rotated = try GrantBackedContentStorage.recipientPolicy(history: revoked)
        #expect(try rotated.keyAuthority == removal.digest())
        #expect(!rotated.recipients.contains(joining.identity.fingerprint))
        #expect(try GrantBackedContentStorage.recipientPolicy(history: history) == policy)
        let identity = revoked.cacheIdentity
        try revoked.append(removal)
        #expect(revoked.cacheIdentity == identity)
        #expect(revoked.orderedStates.map(\.header.generation) == [1, 2, 3])
        let removedBytes = try successors + [removal.encoded()]
        _ = try ItemVaultMembershipAuthority.history(record: record, successors: removedBytes, allowingDeviceRemoval: true, cache: cache)
        #expect(throws: (any Error).self) { try ItemVaultMembershipAuthority.history(record: record, successors: removedBytes, cache: cache) }
        let badPin = ItemVaultSetupRecord(scope: scope, sourceDigest: record.sourceDigest, name: record.name, genesis: record.genesis, pinnedDigest: String(repeating: "0", count: 64))
        #expect(throws: (any Error).self) { try ItemVaultMembershipAuthority.history(record: badPin, successors: successors, cache: cache) }
        #expect(throws: (any Error).self) { try ItemVaultMembershipAuthority.history(record: record, successors: [Data("invalid".utf8)], cache: cache) }
        #expect(throws: (any Error).self) { try GrantBackedContentStorage.keyAuthority(history: history, at: "unknown") }
    }
}
