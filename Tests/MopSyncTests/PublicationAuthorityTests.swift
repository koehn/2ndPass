import Foundation
import Testing
@testable import MopSync

private actor AuthorityReadProbe {
    private(set) var count = 0
    func read() { count += 1 }
}

@Test func hundredRecordsShareOneAuthorityReadPerPhase() async throws {
    let probe = AuthorityReadProbe(), vault = UUID(), head = Data([1])
    for _ in 0..<2 { // preparation and fresh pre-submission check
        let checks = PublicationAuthorityChecks()
        for _ in 0..<100 {
            try await checks.check(vault: vault, authority: head) { await probe.read() }
        }
    }
    #expect(await probe.count == 2)
    // The next batch must not reuse an earlier batch's result either.
    try await PublicationAuthorityChecks().check(vault: vault, authority: head) { await probe.read() }
    #expect(await probe.count == 3)
}

@Test func authorityReadsAreScopedToVaultAndExactMembership() async throws {
    let checks = PublicationAuthorityChecks(), probe = AuthorityReadProbe(), vault = UUID()
    try await checks.check(vault: vault, authority: Data([1])) { await probe.read() }
    try await checks.check(vault: vault, authority: Data([2])) { await probe.read() }
    try await checks.check(vault: UUID(), authority: Data([1])) { await probe.read() }
    #expect(await probe.count == 3)
}

@Test func authorityFailureIsSharedButDoesNotBlockOtherVaultsOrFreshChecks() async throws {
    let checks = PublicationAuthorityChecks(), probe = AuthorityReadProbe(), vault = UUID()
    for _ in 0..<100 {
        await #expect(throws: CloudSyncAdapterError.membershipUnavailable) {
            try await checks.check(vault: vault, authority: Data([1])) {
                await probe.read()
                throw CloudSyncAdapterError.membershipUnavailable
            }
        }
    }
    #expect(await probe.count == 1)
    try await checks.check(vault: UUID(), authority: Data([1])) { await probe.read() }
    try await PublicationAuthorityChecks().check(vault: vault, authority: Data([1])) { await probe.read() }
    #expect(await probe.count == 3)
}

@Test func changedRemoteAuthorityIsRejectedByFreshSubmissionPhase() async throws {
    let vault = UUID(), head = Data([1])
    try await PublicationAuthorityChecks().check(vault: vault, authority: head) {}
    await #expect(throws: CloudSyncAdapterError.membershipUnavailable) {
        try await PublicationAuthorityChecks().check(vault: vault, authority: head) {
            throw CloudSyncAdapterError.membershipUnavailable
        }
    }
}
