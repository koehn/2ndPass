import Foundation
import Testing
import MopVault

struct AccountAuthenticationPolicyTests {
    @Test func concurrentDefaultSetupCannotOverwriteStrictPolicy() async throws {
        let state = FileManager.default.temporaryDirectory.appendingPathComponent("mop-policy-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: state) }
        try AccountAuthenticationPolicy.save(state: state, strict: false)
        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0..<20 {
                group.addTask { try AccountAuthenticationPolicy.save(state: state, strict: index == 10) }
            }
            try await group.waitForAll()
        }
        #expect(try AccountAuthenticationPolicy.strict(state: state))
    }
    @Test func strictPolicyPersistsAndCannotBeWeakenedByDefaultSetup() throws {
        let state = FileManager.default.temporaryDirectory.appendingPathComponent("mop-policy-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: state) }
        #expect(try !AccountAuthenticationPolicy.strict(state: state))
        try AccountAuthenticationPolicy.save(state: state, strict: true)
        #expect(try AccountAuthenticationPolicy.strict(state: state))
        try AccountAuthenticationPolicy.save(state: state, strict: false)
        #expect(try AccountAuthenticationPolicy.strict(state: state))
    }
    @Test func malformedPolicyFailsClosedAndExplicitStrictCanStrengthenDefault() throws {
        let state = FileManager.default.temporaryDirectory.appendingPathComponent("mop-policy-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: state) }
        try AccountAuthenticationPolicy.save(state: state, strict: false)
        #expect(try AccountAuthenticationPolicy.strict(state: state, requested: true))
        try SafeFile.write(Data("invalid".utf8), to: state.appendingPathComponent("account-authentication.json"), replace: true)
        #expect(throws: (any Error).self) { try AccountAuthenticationPolicy.strict(state: state) }
    }
}
