import Foundation
import Testing
import MopCore
import MopAppSupport
@testable import MopCLI

private final class UsageReadService: VaultService, Sendable {
    let identity = ItemUsageIdentity(account: UUID().uuidString, vault: UUID().uuidString, item: UUID().uuidString)
    var authenticatedAt: TimeInterval? { 0 }
    func lock() {}
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult {
        var result = VaultResult()
        if case .read(let reference) = operation {
            guard reference.field != "missing" else { throw MopError.notFound }
            result.value = SecretBytes(utf8: "value"); result.usageIdentity = identity
        }
        return result
    }
}
private actor CLIUsageStore: ItemUsageStoring {
    var count = 0
    let fails: Bool
    init(fails: Bool = false) { self.fails = fails }
    func load(accounts: Set<String>) async throws -> [ItemUsageIdentity: Date] { [:] }
    func record(_ identities: Set<ItemUsageIdentity>, at date: Date) async throws {
        count += 1
        if fails { throw MopError.inputOutput }
    }
    func prune(account: String, vault: String, keeping items: Set<String>, before date: Date) async throws {}
}
@Test func cliCoalescesFieldsOfOneItemAndAwaitsUsagePersistence() async throws {
    let usage = CLIUsageStore(), service = UsageReadService()
    let options = try VaultOptions.parse([])
    let store = CommandStore(options: options, service: service, usageStore: usage)
    _ = try await store.read(SecretReference("sp://personal/login/password"))
    #expect(await usage.count == 1)
    _ = try await store.read(SecretReference("sp://personal/login/username"))
    #expect(await usage.count == 1)
    let anotherCommand = CommandStore(options: options, service: service, usageStore: usage)
    await #expect(throws: MopError.notFound) { try await anotherCommand.read(SecretReference("sp://personal/login/missing")) }
    #expect(await usage.count == 1)
}
@Test func cliUsagePersistenceFailureDoesNotFailRead() async throws {
    let usage = CLIUsageStore(fails: true)
    let store = CommandStore(options: try VaultOptions.parse([]), service: UsageReadService(), usageStore: usage)
    #expect(try await store.read(SecretReference("sp://personal/login/password")) == SecretBytes(utf8: "value"))
    #expect(await usage.count == 1)
}
