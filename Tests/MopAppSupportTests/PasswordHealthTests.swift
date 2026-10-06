import Foundation
import CryptoKit
import Testing
import Synchronization
import MopCore
@testable import MopAppSupport

private actor RangeTransport: BreachTransport {
    var requests: [URLRequest] = []
    let data: Data
    let status: Int
    init(data: Data, status: Int = 200) { self.data = data; self.status = status }
    func response(for request: URLRequest) async throws -> (Data, Int) { requests.append(request); return (data, status) }
    var count: Int { requests.count }
}
private func padded(_ suffix: String? = nil) -> Data {
    var lines = (0..<800).map { String(format: "%035X", $0) + ":0" }
    if let suffix { lines.append(suffix + ":12") }
    return Data((lines.joined(separator: "\r\n") + "\r\n").utf8)
}
@Test func breachClientSendsOnlyPaddedPrefixAndCachesUntilCleared() async throws {
    let password = Data("password".utf8)
    let digest = Insecure.SHA1.hash(data: password).map { String(format: "%02X", $0) }.joined()
    let transport = RangeTransport(data: padded(String(digest.dropFirst(5))))
    let client = PwnedPasswordsClient(transport: transport)
    #expect(try await client.contains(password, force: false))
    #expect(try await client.contains(password, force: false))
    #expect(await transport.count == 1)
    let request = try #require(await transport.requests.first)
    #expect(request.url?.absoluteString == "https://api.pwnedpasswords.com/range/5BAA6")
    #expect(request.value(forHTTPHeaderField: "Add-Padding") == "true")
    #expect(request.httpBody == nil)
    #expect(request.url?.absoluteString.contains(digest) == false)
    await client.clear()
    #expect(try await client.contains(password, force: false))
    #expect(await transport.count == 2)
}
@Test func breachMalformedUnavailableAndPaddingAreNotCleanResults() async throws {
    #expect(try PwnedPasswordsClient.parse(padded()).isEmpty)
    for data in [Data(), Data("ABC:1".utf8), Data([0xff]), Data((String(repeating: "Z", count: 35) + ":1\n").repeated800.utf8)] {
        #expect(throws: BreachCheckFailure.self) { try PwnedPasswordsClient.parse(data) }
    }
    let client = PwnedPasswordsClient(transport: RangeTransport(data: padded(), status: 503))
    await #expect(throws: BreachCheckFailure.self) { try await client.contains(Data("test".utf8), force: false) }
}
private extension String { var repeated800: String { String(repeating: self, count: 800) } }

private final class HealthService: VaultService, Sendable {
    let reads = Mutex(0)
    let values: [String: SecretBytes]
    init(_ values: [String: SecretBytes]) { self.values = values }
    var authenticatedAt: TimeInterval? { 1 }
    func lock() {}
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult {
        reads.withLock { $0 += 1 }
        guard case .read(let reference) = operation, let value = values[(vault ?? "") + ":" + reference.relativePath] else { throw MopError.notFound }
        var result = VaultResult(); result.value = value; return result
    }
}
private actor HealthBreach: BreachChecking {
    func contains(_ lookup: BreachLookup, force: Bool) async throws -> Bool { try await contains(Data(), force: force) }
    var count = 0
    func contains(_ password: Data, force: Bool) async throws -> Bool { count += 1; return false }
    func clear() {}
}
@MainActor @Test func healthScopeExcludesArchivedAndDeletedWithMappingsAndUnicode() async throws {
    var archived = VaultItem(name: "archived", fields: [ItemField(path: "password", type: .password)])
    archived.metadata = ItemMetadata(archived: true)
    var mapped = VaultItem(name: "mapped", fields: [ItemField(path: "secret", type: .concealed)])
    mapped.autoFill = AutoFillMapping(password: "secret")
    let ignored = VaultItem(name: "token", type: .apiCredential, fields: [ItemField(path: "token", type: .concealed)])
    let missing = VaultItem(name: "missing", fields: [ItemField(path: "password", type: .password)])
    let active = VaultItem(name: "active", fields: [ItemField(path: "password", type: .password)])
    var deleted = VaultItem(name: "deleted", fields: [ItemField(path: "password", type: .password)])
    deleted.deletion = ItemDeletion(originalName: "deleted", deletedAt: Date())
    let a = ItemCatalog(vault: "a", revision: "1", items: [archived, deleted, active, mapped, ignored, missing])
    let b = ItemCatalog(vault: "b", revision: "1", items: [VaultItem(name: "unicode", fields: [ItemField(path: "p", type: .password)])])
    let service = HealthService(["a:archived/password": "é", "a:deleted/password": "é", "a:active/password": "é", "a:mapped/secret": "é", "b:unicode/p": SecretBytes(utf8: "e\u{301}")])
    let breach = HealthBreach()
    var progress: [Double] = []
    let report = try await PasswordHealthScanner.scan(catalogs: ["a": a, "b": b], service: service, breach: breach, enabled: true) {
        progress.append($0)
    }
    // Missing fields still finish their work; progress must not stall below completion.
    #expect(progress == [0, 0.25, 0.5, 0.75, 1, 1])
    #expect(report.total == 4)
    #expect(report.checked == 3)
    #expect(report.breachChecked == 3)
    #expect(await breach.count == 3)
    #expect(report.findings.filter { $0.kinds.contains(.reused) }.map(\.item).sorted() == ["active", "mapped"])
    #expect(!report.findings.contains { ["archived", "deleted"].contains($0.item) })
    #expect(service.reads.withLock { $0 } == 4) // Three active values plus one missing; excluded fields are never read.
    let disabled = try await PasswordHealthScanner.scan(catalogs: ["a": a], service: service, breach: breach, enabled: false)
    #expect(disabled.breachChecked == 0)
    #expect(await breach.count == 3)
}

private actor RefreshBreach: BreachChecking {
    func contains(_ lookup: BreachLookup, force: Bool) async throws -> Bool { try await contains(Data(), force: force) }
    var count = 0
    var failing = false
    func fail() { failing = true }
    func contains(_ password: Data, force: Bool) async throws -> Bool {
        count += 1
        if failing { throw BreachCheckFailure.unavailable }
        return true
    }
    func clear() {}
}

@MainActor @Test func incrementalHealthFreshnessChangesAndBackoff() async throws {
    let session = PasswordHealthSession()
    let service = HealthService(["v:a/password": "password", "v:b/password": "password"])
    let breach = RefreshBreach()
    var field = ItemField(path: "password", type: .password); field.recordVersion = "record-1"
    var catalog = ItemCatalog(vault: "v", revision: "1", items: [VaultItem(name: "a", fields: [field]), VaultItem(name: "b", fields: [field])])
    let now = Date(timeIntervalSince1970: 100000)
    _ = try await session.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: now)
    #expect(service.reads.withLock { $0 } == 2)
    #expect(session.isCurrent(catalogs: ["v": catalog], enabled: true, at: now.addingTimeInterval(100)))
    catalog.revision = "2" // An unrelated revision must not reread either password.
    _ = try await session.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: now)
    #expect(service.reads.withLock { $0 } == 2)
    catalog.revision = "3"; catalog.items[0].fields[0].recordVersion = "record-2"
    _ = try await session.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: now)
    #expect(service.reads.withLock { $0 } == 3)
    #expect(await breach.count == 3)
    let tomorrow = now.addingTimeInterval(86401)
    #expect(!session.isCurrent(catalogs: ["v": catalog], enabled: true, at: tomorrow))
    await breach.fail()
    let failed = try await session.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: tomorrow)
    #expect(failed.findings.filter { $0.kinds.contains(.exposed) }.count == 2)
    #expect(failed.breachState == .unavailable)
    #expect(session.isCurrent(catalogs: ["v": catalog], enabled: true, at: tomorrow.addingTimeInterval(30)))
    #expect(!session.isCurrent(catalogs: ["v": catalog], enabled: true, at: tomorrow.addingTimeInterval(61)))
    _ = try await session.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: tomorrow.addingTimeInterval(30))
    #expect(await breach.count == 5)
    _ = try await session.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, force: true, at: tomorrow.addingTimeInterval(31))
    #expect(await breach.count == 7)
    catalog.revision = "4"; catalog.items.removeLast()
    let removed = try await session.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: false, at: tomorrow)
    #expect(removed.findings.allSatisfy { !$0.kinds.contains(.reused) })
    #expect(removed.total == 1)
}

@MainActor @Test func archivingAndDeletingRemoveCachedHealthFindings() async throws {
    let session = PasswordHealthSession()
    let service = HealthService(["v:a/password": "password", "v:b/password": "password"])
    let breach = HealthBreach()
    var field = ItemField(path: "password", type: .password); field.recordVersion = "1"
    var catalog = ItemCatalog(vault: "v", revision: "1", items: [VaultItem(name: "a", fields: [field]), VaultItem(name: "b", fields: [field])])
    let initial = try await session.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true)
    #expect(initial.findings.filter { $0.kinds.contains(.reused) }.count == 2)
    catalog.revision = "2"
    catalog.items[0].metadata = ItemMetadata(archived: true)
    catalog.items[1].deletion = ItemDeletion(originalName: "b", deletedAt: Date())
    let excluded = try await session.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true)
    #expect(excluded.findings.isEmpty)
    #expect(excluded.total == 0 && excluded.checked == 0 && excluded.breachChecked == 0)
    #expect(service.reads.withLock { $0 } == 2)
    #expect(await breach.count == 2)
    catalog.revision = "3"; catalog.items[0].metadata = nil; catalog.items[1].deletion = nil
    let restored = try await session.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true)
    #expect(restored.total == 2 && restored.checked == 2)
    #expect(service.reads.withLock { $0 } == 4)
}

@MainActor @Test func cloudHealthCacheRestoresResultsWithoutReadingOrCheckingPasswords() async throws {
    let service = HealthService(["v:a/password": "password", "v:b/password": "password"])
    let breach = RefreshBreach()
    var field = ItemField(path: "password", type: .password); field.recordVersion = "record-a"
    var other = field; other.recordVersion = "record-b"
    var catalog = ItemCatalog(vault: "v", revision: "1", items: [VaultItem(name: "a", fields: [field]), VaultItem(name: "b", fields: [other])])
    let now = Date(timeIntervalSince1970: 100000)
    let first = try await PasswordHealthSession().scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: now)
    catalog.security = VaultSecurityMetadata(); catalog.security?.passwordChecks = first.cachedChecks["v"]
    catalog.revision = "cache-publication"
    let anotherDevice = PasswordHealthSession()
    #expect(anotherDevice.canRestoreCloudResults(catalogs: ["v": catalog], enabled: true, at: now.addingTimeInterval(100)))
    let restored = try await anotherDevice.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: now.addingTimeInterval(100))
    #expect(restored.usedCloudCache && restored.completedAt == now)
    #expect(restored.findings.count == 2)
    #expect(restored.findings.allSatisfy { $0.kinds == [.weak, .exposed, .reused] })
    #expect(service.reads.withLock { $0 } == 2)
    #expect(await breach.count == 2)
    #expect(restored.cachedChecks == first.cachedChecks)
    // A changed password cannot inherit yesterday's evidence.
    catalog.revision = "changed"; catalog.items[0].fields[0].recordVersion = "replacement"
    let changed = try await anotherDevice.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: now.addingTimeInterval(200))
    #expect(!changed.usedCloudCache)
    #expect(await breach.count == 3) // Only the replacement needed a breach check.
    catalog.security?.passwordChecks = changed.cachedChecks["v"]
    _ = try await PasswordHealthSession().scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: now.addingTimeInterval(86601))
    #expect(await breach.count == 5)
    _ = try await PasswordHealthSession().scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, force: true, at: now.addingTimeInterval(201))
    #expect(await breach.count == 7)
    catalog.security?.passwordChecks?[0].reuseResult?.batch = UUID()
    #expect(!PasswordHealthSession().canRestoreCloudResults(catalogs: ["v": catalog], enabled: true, at: now.addingTimeInterval(201)))
    catalog.security?.passwordChecks?[0].strengthResult?.checkedAt = now.addingTimeInterval(999999)
    #expect(!PasswordHealthSession().canRestoreCloudResults(catalogs: ["v": catalog], enabled: true, at: now))
}

@MainActor @Test func dailyBreachRefreshDoesNotReevaluateStrengthOrReuse() async throws {
    var estimates = 0
    func scanner() -> PasswordHealthSession {
        PasswordHealthSession { _, _ in estimates += 1; return .weak }
    }
    let service = HealthService(["v:a/password": "password", "v:b/password": "password"])
    let breach = HealthBreach()
    var first = ItemField(path: "password", type: .password); first.recordVersion = "a"
    var second = first; second.recordVersion = "b"
    var catalog = ItemCatalog(vault: "v", revision: "1", items: [VaultItem(name: "a", fields: [first]), VaultItem(name: "b", fields: [second])])
    let now = Date(timeIntervalSince1970: 100000)
    let initial = try await scanner().scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: now)
    catalog.security = VaultSecurityMetadata(); catalog.security?.passwordChecks = initial.cachedChecks["v"]
    let nextSession = scanner(), tomorrow = now.addingTimeInterval(86401)
    let daily = try await nextSession.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: tomorrow)
    #expect(estimates == 2)
    #expect(await breach.count == 4)
    #expect(daily.cachedChecks["v"]?.map(\.strengthResult) == initial.cachedChecks["v"]?.map(\.strengthResult))
    #expect(daily.cachedChecks["v"]?.map(\.reuseResult) == initial.cachedChecks["v"]?.map(\.reuseResult))
    catalog.security?.passwordChecks = daily.cachedChecks["v"]
    let disabled = try await scanner().scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: false, at: now.addingTimeInterval(86400 * 90))
    #expect(disabled.usedCloudCache && service.reads.withLock { $0 } == 4)
    #expect(estimates == 2)
    // An account-context edit changes strength inputs, but neither password bytes nor reuse.
    catalog.revision = "2"; catalog.items[0].fields.append(ItemField(path: "username", type: .username, value: "alice"))
    let context = try await nextSession.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: tomorrow)
    #expect(estimates == 3)
    #expect(await breach.count == 4)
    #expect(context.cachedChecks["v"]?.map(\.reuseResult) == daily.cachedChecks["v"]?.map(\.reuseResult))
    catalog.revision = "3"; catalog.items[0].fields[0].recordVersion = "changed"
    _ = try await nextSession.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: tomorrow)
    #expect(estimates == 4)
    #expect(await breach.count == 5)
    _ = try await nextSession.scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, force: true, at: tomorrow)
    #expect(estimates == 4)
    #expect(await breach.count == 7)
}

@MainActor @Test func anotherItemsUpdateDoesNotRestartSuccessfulHIBPClockOnAnotherDevice() async throws {
    let service = HealthService(["v:a/password": "one-password", "v:b/password": "another-password"])
    let breach = HealthBreach()
    var a = ItemField(path: "password", type: .password); a.recordVersion = "a"
    var b = a; b.recordVersion = "b"
    var catalog = ItemCatalog(vault: "v", revision: "1", items: [VaultItem(name: "a", fields: [a]), VaultItem(name: "b", fields: [b])])
    let now = Date(timeIntervalSince1970: 100000)
    let first = try await PasswordHealthSession().scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: now)
    catalog.security = VaultSecurityMetadata(); catalog.security?.passwordChecks = first.cachedChecks["v"]
    catalog.revision = "2"; catalog.items[1].fields[0].recordVersion = "b-changed"
    let second = try await PasswordHealthSession().scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: now.addingTimeInterval(100))
    #expect(await breach.count == 3)
    #expect(second.cachedChecks["v"]?.first { $0.record == "a" }?.breachResult?.checkedAt == now)
    catalog.security?.passwordChecks = second.cachedChecks["v"]
    _ = try await PasswordHealthSession().scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: now.addingTimeInterval(86399))
    #expect(await breach.count == 3)
    let expired = try await PasswordHealthSession().scan(catalogs: ["v": catalog], service: service, breach: breach, enabled: true, at: now.addingTimeInterval(86400))
    #expect(await breach.count == 4)
    #expect(expired.cachedChecks["v"]?.first { $0.record == "b-changed" }?.breachResult?.checkedAt == now.addingTimeInterval(100))
}

@MainActor @Test func healthScannerPublishesBoundedBatchesWithProvisionalReuse() async throws {
    let names = (0..<25).map { String(format: "item%02d", $0) }
    let service = HealthService(Dictionary(uniqueKeysWithValues: names.map { ("v:\($0)/password", SecretBytes(utf8: "password")) }))
    let items = names.map { name in
        var field = ItemField(path: "password", type: .password); field.recordVersion = name
        return VaultItem(name: name, fields: [field])
    }
    let catalog = ItemCatalog(vault: "v", revision: "1", items: items)
    let batches = Mutex<[Int]>([])
    let report = try await PasswordHealthSession().scan(catalogs: ["v": catalog], service: service,
        breach: HealthBreach(), enabled: false, batch: { partial in
            #expect(partial.state == .incomplete && partial.completedAt == nil)
            #expect(partial.cachedChecks["v"]?.allSatisfy { $0.reuseResult == nil } == true)
            #expect(!partial.findings.contains { $0.kinds.contains(.reused) })
            batches.withLock { $0.append(partial.checked) }
        })
    let counts = batches.withLock { $0 }
    #expect(counts.first == 1 && counts.count >= 3)
    #expect(zip(counts, counts.dropFirst()).allSatisfy { $1 > $0 && $1 - $0 <= 10 })
    #expect(counts.last.map { 25 - $0 <= 10 } == true)
    #expect(report.checked == 25 && report.state == .checked)
    #expect(report.findings.allSatisfy { $0.kinds.contains(.reused) })
}
