import Foundation
import Synchronization
import AuthenticationServices
import Testing
import MopCore
@testable import MopAppSupport

private func login() -> VaultItem {
    VaultItem(name: "Example", type: .login, fields: [
        ItemField(path: "username", type: .username, value: "alice"),
        ItemField(path: "password", type: .password, value: "must-not-be-indexed"),
        ItemField(path: "website", type: .website, value: "https://Example.COM/login?secret=private")])
}
@Test func autoFillIndexesOnlyLoginMetadataAndOpaqueLocators() throws {
    let id = UUID().uuidString
    var item = login()
    item.fields.append(ItemField(path: "alternate", type: .website, value: "example.com"))
    let entries = AutoFillEntry.entries(catalog: ItemCatalog(vault: "personal", revision: "", items: [item]), vaultID: id)
    let entry = try #require(entries.first)
    #expect(entries.count == 1)
    #expect(entry.website == "example.com")
    #expect(entry.username == "alice")
    #expect(AutoFillEntry.vaultID(entry.recordIdentifier) == id)
    #expect(!entry.recordIdentifier.contains("Example"))
    #expect(!entry.recordIdentifier.contains("alice"))
    #expect((entry.identity as? ASPasswordCredentialIdentity)?.serviceIdentifier.identifier == "example.com")
    item.fields[1].value = "new-password"
    let next = AutoFillEntry.entries(catalog: ItemCatalog(vault: "renamed", revision: "new", items: [item]), vaultID: id)
    #expect(next.first?.recordIdentifier == entry.recordIdentifier)
    item.fields[0].value = "bob"
    #expect(AutoFillEntry.entries(catalog: ItemCatalog(vault: "personal", revision: "", items: [item]), vaultID: id).first?.recordIdentifier != entry.recordIdentifier)
}
@Test func autoFillRejectsAmbiguousAndNonLoginItems() {
    let id = UUID().uuidString
    var item = login()
    item.fields[1].path = "first-secret"
    item.fields.append(ItemField(path: "other", type: .password))
    #expect(AutoFillEntry.entries(catalog: ItemCatalog(vault: "v", revision: "", items: [item]), vaultID: id).isEmpty)
    item = login(); item.type = .apiCredential
    #expect(AutoFillEntry.entries(catalog: ItemCatalog(vault: "v", revision: "", items: [item]), vaultID: id).isEmpty)
    #expect(AutoFillEntry.vaultID("../../private") == nil)
    for website in ["javascript:alert(1)", "https://user:password@example.com", "https://", "file:///tmp/secret", "https://exam ple.com"] {
        #expect(AutoFillEntry.website(website) == nil)
    }
}

@Test func sharedAutoFillIndexPreservesVaultsWithoutReadingAppleStore() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let index = AutoFillIndex(directory: root)
    let first = UUID().uuidString, second = UUID().uuidString
    let catalog = ItemCatalog(vault: "personal", revision: "", items: [login()])
    let a = AutoFillEntry.entries(catalog: catalog, vaultID: first).map(AutoFillIdentity.init)
    let b = AutoFillEntry.entries(catalog: catalog, vaultID: second).map(AutoFillIdentity.init)
    #expect(try index.load().isEmpty)
    try index.update { _ in a }
    try index.update { $0 + b }
    // A different process/instance can load the picker without vault authentication.
    #expect(try AutoFillIndex(directory: root).load().count == 2)
    let data = try Data(contentsOf: root.appendingPathComponent("identities.json"))
    let rows = try #require(JSONSerialization.jsonObject(with: data) as? [[String: Any]])
    #expect(rows.allSatisfy { Set($0.keys) == ["website", "username", "recordIdentifier", "kind"] })
    #expect(!String(decoding: data, as: UTF8.self).contains("must-not-be-indexed"))
    try index.update { $0.filter { AutoFillEntry.vaultID($0.recordIdentifier) != first } }
    #expect(try index.load() == b)
    try index.update { _ in [] }
    #expect(try index.load().isEmpty)
}

private actor PublishedAutoFillIdentities {
    var rows: [AutoFillIdentity] = []
    func save(_ rows: [AutoFillIdentity]) { self.rows = rows }
}

@Test func autoFillPublisherKeepsAllVaultsAcrossRefreshAndEdits() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let published = PublishedAutoFillIdentities()
    let publisher = AutoFillPublisher(directory: root, publish: { await published.save($0) })
    let first = UUID().uuidString, second = UUID().uuidString
    let catalog = ItemCatalog(vault: "personal", revision: "", items: [login()])
    try await publisher.publish(catalog: catalog, vaultID: first)
    try await publisher.publish(catalog: catalog, vaultID: second)
    try await publisher.prune(keeping: [first, second])
    try await publisher.publish(catalog: catalog, vaultID: first)
    #expect(try AutoFillIndex(directory: root).load().count == 2)
    #expect(await published.rows.count == 2)
    try await publisher.remove(vaultID: first)
    #expect(try AutoFillIndex(directory: root).load().map { AutoFillEntry.vaultID($0.recordIdentifier) } == [second])
    #expect(await published.rows.count == 1)
}

@Test func autoFillUsesPrimaryLoginFieldsWithAdditionalFields() throws {
    var item = login()
    item.fields += [ItemField(path: "contact", type: .email, value: "contact@example.net"),
                    ItemField(path: "other-user", type: .username, value: "secondary"),
                    ItemField(path: "other-password", type: .password),
                    ItemField(path: "notes", type: .notes, value: "notes")]
    let entry = try #require(AutoFillEntry.entries(catalog: ItemCatalog(vault: "v", revision: "", items: [item]), vaultID: UUID().uuidString).first)
    #expect(entry.username == "alice")
    #expect(entry.reference.field == "password")
    #expect(AutoFillEntry.exclusionReason(for: item) == nil)
}
@Test func autoFillExplainsFieldNamesWithoutCorrectTypes() {
    var item = login()
    item.fields[0].type = .text
    #expect(AutoFillEntry.exclusionReason(for: item)?.contains("Username") == true)
    item.fields[0].type = .username; item.fields[1].type = .concealed
    #expect(AutoFillEntry.exclusionReason(for: item)?.contains("Password") == true)
    item.fields[1].type = .password; item.fields[2].type = .text
    #expect(AutoFillEntry.exclusionReason(for: item)?.contains("Website") == true)
}

@Test func autoFillCodesUsePrimaryOTPWithoutRequiringPassword() throws {
    let id = UUID().uuidString
    var item = login()
    item.fields.removeAll { $0.type == .password }
    item.fields += [ItemField(path: "otp", type: .otp, value: "JBSWY3DPEHPK3PXP"),
                    ItemField(path: "secondary", type: .otp),
                    ItemField(path: "alternate", type: .website, value: "other.example.com")]
    func entries() -> [AutoFillEntry] {
        AutoFillEntry.entries(catalog: ItemCatalog(vault: "v", revision: "", items: [item]), vaultID: id)
    }
    #expect(entries().count == 2)
    #expect(entries().allSatisfy { $0.kind == .oneTimeCode && $0.reference.field == "otp" })
    let entry = try #require(entries().first)
    let identity = try #require(entry.identity as? ASOneTimeCodeCredentialIdentity)
    #expect(identity.label == "alice")
    #expect(AutoFillIdentity(identity: identity)?.kind == .oneTimeCode)
    #expect(AutoFillEntry.vaultID(entry.recordIdentifier) == id)
    #expect(AutoFillEntry.exclusionReason(for: item, kind: .oneTimeCode) == nil)
    item.fields.removeAll { $0.path == "otp" }
    #expect(entries().first?.reference.field == "secondary")
    item.fields.append(ItemField(path: "third", type: .otp))
    #expect(entries().isEmpty)
    #expect(AutoFillEntry.exclusionReason(for: item, kind: .oneTimeCode)?.contains("primary") == true)
    item.fields.removeAll { $0.path == "third" }
    item.type = .custom
    #expect(entries().isEmpty)
    item.type = .login
    item.deletion = ItemDeletion(originalName: item.name, deletedAt: Date())
    #expect(entries().isEmpty)
    item.deletion = nil
    item.fields.removeAll { $0.type == .username }
    #expect(entries().isEmpty)
}

@Test func autoFillMixedIndexUpgradesLegacyRowsAndKeepsSecretsOut() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let id = UUID().uuidString
    var item = login()
    let catalog = ItemCatalog(vault: "v", revision: "", items: [item])
    let password = try #require(AutoFillEntry.entries(catalog: catalog, vaultID: id).first)
    let index = AutoFillIndex(directory: root)
    try index.update { _ in [AutoFillIdentity(entry: password)] }
    let file = root.appendingPathComponent("identities.json")
    var legacy = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [[String: Any]])
    legacy[0].removeValue(forKey: "kind")
    try JSONSerialization.data(withJSONObject: legacy).write(to: file)
    #expect(try index.load().first?.kind == .password)
    item.fields.append(ItemField(path: "otp", type: .otp, value: "JBSWY3DPEHPK3PXP"))
    let mixed = ItemCatalog(vault: "v", revision: "", items: [item])
    let published = PublishedAutoFillIdentities()
    let publisher = AutoFillPublisher(directory: root, publish: { await published.save($0) })
    try await publisher.publish(catalog: mixed, vaultID: id)
    let rows = try index.load()
    #expect(Set(rows.map(\.kind)) == [.password, .oneTimeCode])
    #expect(rows.first { $0.kind == .password }?.recordIdentifier == password.recordIdentifier)
    #expect(Set(rows.map(\.recordIdentifier)).count == 2)
    #expect(await published.rows == rows)
    let data = try Data(contentsOf: file)
    let objects = try #require(JSONSerialization.jsonObject(with: data) as? [[String: Any]])
    #expect(objects.allSatisfy { Set($0.keys) == ["website", "username", "recordIdentifier", "kind"] })
    #expect(!String(decoding: data, as: UTF8.self).contains("JBSWY3DPEHPK3PXP"))
    #expect(!String(decoding: data, as: UTF8.self).contains("must-not-be-indexed"))
    let second = UUID().uuidString
    try await publisher.publish(catalog: mixed, vaultID: second)
    try await publisher.remove(vaultID: id)
    #expect(try index.load().count == 2)
    try await publisher.prune(keeping: [])
    #expect(try index.load().isEmpty)
    #expect(await published.rows.isEmpty)
    var invalid = objects
    let codeIndex = try #require(invalid.firstIndex { $0["kind"] as? String == "oneTimeCode" })
    invalid[codeIndex]["kind"] = "password"
    try JSONSerialization.data(withJSONObject: invalid).write(to: file)
    #expect(throws: MopError.invalidVault) { try index.load() }
}

private final class CodeReadService: VaultService, Sendable {
    enum Outcome: Sendable { case missingExpiry, expired, invalidSeed, cancel, valid }
    let outcome: Outcome
    let catalog: ItemCatalog
    let locked = Synchronization.Mutex(false)
    var authenticatedAt: TimeInterval? { locked.withLock { $0 ? nil : 1 } }
    init(outcome: Outcome) {
        self.outcome = outcome
        var item = login()
        item.fields.append(ItemField(path: "otp", type: .otp))
        catalog = ItemCatalog(vault: "v", revision: "", items: [item])
    }
    func lock() { locked.withLock { $0 = true } }
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult {
        #expect(offline)
        var result = VaultResult()
        switch operation {
        case .catalog: result.catalog = catalog
        case .read:
            if outcome == .invalidSeed { throw MopError.invalidOTP }
            if outcome == .cancel { withUnsafeCurrentTask { $0?.cancel() } }
            result.value = SecretBytes(utf8: "123456")
            result.otpPeriod = 30
            if outcome != .missingExpiry {
                result.otpExpiresAt = Date().addingTimeInterval(outcome == .expired ? -30 : 30)
            }
        default: throw MopError.notFound
        }
        return result
    }
}

@Test func autoFillCodeRejectsInvalidResultsAndLocksOnCancellation() async throws {
    let id = UUID().uuidString
    for outcome in [CodeReadService.Outcome.missingExpiry, .expired, .invalidSeed] {
        let service = CodeReadService(outcome: outcome)
        let entry = try #require(AutoFillEntry.entries(catalog: service.catalog, vaultID: id).first { $0.kind == .oneTimeCode })
        await #expect(throws: MopError.invalidOTP) {
            _ = try await AutoFillAccess.systemOneTimeCode(recordIdentifier: entry.recordIdentifier, service: service)
        }
        #expect(!service.isAuthenticated)
    }
    let service = CodeReadService(outcome: .cancel)
    let entry = try #require(AutoFillEntry.entries(catalog: service.catalog, vaultID: id).first { $0.kind == .oneTimeCode })
    let task = Task {
        try await AutoFillAccess.systemOneTimeCode(recordIdentifier: entry.recordIdentifier, service: service)
    }
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(!service.isAuthenticated)

    let mismatch = CodeReadService(outcome: .valid)
    let password = try #require(AutoFillEntry.entries(catalog: mismatch.catalog, vaultID: id).first { $0.kind == .password })
    await #expect(throws: MopError.notFound) {
        _ = try await AutoFillAccess.systemOneTimeCode(recordIdentifier: password.recordIdentifier, service: mismatch)
    }
    #expect(!mismatch.isAuthenticated)
}
