import Foundation
import Synchronization
import Testing
import MopCore
@testable import MopAppSupport

private final class LoginSaveService: VaultService {
    enum Outcome: Sendable { case success, readOnly, duplicate, writeFailure, cancelled, lockedAfterSave }
    struct State {
        var authenticated = true
        var generation = 0
        var locks = 0
        var prompts = 0
        var saved: ItemEdit?
    }
    let outcome: Outcome
    let state = Mutex(State())
    let vault = UUID().uuidString
    init(_ outcome: Outcome) { self.outcome = outcome }
    var authenticatedAt: TimeInterval? { state.withLock { $0.authenticated ? 1 : nil } }
    var sessionGeneration: Int { state.withLock { $0.generation } }
    func lock() { state.withLock { $0.authenticated = false; $0.generation += 1; $0.locks += 1 } }
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult {
        #expect(vault == self.vault)
        state.withLock { if !$0.authenticated { $0.prompts += 1; $0.authenticated = true } }
        var result = VaultResult()
        var catalog = ItemCatalog(vault: "personal", revision: "verified-revision", items: [])
        catalog.canEdit = outcome != .readOnly
        switch operation {
        case .catalog: result.catalog = catalog
        case .save(let edit):
            #expect(edit.create && edit.originalName == nil)
            #expect(edit.revision == catalog.revision)
            if outcome == .duplicate { throw MopError.duplicate }
            if outcome == .writeFailure { throw MopError.inputOutput }
            state.withLock { $0.saved = edit }
            catalog.items = [edit.item]; result.catalog = catalog
            if outcome == .cancelled { withUnsafeCurrentTask { $0?.cancel() } }
            if outcome == .lockedAfterSave { lock() }
        default: Issue.record("Unexpected operation"); throw MopError.notFound
        }
        return result
    }
}

@Test func newAutoFillLoginSavesBeforePreparingCredentialAndAuthenticatesFreshly() async throws {
    let service = LoginSaveService(.success)
    let password = try PasswordGenerator.generate(PasswordOptions())
    let draft = AutoFillLoginDraft(name: " Example ", username: "alice", password: password, website: "example.test")
    let result = try await draft.saveAndPrepareFill(vault: service.vault, service: service)
    let saved = try #require(service.state.withLock { $0.saved })
    #expect(saved.item.name == "Example")
    #expect(saved.item.fields.first { $0.path == "website" }?.value == "example.test")
    #expect(saved.item.fields.first { $0.path == "password" }?.value == result.credential.password)
    #expect(result.credential.user == "alice" && result.credential.password == password)
    #expect(service.state.withLock { $0.prompts } == 1)
    #expect(service.state.withLock { $0.locks } == 2)
    #expect(!service.isAuthenticated)
}

@Test(arguments: [LoginSaveService.Outcome.readOnly, .duplicate, .writeFailure, .cancelled, .lockedAfterSave])
private func newAutoFillLoginDoesNotReturnCredentialWhenSaveCannotComplete(outcome: LoginSaveService.Outcome) async throws {
    let service = LoginSaveService(outcome)
    let draft = AutoFillLoginDraft(name: "Example", username: "alice", password: "new-password", website: "example.test")
    let operation = Task { try await draft.saveAndPrepareFill(vault: service.vault, service: service) }
    do {
        _ = try await operation.value
        Issue.record("A failed or interrupted save must not return a fill credential")
    } catch {}
    #expect(!service.isAuthenticated)
    if outcome == .readOnly || outcome == .duplicate || outcome == .writeFailure {
        #expect(service.state.withLock { $0.saved } == nil)
    }
}

@Test func newAutoFillLoginRejectsIncompleteDraftBeforeAuthentication() async throws {
    let service = LoginSaveService(.success)
    let draft = AutoFillLoginDraft(name: "Example", username: "", password: "new-password", website: "example.test")
    #expect(!draft.canSaveAndFill)
    await #expect(throws: AutoFillLoginSaveError.self) {
        try await draft.saveAndPrepareFill(vault: service.vault, service: service)
    }
    #expect(service.state.withLock { $0.prompts } == 0)
    #expect(service.state.withLock { $0.saved } == nil)
}

private final class RememberWebsiteService: VaultService {
    let vault = UUID().uuidString
    let saved = Mutex<ItemEdit?>(nil)
    var authenticatedAt: TimeInterval? { 1 }
    let readOnly: Bool
    let failSave: Bool
    let item = VaultItem(name: "Login", type: .login, fields: [
        ItemField(path: "username", type: .username, value: "alice"),
        ItemField(path: "password", type: .password, value: nil),
        ItemField(path: "website", type: .website, value: "https://old.test/login"),
        ItemField(path: "website2", type: .text, value: "Keep this note")
    ])
    init(readOnly: Bool = false, failSave: Bool = false) { self.readOnly = readOnly; self.failSave = failSave }
    func lock() {}
    var catalog: ItemCatalog {
        var result = ItemCatalog(vault: "personal", revision: "revision", items: [item])
        result.canEdit = !readOnly
        return result
    }
    var identity: AutoFillIdentity { AutoFillIdentity(entry: AutoFillEntry.entries(catalog: catalog, vaultID: vault)[0]) }
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult {
        #expect(vault == self.vault && !offline)
        var result = VaultResult()
        switch operation {
        case .catalog: result.catalog = catalog
        case .save(let edit):
            if failSave { throw MopError.inputOutput }
            saved.withLock { $0 = edit }
            result.catalog = catalog
        default: throw MopError.notFound
        }
        return result
    }
}

@Test func autoFillRememberAddsHostPreservingExistingFieldsAndMakesItMatch() async throws {
    let service = RememberWebsiteService()
    try await AutoFillRememberWebsite.save(["https://NEW.test/login?private=value"], for: service.identity, service: service)
    let edit = try #require(service.saved.withLock { $0 })
    #expect(!edit.create && edit.originalName == "Login" && edit.revision == "revision")
    #expect(Array(edit.item.fields.prefix(4)) == service.item.fields)
    #expect(edit.item.fields.last?.path == "website3")
    #expect(edit.item.fields.last?.value == "new.test")
    var catalog = service.catalog; catalog.items = [edit.item]
    #expect(Set(AutoFillEntry.entries(catalog: catalog, vaultID: service.vault).map(\.website)) == ["old.test", "new.test"])
}

@Test func autoFillRememberDoesNotDuplicateExistingHost() async throws {
    let service = RememberWebsiteService()
    try await AutoFillRememberWebsite.save(["https://old.test/another-path"], for: service.identity, service: service)
    #expect(service.saved.withLock { $0 } == nil)
}

@Test func autoFillRememberPropagatesPermissionAndSaveFailures() async throws {
    for service in [RememberWebsiteService(readOnly: true), RememberWebsiteService(failSave: true)] {
        await #expect(throws: (any Error).self) {
            try await AutoFillRememberWebsite.save(["new.test"], for: service.identity, service: service)
        }
        #expect(service.saved.withLock { $0 } == nil)
    }
}

@MainActor @Test func autoFillRememberFailurePreventsCredentialDelivery() async throws {
    let service = RememberWebsiteService(failSave: true)
    let session = AutoFillRequestSession(service: service)
    await #expect(throws: MopError.inputOutput) {
        _ = try await session.password(service.identity, remembering: ["new.test"])
    }
    #expect(throws: AutoFillSessionError.ended) { try session.check() }
}
