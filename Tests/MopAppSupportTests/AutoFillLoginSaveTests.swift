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
