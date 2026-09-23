import Foundation
import Testing
import MopCore
@testable import MopApp

struct ItemDraftTests {
    private var item: VaultItem {
        VaultItem(name: "login", type: .login, fields: [
            ItemField(path: "username", type: .username, value: "alice", isTemplate: true),
            ItemField(path: "password", type: .password, isTemplate: true),
            ItemField(path: "notes", type: .notes, value: "details", isTemplate: true)
        ])
    }
    @Test func templatesIncludeNotesAndLegacyProtectionSurvivesTypeChange() {
        for type in ItemType.allCases {
            #expect(type.template.contains { $0.path == "notes" && $0.type == .notes })
            #expect(type.template.allSatisfy { $0.isTemplate == true })
        }
        let legacy = VaultItem(name: "login", type: .login, fields: [
            ItemField(path: "password", type: .password), ItemField(path: "extra", value: "custom")
        ])
        var draft = ItemDraft(vault: "uuid", revision: "r1", item: legacy)
        #expect(draft.fields[0].isTemplate && !draft.fields[1].isTemplate)
        draft.type = .custom
        #expect(draft.item.isTemplateField(draft.item.fields[0]))
        #expect(!draft.item.isTemplateField(draft.item.fields[1]))
    }

    @Test func unchangedPasswordsUseStoredRatingAndOnlyEditsAreEstimated() {
        var stored = ItemField(path: "password", type: .password)
        stored.passwordQuality = .strong
        var field = ItemDraft.Field(stored)
        #expect(field.storedPasswordQuality == .strong)
        #expect(field.passwordToEstimate == nil)
        field.loadedPassword = "stored-password"
        field.value = "stored-password"
        #expect(field.passwordToEstimate == nil)
        field.value = "changed-password"
        #expect(field.passwordToEstimate == "changed-password")
        field.value = ""
        #expect(field.passwordToEstimate == "")
        field.value = "stored-password"
        #expect(field.passwordToEstimate == nil)
        var unrated = ItemDraft.Field(ItemField(path: "password", type: .password))
        unrated.loadedPassword = "old-password"; unrated.value = "old-password"
        #expect(unrated.storedPasswordQuality == nil && unrated.passwordToEstimate == nil)
    }

    @Test func editingDoesNotReadOrReplaceUntouchedSecrets() {
        let draft = ItemDraft(vault: "uuid", revision: "r1", item: item)
        #expect(draft.item == item)
        #expect(draft.fields[1].value == nil)
        #expect(draft.revision == "r1")
    }
    @Test func replacementTargetsOnlyOneFieldAndAllowsEmptyValues() {
        let draft = ItemDraft(vault: "uuid", revision: "r1", item: item, mode: .value("password"))
        #expect(draft.item.fields[1].value == nil)
        #expect(draft.item.fields[0] == item.fields[0] && draft.item.fields[2] == item.fields[2])
        let visible = ItemDraft(vault: "uuid", revision: "r1", item: item, mode: .value("notes"))
        #expect(visible.fields[2].value == "details")
    }
    @Test func draggingPreservesValuesAndStableIdentity() {
        var draft = ItemDraft(vault: "uuid", revision: "r1", item: item)
        let first = draft.fields[0], last = draft.fields[2]
        draft.move(first.id, to: last.id)
        #expect(draft.item.fields.map(\.path) == ["password", "notes", "username"])
        #expect(draft.fields[2].id == first.id && draft.fields[2].dragID == first.dragID)
        #expect(draft.fields[0].value == nil && draft.fields[2].value == "alice")
        draft.move(first.id, to: draft.fields[0].id)
        #expect(draft.item == item)
    }
    @Test func foreignOrSingleValueMovesCannotReorderFields() {
        var draft = ItemDraft(vault: "uuid", revision: "r1", item: item)
        draft.move("foreign", to: draft.fields[1].id)
        #expect(draft.item == item)
        draft.mode = .value("password")
        draft.move(draft.fields[0].id, to: draft.fields[2].id)
        #expect(draft.item == item)
    }
    @Test func validationProtectsPathsAndRequiresAtLeastOneField() {
        var draft = ItemDraft(vault: "uuid", revision: "r1", item: item)
        #expect(draft.valid(vaultName: "personal"))
        draft.fields.append(ItemDraft.Field(ItemField(path: "username", value: "duplicate"), existing: false))
        #expect(!draft.valid(vaultName: "personal"))
        draft.fields.removeLast()
        draft.fields.append(ItemDraft.Field(ItemField(path: "section/new field", value: ""), existing: false))
        #expect(draft.valid(vaultName: "personal"))
        #expect(draft.item.fields.last?.path == "section/new%20field")
        draft.fields = []
        #expect(!draft.valid(vaultName: "personal"))
    }
}
