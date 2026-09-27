import Foundation
import Testing
@testable import MopCore

@Suite struct ImportPlannerTests {
    func login(_ name: String = "Login", website: String = "https://example.test", password: String = "secret") -> VaultItem {
        VaultItem(name: name, type: .login, fields: [ItemField(path: "username", type: .username, value: "user"), ItemField(path: "password", type: .password, value: password), ItemField(path: "website", type: .website, value: website)])
    }
    @Test func duplicatesConflictsAndSafeReport() throws {
        let document = ImportDocument(format: .appleCSV, records: [ImportRecord(id: 1, item: login()), ImportRecord(id: 2, item: login(password: "different")), ImportRecord(id: 3, item: login("New", website: "https://other.test"))])
        let plan = try ImportPlanner.prepare(document, existing: [login()])
        #expect(plan.report.rows.map(\.disposition) == [.duplicate, .conflict, .ready])
        #expect(plan.items.count == 1)
        let report = String(decoding: try JSONEncoder().encode(plan.report), as: UTF8.self)
        #expect(!report.contains("secret") && !report.contains("different"))
        #expect(try ImportPlanner.prepare(document, existing: [login()] + plan.items).items.isEmpty)
    }
    @Test func titleCollisionAndSourceIdentity() throws {
        let item = login(website: "https://other.test")
        let document = ImportDocument(format: .chromeCSV, records: [ImportRecord(id: 1, item: item), ImportRecord(id: 2, item: item)])
        let plan = try ImportPlanner.prepare(document, existing: [login()])
        #expect(plan.items.first?.name == "Login (2)")
        #expect(plan.report.rows[1].disposition == .duplicate)
        var a = login(), b = login("Renamed", website: "https://new.test")
        a.metadata = ItemMetadata(source: .init(provider: "test", container: "v", item: "i")); b.metadata = a.metadata
        #expect(try ImportPlanner.prepare(.init(format: .auto, records: [.init(id: 1, item: b)]), existing: [a]).report.rows[0].disposition == .conflict)
    }
    @Test func selectionAndArchivedMatching() throws {
        var item = login(); item.metadata = ItemMetadata(archived: true)
        let document = ImportDocument(format: .auto, records: [.init(id: 1, item: item)])
        #expect(try ImportPlanner.prepare(document, existing: [item]).report.rows[0].disposition == .ready)
        #expect(try ImportPlanner.prepare(document, existing: [], selected: []).report.rows[0].disposition == .excluded)
        #expect(throws: ImportFailure.invalidSelection) { try ImportPlanner.prepare(document, existing: [], selected: [2]) }
    }
    @Test func archivedItemsNeverParticipateInMatching() throws {
        var active = login()
        active.metadata = .init(source: .init(provider: "1password", container: "vault", item: "id"))
        var archived = active
        archived.metadata?.archived = true
        let incomingActive = ImportDocument(format: .onePasswordArchive, records: [.init(id: 1, item: active)])
        let plan = try ImportPlanner.prepare(incomingActive, existing: [archived])
        #expect(plan.report.ready == 1)
        #expect(plan.items.first?.name == "Login (2)")
        let incomingArchived = ImportDocument(format: .onePasswordArchive, records: [.init(id: 1, item: archived)])
        #expect(try ImportPlanner.prepare(incomingArchived, existing: [active]).report.ready == 1)
        for items in [[archived, active], [active, archived], [archived, archived]] {
            let document = ImportDocument(format: .onePasswordArchive, records: items.enumerated().map { .init(id: $0.offset + 1, item: $0.element) })
            #expect(try ImportPlanner.prepare(document, existing: []).report.ready == 2)
        }
    }
    @Test func olderItemsDecodeWithoutMetadata() throws {
        let item = try JSONDecoder().decode(VaultItem.self, from: Data(#"{"name":"old","type":"password","fields":[{"path":"password","type":"password"}]}"#.utf8))
        #expect(item.metadata == nil && !item.isArchived && !item.isFavorite)
        #expect(!item.requiresExtendedModel)
    }
}

extension ImportPlannerTests {
    @Test func distinctExportIdentitiesPreserveGenericTitlesAndIdenticalCredentials() throws {
        var records: [ImportRecord] = []
        for index in 1...4 {
            var item = login("Terminal", password: index == 4 ? "changed-private-value" : "private-value")
            item.metadata = .init(source: .init(provider: "1password", container: "vault", item: "id-\(index)"))
            records.append(.init(id: index, item: item))
        }
        let document = ImportDocument(format: .onePasswordArchive, records: records)
        let first = try ImportPlanner.prepare(document, existing: [])
        #expect(first.report.rows.allSatisfy { $0.disposition == .ready })
        #expect(first.items.map(\.name) == ["Terminal", "Terminal (2)", "Terminal (3)", "Terminal (4)"])
        let second = try ImportPlanner.prepare(document, existing: first.items)
        #expect(second.report.rows.allSatisfy { $0.disposition == .duplicate })
        #expect(second.report.rows[1].warnings.joined().contains("existing item \"Terminal (2)\""))
        #expect(second.report.rows[1].warnings.joined().contains("same source item identity"))
        let repeated = try ImportPlanner.prepare(.init(format: .onePasswordArchive, records: [records[0], .init(id: 5, item: records[0].item)]), existing: [])
        #expect(repeated.report.rows[1].disposition == .duplicate)
        #expect(repeated.report.rows[1].warnings.joined().contains("earlier import row 1"))
        #expect(!repeated.report.rows[1].warnings.joined().contains("private-value"))
    }

    @Test func emptyTemplateFieldsDoNotTurnDuplicatesIntoConflicts() throws {
        var existing = login()
        existing.fields.append(ItemField(path: "notes", type: .notes, value: ""))
        let report = try ImportPlanner.prepare(.init(format: .auto, records: [.init(id: 1, item: login())]), existing: [existing]).report
        #expect(report.rows[0].disposition == .duplicate)
    }
}

extension ImportPlannerTests {
    @Test func invalidFieldReportsItsNameWithoutItsValue() throws {
        var item = login("Hotmail Test Account")
        item.fields.append(ItemField(path: "bad%00field", type: .concealed, value: "private-value"))
        let plan = try ImportPlanner.prepare(.init(format: .auto, records: [.init(id: 1, item: item)]), existing: [])
        #expect(plan.report.rows[0].disposition == .invalid)
        #expect(plan.report.rows[0].warnings == ["Invalid field name or encoded path: \"bad\\0field\"."])
        #expect(!String(decoding: try JSONEncoder().encode(plan.report), as: UTF8.self).contains("private-value"))
    }
}

extension ImportPlannerTests {
    @Test func conflictsDescribeIdentityAndChangesWithoutSecretValues() throws {
        var existing = login("Stored item", password: "old-private-value")
        existing.fields.append(.init(path: "legacy-address", type: .concealed, value: "old-private-address"))
        existing.metadata = .init(tags: ["private-tag"], favorite: true)
        var incoming = login("Incoming", password: "new-private-value")
        incoming.fields.append(.init(path: "address", type: .address, value: #"{"street":"new-private-address"}"#))
        incoming.fields[0].type = .concealed
        incoming.metadata = .init(tags: [], source: .init(provider: "test", container: "private-container", item: "private-id"))
        existing.metadata?.source = incoming.metadata?.source
        let row = try ImportPlanner.prepare(.init(format: .auto, records: [.init(id: 1, item: incoming)]), existing: [existing]).report.rows[0]
        let warnings = row.warnings.joined(separator: " ")
        #expect(row.disposition == .conflict)
        #expect(warnings.contains("existing item \"Stored item\"") && warnings.contains("same source item identity"))
        #expect(warnings.contains("field \"password\" content changed"))
        #expect(warnings.contains("field \"username\" type Username → Concealed"))
        #expect(warnings.contains("fields only in source: \"address\"") && warnings.contains("fields only in matching item: \"legacy-address\""))
        #expect(warnings.contains("favorite status") && warnings.contains("tags"))
        #expect(!warnings.contains("private-"))
    }
    @Test func sameFileConflictReportsEarlierRowAndRenamedDestination() throws {
        let first = login("Login", website: "https://other.test")
        let second = login("Another title", website: "https://other.test", password: "new-secret")
        let plan = try ImportPlanner.prepare(.init(format: .auto, records: [.init(id: 7, item: first), .init(id: 12, item: second)]), existing: [login()])
        #expect(plan.items.first?.name == "Login (2)")
        #expect(plan.report.rows[1].disposition == .conflict)
        #expect(plan.report.rows[1].warnings[0].contains("earlier import row 7, item \"Login (2)\""))
        #expect(plan.report.rows[1].warnings[0].contains("same website and username"))
        #expect(!plan.report.rows[1].warnings.joined().contains("new-secret"))
    }
    @Test func titleMatchAndMultipleCandidatesExplainEveryConflictingItem() throws {
        let a = VaultItem(name: "Note", type: .secureNote, fields: [.init(path: "note", value: "a")])
        let b = VaultItem(name: "Note", type: .secureNote, fields: [.init(path: "note", value: "b")])
        let row = try ImportPlanner.prepare(.init(format: .auto, records: [.init(id: 1, item: b)]), existing: [a]).report.rows[0]
        #expect(row.warnings[0].contains("same item type and title"))
        let plan = try ImportPlanner.prepare(.init(format: .auto, records: [.init(id: 1, item: login())]), existing: [login("Exact"), login("Other", password: "changed")])
        #expect(plan.report.rows[0].disposition == .conflict)
        #expect(plan.report.rows[0].warnings[0].contains("Other"))
        #expect(!plan.report.rows[0].warnings[0].contains("Exact"))
    }
}
