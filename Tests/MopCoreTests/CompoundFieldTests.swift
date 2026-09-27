import Foundation
import Testing
@testable import MopCore

@Suite struct CompoundFieldTests {
    @Test func editingPreservesUnknownNestedDataAndLeadingZeros() throws {
        let original = try CompoundField(#"{"accountNo":"000123","routingNo":"001122","unknown":{"list":[true,7,"kept"]},"zip":"00001"}"#)
        let changed = try original.replacing("owner", with: "New owner")
        #expect(changed.text(for: "accountNo") == "000123")
        #expect(changed.text(for: "routingNo") == "001122")
        #expect(changed.valueDescription(for: "unknown") == original.valueDescription(for: "unknown"))
        #expect(changed.displayText(for: .bankAccount).contains("Account number: 000123"))
        #expect(changed.displayText(for: .address).contains("Postal code: 00001"))
        #expect(FieldType.bankAccount.concealed && FieldType.address.concealed)
        for invalid in ["", "[]", "null", "123", "not JSON"] {
            #expect(throws: CompoundFieldFailure.invalid) { try CompoundField(invalid) }
        }
    }
}

extension CompoundFieldTests {
    @Test func invalidCompoundImportNamesTheFieldWithoutPrintingItsContent() throws {
        var field = ItemField(path: "bank", type: .bankAccount, value: "private-invalid-value")
        field.label = "Checking account"
        let document = ImportDocument(format: .auto, records: [.init(id: 1, item: .init(name: "Bank", fields: [field]))])
        let row = try ImportPlanner.prepare(document, existing: []).report.rows[0]
        #expect(row.disposition == .invalid)
        #expect(row.warnings[0].contains("Checking account") && row.warnings[0].contains("Bank account"))
        #expect(!row.warnings[0].contains("private-invalid-value"))
    }
}
