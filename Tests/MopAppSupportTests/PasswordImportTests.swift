import Foundation
import Testing
import ZIPFoundation
import MopCore
@testable import MopAppSupport

@Suite struct PasswordImportTests {
    @Test func allCSVAdaptersAndExactSecrets() throws {
        let fixtures: [(ImportFormat, String)] = [
            (.appleCSV, "Title,URL,Username,Password,Notes,OTPAuth\r\nExample,https://example.test,alice, secret ,note,\r\n"),
            (.chromeCSV, "name,url,username,password\nExample,https://example.test,alice, secret \n"),
            (.onePasswordCSV, "Title,Website,Username,Password,Notes,Favorite Status,Archived Status,Tags\nExample,https://example.test,alice, secret ,note,true,true,work\n"),
            (.bitwardenCSV, "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nwork,1,login,Example,note,,0,https://example.test,alice, secret ,\n"),
            (.lastPassCSV, "url,username,password,extra,name,grouping,fav\nhttps://example.test,alice, secret ,note,Example,work,1\n")
        ]
        for (format, csv) in fixtures {
            let document = try PasswordImport.parse(Data(csv.utf8))
            #expect(document.format == format)
            let item = try #require(document.records.first?.item)
            #expect(item.type == .login)
            #expect(item.fields.first { $0.type == .password }?.value == " secret ")
        }
    }
    @Test func CSVQuotingBOMAndInvalidRecords() throws {
        let csv = "\u{feff}Title,URL,Username,Password,Notes\r\n\"A, B\",https://example.test,a,\"x\"\"y\",\"line1\nline2\"\r\nbad,row\r\n"
        let records = try PasswordImport.parse(Data(csv.utf8)).records
        #expect(records.count == 2)
        #expect(records[0].item?.name == "A, B")
        #expect(records[0].item?.fields.first { $0.type == .password }?.value == "x\"y")
        #expect(records[0].item?.fields.first { $0.type == .notes }?.value == "line1\nline2")
        #expect(records[1].item == nil)
        #expect(throws: ImportFailure.invalidDocument) { try PasswordImport.parse(Data("Title,URL,Username,Password\n\"unfinished".utf8)) }
        #expect(throws: ImportFailure.invalidDocument) { try PasswordImport.parse(Data("url,url,username,password\n".utf8)) }
    }
    @Test func OTPAndRecoveryDataRemainConcealedWhenUnsupported() throws {
        let csv = "Title,URL,Username,Password,OTPAuth\nA,https://example.test,u,p,otpauth://totp?secret=JBSWY3DPEHPK3PXP\nB,https://other.test,u,p,otpauth://hotp?secret=JBSWY3DPEHPK3PXP\n"
        let document = try PasswordImport.parse(Data(csv.utf8))
        #expect(document.records[0].item?.fields.last?.type == .otp)
        #expect(document.records[1].item?.fields.last?.type == .concealed)
        #expect(!document.records[1].warnings.isEmpty)
    }
    @Test func bitwardenRichTypesAndWarnings() throws {
        let json = #"{"encrypted":false,"folders":[{"id":"f","name":"Work"}],"items":[{"id":"a","folderId":"f","type":1,"name":"Login","favorite":true,"archivedDate":"2026-01-01","login":{"username":"u","password":"p","uris":[{"uri":"https://a.test"},{"uri":"https://b.test"}],"fido2Credentials":[{"keyValue":"not-imported"}]},"fields":[{"name":"Recovery codes","value":"a\nb"}],"attachments":[{"id":"x"}]},{"id":"b","type":3,"name":"Card","card":{"number":"4111111111111111","code":"123","expMonth":"01","expYear":"2030"}},{"id":"c","type":4,"name":"Identity","identity":{"firstName":"A","ssn":"secret"}},{"id":"d","type":5,"name":"SSH","sshKey":{"privateKey":"private","publicKey":"public","fingerprint":"hash"}}]}"#
        let records = try PasswordImport.parse(Data(json.utf8)).records
        #expect(records.map { $0.item?.type } == [.login, .paymentCard, .identity, .sshKey])
        let login = try #require(records[0].item)
        #expect(login.isArchived && login.isFavorite)
        #expect(login.metadata?.tags == ["Work"])
        #expect(login.fields.filter { $0.type == .website }.count == 2)
        #expect(login.fields.contains { $0.type == .recoveryCodes })
        #expect(records[0].warnings.count == 2)
        #expect(!login.fields.contains { $0.value?.contains("not-imported") == true })
        #expect(records[1].item?.fields.first { $0.path == "number" }?.type == .cardNumber)
        #expect(records[2].item?.fields.first { $0.path == "ssn" }?.type.concealed == true)
        #expect(records[3].item?.fields.first { $0.path == "privateKey" }?.type == .privateKey)
    }
    private func archive(_ entries: [(String, String)]) throws -> Data {
        let archive = try Archive(accessMode: .create)
        for (path, string) in entries {
            let data = Data(string.utf8)
            try archive.addEntry(with: path, type: .file, uncompressedSize: Int64(data.count), provider: { position, size in
                data.subdata(in: Int(position)..<(Int(position) + size))
            })
        }
        return try #require(archive.data)
    }
    @Test func onePasswordArchiveAndTraversalRejection() throws {
        let root = #"{"accounts":[{"attrs":{"uuid":"account"},"vaults":[{"attrs":{"uuid":"vault","name":"Work"},"items":[{"uuid":"item","categoryUuid":"114","favIndex":1,"state":"archived","overview":{"title":"SSH","tags":["dev"]},"details":{"sections":[{"fields":[{"title":"Key","value":{"sshKey":{"metadata":{"privateKey":"private","publicKey":"public"}}}}]}],"documentAttributes":{"fileName":"attachment"}}}]}]}]}"#
        let entries = [("export.attributes", "{\"version\":3}"), ("export.data", root)]
        let document = try PasswordImport.parse(archive(entries))
        let item = try #require(document.records.first?.item)
        #expect(item.type == .sshKey && item.isArchived && item.isFavorite)
        #expect(item.metadata?.source?.container == "account:vault")
        #expect(item.fields.first { $0.type == .privateKey }?.value == "private")
        #expect(document.records[0].warnings.count == 1)
        #expect(document.records[0].warnings[0].contains("Attachment \"attachment\" skipped: no valid documentId"))
        #expect(throws: ImportFailure.invalidDocument) { try PasswordImport.parse(archive(entries + [("../bad", "ignored")])) }
        #expect(throws: ImportFailure.invalidDocument) { try PasswordImport.parse(archive(entries + [("export.data", root)])) }
    }
    @Test func boundsAndMalformedJSON() throws {
        #expect(throws: ImportFailure.tooLarge) { try PasswordImport.parse(Data(repeating: 0, count: PasswordImport.maximumBytes + 1)) }
        #expect(throws: ImportFailure.invalidDocument) { try PasswordImport.parse(Data(#"{"encrypted":true,"items":[]}"#.utf8), format: .bitwardenJSON) }
        #expect(throws: ImportFailure.tooLarge) { try PasswordImport.parse(Data(("url,username,password\n" + String(repeating: "https://a.test,u,p\n", count: 10_001)).utf8)) }
    }
}

extension PasswordImportTests {
    @Test func dateFieldsUseSourceTypeAndPreserveEmptyValues() throws {
        let root = #"{"accounts":[{"vaults":[{"items":[{"categoryUuid":"004","overview":{"title":"Identity"},"details":{"sections":[{"fields":[{"id":"validFrom","title":"valid from","value":{"date":null}},{"id":"expires","title":"expires","value":{"date":null}},{"id":"issued","title":"issued","value":{"date":1704067200}}]}]}}]}]}]}"#
        let records = try PasswordImport.parse(archive([("export.attributes", "{\"version\":3}"), ("export.data", root)])).records
        let item = try #require(records.first?.item)
        #expect(item.fields.map(\.type) == [.date, .date, .date])
        #expect(item.fields.map(\.value) == ["", "", "2024-01-01"])
        #expect(item.fields.map(\.label) == ["valid from", "expires", "issued"])
        #expect(records[0].warnings.isEmpty)
        #expect(try ImportPlanner.prepare(.init(format: .onePasswordArchive, records: records), existing: []).report.ready == 1)
    }

    @Test func monthYearFieldsUseSourceTypeAndPreserveEmptyValues() throws {
        let root = #"{"accounts":[{"vaults":[{"items":[{"categoryUuid":"002","overview":{"title":"Card"},"details":{"sections":[{"fields":[{"id":"validFrom","title":"valid from","value":{"monthYear":null}},{"id":"customDate","title":"issued","value":{"monthYear":202403}},{"id":"expiry","value":{"monthYear":203001}}]}]}}]}]}]}"#
        let records = try PasswordImport.parse(archive([("export.attributes", "{\"version\":3}"), ("export.data", root)])).records
        let item = try #require(records.first?.item)
        #expect(item.fields.map(\.type) == [.expirationMonthYear, .expirationMonthYear, .expirationMonthYear])
        #expect(item.fields.map(\.value) == ["", "03/2024", "01/2030"])
        #expect(item.fields.first?.label == "valid from")
        #expect(records[0].warnings.isEmpty)
        #expect(try ImportPlanner.prepare(.init(format: .onePasswordArchive, records: records), existing: []).report.ready == 1)
    }

    @Test func richArchiveCategoriesDatesAndAddresses() throws {
        let root = #"{"accounts":[{"attrs":{"uuid":"a"},"vaults":[{"attrs":{"uuid":"v"},"items":[{"uuid":"card","categoryUuid":"002","overview":{"title":"Card"},"details":{"sections":[{"fields":[{"id":"ccnum","value":{"creditCardNumber":"4111111111111111"}},{"id":"expiry","value":{"monthYear":203001}}]}]}},{"uuid":"identity","categoryUuid":"004","overview":{"title":"Identity"},"details":{"sections":[{"fields":[{"id":"address","value":{"address":{"street":"Road","city":"Town","zip":"12345"}}},{"id":"email","value":{"email":{"email_address":"a@example.test"}}}]}]}},{"uuid":"db","categoryUuid":"102","overview":{"title":"DB"},"details":{"notesPlain":"db"}},{"uuid":"api","categoryUuid":"112","overview":{"title":"API"},"details":{"notesPlain":"api"}}]}]}]}"#
        let data = try archive([("export.attributes", "{\"version\":3}"), ("export.data", root)])
        let records = try PasswordImport.parse(data).records
        #expect(records.map { $0.item?.type } == [.paymentCard, .identity, .database, .apiCredential])
        #expect(records[0].item?.fields.first { $0.path == "expiration" }?.value == "01/2030")
        let address = try #require(records[1].item?.fields.first { $0.type == .address }?.value)
        #expect(try CompoundField(address).text(for: "street") == "Road")
        #expect(records[1].item?.fields.first { $0.type == .email }?.value == "a@example.test")
    }
    @Test func encryptedTrailingArchiveEntryCannotBeSilentlyIgnored() throws {
        var bytes = try archive([("export.attributes", "{\"version\":3}"), ("export.data", "{\"accounts\":[]}"), ("files/ignored", "attachment")])
        let signature: [UInt8] = [0x50, 0x4b, 0x01, 0x02]
        let positions = (0..<(bytes.count - 4)).filter { Array(bytes[$0..<($0 + 4)]) == signature }
        let last = try #require(positions.last)
        bytes[last + 8] |= 1 // Central-directory encryption flag: ZIPFoundation stops iterating here.
        #expect(throws: ImportFailure.invalidDocument) { try PasswordImport.parse(bytes) }
    }
    @Test func invalidJSONRecordDoesNotDiscardValidNeighbors() throws {
        let document = try PasswordImport.parse(Data(#"{"items":[null,{"type":2,"name":"Note","notes":"secret"}]}"#.utf8))
        #expect(document.records[0].item == nil)
        #expect(document.records[1].item?.type == .secureNote)
    }
}

extension PasswordImportTests {
    @Test func passwordBeginningWithBraceRetainsPasswordType() throws {
        let root = #"{"accounts":[{"attrs":{"uuid":"a"},"vaults":[{"attrs":{"uuid":"v"},"items":[{"uuid":"i","categoryUuid":"001","overview":{"title":"Login"},"details":{"sections":[{"fields":[{"id":"password","value":{"concealed":"{secret}"}}]}]}}]}]}]}"#
        let data = try archive([("export.attributes", "{\"version\":3}"), ("export.data", root)])
        let field = try #require(PasswordImport.parse(data).records.first?.item?.fields.first)
        #expect(field.type == .password && field.value == "{secret}")
    }
}

extension PasswordImportTests {
    @Test func spacedTitlesAndUnicodeSourceFieldsAreImportable() throws {
        let csv = "Title,URL,Username,Password,Security Question,Cafe\u{301}\nHotmail Test Account,https://example.test,user,secret-password,secret-answer,secret-extra\n"
        let document = try PasswordImport.parse(Data(csv.utf8))
        let plan = try ImportPlanner.prepare(document, existing: [])
        #expect(plan.report.rows[0].disposition == .ready)
        #expect(plan.items[0].name == "Hotmail Test Account")
        #expect(plan.items[0].fields.contains { $0.path == "source-caf%C3%A9" && $0.value == "secret-extra" })
        let warnings = plan.report.rows[0].warnings
        #expect(warnings.count == 1)
        #expect(warnings[0].contains("security question"))
        #expect(warnings[0].contains("cafe\u{301}"))
        let report = String(decoding: try JSONEncoder().encode(plan.report), as: UTF8.self)
        #expect(!report.contains("secret-password"))
        #expect(!report.contains("secret-answer"))
        #expect(!report.contains("secret-extra"))
    }
}


extension PasswordImportTests {
    @Test func passwordHistoryIsIgnored() throws {
        let root = #"{"accounts":[{"vaults":[{"items":[{"categoryUuid":"001","overview":{"title":"Login"},"details":{"password":"current-password","passwordHistory":[{"value":"old-password","time":1}]}}]}]}]}"#
        let archiveDocument = try PasswordImport.parse(archive([("export.attributes", "{\"version\":3}"), ("export.data", root)]))
        let json = #"{"items":[{"type":1,"name":"Login","login":{"password":"current-password"},"passwordHistory":[{"password":"old-password"}]}]}"#
        let csv = "Title,URL,Username,Password,passwordHistory\nLogin,https://example.test,user,current-password,old-password\n"
        for document in [archiveDocument, try PasswordImport.parse(Data(json.utf8)), try PasswordImport.parse(Data(csv.utf8))] {
            let record = try #require(document.records.first)
            let item = try #require(record.item)
            #expect(item.fields.contains { $0.type == .password && $0.value == "current-password" })
            #expect(!item.fields.contains { $0.path.lowercased().contains("passwordhistory") || $0.value?.contains("old-password") == true })
            #expect(record.warnings.isEmpty)
        }
    }
}

extension PasswordImportTests {
    @Test func htmlFormIsIgnoredWhileLoginFieldsAreImported() throws {
        let root = #"{"accounts":[{"vaults":[{"items":[{"categoryUuid":"001","overview":{"title":"Login"},"details":{"loginFields":[{"designation":"username","value":"user"},{"designation":"password","value":"current-password"}],"htmlForm":{"htmlMethod":"POST","htmlAction":"https://example.test/submit","htmlId":"login-form","htmlName":"signin"}}}]}]}]}"#
        let document = try PasswordImport.parse(archive([("export.attributes", "{\"version\":3}"), ("export.data", root)]))
        let record = try #require(document.records.first)
        let item = try #require(record.item)
        #expect(item.fields.count == 2)
        #expect(item.fields.contains { $0.type == .username && $0.value == "user" })
        #expect(item.fields.contains { $0.type == .password && $0.value == "current-password" })
        #expect(record.warnings.isEmpty)
    }
}

extension PasswordImportTests {
    @Test func unnamedLoginFieldsHaveUniqueValidPaths() throws {
        let root = #"{"accounts":[{"vaults":[{"items":[{"categoryUuid":"001","overview":{"title":"Hotmail Test Account"},"details":{"loginFields":[{"designation":"username","value":"user"},{"designation":"password","value":"current-password"},{"name":"unnamed-field","value":"named-value"},{"name":"","designation":"","value":"empty-name-value"},{"value":"missing-name-value"},{"name":"","value":""}]}}]}]}]}"#
        let document = try PasswordImport.parse(archive([("export.attributes", "{\"version\":3}"), ("export.data", root)]))
        let plan = try ImportPlanner.prepare(document, existing: [])
        #expect(plan.report.rows[0].disposition == .ready)
        let item = try #require(plan.items.first)
        #expect(item.fields.count == 5)
        #expect(item.fields.contains { $0.path == "unnamed-field" && $0.value == "named-value" })
        #expect(item.fields.contains { $0.path == "unnamed-field-2" && $0.type == .concealed && $0.value == "empty-name-value" })
        #expect(item.fields.contains { $0.path == "unnamed-field-3" && $0.type == .concealed && $0.value == "missing-name-value" })
        #expect(plan.report.rows[0].warnings.isEmpty)
    }
}

extension PasswordImportTests {
    private func binaryArchive(_ entries: [(String, Data)]) throws -> Data {
        let archive = try Archive(accessMode: .create)
        for (path, data) in entries {
            try archive.addEntry(with: path, type: .file, uncompressedSize: Int64(data.count)) { position, size in
                data.subdata(in: Int(position)..<(Int(position) + size))
            }
        }
        return try #require(archive.data)
    }
    @Test(arguments: ["__", "___"], ["fileReference", "file"]) func attachmentImportPreservesBinaryFilesAndDocumentItems(separator: String, sourceType: String) throws {
        let root = #"{"accounts":[{"vaults":[{"items":[{"categoryUuid":"001","overview":{"title":"Login"},"details":{"sections":[{"fields":[{"title":"Proof","value":{"fileReference":{"documentId":"a","fileName":"proof.bin","decryptedSize":4}}},{"title":"Other proof","value":{"fileReference":{"documentId":"b","fileName":"proof.bin","decryptedSize":0}}}]}]}},{"categoryUuid":"006","overview":{"title":"Document"},"details":{"documentAttributes":{"documentId":"a","fileName":"proof.bin","decryptedSize":4}}}]}]}]}"#
        let source = root.replacingOccurrences(of: "\"fileReference\":", with: "\"\(sourceType)\":")
        let payload = Data([0, 0xff, 0x80, 0x42])
        let bytes = try binaryArchive([("export.attributes", Data("{\"version\":3}".utf8)), ("export.data", Data(source.utf8)), ("files/a\(separator)proof.bin", payload), ("files/b\(separator)proof.bin", Data())])
        let document = try PasswordImport.parse(bytes)
        let plan = try ImportPlanner.prepare(document, existing: [])
        #expect(plan.report.ready == 2)
        #expect(plan.report.rows.allSatisfy { $0.warnings.isEmpty })
        #expect(plan.items[0].fields.map(\.path) == ["attachment-proof.bin", "attachment-proof.bin-2"])
        #expect(try Attachment.decode(plan.items[0].fields[0].value!).data == payload)
        #expect(try Attachment.decode(plan.items[0].fields[1].value!).data.isEmpty)
        #expect(plan.items[1].type == .document)
        #expect(try Attachment.decode(plan.items[1].fields[0].value!).data == payload)
    }
    @Test func missingAndOversizedAttachmentsHaveActionableWarnings() throws {
        let root = #"{"accounts":[{"vaults":[{"items":[{"categoryUuid":"001","overview":{"title":"Login"},"details":{"password":"private-password","files":[{"documentId":"missing","fileName":"lost.pdf"},{"documentId":"large","fileName":"big.bin"},{"documentId":"wrong","fileName":"wrong.txt","decryptedSize":20}]}}]}]}]}"#
        let bytes = try binaryArchive([("export.attributes", Data("{\"version\":3}".utf8)), ("export.data", Data(root.utf8)), ("files/large___big.bin", Data(repeating: 0, count: Attachment.maximumBytes + 1)), ("files/wrong___wrong.txt", Data([1, 2]))])
        let document = try PasswordImport.parse(bytes)
        let warnings = document.records[0].warnings.joined(separator: " ")
        #expect(warnings.contains("lost.pdf") && warnings.contains("Mop could not locate an archive file matching its documentId"))
        #expect(warnings.contains("big.bin") && warnings.contains("8388609 bytes"))
        #expect(warnings.contains("wrong.txt") && warnings.contains("metadata says 20 bytes; archive contains 2 bytes"))
        #expect(!warnings.contains("private-password"))
        #expect(document.records[0].item?.fields.count == 1)
    }
    @Test func warningsIdentifyStructureCategoryAndConcealGuardedFields() throws {
        let root = #"{"accounts":[{"vaults":[{"items":[{"categoryUuid":"106","overview":{"title":"Passport"},"details":{"sections":[{"title":"Travel","fields":[{"title":"Issued by","id":"issuer","value":{"customLocation":{"city":"private-city","lines":["private-street"]}}},{"title":"Account","id":"username","guarded":true,"value":{"string":"private-username"}}]}]}}]}]}]}"#
        let document = try PasswordImport.parse(archive([("export.attributes", "{\"version\":3}"), ("export.data", root)]))
        let record = document.records[0], warnings = document.records[0].warnings.joined(separator: " ")
        #expect(warnings.contains("Issued by") && warnings.contains("issuer") && warnings.contains("Travel"))
        #expect(warnings.contains("customLocation") && warnings.contains("city") && warnings.contains("array (1 entries)"))
        #expect(warnings.contains("Passport (\"106\")"))
        #expect(!warnings.contains("private-city") && !warnings.contains("private-street") && !warnings.contains("private-username"))
        #expect(!warnings.contains("re-prompt"))
        #expect(record.item?.fields.first { $0.path == "username" }?.type == .concealed)
    }
}

extension PasswordImportTests {
    @Test func bankAccountsAndMultipleAddressesPreserveSourceComponents() throws {
        let fields: [[String: Any]] = [
            ["id": "bankName", "value": ["string": "Test bank"]],
            ["id": "owner", "value": ["string": "Test owner"]],
            ["id": "accountNo", "value": ["string": "0000123"]],
            ["id": "routingNo", "value": ["string": "001122"]],
            ["id": "iban", "value": ["string": "DE00 0000"]],
            ["id": "accountNo", "title": "Second number", "value": ["string": "00234"]],
            ["id": "branchAddress", "value": ["address": ["street": "Street", "city": "Town", "zip": "00123", "extra": ["code": "kept"]]]],
            ["id": "postalAddress", "value": ["address": ["street": "Other street", "zip": "00045"]]]
        ]
        let object: [String: Any] = ["accounts": [["vaults": [["items": [["categoryUuid": "101", "overview": ["title": "Bank"], "details": ["sections": [["title": "Account", "fields": fields]]]]]]]]]]
        let data = try JSONSerialization.data(withJSONObject: object)
        let document = try PasswordImport.parse(binaryArchive([("export.attributes", Data("{\"version\":3}".utf8)), ("export.data", data)]))
        let item = try #require(document.records[0].item)
        let bank = try CompoundField(#require(item.fields.first { $0.type == .bankAccount }?.value))
        #expect(bank.text(for: "accountNo") == "0000123" && bank.text(for: "routingNo") == "001122")
        #expect(bank.text(for: "iban") == "DE00 0000")
        #expect(item.fields.contains { $0.value == "00234" })
        let addresses = item.fields.filter { $0.type == .address }
        #expect(addresses.map(\.path) == ["branchAddress", "postalAddress"])
        let address = try CompoundField(#require(addresses.first?.value))
        #expect(address.text(for: "zip") == "00123" && address.valueDescription(for: "extra").contains("kept"))
        #expect(!document.records[0].warnings.contains { $0.contains("Structured field") || $0.contains("concealed JSON") })
        #expect(try ImportPlanner.prepare(document, existing: []).report.ready == 1)
    }
    @Test func bitwardenAddressAndBankAccountAliasesArePreserved() throws {
        let json = #"{"items":[{"type":4,"name":"Person","identity":{"firstName":"Test","address1":"Street","address2":"Unit 1","address3":"Floor 2","postalCode":"00123","city":"Town"}},{"type":99,"name":"Bank","bankAccount":{"nameOnAccount":"Test","owner":"Alternate owner","accountNumber":"0000123","routingNumber":"001122","swiftCode":"BIC","custom":{"extra":"kept"}}}]}"#
        let document = try PasswordImport.parse(Data(json.utf8))
        let address = try CompoundField(#require(document.records[0].item?.fields.first { $0.type == .address }?.value))
        #expect(address.text(for: "street2") == "Unit 1" && address.text(for: "street3") == "Floor 2")
        #expect(address.text(for: "zip") == "00123")
        let bank = try CompoundField(#require(document.records[1].item?.fields.first { $0.type == .bankAccount }?.value))
        #expect(bank.text(for: "accountNo") == "0000123" && bank.text(for: "routingNo") == "001122")
        #expect(bank.text(for: "swift") == "BIC" && bank.valueDescription(for: "custom").contains("kept"))
        #expect(bank.text(for: "owner") == "Alternate owner" && bank.text(for: "nameOnAccount") == "Test")
    }
}
