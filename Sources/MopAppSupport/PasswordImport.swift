import Foundation
import CoreFoundation
import MopCore
import ZIPFoundation

public enum PasswordImport {
    public static let maximumBytes = 64 * 1024 * 1024
    public static func read(_ source: URL, format: ImportFormat = .auto) throws -> ImportDocument {
        let access = source.startAccessingSecurityScopedResource()
        defer { if access { source.stopAccessingSecurityScopedResource() } }
        var result: Result<ImportDocument, Error>?
        var coordinationError: NSError?
        NSFileCoordinator().coordinate(readingItemAt: source, options: [], error: &coordinationError) { url in
            result = Result {
                let handle = try FileHandle(forReadingFrom: url)
                defer { try? handle.close() }
                var bytes = try handle.read(upToCount: maximumBytes + 1) ?? Data()
                defer { SecretBytes.wipe(&bytes) }
                return try parse(bytes, format: format)
            }
        }
        if coordinationError != nil { throw MopError.inputOutput }
        guard let result else { throw MopError.inputOutput }
        return try result.get()
    }
    public static func parse(_ bytes: Data, format requested: ImportFormat = .auto) throws -> ImportDocument {
        guard bytes.count <= maximumBytes else { throw ImportFailure.tooLarge }
        do {
            var format = requested
            if format == .auto {
                if bytes.starts(with: [0x50, 0x4b]) { format = .onePasswordArchive }
                else if let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any], object["items"] != nil { format = .bitwardenJSON }
            }
            if format == .onePasswordArchive { return try archive(bytes) }
            if format == .bitwardenJSON { return try bitwarden(bytes) }
            return try csv(bytes, format: format)
        } catch let failure as ImportFailure { throw failure }
        catch is CancellationError { throw CancellationError() }
        catch { throw ImportFailure.invalidDocument }
    }
    static func text(_ value: Any?) -> String {
        if let value = value as? String { return value }
        if let value = value as? NSNumber { return value.stringValue }
        return ""
    }
    static func encoded(_ value: Any) -> String {
        if JSONSerialization.isValidJSONObject(value), let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), let result = String(data: data, encoding: .utf8) { return result }
        return text(value)
    }
    static func flag(_ value: Any?) -> Bool { ["1", "true", "yes"].contains(text(value).lowercased()) }
    static func finish(_ item: VaultItem, id: Int, warnings: [String] = []) -> ImportRecord {
        var item = item, warnings = warnings
        item.name = item.name.precomposedStringWithCanonicalMapping
        if item.name.isEmpty { item.name = item.fields.first(where: { $0.type == .website && !($0.value ?? "").isEmpty })?.value ?? "Imported item \(id)" }
        for index in item.fields.indices where item.fields[index].type == .otp {
            if (try? TimeBasedOTP(item.fields[index].value ?? "")) == nil {
                item.fields[index].type = .concealed
                warnings.append("Field \(quoted(item.fields[index].label ?? item.fields[index].path)): invalid or unsupported TOTP configuration; retained as concealed text. Code generation is unavailable.")
            }
        }
        let retained = item.fields.filter { $0.path.hasPrefix("source-") }.map { field in
            let value = field.value ?? ""
            let structure = (try? JSONSerialization.jsonObject(with: Data(value.utf8))).map { shape($0) } ?? "text"
            return quoted(field.label ?? field.path.removingPercentEncoding ?? field.path) + " (" + structure + ")"
        }
        if !retained.isEmpty {
            warnings.append("Source fields kept as hidden reference data: " + retained.joined(separator: ", ") + ". 2ndPass does not interpret these fields.")
        }
        if item.fields.isEmpty { return ImportRecord(id: id, item: item, warnings: warnings + ["No importable fields or attachments remain in this item."]) }
        return ImportRecord(id: id, item: item, warnings: warnings)
    }
    static func add(_ path: String, _ type: FieldType, _ value: Any?, to item: inout VaultItem, label: String? = nil, allowEmpty: Bool = false) {
        let value = text(value)
        guard allowEmpty || !value.isEmpty else { return }
        // Browser-saved login fields can have neither a name nor a designation.
        // Keep their values under a valid, collision-safe path.
        let base = SecretReference.encode((path.isEmpty ? "unnamed-field" : path).precomposedStringWithCanonicalMapping)
        if item.fields.contains(where: { $0.path == base && $0.type == type && $0.value == value }) { return }
        var name = base, suffix = 2
        while item.fields.contains(where: { $0.path == name }) { name = "\(base)-\(suffix)"; suffix += 1 }
        var field = ItemField(path: name, type: type, value: value)
        field.label = label?.isEmpty == false ? label : nil; item.fields.append(field)
    }
    static func preserve(_ values: [String: Any], excluding keys: Set<String>, to item: inout VaultItem) {
        for key in values.keys.sorted() where !keys.contains(key) {
            guard let value = values[key], !(value is NSNull) else { continue }
            add("source-" + key, .concealed, encoded(value), to: &item, label: key)
        }
    }

    static func quoted(_ text: String) -> String { (text.count > 160 ? String(text.prefix(160)) + "…" : text).debugDescription }
    /// Describe structure only: property names, types and counts, never scalar values.
    static func categoryDescription(_ id: String) -> String {
        let name = ["100": "Software License", "101": "Bank Account", "103": "Driver License", "104": "Outdoor License", "105": "Membership", "106": "Passport", "107": "Rewards Program", "108": "Social Security Number", "109": "Wireless Router", "110": "Server", "111": "Email Account", "113": "Medical Record"][id] ?? "Unknown category"
        return name + " (" + quoted(id.isEmpty ? "missing categoryUuid" : id) + ")"
    }
    static func shape(_ value: Any, depth: Int = 0) -> String {
        if let object = value as? [String: Any] {
            if depth >= 2 { return "object (\(object.count) properties)" }
            let keys = object.keys.sorted()
            return "object {" + keys.prefix(12).map { quoted($0) + ": " + shape(object[$0]!, depth: depth + 1) }.joined(separator: ", ") + (keys.count > 12 ? ", …" : "") + "}"
        }
        if let array = value as? [Any] { return "array (\(array.count) entries)" }
        if value is NSNull { return "null" }
        if value is String { return "text" }
        if value is NSNumber { return "number/boolean" }
        return "unknown value"
    }

    static func importAttachment(_ raw: Any, label: String, archive: Archive, paths: Set<String>, contents: inout [String: Data], total: inout Int, item: inout VaultItem, warnings: inout [String]) throws {
        var info = raw as? [String: Any] ?? [:]
        if let nested = info["documentAttributes"] as? [String: Any] ?? info["fileReference"] as? [String: Any] ?? info["attrs"] as? [String: Any] { info = nested }
        let id = text(info["documentId"] ?? info["documentID"] ?? (raw as? String))
        let exportedName = text(info["fileName"] ?? info["name"])
        let display = quoted(exportedName.isEmpty ? (label.isEmpty ? "unnamed" : label) : exportedName)
        guard !id.isEmpty, !id.contains("/"), !id.contains("\\") else {
            warnings.append("Attachment \(display) skipped: no valid documentId in \(shape(raw))."); return
        }
        // Exporters use both the documented triple underscore and a double
        // underscore separator. Match the complete ID, never filename alone.
        let prefixes = ["files/" + id + "___", "files/" + id + "__"]
        let matches = paths.filter { path in
            prefixes.contains { path.hasPrefix($0) && !path.dropFirst($0.count).contains("/") }
        }.sorted()
        let exact = prefixes.map { $0 + exportedName }.filter { matches.contains($0) }
        let path = exact.count == 1 ? exact[0] : exact.isEmpty && matches.count == 1 ? matches[0] : nil
        guard let path, let entry = archive[path], entry.type == .file else {
            warnings.append("Attachment \(display) skipped: \(matches.isEmpty ? "2ndPass could not locate an archive file matching its documentId (checked double- and triple-underscore filenames)" : "multiple archive files match its documentId")."); return
        }
        guard entry.uncompressedSize <= Attachment.maximumBytes else {
            warnings.append("Attachment \(display) skipped: \(entry.uncompressedSize) bytes exceeds the 8 MiB attachment limit."); return
        }
        var data: Data
        if let cached = contents[path] { data = cached }
        else {
            data = Data()
            let crc = try archive.extract(entry, consumer: { chunk in
                try Task.checkCancellation()
                guard total <= maximumBytes - chunk.count, data.count <= Attachment.maximumBytes - chunk.count else { throw ImportFailure.tooLarge }
                total += chunk.count; data.append(chunk)
            })
            guard crc == entry.checksum else { throw ImportFailure.invalidDocument }
            contents[path] = data
        }
        defer { SecretBytes.wipe(&data) }
        if let expected = info["decryptedSize"] as? NSNumber, expected.int64Value != Int64(data.count) {
            warnings.append("Attachment \(display) skipped: metadata says \(expected.int64Value) bytes; archive contains \(data.count) bytes."); return
        }
        let prefix = prefixes.first(where: { path.hasPrefix($0) })!
        let sourceName = exportedName.isEmpty ? String(path.dropFirst(prefix.count)) : exportedName
        let name = sourceName.split(whereSeparator: { $0 == "/" || $0 == "\\" }).last.map(String.init) ?? "attachment"
        do {
            let attachment = try Attachment(fileName: name, data: data)
            add("attachment-" + name, .attachment, try attachment.encodedValue(), to: &item, label: label.isEmpty ? name : label)
        } catch {
            warnings.append("Attachment \(display) skipped: \((error as? AttachmentFailure)?.errorDescription ?? "invalid file").")
        }
    }

    static func csvRows(_ bytes: Data) throws -> [[String]] {
        guard var string = String(data: bytes, encoding: .utf8) else { throw ImportFailure.invalidDocument }
        if string.first == "\u{feff}" { string.removeFirst() }
        let input = Array(string.utf8)
        var rows: [[String]] = [], row: [String] = [], field: [UInt8] = []
        var quoted = false, closed = false, index = 0
        func decoded() -> String { String(decoding: field, as: UTF8.self) }
        while index < input.count {
            let c = input[index]
            if quoted {
                if c == 34 {
                    if index + 1 < input.count && input[index + 1] == 34 { field.append(34); index += 1 }
                    else { quoted = false; closed = true }
                } else { field.append(c) }
            } else if c == 34 {
                guard field.isEmpty && !closed else { throw ImportFailure.invalidDocument }; quoted = true
            } else if c == 44 {
                row.append(decoded()); field.removeAll(keepingCapacity: true); closed = false
            } else if c == 10 || c == 13 {
                row.append(decoded()); field.removeAll(keepingCapacity: true); closed = false
                if row.contains(where: { !$0.isEmpty }) { rows.append(row) }
                row.removeAll(keepingCapacity: true)
                if c == 13 && index + 1 < input.count && input[index + 1] == 10 { index += 1 }
                if rows.count > 10_001 { throw ImportFailure.tooLarge }
            } else {
                guard !closed else { throw ImportFailure.invalidDocument }; field.append(c)
            }
            index += 1
        }
        guard !quoted else { throw ImportFailure.invalidDocument }
        if !row.isEmpty || !field.isEmpty || closed { row.append(decoded()); rows.append(row) }
        guard rows.count <= 10_001 else { throw ImportFailure.tooLarge }
        return rows
    }
    static func csv(_ bytes: Data, format requested: ImportFormat) throws -> ImportDocument {
        let rows = try csvRows(bytes)
        guard let first = rows.first else { throw ImportFailure.invalidDocument }
        let headers = first.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        guard Set(headers).count == headers.count, !headers.contains("") else { throw ImportFailure.invalidDocument }
        let keys = Set(headers)
        var format = requested
        if format == .auto {
            if keys.contains("login_uri") { format = .bitwardenCSV }
            else if keys.contains("grouping") && keys.contains("extra") { format = .lastPassCSV }
            else if keys.contains("title") && keys.contains("website") { format = .onePasswordCSV }
            else if keys.contains("title") && keys.contains("url") { format = .appleCSV }
            else if keys.isSuperset(of: ["url", "username", "password"]) { format = .chromeCSV }
            else { throw ImportFailure.unsupportedFormat }
        }
        let required: Set<String>
        switch format {
        case .bitwardenCSV: required = ["type", "name", "login_uri", "login_username", "login_password"]
        case .onePasswordCSV: required = ["title", "website", "username", "password"]
        case .lastPassCSV: required = ["url", "username", "password", "extra", "name"]
        case .appleCSV: required = ["title", "url", "username", "password"]
        case .chromeCSV: required = ["url", "username", "password"]
        default: throw ImportFailure.unsupportedFormat
        }
        guard keys.isSuperset(of: required) else { throw ImportFailure.unsupportedFormat }
        let records = try rows.dropFirst().enumerated().map { offset, row -> ImportRecord in
            try Task.checkCancellation()
            let id = offset + 1
            guard row.count == headers.count else { return ImportRecord(id: id, item: nil, warnings: ["CSV row has \(row.count) columns; the header defines \(headers.count). Row skipped."]) }
            let values = Dictionary(uniqueKeysWithValues: zip(headers, row))
            let bitwarden = format == .bitwardenCSV
            let url = values[bitwarden ? "login_uri" : format == .onePasswordCSV ? "website" : "url"] ?? ""
            let username = values[bitwarden ? "login_username" : "username"] ?? ""
            let password = values[bitwarden ? "login_password" : "password"] ?? ""
            let note = values[format == .lastPassCSV ? "extra" : "notes"] ?? ""
            var type: ItemType = url.isEmpty && username.isEmpty ? .password : .login
            if (bitwarden && values["type"] == "note") || (format == .lastPassCSV && url == "http://sn") { type = .secureNote }
            if bitwarden && !["login", "note"].contains(values["type"] ?? "") { type = .custom }
            var item = VaultItem(name: values["title"] ?? values["name"] ?? "", type: type, fields: [])
            add("username", .username, username, to: &item); add("password", .password, password, to: &item)
            if type != .secureNote { add("website", .website, url, to: &item) }
            add(type == .secureNote ? "note" : "notes", type == .secureNote ? .concealed : .notes, note, to: &item)
            add("otp", .otp, values["otpauth"] ?? values["one-time password"] ?? values["login_totp"], to: &item)
            let tags = [values["folder"], values["grouping"]].compactMap { $0 }.filter { !$0.isEmpty } + (values["tags"] ?? "").split(separator: ",").map(String.init)
            item.metadata = ItemMetadata(tags: tags, favorite: flag(values["favorite"] ?? values["favorite status"] ?? values["fav"]), archived: flag(values["archived"] ?? values["archived status"]))
            let known: Set<String> = ["title", "name", "url", "website", "username", "password", "notes", "extra", "otpauth", "one-time password", "login_uri", "login_username", "login_password", "login_totp", "type", "folder", "grouping", "tags", "favorite", "favorite status", "fav", "archived", "archived status", "passwordhistory"]
            preserve(values, excluding: known, to: &item)
            var warnings: [String] = []
            if type == .custom { warnings.append("Source category \(quoted(values["type"] ?? "missing")) has no 2ndPass template; imported as Custom with \(item.fields.count) fields.") }
            return finish(item, id: id, warnings: warnings)
        }
        return ImportDocument(format: format, records: records)
    }
    static func bitwarden(_ bytes: Data) throws -> ImportDocument {
        guard let root = try JSONSerialization.jsonObject(with: bytes) as? [String: Any], !flag(root["encrypted"]),
              let entries = root["items"] as? [Any], entries.count <= 10_000 else { throw ImportFailure.invalidDocument }
        var folders: [String: String] = [:]
        for folder in (root["folders"] as? [[String: Any]] ?? []) + (root["collections"] as? [[String: Any]] ?? []) {
            folders[text(folder["id"])] = text(folder["name"])
        }
        let records = try entries.enumerated().map { offset, raw -> ImportRecord in
            try Task.checkCancellation()
            guard let entry = raw as? [String: Any] else { return ImportRecord(id: offset + 1, item: nil, warnings: ["Expected an item object; found a non-object value. Record skipped."]) }
            let type: ItemType
            switch text(entry["type"]) {
            case "1": type = .login
            case "2": type = .secureNote
            case "3": type = .paymentCard
            case "4": type = .identity
            case "5": type = .sshKey
            default: type = .custom
            }
            var item = VaultItem(name: text(entry["name"]), type: type, fields: [])
            var warnings: [String] = []
            var tags = ([text(entry["folderId"])] + (entry["collectionIds"] as? [String] ?? [])).compactMap { folders[$0] }
            tags = Array(Set(tags)).sorted()
            let id = text(entry["id"]), container = text(entry["organizationId"])
            item.metadata = ItemMetadata(tags: tags, favorite: flag(entry["favorite"]), archived: flag(entry["archived"]) || (entry["archivedDate"] != nil && !(entry["archivedDate"] is NSNull)),
                source: id.isEmpty ? nil : ImportSourceIdentity(provider: "bitwarden", container: container.isEmpty ? "personal" : container, item: id))
            item.metadata?.createdAt = importedDate(entry["creationDate"])
            item.metadata?.updatedAt = importedDate(entry["revisionDate"])
            add(type == .secureNote ? "note" : "notes", type == .secureNote ? .concealed : .notes, entry["notes"], to: &item)
            if let login = entry["login"] as? [String: Any] {
                add("username", .username, login["username"], to: &item)
                add("password", .password, login["password"], to: &item)
                add("otp", .otp, login["totp"], to: &item)
                for uri in login["uris"] as? [[String: Any]] ?? [] { add("website", .website, uri["uri"], to: &item) }
                if let passkeys = login["fido2Credentials"] as? [Any], !passkeys.isEmpty { warnings.append("Bitwarden login.fido2Credentials contains \(passkeys.count) passkey(s); none imported. Re-enroll these credentials before removing the source item.") }
                preserve(login, excluding: ["username", "password", "totp", "uris", "fido2Credentials"], to: &item)
            }
            if let card = entry["card"] as? [String: Any] {
                for (key, path, fieldType) in [("cardholderName", "cardholder", FieldType.text), ("number", "number", .cardNumber), ("brand", "brand", .text), ("code", "securityCode", .concealed)] {
                    add(path, fieldType, card[key], to: &item)
                }
                let month = text(card["expMonth"]), year = text(card["expYear"])
                if !month.isEmpty || !year.isEmpty { add("expiration", .expirationMonthYear, month + "/" + year, to: &item) }
                preserve(card, excluding: ["cardholderName", "number", "brand", "code", "expMonth", "expYear"], to: &item)
            }
            if let identity = entry["identity"] as? [String: Any] {
                let addressKeys = ["address1": "street", "address2": "street2", "address3": "street3", "city": "city", "state": "state", "postalCode": "zip", "country": "country"]
                var address: [String: Any] = [:]
                for key in identity.keys.sorted() {
                    if let destination = addressKeys[key] {
                        if let value = identity[key], !(value is NSNull) { address[destination] = value }
                    } else {
                        let kind: FieldType = ["ssn", "passportNumber", "licenseNumber"].contains(key) ? .concealed : key == "email" ? .email : key == "phone" ? .phone : key == "username" ? .username : .text
                        add(key, kind, identity[key], to: &item)
                    }
                }
                if address.values.contains(where: { !text($0).isEmpty }) { add("address", .address, encoded(address), to: &item, label: "Address") }
            }
            if let account = entry["bankAccount"] as? [String: Any] {
                let aliases = ["nameOnAccount": "owner", "accountNumber": "accountNo", "routingNumber": "routingNo", "swiftCode": "swift", "pin": "telephonePin", "bankContactPhone": "branchPhone"]
                var bank: [String: Any] = [:]
                for key in account.keys.sorted() {
                    // If both spellings occur, retain both instead of allowing
                    // an alias to overwrite the explicitly named component.
                    let destination = aliases[key].flatMap { account[$0] == nil ? $0 : nil } ?? key
                    bank[destination] = account[key]
                }
                if !bank.isEmpty { add("bank-account", .bankAccount, encoded(bank), to: &item, label: "Bank account") }
            }
            if let ssh = entry["sshKey"] as? [String: Any] {
                add("privateKey", .privateKey, ssh["privateKey"], to: &item)
                add("publicKey", .text, ssh["publicKey"], to: &item)
                add("fingerprint", .text, ssh["fingerprint"], to: &item)
                preserve(ssh, excluding: ["privateKey", "publicKey", "fingerprint"], to: &item)
            }
            for field in entry["fields"] as? [[String: Any]] ?? [] {
                let label = text(field["name"])
                let kind: FieldType = label.lowercased().contains("recovery code") || label.lowercased().contains("backup code") ? .recoveryCodes : .concealed
                add(label.isEmpty ? "custom" : label, kind, field["value"], to: &item, label: label)
                if field["linkedId"] != nil { warnings.append("Custom field \(quoted(label.isEmpty ? "unnamed" : label)) has a Bitwarden linkedId; its current value is retained, but it will not follow changes to the linked field.") }
            }
            for rawAttachment in entry["attachments"] as? [Any] ?? [] {
                let info = rawAttachment as? [String: Any] ?? [:]
                warnings.append("Attachment \(quoted(text(info["fileName"]).isEmpty ? "unnamed" : text(info["fileName"]))) is listed in Bitwarden JSON, but the export contains no file bytes. Add the original file separately.")
            }
            if flag(entry["reprompt"]) { warnings.append("Bitwarden reprompt is enabled for this item. 2ndPass uses its own unlock policy; it cannot request the source master password.") }
            if entry["deletedDate"] != nil && !(entry["deletedDate"] is NSNull) {
                return ImportRecord(id: offset + 1, item: nil, warnings: ["Bitwarden deletedDate is set; this item is in the source trash and was skipped."])
            }
            preserve(entry, excluding: ["id", "organizationId", "folderId", "collectionIds", "type", "name", "notes", "favorite", "archived", "archivedDate", "login", "card", "identity", "bankAccount", "sshKey", "secureNote", "fields", "attachments", "reprompt", "deletedDate", "revisionDate", "creationDate", "passwordHistory"], to: &item)
            if type == .custom { warnings.append("Bitwarden item type \(quoted(text(entry["type"]))) has no 2ndPass template; imported as Custom with \(item.fields.count) fields.") }
            return finish(item, id: offset + 1, warnings: warnings)
        }
        return ImportDocument(format: .bitwardenJSON, records: records)
    }
    private static func zipEntryCount(_ data: Data) throws -> Int {
        guard data.count >= 22 else { throw ImportFailure.invalidDocument }
        func number(_ offset: Int, _ length: Int) -> UInt64 {
            guard offset >= 0, offset + length <= data.count else { return UInt64.max }
            return (0..<length).reduce(0) { $0 | (UInt64(data[offset + $1]) << (8 * $1)) }
        }
        for index in stride(from: data.count - 22, through: max(0, data.count - 65_557), by: -1) {
            guard number(index, 4) == 0x06054b50, number(index + 20, 2) == UInt64(data.count - index - 22) else { continue }
            guard number(index + 4, 2) == 0, number(index + 6, 2) == 0 else { throw ImportFailure.invalidDocument }
            let count = number(index + 10, 2)
            if count != 65_535 {
                guard number(index + 8, 2) == count else { throw ImportFailure.invalidDocument }
                return Int(count)
            }
            // ZIP64 locator and EOCD are bounded by the already bounded input buffer.
            guard index >= 20, number(index - 20, 4) == 0x07064b50, number(index - 16, 4) == 0,
                  number(index - 4, 4) == 1 else { throw ImportFailure.invalidDocument }
            let offset = number(index - 12, 8)
            guard offset <= UInt64(data.count - 56) else { throw ImportFailure.invalidDocument }
            let start = Int(offset)
            guard number(start, 4) == 0x06064b50, number(start + 16, 4) == 0, number(start + 20, 4) == 0,
                  number(start + 24, 8) == number(start + 32, 8), number(start + 32, 8) <= UInt64(data.count / 46) else { throw ImportFailure.invalidDocument }
            return Int(number(start + 32, 8))
        }
        throw ImportFailure.invalidDocument
    }

    static func archive(_ bytes: Data) throws -> ImportDocument {
        let expectedEntries = try zipEntryCount(bytes)
        let archive = try Archive(data: bytes, accessMode: .read)
        var paths = Set<String>(), contents: [String: Data] = [:], total = 0
        defer { for key in contents.keys { let count = contents[key]?.count ?? 0; contents[key]?.resetBytes(in: 0..<count) } }
        for entry in archive {
            try Task.checkCancellation()
            guard paths.insert(entry.path).inserted, !entry.path.hasPrefix("/"), !entry.path.contains("\\"),
                  !entry.path.split(separator: "/").contains(".."), entry.type != .symlink else { throw ImportFailure.invalidDocument }
            guard ["export.attributes", "export.data"].contains(entry.path) else { continue }
            guard entry.type == .file, entry.uncompressedSize <= maximumBytes else { throw ImportFailure.tooLarge }
            var data = Data()
            let crc = try archive.extract(entry, consumer: { chunk in
                try Task.checkCancellation()
                guard total <= maximumBytes - chunk.count else { throw ImportFailure.tooLarge }
                total += chunk.count; data.append(chunk)
            })
            guard crc == entry.checksum else { throw ImportFailure.invalidDocument }
            contents[entry.path] = data
        }
        guard paths.count == expectedEntries else { throw ImportFailure.invalidDocument }
        guard let attributes = contents["export.attributes"], let root = contents["export.data"],
              let info = try JSONSerialization.jsonObject(with: attributes) as? [String: Any], text(info["version"]) == "3",
              let object = try JSONSerialization.jsonObject(with: root) as? [String: Any],
              let accounts = object["accounts"] as? [[String: Any]] else { throw ImportFailure.invalidDocument }
        var records: [ImportRecord] = []
        for account in accounts {
            let accountInfo = account["attrs"] as? [String: Any] ?? [:]
            guard let vaults = account["vaults"] as? [[String: Any]] else { throw ImportFailure.invalidDocument }
            for vault in vaults {
                let attrs = vault["attrs"] as? [String: Any] ?? [:]
                guard let items = vault["items"] as? [Any] else { throw ImportFailure.invalidDocument }
                for raw in items {
                    try Task.checkCancellation()
                    guard records.count < 10_000 else { throw ImportFailure.tooLarge }
                    guard let source = raw as? [String: Any] else { records.append(.init(id: records.count + 1, item: nil, warnings: ["Expected an item object; found a non-object value. Record skipped."])); continue }
                    let overview = source["overview"] as? [String: Any] ?? [:], details = source["details"] as? [String: Any] ?? [:]
                    let type: ItemType
                    switch text(source["categoryUuid"]) {
                    case "001": type = .login
                    case "002": type = .paymentCard
                    case "003": type = .secureNote
                    case "004": type = .identity
                    case "005": type = .password
                    case "006": type = .document
                    case "102": type = .database
                    case "114": type = .sshKey
                    case "112": type = .apiCredential
                    default: type = .custom
                    }
                    var item = VaultItem(name: text(overview["title"]), type: type, fields: [])
                    var warnings: [String] = []
                    var tags = overview["tags"] as? [String] ?? []
                    let vaultName = text(attrs["name"]); if !vaultName.isEmpty { tags.append(vaultName) }
                    let sourceID = text(source["uuid"])
                    item.metadata = ItemMetadata(tags: Array(Set(tags)).sorted(), favorite: (source["favIndex"] as? Int ?? 0) > 0,
                        archived: flag(source["state"]) || text(source["state"]) == "archived",
                        source: sourceID.isEmpty ? nil : ImportSourceIdentity(provider: "1password", container: text(accountInfo["uuid"]) + ":" + text(attrs["uuid"]), item: sourceID))
                    item.metadata?.createdAt = importedDate(source["createdAt"])
                    item.metadata?.updatedAt = importedDate(source["updatedAt"])
                    add(type == .secureNote ? "note" : "notes", type == .secureNote ? .concealed : .notes, details["notesPlain"], to: &item)
                    add("password", .password, details["password"], to: &item)
                    var urls = overview["urls"] as? [[String: Any]] ?? []
                    let primary = text(overview["url"])
                    if !primary.isEmpty && !urls.contains(where: { text($0["url"]) == primary }) { urls.insert(["url": primary], at: 0) }
                    for url in urls { add("website", .website, url["url"], to: &item) }
                    for field in details["loginFields"] as? [[String: Any]] ?? [] {
                        let designation = text(field["designation"])
                        let kind: FieldType = designation == "username" ? .username : designation == "password" ? .password : .concealed
                        add(designation.isEmpty ? text(field["name"]) : designation, kind, field["value"], to: &item)
                    }
                    let bankKeys = Set(CompoundField.components(for: .bankAccount).map(\.key))
                    for section in details["sections"] as? [[String: Any]] ?? [] {
                        var bank: [String: Any] = [:]
                        for field in section["fields"] as? [[String: Any]] ?? [] {
                            let label = text(field["title"]), fieldID = text(field["id"])
                            guard let value = field["value"] as? [String: Any] else { continue }
                            if let file = value["fileReference"] ?? value["file"] {
                                try importAttachment(file, label: label, archive: archive, paths: paths, contents: &contents, total: &total, item: &item, warnings: &warnings)
                                continue
                            }
                            if value["passkey"] != nil { warnings.append("Field \(quoted(label.isEmpty ? fieldID : label)) (source type passkey) was skipped; 2ndPass cannot import passkeys. Re-enroll it before removing the source item."); continue }
                            if let ssh = value["sshKey"] as? [String: Any] {
                                let metadata = ssh["metadata"] as? [String: Any] ?? [:]
                                add("privateKey", .privateKey, metadata["privateKey"] ?? ssh["privateKey"], to: &item)
                                add("publicKey", .text, metadata["publicKey"] ?? ssh["publicKey"], to: &item)
                                add("fingerprint", .text, metadata["fingerprint"] ?? ssh["fingerprint"], to: &item)
                                continue
                            }
                            if let address = value["address"] as? [String: Any] {
                                add(fieldID.isEmpty ? "address" : fieldID, .address, encoded(address), to: &item, label: label.isEmpty ? "Address" : label)
                                continue
                            }
                            if let account = value["bankAccount"] as? [String: Any] {
                                add(fieldID.isEmpty ? "bank-account" : fieldID, .bankAccount, encoded(account), to: &item, label: label.isEmpty ? "Bank account" : label)
                                continue
                            }
                            if text(source["categoryUuid"]) == "101", bankKeys.contains(fieldID), bank[fieldID] == nil,
                               value.count == 1, let single = value.values.first, single is String || single is NSNumber {
                                bank[fieldID] = text(single)
                                continue
                            }
                            if let email = value["email"] as? [String: Any] {
                                add("email", flag(field["guarded"]) ? .concealed : .email, email["email_address"], to: &item, label: label)
                                preserve(email, excluding: ["email_address"], to: &item)
                                continue
                            }
                            let mapped: (String, FieldType)? = [
                                "ccnum": ("number", .cardNumber), "cvv": ("securityCode", .concealed), "cardholder": ("cardholder", .text),
                                "expiry": ("expiration", .expirationMonthYear), "type": ("brand", .text), "pin": ("pin", .concealed),
                                "firstname": ("firstName", .text), "lastname": ("lastName", .text), "initial": ("middleName", .text),
                                "company": ("company", .text), "email": ("email", .email), "phone": ("phone", .phone), "defphone": ("phone", .phone),
                                "birthdate": ("birthDate", .date), "credential": ("token", .concealed), "hostname": ("endpoint", .website),
                                "server": ("server", .text), "database": ("database", .text), "username": ("username", .username), "password": ("password", .password)
                            ][fieldID]
                            let kind: FieldType = value["monthYear"] != nil ? .expirationMonthYear : value["date"] != nil ? .date : value["totp"] != nil ? .otp : label.lowercased().contains("recovery code") || label.lowercased().contains("backup code") ? .recoveryCodes : mapped?.1 ?? .concealed
                            let path = kind == .otp ? "otp" : mapped?.0 ?? (label.isEmpty ? (fieldID.isEmpty ? "custom" : fieldID) : label)
                            var content: String
                            var structured = false
                            let emptyDate = value.count == 1 && (value["monthYear"] is NSNull || value["date"] is NSNull)
                            if emptyDate { content = "" }
                            else if value.count == 1, let single = value.values.first, single is String || single is NSNumber { content = text(single) }
                            else { content = encoded(value); structured = true; warnings.append("Field \(quoted(label.isEmpty ? path : label)) (id \(quoted(fieldID)), section \(quoted(text(section["title"])))) contains \(shape(value)); retained as concealed JSON instead of editable subfields.") }
                            if value["monthYear"] != nil, content.count == 6, content.allSatisfy(\.isNumber) {
                                content = String(content.suffix(2)) + "/" + String(content.prefix(4))
                            }
                            if let timestamp = value["date"] as? NSNumber {
                                let seconds = timestamp.doubleValue
                                if seconds.isFinite && abs(seconds) < 253_402_300_800 {
                                    let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withFullDate]; formatter.timeZone = TimeZone(secondsFromGMT: 0)
                                    content = formatter.string(from: Date(timeIntervalSince1970: seconds))
                                }
                            }
                            add(path, structured || (flag(field["guarded"]) && !kind.concealed) ? .concealed : kind, content, to: &item, label: label.isEmpty ? nil : label, allowEmpty: emptyDate)
                        }
                        if !bank.isEmpty {
                            let title = text(section["title"])
                            add("bank-account", .bankAccount, encoded(bank), to: &item, label: title.isEmpty ? "Bank account" : title)
                        }
                    }
                    if let file = details["documentAttributes"] {
                        try importAttachment(file, label: "", archive: archive, paths: paths, contents: &contents, total: &total, item: &item, warnings: &warnings)
                    }
                    if let file = source["file"] {
                        try importAttachment(file, label: "", archive: archive, paths: paths, contents: &contents, total: &total, item: &item, warnings: &warnings)
                    }
                    for file in details["files"] as? [Any] ?? [] {
                        try importAttachment(file, label: "", archive: archive, paths: paths, contents: &contents, total: &total, item: &item, warnings: &warnings)
                    }
                    preserve(details, excluding: ["notesPlain", "password", "loginFields", "sections", "documentAttributes", "files", "passwordHistory", "htmlForm"], to: &item)
                    if type == .custom { warnings.append("1Password \(categoryDescription(text(source["categoryUuid"]))) has no 2ndPass template; imported as Custom with \(item.fields.count) fields. Source section titles: \((details["sections"] as? [[String: Any]] ?? []).map { quoted(text($0["title"])) }.joined(separator: ", ")).") }
                    records.append(finish(item, id: records.count + 1, warnings: warnings))
                }
            }
        }
        return ImportDocument(format: .onePasswordArchive, records: records)
    }
}


// Unknown or malformed historical dates remain unknown rather than becoming the import date.
private func importedDate(_ value: Any?) -> Date? {
    if let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() {
        let seconds = number.doubleValue
        return seconds.isFinite && seconds >= 0 ? Date(timeIntervalSince1970: seconds) : nil
    }
    guard let text = value as? String else { return nil }
    let parser = ISO8601DateFormatter()
    parser.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let date = parser.date(from: text) { return date }
    parser.formatOptions = [.withInternetDateTime]
    return parser.date(from: text)
}
