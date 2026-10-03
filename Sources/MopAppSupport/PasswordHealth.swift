import Foundation
import CryptoKit
import MopCore

public protocol BreachChecking: Sendable {
    func contains(_ password: Data, force: Bool) async throws -> Bool
    func clear() async
}
public protocol BreachTransport: Sendable {
    func response(for request: URLRequest) async throws -> (Data, Int)
}
public struct URLBreachTransport: BreachTransport {
    public init() {}
    public func response(for request: URLRequest) async throws -> (Data, Int) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil; configuration.httpCookieStorage = nil
        let session = URLSession(configuration: configuration, delegate: NoBreachRedirects(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (data, response) = try await session.data(for: request)
        return (data, (response as? HTTPURLResponse)?.statusCode ?? 0)
    }
}
private final class NoBreachRedirects: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) { completionHandler(nil) }
}
public enum BreachCheckFailure: Error { case unavailable, malformed }
public actor PwnedPasswordsClient: BreachChecking {
    private let transport: any BreachTransport
    private var cache: [String: (Date, Set<String>)] = [:]
    private var generation = UUID()
    public init(transport: any BreachTransport = URLBreachTransport()) { self.transport = transport }
    public func clear() { generation = UUID(); cache.removeAll() }
    public func contains(_ password: Data, force: Bool = false) async throws -> Bool {
        try Task.checkCancellation()
        let hash = Insecure.SHA1.hash(data: password).map { String(format: "%02X", $0) }.joined()
        let prefix = String(hash.prefix(5)), suffix = String(hash.dropFirst(5))
        if !force, let (date, suffixes) = cache[prefix], Date().timeIntervalSince(date) < 86400 { return suffixes.contains(suffix) }
        let token = generation
        var request = URLRequest(url: URL(string: "https://api.pwnedpasswords.com/range/" + prefix)!)
        request.setValue("true", forHTTPHeaderField: "Add-Padding")
        request.timeoutInterval = 20
        let (data, status) = try await transport.response(for: request)
        try Task.checkCancellation()
        guard token == generation else { throw CancellationError() }
        guard status == 200 else { throw BreachCheckFailure.unavailable }
        let suffixes = try Self.parse(data)
        cache[prefix] = (Date(), suffixes)
        return suffixes.contains(suffix)
    }
    public static func parse(_ data: Data) throws -> Set<String> {
        guard data.count <= 2 * 1024 * 1024, let text = String(data: data, encoding: .utf8), !text.isEmpty else { throw BreachCheckFailure.malformed }
        let lines = text.components(separatedBy: .newlines).filter { !$0.isEmpty }
        // Padded responses contain at least 800 rows; fewer indicates truncation.
        guard lines.count >= 800 else { throw BreachCheckFailure.malformed }
        var suffixes = Set<String>()
        for line in lines {
            let parts = line.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count == 2, parts[0].count == 35,
                  parts[0].utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) }),
                  !parts[1].isEmpty, parts[1].utf8.allSatisfy({ (48...57).contains($0) }),
                  let count = UInt64(parts[1]) else { throw BreachCheckFailure.malformed }
            if count > 0 { suffixes.insert(String(parts[0])) }
        }
        return suffixes
    }
}
public enum PasswordHealthKind: String, CaseIterable, Sendable {
    case exposed = "Exposed Passwords", reused = "Reused Passwords", weak = "Weak Passwords"
}
public struct PasswordHealthFinding: Sendable, Identifiable {
    public let vaultID: String
    public let vaultName: String
    public let item: String
    public let account: String
    public let path: String
    public let archived: Bool
    public var kinds: Set<PasswordHealthKind>
    public var reuseGroup: Int?
    public var breachCheckedAt: Date? = nil
    public var id: String { vaultID + ":" + item + ":" + path }
}
public enum PasswordHealthCheckState: String, Sendable {
    case notChecked, checked, disabled, incomplete, unavailable
}
public struct PasswordHealthReport: Sendable {
    public var state: PasswordHealthCheckState = .notChecked
    public var breachState: PasswordHealthCheckState = .notChecked
    public var findings: [PasswordHealthFinding] = []
    public var checked = 0
    public var total = 0
    public var breachChecked = 0
    public var completedAt: Date?
    public var cachedChecks: [String: [CachedPasswordCheck]] = [:]
    public var usedCloudCache = false
    public init() {}
}
public enum PasswordHealthScanner {
    public static func scan(catalogs: [String: ItemCatalog], service: any VaultService, breach: any BreachChecking,
                            enabled: Bool, force: Bool = false,
                            progress: @MainActor @Sendable (Double) -> Void = { _ in }) async throws -> PasswordHealthReport {
        try await PasswordHealthSession().scan(catalogs: catalogs, service: service, breach: breach,
                                               enabled: enabled, force: force, progress: progress)
    }
}

/// Unlocked-session cache. Stores keyed fingerprints and results, never plaintext passwords.
@MainActor public final class PasswordHealthSession {
    private struct Key: Hashable { let vault: String; let item: String; let path: String }
    private struct Entry {
        var version: String
        var context: [String]
        var fingerprint: Data
        var weak: Bool
        var exposed = false
        var checkedAt: Date?
        var retryAt: Date = .distantPast
        var failures = 0
    }
    private var entries: [Key: Entry] = [:]
    private var sessionKey = SymmetricKey(size: .bits256)
    private var revisions: [String: String] = [:]
    private var previousEnabled: Bool?
    private var nextCheck: Date = .distantPast
    public init() {}
    public var nextRefreshDate: Date { nextCheck }
    public func adoptCacheRevision(vault: String, from: String, to: String) {
        if revisions[vault] == from { revisions[vault] = to }
    }
    public func clear() {
        entries.removeAll(); sessionKey = SymmetricKey(size: .bits256)
        revisions = [:]; previousEnabled = nil; nextCheck = .distantPast
    }
    public func isCurrent(catalogs: [String: ItemCatalog], enabled: Bool, at now: Date = Date()) -> Bool {
        revisions == catalogs.mapValues(\.revision) && previousEnabled == enabled && now < nextCheck
    }
    private typealias Field = (String, ItemCatalog, VaultItem, ItemField)
    private func snapshot(_ catalogs: [String: ItemCatalog]) throws -> (fields: [Field], scope: String) {
        let fields = catalogs.sorted { $0.key < $1.key }.flatMap { vaultID, catalog in
            catalog.items.filter { $0.deletion == nil && !$0.isArchived }.flatMap { item in
                item.fields.filter { $0.type == .password || ($0.path == item.autoFill?.password && [.concealed, .text, .username, .email].contains($0.type)) }
                    .map { (vaultID, catalog, item, $0) }
            }
        }
        // Scope hashes record identities and account context, never password bytes.
        // A different accessible field set invalidates cached cross-vault reuse results.
        let scopeRows = fields.map { vaultID, _, item, field in
            [vaultID, item.storageID ?? item.name, field.path, field.recordVersion ?? "",
             item.name, item.fields.first { [.username, .email].contains($0.type) }?.value ?? ""]
        }
        let scope = SHA256.hash(data: try JSONEncoder().encode(scopeRows)).map { String(format: "%02x", $0) }.joined()
        return (fields, scope)
    }
    private func cached(_ catalog: ItemCatalog, _ item: VaultItem, _ field: ItemField, at now: Date) -> CachedPasswordCheck? {
        guard let record = field.recordVersion else { return nil }
        let context = [item.name, item.fields.first { [.username, .email].contains($0.type) }?.value ?? ""]
        return catalog.security?.passwordChecks?.first {
            $0.record == record && $0.context == context && $0.evaluator == 1 && $0.checkedAt <= now &&
            ($0.breachCheckedAt.map { $0 <= now } ?? true)
        }
    }
    private func canRestore(_ checks: [CachedPasswordCheck], count: Int, scope: String, enabled: Bool, now: Date) -> Bool {
        entries.values.allSatisfy({ $0.failures == 0 }) && count > 0 && checks.count == count &&
        Set(checks.map(\.batch)).count == 1 && checks.allSatisfy {
            $0.scope == scope && now.timeIntervalSince($0.checkedAt) < 86400 &&
            (!enabled || $0.breachCheckedAt.map { now.timeIntervalSince($0) < 86400 } == true)
        }
    }
    public func canRestoreCloudResults(catalogs: [String: ItemCatalog], enabled: Bool, at now: Date = Date()) -> Bool {
        guard let (fields, scope) = try? snapshot(catalogs) else { return false }
        let checks = fields.compactMap { _, catalog, item, field in cached(catalog, item, field, at: now) }
        return canRestore(checks, count: fields.count, scope: scope, enabled: enabled, now: now)
    }
    public func scan(catalogs: [String: ItemCatalog], service: any VaultService, breach: any BreachChecking,
                     enabled: Bool, force: Bool = false, at now: Date = Date(),
                     progress: @MainActor @Sendable (Double) -> Void = { _ in }) async throws -> PasswordHealthReport {
        var report = PasswordHealthReport()
        var groups: [Data: [Int]] = [:]
        var live = Set<Key>()
        var next = Date.distantFuture
        let (fields, scope) = try snapshot(catalogs)
        let cachedFields = fields.compactMap { _, catalog, item, field in cached(catalog, item, field, at: now) }
        if !force, canRestore(cachedFields, count: fields.count, scope: scope, enabled: enabled, now: now) {
            var reuseGroups: [UUID: Int] = [:]
            for (index, (vaultID, catalog, item, field)) in fields.enumerated() {
                let saved = cachedFields[index]
                var finding = PasswordHealthFinding(vaultID: vaultID, vaultName: catalog.vault, item: item.name,
                    account: saved.context[1], path: field.path, archived: false, kinds: [])
                if saved.weak { finding.kinds.insert(.weak) }
                if enabled && saved.exposed { finding.kinds.insert(.exposed) }
                if let group = saved.reuseGroup {
                    if reuseGroups[group] == nil { reuseGroups[group] = reuseGroups.count + 1 }
                    finding.kinds.insert(.reused); finding.reuseGroup = reuseGroups[group]
                }
                finding.breachCheckedAt = saved.breachCheckedAt
                if !finding.kinds.isEmpty { report.findings.append(finding) }
                report.cachedChecks[vaultID, default: []].append(saved)
            }
            report.total = fields.count; report.checked = fields.count
            report.breachChecked = enabled ? fields.count : 0
            report.state = .checked; report.breachState = enabled ? .checked : .disabled
            report.completedAt = cachedFields.map(\.checkedAt).min(); report.usedCloudCache = true
            revisions = catalogs.mapValues(\.revision); previousEnabled = enabled
            nextCheck = cachedFields.map { min($0.checkedAt, enabled ? ($0.breachCheckedAt ?? $0.checkedAt) : $0.checkedAt).addingTimeInterval(86400) }.min() ?? .distantFuture
            progress(1)
            return report
        }
        report.total = fields.count
        progress(0)
        if force { await breach.clear() }
        for (index, (vaultID, catalog, item, field)) in fields.enumerated() {
            try Task.checkCancellation()
            let key = Key(vault: vaultID, item: item.storageID ?? item.name, path: field.path)
            live.insert(key)
            let version = field.recordVersion ?? catalog.revision
            let account = item.fields.first { [.username, .email].contains($0.type) }?.value ?? ""
            let context = [item.name, account]
            var entry = entries[key]
            if entry?.version != version { entry = nil }
            let saved = cached(catalog, item, field, at: now)
            let needsLocal = entry == nil || entry?.context != context
            let due = entry.map { $0.failures > 0 ? $0.retryAt : ($0.checkedAt?.addingTimeInterval(86400) ?? .distantPast) } ?? saved?.breachCheckedAt?.addingTimeInterval(86400) ?? .distantPast
            let needsBreach = enabled && (force || now >= due)
            if needsLocal || needsBreach {
                let reference = try SecretReference(vault: catalog.vault, relativePath: SecretReference.encode(item.name) + "/" + field.path)
                if let value = try? await service.readLocal(reference, vault: vaultID).value {
                    var bytes = Data(value)
                    defer { SecretBytes.wipe(&bytes) }
                    try Task.checkCancellation()
                    if needsLocal {
                        let quality = PasswordEstimator.estimate(String(decoding: bytes, as: UTF8.self), userInputs: context)
                        let fingerprint = Data(HMAC<SHA256>.authenticationCode(for: bytes, using: sessionKey))
                        // Preserve breach evidence when only account context changed.
                        var updated = entry ?? Entry(version: version, context: context, fingerprint: fingerprint, weak: false)
                        updated.context = context; updated.fingerprint = fingerprint
                        updated.weak = quality == .veryWeak || quality == .weak
                        if entry == nil, let saved {
                            updated.exposed = saved.exposed; updated.checkedAt = saved.breachCheckedAt
                        }
                        entry = updated
                    }
                    if needsBreach {
                        do {
                            let exposed = try await breach.contains(bytes, force: false)
                            try Task.checkCancellation()
                            entry?.exposed = exposed; entry?.checkedAt = now
                            entry?.failures = 0; entry?.retryAt = .distantPast
                        } catch is CancellationError { throw CancellationError() }
                        catch {
                            try Task.checkCancellation()
                            entry?.failures += 1
                            let delay = min(3600.0, 60 * pow(2, Double(min(entry?.failures ?? 1, 7) - 1)))
                            entry?.retryAt = now.addingTimeInterval(delay)
                        }
                    }
                } else {
                    try Task.checkCancellation()
                    next = min(next, now.addingTimeInterval(60))
                }
            }
            if let entry {
                entries[key] = entry
                var finding = PasswordHealthFinding(vaultID: vaultID, vaultName: catalog.vault, item: item.name,
                    account: account, path: field.path, archived: item.isArchived, kinds: [])
                finding.breachCheckedAt = entry.checkedAt
                if entry.weak { finding.kinds.insert(.weak) }
                if enabled && entry.exposed { finding.kinds.insert(.exposed) }
                if enabled {
                    let expiry = entry.checkedAt?.addingTimeInterval(86400) ?? .distantPast
                    if now < expiry && entry.failures == 0 { report.breachChecked += 1 }
                    let due = entry.failures > 0 ? entry.retryAt : expiry
                    next = min(next, due > now ? due : now.addingTimeInterval(60))
                }
                groups[entry.fingerprint, default: []].append(report.findings.count)
                report.findings.append(finding); report.checked += 1
            } else { entries.removeValue(forKey: key) }
            progress(Double(index + 1) / Double(max(fields.count, 1)))
        }
        try Task.checkCancellation()
        entries = entries.filter { live.contains($0.key) }
        var group = 0
        for indices in groups.values.sorted(by: { ($0.first ?? 0) < ($1.first ?? 0) }) {
            let items = Set(indices.map { report.findings[$0].vaultID + ":" + report.findings[$0].item })
            guard items.count > 1 else { continue }; group += 1
            for i in indices { report.findings[i].kinds.insert(.reused); report.findings[i].reuseGroup = group }
        }
        var persistedGroups: [Int: UUID] = [:]
        let batch = UUID()
        for finding in report.findings {
            guard let catalog = catalogs[finding.vaultID],
                  let item = catalog.items.first(where: { $0.name == finding.item }),
                  let field = item.fields.first(where: { $0.path == finding.path }), let record = field.recordVersion else { continue }
            let key = Key(vault: finding.vaultID, item: item.storageID ?? item.name, path: field.path)
            guard let entry = entries[key] else { continue }
            if let group = finding.reuseGroup, persistedGroups[group] == nil { persistedGroups[group] = UUID() }
            let check = CachedPasswordCheck(record: record, context: entry.context, weak: entry.weak,
                exposed: entry.exposed, checkedAt: now, breachCheckedAt: entry.checkedAt,
                reuseGroup: finding.reuseGroup.flatMap { persistedGroups[$0] }, scope: scope, batch: batch)
            report.cachedChecks[finding.vaultID, default: []].append(check)
        }
        report.findings.removeAll { $0.kinds.isEmpty }
        report.state = report.checked == report.total ? .checked : .incomplete
        report.breachState = !enabled ? .disabled : report.breachChecked == report.total ? .checked : report.breachChecked == 0 ? .unavailable : .incomplete
        report.completedAt = now
        revisions = catalogs.mapValues(\.revision); previousEnabled = enabled; nextCheck = next
        progress(1)
        return report
    }
}
