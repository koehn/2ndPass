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

/// Each check has its own validity: strength follows value/context, reuse follows
/// the active credential set, and only breach results expire with elapsed time.
@MainActor public final class PasswordHealthSession {
    private struct Key: Hashable { let vault: String; let item: String; let path: String }
    private struct Entry {
        var version: String
        var fingerprint: Data?
        var strength: CachedStrengthResult?
        var breach: CachedBreachResult?
        var reuse: CachedReuseResult?
        var retryAt: Date = .distantPast
        var failures = 0
    }
    private typealias Field = (String, ItemCatalog, VaultItem, ItemField)
    private var entries: [Key: Entry] = [:]
    private var sessionKey = SymmetricKey(size: .bits256)
    private var revisions: [String: String] = [:]
    private var producedCaches: [String: [CachedPasswordCheck]] = [:]
    private var observedCaches: [String: [CachedPasswordCheck]] = [:]
    private var previousEnabled: Bool?
    private var nextCheck: Date = .distantPast
    private let estimate: (String, [String]) -> PasswordQuality
    public init(estimate: @escaping (String, [String]) -> PasswordQuality = { PasswordEstimator.estimate($0, userInputs: $1) }) {
        self.estimate = estimate
    }
    public var nextRefreshDate: Date { nextCheck }
    public func adoptCacheRevision(vault: String, from: String, to: String, checks: [CachedPasswordCheck] = []) {
        if revisions[vault] == from {
            revisions[vault] = to
            if producedCaches[vault] == checks { observedCaches[vault] = checks }
        }
    }
    public func clear() {
        entries.removeAll(); sessionKey = SymmetricKey(size: .bits256)
        revisions = [:]; observedCaches = [:]; producedCaches = [:]; previousEnabled = nil; nextCheck = .distantPast
    }
    public func isCurrent(catalogs: [String: ItemCatalog], enabled: Bool, at now: Date = Date()) -> Bool {
        revisions == catalogs.mapValues(\.revision) && observedCaches == catalogs.mapValues { $0.security?.passwordChecks ?? [] } && previousEnabled == enabled && now < nextCheck
    }
    private func key(_ field: Field) -> Key {
        Key(vault: field.0, item: field.2.storageID ?? field.2.name, path: field.3.path)
    }
    private func context(_ item: VaultItem) -> [String] {
        [item.name, item.fields.first { [.username, .email].contains($0.type) }?.value ?? ""]
    }
    private func snapshot(_ catalogs: [String: ItemCatalog]) throws -> (fields: [Field], scope: String) {
        let fields = catalogs.sorted { $0.key < $1.key }.flatMap { vaultID, catalog in
            catalog.items.filter { $0.deletion == nil && !$0.isArchived }.sorted { ($0.storageID ?? $0.name) < ($1.storageID ?? $1.name) }.flatMap { item in
                item.fields.filter { $0.type == .password || ($0.path == item.autoFill?.password && [.concealed, .text, .username, .email].contains($0.type)) }
                    .sorted { $0.path < $1.path }.map { (vaultID, catalog, item, $0) }
            }
        }
        // Reuse depends on active secret identities, not account labels or time.
        let rows = fields.map { vault, catalog, item, field in
            [vault, item.storageID ?? item.name, field.historyID?.uuidString ?? field.path, field.recordVersion ?? catalog.revision]
        }
        let scope = SHA256.hash(data: try JSONEncoder().encode(rows)).map { String(format: "%02x", $0) }.joined()
        return (fields, scope)
    }
    private func entry(_ field: Field, now: Date) -> Entry {
        let (_, catalog, item, property) = field
        let version = property.recordVersion ?? catalog.revision
        var result = entries[key(field)].flatMap { $0.version == version ? $0 : nil } ?? Entry(version: version)
        if let record = property.recordVersion,
           let saved = catalog.security?.passwordChecks?.first(where: { $0.record == record }) {
            if let strength = saved.strengthResult, strength.checkedAt <= now, strength.checkedAt.timeIntervalSince1970.isFinite, strength.evaluator == 1,
               strength.context == context(item), result.strength == nil || strength.checkedAt > result.strength!.checkedAt {
                result.strength = strength
            }
            let breach = saved.breachResult
            if let breach, breach.checkedAt <= now, breach.checkedAt.timeIntervalSince1970.isFinite,
               result.breach == nil || breach.checkedAt > result.breach!.checkedAt {
                result.breach = breach; result.failures = 0; result.retryAt = .distantPast
            }
            if let reuse = saved.reuseResult, reuse.checkedAt <= now, reuse.checkedAt.timeIntervalSince1970.isFinite,
               result.reuse == nil || reuse.checkedAt > result.reuse!.checkedAt { result.reuse = reuse }
        }
        if result.strength?.context != context(item) || result.strength?.evaluator != 1 { result.strength = nil }
        return result
    }
    private func validReuse(_ values: [Entry], scope: String) -> Bool {
        values.allSatisfy { $0.reuse?.scope == scope } && Set(values.compactMap { $0.reuse?.batch }).count <= 1
    }
    public func canRestoreCloudResults(catalogs: [String: ItemCatalog], enabled: Bool, at now: Date = Date()) -> Bool {
        guard let (fields, scope) = try? snapshot(catalogs) else { return false }
        let values = fields.map { entry($0, now: now) }
        return validReuse(values, scope: scope) && values.allSatisfy {
            $0.strength != nil && (!enabled || ($0.failures == 0 && $0.breach.map { now.timeIntervalSince($0.checkedAt) < 86400 } == true))
        }
    }
    public func scan(catalogs: [String: ItemCatalog], service: any VaultService, breach: any BreachChecking,
                     enabled: Bool, force: Bool = false, at now: Date = Date(), eagerLocalResults: Bool = false,
                     progress: @MainActor @Sendable (Double) -> Void = { _ in },
                     beforeWork: @MainActor @Sendable () async throws -> Void = {},
                     batch: @MainActor @Sendable (PasswordHealthReport) async throws -> Void = { _ in }) async throws -> PasswordHealthReport {
        let (fields, scope) = try snapshot(catalogs)
        var values = fields.map { entry($0, now: now) }
        let rebuildReuse = !validReuse(values, scope: scope)
        var next = Date.distantFuture
        var didWork = false
        var lastBatchCount = 0
        var lastBatchTime = ContinuousClock.now
        let evidenceBatch = UUID()
        progress(0)
        // Start a daily refresh with fresh ranges; fields sharing a prefix can
        // still share the response within this scan.
        let expiredBreach = enabled && values.contains { value in
            value.breach.map { now.timeIntervalSince($0.checkedAt) >= 86400 } == true &&
                (value.failures == 0 || now >= value.retryAt)
        }
        if force || expiredBreach { await breach.clear() }
        // Saved replacements get local feedback before unchanged or daily work.
        let order = fields.indices.sorted { left, right in
            let leftNeedsStrength = values[left].strength == nil
            let rightNeedsStrength = values[right].strength == nil
            return leftNeedsStrength != rightNeedsStrength ? leftNeedsStrength : left < right
        }
        for (position, i) in order.enumerated() {
            try Task.checkCancellation()
            let (vaultID, catalog, item, field) = fields[i]
            var value = values[i]
            let needsStrength = value.strength == nil
            let needsFingerprint = rebuildReuse && value.fingerprint == nil
            let due = value.failures > 0 ? value.retryAt : value.breach?.checkedAt.addingTimeInterval(86400) ?? .distantPast
            let needsBreach = enabled && (force || now >= due)
            if needsStrength || needsFingerprint || needsBreach {
                await Task.yield()
                try await beforeWork()
                try Task.checkCancellation()
                didWork = true
                let reference = try SecretReference(vault: catalog.vault, relativePath: SecretReference.encode(item.name) + "/" + field.path)
                if let secret = try? await service.readLocal(reference, vault: vaultID).value {
                    var bytes = Data(secret)
                    defer { SecretBytes.wipe(&bytes) }
                    try Task.checkCancellation()
                    if needsStrength {
                        let inputs = context(item), quality = estimate(String(decoding: bytes, as: UTF8.self), inputs)
                        value.strength = CachedStrengthResult(weak: quality == .weak || quality == .veryWeak, checkedAt: now, context: inputs, quality: quality)
                    }
                    if needsFingerprint { value.fingerprint = Data(HMAC<SHA256>.authenticationCode(for: bytes, using: sessionKey)) }
                    if eagerLocalResults && needsStrength {
                        // A slow or unavailable HIBP request must not retain the
                        // previous password's weak warning after local evaluation.
                        values[i] = value; entries[key(fields[i])] = value
                        var localValues = values
                        if rebuildReuse { for index in localValues.indices { localValues[index].reuse = nil } }
                        var ignoredNext = Date.distantFuture
                        var local = makeReport(catalogs: catalogs, fields: fields, values: localValues, scope: scope,
                            enabled: enabled, now: now, didWork: true, evidenceBatch: evidenceBatch, next: &ignoredNext)
                        local.state = .incomplete; local.completedAt = nil
                        if enabled { local.breachState = .incomplete }
                        let completedRecords = Set(order.prefix(position + 1).compactMap { fields[$0].3.recordVersion })
                        local.cachedChecks = local.cachedChecks.mapValues { $0.filter { completedRecords.contains($0.record) } }
                        try await batch(local)
                        try Task.checkCancellation()
                    }
                    if needsBreach {
                        do {
                            let exposed = try await breach.contains(bytes, force: false)
                            try Task.checkCancellation()
                            value.breach = CachedBreachResult(exposed: exposed, checkedAt: now)
                            value.failures = 0; value.retryAt = .distantPast
                        } catch is CancellationError { throw CancellationError() }
                        catch {
                            try Task.checkCancellation()
                            value.failures += 1
                            value.retryAt = now.addingTimeInterval(min(3600, 60 * pow(2, Double(min(value.failures, 7) - 1))))
                        }
                    }
                } else {
                    try Task.checkCancellation()
                    next = min(next, now.addingTimeInterval(60))
                }
            }
            values[i] = value; entries[key(fields[i])] = value
            progress(Double(position + 1) / Double(max(fields.count, 1)))
            let completed = position + 1
            if didWork, completed < fields.count,
               lastBatchCount == 0 || completed - lastBatchCount >= 10 || lastBatchTime.duration(to: .now) >= .seconds(1) {
                var partialValues = values
                // Reuse is a comparison across the whole scope, not a per-item
                // completion. Never publish a partial comparison as clean.
                if rebuildReuse { for index in partialValues.indices { partialValues[index].reuse = nil } }
                var ignoredNext = Date.distantFuture
                var partial = makeReport(catalogs: catalogs, fields: fields, values: partialValues, scope: scope, enabled: enabled,
                    now: now, didWork: didWork, evidenceBatch: evidenceBatch, next: &ignoredNext)
                partial.state = .incomplete
                if enabled { partial.breachState = .incomplete }
                partial.completedAt = nil
                let completedRecords = Set(order.prefix(completed).compactMap { fields[$0].3.recordVersion })
                partial.cachedChecks = partial.cachedChecks.mapValues { $0.filter { completedRecords.contains($0.record) } }
                try await batch(partial)
                try Task.checkCancellation()
                lastBatchCount = completed; lastBatchTime = .now
            }
        }
        try Task.checkCancellation()
        if rebuildReuse {
            var groups: [Data: [Int]] = [:]
            for i in values.indices { if let fingerprint = values[i].fingerprint { groups[fingerprint, default: []].append(i) } }
            let batch = UUID()
            // Incomplete comparison must never become a reusable clean result.
            let complete = values.allSatisfy { $0.fingerprint != nil }
            for i in values.indices { values[i].reuse = nil }
            for indices in groups.values {
                let distinct = Set(indices.map { key(fields[$0]).vault + ":" + key(fields[$0]).item })
                let group = distinct.count > 1 ? UUID() : nil
                for i in indices { values[i].reuse = CachedReuseResult(group: group, scope: complete ? scope : "", batch: batch, checkedAt: now) }
            }
        }
        for i in fields.indices { entries[key(fields[i])] = values[i] }
        let live = Set(fields.map(key)); entries = entries.filter { live.contains($0.key) }
        let report = makeReport(catalogs: catalogs, fields: fields, values: values, scope: scope, enabled: enabled, now: now,
            didWork: didWork, evidenceBatch: evidenceBatch, next: &next)
        producedCaches = report.cachedChecks
        revisions = catalogs.mapValues(\.revision); observedCaches = catalogs.mapValues { $0.security?.passwordChecks ?? [] }
        previousEnabled = enabled; nextCheck = next
        progress(1)
        return report
    }
    private func makeReport(catalogs: [String: ItemCatalog], fields: [Field], values: [Entry], scope: String, enabled: Bool, now: Date,
                            didWork: Bool, evidenceBatch: UUID, next: inout Date) -> PasswordHealthReport {
        var report = PasswordHealthReport(), groupNumbers: [UUID: Int] = [:]
        report.total = fields.count
        report.cachedChecks = catalogs.mapValues { _ in [] }
        for i in fields.indices {
            let (vaultID, catalog, item, field) = fields[i], value = values[i]
            guard let strength = value.strength else { continue }
            var finding = PasswordHealthFinding(vaultID: vaultID, vaultName: catalog.vault, item: item.name,
                account: context(item)[1], path: field.path, archived: false, kinds: [])
            if strength.weak { finding.kinds.insert(.weak) }
            if enabled && value.breach?.exposed == true { finding.kinds.insert(.exposed) }
            finding.breachCheckedAt = value.breach?.checkedAt
            if let group = value.reuse?.group {
                if groupNumbers[group] == nil { groupNumbers[group] = groupNumbers.count + 1 }
                finding.kinds.insert(.reused); finding.reuseGroup = groupNumbers[group]
            }
            if !finding.kinds.isEmpty { report.findings.append(finding) }
            report.checked += 1
            if enabled {
                let expiry = value.breach?.checkedAt.addingTimeInterval(86400) ?? .distantPast
                if now < expiry && value.failures == 0 { report.breachChecked += 1 }
                let due = value.failures > 0 ? value.retryAt : expiry
                next = min(next, due > now ? due : now.addingTimeInterval(60))
            }
            if let record = field.recordVersion {
                let reuse = value.reuse.flatMap { $0.scope.isEmpty ? nil : $0 }
                var check = CachedPasswordCheck(record: record, context: strength.context, weak: strength.weak,
                    exposed: value.breach?.exposed ?? false, checkedAt: strength.checkedAt, breachCheckedAt: value.breach?.checkedAt,
                    reuseGroup: reuse?.group, scope: reuse?.scope ?? scope, batch: reuse?.batch ?? evidenceBatch)
                check.strengthResult = strength; check.breachResult = value.breach; check.reuseResult = reuse
                report.cachedChecks[vaultID, default: []].append(check)
            }
        }
        report.state = report.checked == report.total && values.allSatisfy({ $0.reuse?.scope == scope }) ? .checked : .incomplete
        report.breachState = !enabled ? .disabled : report.breachChecked == report.total ? .checked : report.breachChecked == 0 ? .unavailable : .incomplete
        report.cachedChecks = report.cachedChecks.mapValues { $0.sorted { $0.record < $1.record } }
        report.completedAt = enabled ? values.compactMap { $0.breach?.checkedAt }.min() : values.compactMap { $0.strength?.checkedAt }.min()
        report.usedCloudCache = !didWork
        return report
    }

}
