import Foundation
import CryptoKit
import MopCore

public protocol BreachChecking: Sendable {
    func contains(_ password: Data, force: Bool) async throws -> Bool
    func contains(_ lookup: BreachLookup, force: Bool) async throws -> Bool
    func clear() async
}
/// Hash material only; safe to queue without retaining the password bytes.
public struct BreachLookup: Sendable, Equatable {
    public let prefix: String
    public let suffix: String
    public init(_ password: Data) {
        let hash = Insecure.SHA1.hash(data: password).map { String(format: "%02X", $0) }.joined()
        prefix = String(hash.prefix(5)); suffix = String(hash.dropFirst(5))
    }
}
public extension BreachChecking {
    func contains(_ password: Data, force: Bool) async throws -> Bool {
        try await contains(BreachLookup(password), force: force)
    }
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
    private var pending: [String: Task<Set<String>, Error>] = [:]
    public func clear() {
        generation = UUID(); cache.removeAll()
        for task in pending.values { task.cancel() }
        pending.removeAll()
    }
    public func contains(_ lookup: BreachLookup, force: Bool = false) async throws -> Bool {
        try Task.checkCancellation()
        let prefix = lookup.prefix
        if !force, let (date, suffixes) = cache[prefix], Date().timeIntervalSince(date) < 86400 {
            return suffixes.contains(lookup.suffix)
        }
        let token = generation
        let task: Task<Set<String>, Error>
        if let existing = pending[prefix] { task = existing }
        else {
            let transport = transport
            task = Task {
                var request = URLRequest(url: URL(string: "https://api.pwnedpasswords.com/range/" + prefix)!)
                request.setValue("true", forHTTPHeaderField: "Add-Padding")
                request.timeoutInterval = 20
                let (data, status) = try await transport.response(for: request)
                try Task.checkCancellation()
                guard status == 200 else { throw BreachCheckFailure.unavailable }
                return try Self.parse(data)
            }
            pending[prefix] = task
        }
        do {
            let suffixes = try await task.value
            try Task.checkCancellation()
            guard token == generation else { throw CancellationError() }
            cache[prefix] = (Date(), suffixes); pending[prefix] = nil
            return suffixes.contains(lookup.suffix)
        } catch {
            if token == generation { pending[prefix] = nil }
            throw error
        }
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
public enum HealthFreshness: String, Sendable { case current, pending, stale, unavailable, disabled }
public enum HealthExecution: String, Sendable { case idle, queued, running, paused }
public struct HealthCheckStatus: Sendable {
    public var freshness: HealthFreshness
    public var execution: HealthExecution = .idle
}
public struct PasswordFieldHealth: Sendable {
    public let vaultID: String
    public let item: String
    public let path: String
    public var strength: HealthCheckStatus
    public var reuse: HealthCheckStatus
    public var breach: HealthCheckStatus
}
public struct PasswordHealthReport: Sendable {
    public var fields: [PasswordFieldHealth] = []
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
        var lookup: BreachLookup?
        var readRetry: Date = .distantPast
    }
    private typealias Field = (String, ItemCatalog, VaultItem, ItemField)
    private var entries: [Key: Entry] = [:]
    private var sessionKey = SymmetricKey(size: .bits256)
    private var revisions: [String: String] = [:]
    private var producedCaches: [String: [CachedPasswordCheck]] = [:]
    private var observedCaches: [String: [CachedPasswordCheck]] = [:]
    private var previousEnabled: Bool?
    private var nextCheck: Date = .distantPast
    private let estimate: @Sendable (String, [String]) -> PasswordQuality
    private var liveCatalogs: [String: ItemCatalog] = [:]
    private var liveFields: [Field] = []
    private var liveScope = ""
    private var liveByKey: [Key: Field] = [:]
    private var liveEnabled = true
    private var didLiveWork = false
    private var liveAllowed = false
    private var liveScopeComplete = true
    private var pausedItem: (String, String)?
    private var localTask: Task<Void, Never>?
    private var localKey: Key?
    private var resetTask: Task<Void, Never>?
    private var networkTasks: [Key: Task<Void, Never>] = [:]
    private var forced: Set<Key> = []
    private var liveGeneration = UUID()
    private let liveEvidenceBatch = UUID()
    private var publishTask: Task<Void, Never>?
    private var liveUpdate: (@MainActor (PasswordHealthReport) -> Void)?
    private var liveService: (any VaultService)?
    private var liveBreach: (any BreachChecking)?
    private var clock: @Sendable () -> Date = Date.init
    var hasPendingUpdates: Bool { publishTask != nil || resetTask != nil }
    public var hasRunningWork: Bool { localTask != nil || !networkTasks.isEmpty }
    public init(estimate: @escaping @Sendable (String, [String]) -> PasswordQuality = { PasswordEstimator.estimate($0, userInputs: $1) }) {
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
        stopLive(); liveCatalogs = [:]; liveFields = []; liveByKey = [:]; liveUpdate = nil
        entries.removeAll(); sessionKey = SymmetricKey(size: .bits256)
        revisions = [:]; observedCaches = [:]; producedCaches = [:]; previousEnabled = nil; nextCheck = .distantPast
    }
    public func isCurrent(catalogs: [String: ItemCatalog], enabled: Bool, at now: Date = Date()) -> Bool {
        revisions == catalogs.mapValues(\.revision) && observedCaches == catalogs.mapValues { $0.security?.passwordChecks ?? [] } && previousEnabled == enabled && now < nextCheck
    }
    private func key(_ field: Field) -> Key {
        Key(vault: field.0, item: field.2.storageID ?? field.2.name, path: field.3.historyID?.uuidString ?? field.3.path)
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
                     enabled: Bool, force: Bool = false, at now: Date? = nil, eagerLocalResults: Bool = false,
                     progress: @MainActor @Sendable (Double) -> Void = { _ in },
                     beforeWork: @MainActor @Sendable () async throws -> Void = {},
                     batch: @MainActor @Sendable (PasswordHealthReport) async throws -> Void = { _ in }) async throws -> PasswordHealthReport {
        try await beforeWork()
        try Task.checkCancellation()
        let stream = AsyncStream<PasswordHealthReport>.makeStream(bufferingPolicy: .bufferingNewest(1))
        let fixedNow = now
        progress(0)
        reconcile(catalogs: catalogs, service: service, breach: breach, enabled: enabled,
                  active: true, busy: false, force: force, now: { fixedNow ?? Date() }) { report in
            stream.continuation.yield(report)
        }
        defer { stream.continuation.finish(); liveUpdate = nil }
        return try await withTaskCancellationHandler {
            for await report in stream.stream {
                try Task.checkCancellation()
                progress(Double(report.checked) / Double(max(1, report.total)))
                if !hasRunningWork && !hasPendingUpdates {
                    revisions = catalogs.mapValues(\.revision)
                    observedCaches = catalogs.mapValues { $0.security?.passwordChecks ?? [] }
                    previousEnabled = enabled
                    progress(1)
                    return report
                }
                try await batch(report)
            }
            throw CancellationError()
        } onCancel: {
            stream.continuation.finish()
            Task { @MainActor [weak self] in self?.stopLive() }
        }
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

extension PasswordHealthSession {
    /// Reconcile saved evidence synchronously; workers never own catalog snapshots.
    public func reconcile(catalogs: [String: ItemCatalog], service: any VaultService,
                          breach: any BreachChecking, enabled: Bool, active: Bool, busy: Bool, scopeComplete: Bool = true,
                          editingVault: String? = nil, editingItem: String? = nil, force: Bool = false,
                          now: @escaping @Sendable () -> Date = Date.init,
                          update: @escaping @MainActor (PasswordHealthReport) -> Void) {
        didLiveWork = false
        let wasEnabled = liveEnabled
        liveCatalogs = catalogs; liveEnabled = enabled; liveAllowed = active && !busy; liveScopeComplete = scopeComplete
        pausedItem = editingVault.flatMap { vault in editingItem.map { (vault, $0) } }
        liveService = service; liveBreach = breach; liveUpdate = update; clock = now
        guard let (fields, scope) = try? snapshot(catalogs) else { return }
        liveFields = fields; liveScope = scope
        liveByKey = Dictionary(fields.map { (key($0), $0) }, uniquingKeysWith: { _, latest in latest })
        let live = Set(fields.map(key))
        entries = entries.filter { live.contains($0.key) }
        for field in fields { entries[key(field)] = entry(field, now: now()) }
        // Keep obsolete jobs counted until they finish; version guards discard their results.
        if (!active && hasRunningWork) || (wasEnabled && !enabled) || force {
            for task in networkTasks.values { task.cancel() }
            networkTasks.removeAll()
            // Generation guards also reject transports which ignore cancellation.
            liveGeneration = UUID()
            localTask?.cancel(); localTask = nil; localKey = nil
            let generation = liveGeneration
            resetTask = Task { [weak self] in
                await breach.clear()
                guard let self, self.liveGeneration == generation else { return }
                self.resetTask = nil; self.pumpLive()
            }
        }
        if force && enabled { forced = live }
        if !enabled { forced.removeAll() }
        emitLive(immediate: true)
        pumpLive()
    }

    private func stopLive() {
        resetTask?.cancel(); resetTask = nil
        liveGeneration = UUID(); localTask?.cancel(); localTask = nil; localKey = nil
        for task in networkTasks.values { task.cancel() }
        networkTasks.removeAll(); publishTask?.cancel(); publishTask = nil; forced.removeAll()
    }
    private func paused(_ field: Field) -> Bool {
        pausedItem.map { $0.0 == field.0 && $0.1 == field.2.name } ?? false
    }
    private func breachDue(_ key: Key, _ value: Entry, now: Date) -> Bool {
        liveEnabled && (forced.contains(key) || now >= (value.failures > 0 ? value.retryAt : value.breach?.checkedAt.addingTimeInterval(86400) ?? .distantPast))
    }
    private func currentField(_ key: Key, version: String) -> Field? {
        guard let field = liveByKey[key], (field.3.recordVersion ?? field.1.revision) == version else { return nil }
        return field
    }
    private func rebuildLiveReuse(_ fields: [Field], scope: String) {
        // Loading is not a credential change. Keep the completed batch until
        // the full scope can be compared; replacing it during each catalog
        // refresh can leave different vaults persisted with different batches.
        guard liveScopeComplete else { return }
        let values = fields.compactMap { entries[key($0)] }
        guard !validReuse(values, scope: scope) else { return }
        for field in fields { entries[key(field)]?.reuse = nil }
        guard values.count == fields.count, values.allSatisfy({ $0.fingerprint != nil }) else { return }
        var groups: [Data: [Field]] = [:]
        for field in fields { groups[entries[key(field)]!.fingerprint!, default: []].append(field) }
        let batch = UUID(), now = clock()
        for group in groups.values {
            let distinct = Set(group.map { key($0).vault + ":" + key($0).item })
            let id: UUID? = distinct.count > 1 ? UUID() : nil
            for field in group { entries[key(field)]?.reuse = CachedReuseResult(group: id, scope: scope, batch: batch, checkedAt: now) }
        }
    }
    private func pumpLive() {
        guard let service = liveService, let breach = liveBreach else { return }
        let fields = liveFields, scope = liveScope
        rebuildLiveReuse(fields, scope: scope)
        guard liveAllowed, resetTask == nil else { emitLive(); return }
        let now = clock(), generation = liveGeneration
        let needsReuse = !validReuse(fields.compactMap { entries[key($0)] }, scope: scope)
        let ordered = fields.sorted { (entries[key($0)]?.strength == nil ? 0 : 1) < (entries[key($1)]?.strength == nil ? 0 : 1) }
        if localTask == nil, let field = ordered.first(where: {
            guard !paused($0), let value = entries[key($0)], now >= value.readRetry else { return false }
            return value.strength == nil || (needsReuse && value.fingerprint == nil) || (breachDue(key($0), value, now: now) && value.lookup == nil)
        }) {
            let key = key(field), version = entries[key]!.version, inputs = context(field.2), sessionKey = sessionKey, estimate = estimate
            didLiveWork = true
            localKey = key
            localTask = Task(priority: .utility) { [weak self] in
                defer {
                    if let self, self.liveGeneration == generation {
                        self.localTask = nil; self.localKey = nil; self.pumpLive(); self.emitLive()
                    }
                }
                do {
                    guard let self, self.liveGeneration == generation, self.liveAllowed,
                          let current = self.currentField(key, version: version), !self.paused(current) else { return }
                    let reference = try SecretReference(vault: field.1.vault, relativePath: SecretReference.encode(field.2.name) + "/" + field.3.path)
                    guard let secret = try await service.readLocal(reference, vault: field.0).value else { throw MopError.notFound }
                    try Task.checkCancellation()
                    let needsStrength = self.entries[key]?.strength == nil
                    let result = await Task.detached(priority: .utility) {
                        var bytes = Data(secret)
                        defer { SecretBytes.wipe(&bytes) }
                        let quality = needsStrength ? estimate(String(decoding: bytes, as: UTF8.self), inputs) : nil
                        return (quality, Data(HMAC<SHA256>.authenticationCode(for: bytes, using: sessionKey)), BreachLookup(bytes))
                    }.value
                    try Task.checkCancellation()
                    guard self.liveGeneration == generation, let current = self.currentField(key, version: version) else { return }
                    if let quality = result.0, self.context(current.2) == inputs {
                        self.entries[key]?.strength = CachedStrengthResult(weak: quality == .weak || quality == .veryWeak, checkedAt: self.clock(), context: inputs, quality: quality)
                    }
                    self.entries[key]?.fingerprint = result.1; self.entries[key]?.lookup = result.2
                    self.entries[key]?.readRetry = .distantPast
                } catch {
                    if let self, !Task.isCancelled, self.liveGeneration == generation, self.currentField(key, version: version) != nil {
                        self.entries[key]?.readRetry = self.clock().addingTimeInterval(60)
                    }
                }
            }
        }
        for field in ordered where networkTasks.count < 2 {
            let key = key(field)
            guard !paused(field), networkTasks[key] == nil, let value = entries[key], let lookup = value.lookup,
                  breachDue(key, value, now: now) else { continue }
            let version = value.version
            didLiveWork = true
            forced.remove(key)
            networkTasks[key] = Task(priority: .utility) { [weak self] in
                defer {
                    if let self, self.liveGeneration == generation {
                        self.networkTasks[key] = nil; self.pumpLive(); self.emitLive()
                    }
                }
                do {
                    let exposed = try await breach.contains(lookup, force: false)
                    try Task.checkCancellation()
                    guard let self, self.liveGeneration == generation, self.currentField(key, version: version) != nil else { return }
                    self.entries[key]?.breach = CachedBreachResult(exposed: exposed, checkedAt: self.clock())
                    self.entries[key]?.failures = 0; self.entries[key]?.retryAt = .distantPast
                } catch {
                    if let self, !Task.isCancelled, self.liveGeneration == generation, self.currentField(key, version: version) != nil {
                        let failures = (self.entries[key]?.failures ?? 0) + 1
                        self.entries[key]?.failures = failures
                        self.entries[key]?.retryAt = self.clock().addingTimeInterval(min(3600, 60 * pow(2, Double(min(failures, 7) - 1))))
                    }
                }
            }
        }
        emitLive()
    }
    private func emitLive(immediate: Bool = false) {
        if immediate { publishTask?.cancel(); publishTask = nil; publishLive(); return }
        guard publishTask == nil else { return }
        publishTask = Task { [weak self] in
            do { try await Task.sleep(for: .milliseconds(100)) } catch { return }
            guard let self else { return }
            self.publishTask = nil; self.publishLive()
        }
    }
    private func publishLive() {
        let fields = liveFields, scope = liveScope
        rebuildLiveReuse(fields, scope: scope)
        let now = clock(), values = fields.map { field in
            var value = entries[key(field)] ?? entry(field, now: clock())
            // Hide an unconfirmed scope without destroying its saved evidence.
            if !liveScopeComplete { value.reuse = nil }
            return value
        }
        var next = Date.distantFuture
        var report = makeReport(catalogs: liveCatalogs, fields: fields, values: values, scope: scope,
                                enabled: liveEnabled, now: now, didWork: didLiveWork, evidenceBatch: liveEvidenceBatch, next: &next)
        report.fields = fields.enumerated().map { index, field in
            let value = values[index], key = key(field)
            let execution: HealthExecution = !liveAllowed || paused(field) ? .paused : .queued
            let strength: HealthFreshness = value.strength != nil ? .current : value.readRetry > now ? .unavailable : .pending
            let reuse: HealthFreshness = value.reuse?.scope == scope ? .current : value.readRetry > now ? .unavailable : .pending
            let breach: HealthFreshness = !liveEnabled ? .disabled : value.failures > 0 || value.readRetry > now ? .unavailable : value.breach.map { now.timeIntervalSince($0.checkedAt) < 86400 ? .current : .stale } ?? .pending
            if value.readRetry > now { next = min(next, value.readRetry) }
            return PasswordFieldHealth(vaultID: field.0, item: field.2.name, path: field.3.path,
                strength: HealthCheckStatus(freshness: strength, execution: strength == .current ? .idle : localKey == key ? .running : execution),
                reuse: HealthCheckStatus(freshness: reuse, execution: reuse == .current ? .idle : localKey == key ? .running : execution),
                breach: HealthCheckStatus(freshness: breach, execution: networkTasks[key] != nil ? .running : breach == .current || breach == .disabled ? .idle : execution))
        }
        // Timer deadlines remain meaningful even when local evidence is absent.
        for value in values where liveEnabled {
            let due = value.failures > 0 ? value.retryAt : value.breach?.checkedAt.addingTimeInterval(86400)
            if let due, due > now { next = min(next, due) }
        }
        nextCheck = next; producedCaches = report.cachedChecks
        liveUpdate?(report)
    }
}
