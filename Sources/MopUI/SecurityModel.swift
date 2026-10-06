import SwiftUI
import OSLog
import MopCore
import MopAppSupport

private let healthCacheLogger = Logger(subsystem: "com.koehn.mop", category: "PasswordHealthCache")

struct HistorySelection: Identifiable {
    let vault: String
    let item: String
    let path: String
    var id: String { vault + ":" + item + ":" + path }
}

extension AppModel {
    func credentialAccounts(in vault: String) -> [CredentialAccount] {
        guard let catalog = catalogs[vault] else { return [] }
        var accounts = catalog.security?.accounts ?? []
        guard localReady, localError == nil else { return accounts }
        let present = Set(localIdentities.map(\.id))
        for a in accounts.indices {
            for r in accounts[a].registrations.indices {
                let registration = accounts[a].registrations[r]
                if registration.deviceID == catalog.currentDeviceID, !registration.external,
                   let id = registration.localIdentityID, !present.contains(id) {
                    accounts[a].registrations[r].state = .removed
                }
            }
        }
        return accounts
    }
    func reconcileLocalCredentialEvidence() {
        guard supports(.credentialAccounts), authenticated, localReady, !offline, !busy else { return }
        let ids = Set(localIdentities.map(\.id))
        let targets = catalogs.filter { _, catalog in
            catalog.canEdit == true && catalog.security?.accounts.contains { account in
                account.registrations.contains { registration in
                    registration.deviceID == catalog.currentDeviceID && !registration.external && registration.state != .removed && registration.localIdentityID.map { !ids.contains($0) } == true
                }
            } == true
        }
        guard !targets.isEmpty else { return }
        perform { token in
            for (id, source) in targets {
                let result = try await self.service.execute(.reconcileLocalCredentials(ids, revision: source.revision), vault: id, offline: false)
                guard self.current(token), let updated = result.catalog else { return }
                self.catalogs[id] = updated
                if self.vault == id { try self.applyCatalog(updated) }
            }
        }
    }
    func refreshHealth(force: Bool = false, afterSave: Bool = false) {
        guard authenticated, !catalogs.isEmpty else { clearHealth(); return }
        if healthSessionGeneration != service.sessionGeneration {
            clearHealth(); healthSessionGeneration = service.sessionGeneration
        }
        let token = healthToken
        healthSession.reconcile(catalogs: catalogs, service: service, breach: breachClient,
            enabled: breachChecksEnabled, active: isActive, busy: busy || isUpdatingCatalog || loadingVaults, scopeComplete: !isUpdatingCatalog && !loadingVaults,
            editingVault: itemDraft?.vault, editingItem: itemDraft?.originalName, force: force) { [weak self] report in
                guard let self, self.authenticated, self.healthToken == token else { return }
                self.healthReport = report
                self.healthChecking = self.healthSession.hasRunningWork
                self.healthScheduled = report.fields.contains {
                    [$0.strength, $0.reuse, $0.breach].contains { $0.execution == .queued || $0.execution == .paused }
                }
                self.queueHealthCache(flush: !self.healthChecking)
                self.scheduleHealthRefresh()
            }
        healthChecking = healthSession.hasRunningWork
    }
    private func queueHealthCache(flush: Bool) {
        healthCacheDirty = true
        guard isActive, !busy, !isUpdatingCatalog, !loadingVaults, authenticated, healthPublishing == nil else { return }
        if healthCacheTask != nil {
            guard flush else { return }
            healthCacheTask?.cancel()
        }
        let token = healthToken, session = service.sessionGeneration
        healthCacheTask = Task { [weak self] in
            if !flush { do { try await Task.sleep(for: .seconds(2)) } catch { return } }
            guard let self, self.healthToken == token, !Task.isCancelled else { return }
            self.healthCacheTask = nil
            self.healthCacheDirty = false
            await self.persistHealthCache(self.healthReport, snapshots: self.catalogs, token: token, session: session, partial: true)
        }
    }
    private func persistHealthCache(_ report: PasswordHealthReport, snapshots: [String: ItemCatalog], token: UUID, session: Int, partial: Bool = false) async {
        guard supports(.passwordCheckCache) else { healthCacheNotice = "Results are available during this unlocked session."; return }
        guard healthPublishing == nil else { return }
        guard !offline else { healthCacheNotice = "Results are local until iCloud is available."; return }
        healthCacheNotice = snapshots.values.contains { $0.canEdit != true || $0.securityEnabled != true } ? "Some vault results are local to this unlocked session." : nil
        healthPublishing = token
        defer {
            if healthPublishing == token {
                healthPublishing = nil
                if healthCacheDirty { queueHealthCache(flush: false) }
            }
        }
        for id in report.cachedChecks.keys.sorted() {
            let batchChecks = healthReport.cachedChecks[id] ?? []
            guard let source = catalogs[id], source.securityEnabled == true, source.canEdit == true else { continue }
            var checks = batchChecks
            if partial {
                // Preserve unvisited evidence locally too; the storage boundary
                // independently merges it against the latest durable results.
                var merged = Dictionary((source.security?.passwordChecks ?? []).map { ($0.record, $0) }, uniquingKeysWith: { _, newer in newer })
                let liveRecords = Set(source.items.filter { !$0.isArchived && $0.deletion == nil }.flatMap { item in
                    item.fields.filter { $0.type == .password || ($0.path == item.autoFill?.password && [.concealed, .text, .username, .email].contains($0.type)) }.compactMap(\.recordVersion)
                })
                merged = merged.filter { liveRecords.contains($0.key) }
                for check in batchChecks where liveRecords.contains(check.record) {
                    if var saved = merged[check.record] {
                        if saved.strengthResult?.context != check.strengthResult?.context { saved.strengthResult = nil }
                        if saved.reuseResult?.scope != check.reuseResult?.scope { saved.reuseResult = nil }
                        merged[check.record] = check.retainingNewerResults(from: saved)
                    } else { merged[check.record] = check }
                }
                checks = merged.values.sorted { $0.record < $1.record }
            }
            guard (source.security?.passwordChecks ?? []) != checks else { continue }
            guard !Task.isCancelled, authenticated, isActive, !busy, !isUpdatingCatalog, !loadingVaults, healthToken == token, service.sessionGeneration == session,
                  catalogs[id]?.revision == source.revision else { return }
            do {
                healthCacheLogger.notice("Saving health evidence: fields=\(checks.count), loadedVaults=\(self.catalogs.count)")
                let result = try await service.execute(.savePasswordChecks(checks, revision: source.revision), vault: id, offline: false)
                guard !Task.isCancelled, authenticated, healthToken == token, service.sessionGeneration == session,
                      catalogs[id]?.revision == source.revision, let updated = result.catalog else { return }
                healthCacheLogger.notice("Health evidence saved: fields=\(updated.security?.passwordChecks?.count ?? 0)")
                healthSession.adoptCacheRevision(vault: id, from: source.revision, to: updated.revision, checks: updated.security?.passwordChecks ?? [])
                catalogs[id] = updated
                if vault == id { try applyCatalog(updated) }
            } catch {
                guard authenticated, healthToken == token else { return }
                healthCacheLogger.error("Health evidence save failed: domain=\((error as NSError).domain, privacy: .public), code=\((error as NSError).code)")
                if let error = error as? MopError, error == .vaultConflict {
                    healthCacheDirty = true
                    // Refresh the source revision before the next coalesced write.
                    if let result = try? await service.execute(.catalog, vault: id, offline: false),
                       let updated = result.catalog, authenticated, healthToken == token {
                        catalogs[id] = updated
                    }
                }
                healthCacheNotice = "Results are available on this device, but the iCloud cache could not be updated."
            }
        }
    }
    private func scheduleHealthRefresh() {
        healthWakeTask?.cancel(); healthWakeTask = nil
        let delay = healthSession.nextRefreshDate.timeIntervalSinceNow
        guard isActive, delay.isFinite, delay < 86401 else { return }
        let token = healthToken
        healthWakeTask = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(max(1, delay))) } catch { return }
            guard let self, self.authenticated, self.healthToken == token else { return }
            self.refreshHealth()
        }
    }
    func clearHealth() {
        healthCacheDirty = false
        healthCacheTask?.cancel(); healthCacheTask = nil
        healthToken = UUID(); healthPublishing = nil
        healthWakeTask?.cancel(); healthWakeTask = nil
        healthSession.clear(); healthSession = PasswordHealthSession(); healthSessionGeneration = nil
        healthChecking = false; healthScheduled = false; healthReport = PasswordHealthReport(); historySelection = nil; healthCacheNotice = nil
        // Invalidates in-flight cache writes as well as cached ranges.
        let old = breachClient
        Task { await old.clear() }
    }
    func openHealthFinding(_ finding: PasswordHealthFinding) {
        guard authenticated, !busy, itemDraft == nil, let source = catalogs[finding.vaultID] else { return }
        conceal(); selectedLocalIdentityID = nil; passwordQualities = [:]; passwordQualitySource = nil
        collection = .vault(finding.vaultID); vault = finding.vaultID
        try? applyCatalog(source); selectedItem = finding.item
        selected = try? SecretReference(vault: source.vault, relativePath: SecretReference.encode(finding.item) + "/" + finding.path)
    }
    func securityOperation(_ operation: VaultOperation, vault id: String) {
        perform { token in
            let result = try await self.service.execute(operation, vault: id, offline: false)
            guard self.current(token), let catalog = result.catalog else { return }
            self.catalogs[id] = catalog
            if self.vault == id { try self.applyCatalog(catalog) }
        }
    }
    func beginSecurityUpgrade(_ id: String) {
        guard let source = catalogs[id], source.canUpgradeSecurity == true, !busy, !offline else { return }
        pendingSecurityUpgrade = (id, source.revision)
        documentRequest = DocumentRequest(vault: id, generation: securityGeneration)
    }
}
