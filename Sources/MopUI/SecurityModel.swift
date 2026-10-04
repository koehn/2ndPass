import SwiftUI
import MopCore
import MopAppSupport

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
    func refreshHealth(force: Bool = false) {
        guard !isUpdatingCatalog else { return }
        guard healthPublishing == nil else { return }
        guard authenticated, !catalogs.isEmpty else { clearHealth(); return }
        guard itemDraft == nil else { return }
        if healthSessionGeneration != service.sessionGeneration {
            clearHealth(); healthSessionGeneration = service.sessionGeneration
        }
        let request = "\(service.sessionGeneration):\(breachChecksEnabled):" + catalogs.sorted { $0.key < $1.key }.map { "\($0.key):\($0.value.revision)" }.joined(separator: "|")
        if !force {
            if healthChecking && healthRequest == request { return }
            if !healthChecking && healthSession.isCurrent(catalogs: catalogs, enabled: breachChecksEnabled) {
                let report = healthReport, snapshots = catalogs, token = healthToken, session = service.sessionGeneration
                if !offline, !busy, report.cachedChecks.contains(where: { id, checks in
                    snapshots[id]?.canEdit == true && snapshots[id]?.securityEnabled == true && snapshots[id]?.security?.passwordChecks != checks
                }) {
                    healthTask = Task { [weak self] in
                        await self?.persistHealthCache(report, snapshots: snapshots, token: token, session: session)
                    }
                }
                scheduleHealthRefresh()
                return
            }
        }
        healthWakeTask?.cancel(); healthWakeTask = nil
        healthTask?.cancel(); healthToken = UUID(); healthRequest = request
        let token = healthToken, session = service.sessionGeneration, snapshots = catalogs
        let revisions = snapshots.mapValues(\.revision)
        let service = service, breach = breachClient, enabled = breachChecksEnabled, scanner = healthSession
        healthProgress = 0
        healthRestoringCache = !force && scanner.canRestoreCloudResults(catalogs: snapshots, enabled: enabled)
        healthChecking = true
        healthTask = Task { [weak self] in
            do {
                try await Task.sleep(for: .milliseconds(250))
                // Foreground editing and saving take precedence over background reads.
                while self?.busy == true {
                    try await Task.sleep(for: .milliseconds(50))
                }
                try Task.checkCancellation()
                let report = try await scanner.scan(catalogs: snapshots, service: service, breach: breach, enabled: enabled, force: force) { [weak self] fraction in
                    guard let self, !Task.isCancelled, self.healthToken == token,
                          self.service.sessionGeneration == session, self.catalogs.mapValues(\.revision) == revisions else { return }
                    self.healthProgress = fraction
                }
                guard let self, !Task.isCancelled, self.authenticated, self.healthToken == token,
                      self.service.sessionGeneration == session, self.catalogs.mapValues(\.revision) == revisions else { return }
                self.healthReport = report; self.healthChecking = false
                await self.persistHealthCache(report, snapshots: snapshots, token: token, session: session)
                guard self.healthToken == token, !Task.isCancelled else { return }
                if !self.healthSession.isCurrent(catalogs: self.catalogs, enabled: self.breachChecksEnabled) {
                    self.refreshHealth()
                }
                self.scheduleHealthRefresh()
            } catch {
                guard let self, self.healthToken == token else { return }
                self.healthChecking = false
            }
        }
    }
    private func persistHealthCache(_ report: PasswordHealthReport, snapshots: [String: ItemCatalog], token: UUID, session: Int) async {
        guard supports(.passwordCheckCache) else { return }
        guard healthPublishing == nil else { return }
        guard !offline else { healthCacheNotice = "Results are local until iCloud is available."; return }
        healthCacheNotice = nil
        healthPublishing = token
        defer { if healthPublishing == token { healthPublishing = nil } }
        for (id, checks) in report.cachedChecks.sorted(by: { $0.key < $1.key }) {
            guard let source = snapshots[id], source.securityEnabled == true, source.canEdit == true,
                  source.security?.passwordChecks != checks else { continue }
            guard !Task.isCancelled, authenticated, !busy, itemDraft == nil, healthToken == token, service.sessionGeneration == session,
                  catalogs[id]?.revision == source.revision else { return }
            do {
                let result = try await service.execute(.savePasswordChecks(checks, revision: source.revision), vault: id, offline: false)
                guard !Task.isCancelled, authenticated, healthToken == token, service.sessionGeneration == session,
                      catalogs[id]?.revision == source.revision, let updated = result.catalog else { return }
                healthSession.adoptCacheRevision(vault: id, from: source.revision, to: updated.revision)
                catalogs[id] = updated
                if vault == id { try applyCatalog(updated) }
            } catch {
                guard authenticated, healthToken == token else { return }
                healthCacheNotice = "Results are available on this device, but the iCloud cache could not be updated."
            }
        }
    }
    private func scheduleHealthRefresh() {
        healthWakeTask?.cancel(); healthWakeTask = nil
        let delay = healthSession.nextRefreshDate.timeIntervalSinceNow
        guard delay.isFinite, delay < 86401 else { return }
        let token = healthToken
        healthWakeTask = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(max(1, delay))) } catch { return }
            guard let self, self.authenticated, self.healthToken == token else { return }
            self.refreshHealth()
        }
    }
    func clearHealth() {
        healthTask?.cancel(); healthTask = nil; healthToken = UUID(); healthPublishing = nil
        healthWakeTask?.cancel(); healthWakeTask = nil
        healthSession.clear(); healthSession = PasswordHealthSession(); healthRequest = nil; healthSessionGeneration = nil
        healthChecking = false; healthRestoringCache = false; healthProgress = 0; healthReport = PasswordHealthReport(); historySelection = nil; healthCacheNotice = nil
        // Invalidates in-flight cache writes as well as cached ranges.
        let old = breachClient
        Task { await old.clear() }
    }
    func openHealthFinding(_ finding: PasswordHealthFinding) {
        guard authenticated, !busy, itemDraft == nil, let source = catalogs[finding.vaultID] else { return }
        conceal(); selectedLocalIdentityID = nil; passwordQualities = [:]
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
