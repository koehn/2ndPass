import SwiftUI
import MopCore
import MopAppSupport
import MopLocalIdentity

struct SecurityHealthView: View {
    @Bindable var model: AppModel
    var showDetail: () -> Void
    @State private var vault = ""
    @State private var query = ""
    @State private var category: PasswordHealthKind?
    @State private var registrations = false
    @State private var upgrade: String?
    private var activeFindings: [PasswordHealthFinding] {
        model.healthReport.findings.filter { finding in
            model.catalogs[finding.vaultID]?.items.contains {
                $0.name == finding.item && !$0.isArchived && $0.deletion == nil
            } == true
        }
    }
    private var findings: [PasswordHealthFinding] {
        activeFindings.filter {
            (vault.isEmpty || $0.vaultID == vault) && (category == nil || $0.kinds.contains(category!)) &&
            (query.isEmpty || ($0.item + " " + $0.account + " " + $0.vaultName).localizedCaseInsensitiveContains(query))
        }.sorted { ($0.reuseGroup ?? 0, $0.item, $0.path) < ($1.reuseGroup ?? 0, $1.item, $1.path) }
    }
    var body: some View {
        List {
            if !model.authenticated {
                Label("Security is locked", systemImage: "lock")
                if model.supports(.credentialAccounts) { Button("Credential Backups") { model.openLocalVault(); registrations = true } }
                Button("Unlock") { model.unlock() }.disabled(!model.canUnlock)
            } else {
                Section {
                    Picker("Vault", selection: $vault) {
                        Text("All accessible vaults").tag("")
                        ForEach(model.vaults) { Text($0.name ?? $0.id).tag($0.id) }
                    }
                    TextField("Search accounts", text: $query)
                    VStack(alignment: .leading, spacing: 8) {
                        Text("\(model.healthReport.checked) of \(model.healthReport.total) password fields checked in \(model.catalogs.count) of \(model.vaults.count) vaults.").font(.caption)
                        if model.catalogs.count < model.vaults.count { Label("Incomplete: some vaults are unavailable or locked", systemImage: "exclamationmark.triangle") }
                        if model.offline { Text("Using cached vault data. Corrections require a connection.").font(.caption) }
                        if let date = model.healthReport.completedAt { Text("Checked \(date.formatted())").font(.caption).foregroundStyle(.secondary) }
                        if model.healthReport.usedCloudCache { Text("Using saved iCloud results").font(.caption).foregroundStyle(.secondary) }
                        if let notice = model.healthCacheNotice { Text(notice).font(.caption).foregroundStyle(.secondary) }
                        if model.healthScheduled { Text("Automatic checks will run when idle.").font(.caption).foregroundStyle(.secondary) }
                        if !model.breachChecksEnabled { Text("Breach checks disabled").font(.caption) }
                        else if model.healthReport.breachChecked < model.healthReport.total && !model.healthChecking && !model.healthScheduled {
                            Label("Breach check incomplete or unavailable", systemImage: "wifi.exclamationmark").font(.caption)
                        }
                        HStack {
                            if model.healthChecking && !model.healthRestoringCache {
                                ProgressView("Checking passwords…", value: model.healthProgress, total: 1)
                                    .progressViewStyle(.linear)
                                    .accessibilityIdentifier("password-check-progress")
                            }
                            Spacer()
                            Button("Check Now") { model.refreshHealth(force: true) }.disabled(model.healthChecking)
                        }
                    }
                    DisclosureGroup("Breach check settings") {
                        Toggle("Check exposed passwords with HIBP", isOn: $model.breachChecksEnabled)
                        Text(model.supports(.passwordCheckCache) ? "Results sync encrypted with each vault. Breach checks refresh daily; strength and reuse update when credentials change. Vault members can see them." : "Results remain available during this unlocked session. Synchronizing cached results is not yet available.").font(.caption)
                        Text("HIBP receives a five-character password hash prefix and your network address. Your password and account details are not sent.").font(.caption)
                    }
                }
                Section {
                    Menu {
                        Picker("Categories", selection: $category) {
                            Text("All findings (\(findingCount()))").tag(nil as PasswordHealthKind?)
                            ForEach(PasswordHealthKind.allCases, id: \.self) { kind in
                                Text("\(kind.rawValue) (\(findingCount(kind)))").tag(Optional(kind))
                            }
                        }.pickerStyle(.inline)
                        Divider()
                        if model.supports(.credentialAccounts) { Button("Credential Backups (\(backupCount))") { registrations = true } }
                    } label: {
                        HStack {
                            Text("Categories")
                            Spacer()
                            Text("\(category?.rawValue ?? "All findings") (\(findingCount(category)))")
                                .foregroundStyle(.secondary)
                        }
                    }
                    .accessibilityIdentifier("security-categories-menu")
                }
                Section("Accounts") {
                    if findings.isEmpty { Text(model.healthChecking ? "Waiting for check results" : model.healthReport.completedAt == nil ? "Passwords have not been checked" : "No findings among checked items").foregroundStyle(.secondary) }
                    ForEach(findings) { finding in
                        Button {
                            model.openHealthFinding(finding)
                            if model.vault == finding.vaultID, model.selectedItem == finding.item { showDetail() }
                        } label: {
                            VStack(alignment: .leading, spacing: 5) {
                                Text(finding.item).font(.headline)
                                Text([finding.account, finding.vaultName, finding.path].filter { !$0.isEmpty }.joined(separator: " · ")).font(.caption)
                                if finding.kinds.contains(.exposed) {
                                    Text("This password appears in known breach data.")
                                    if let date = finding.breachCheckedAt {
                                        Text("Breach data checked \(date.formatted())").font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                                if finding.kinds.contains(.weak) { Text("Easy to guess. Choose a strong, unique password.") }
                                if let group = finding.reuseGroup { Text("Reused password · group \(group)") }
                            }
                        }.buttonStyle(.plain).accessibilityIdentifier("security-finding-" + finding.id)
                    }
                }
                Section("History and backup tracking") {
                    ForEach(model.vaults.filter { model.catalogs[$0.id]?.securityEnabled == false }) { descriptor in
                        VStack(alignment: .leading) {
                            Text("\(descriptor.name ?? "Vault") requires an upgrade")
                            if model.catalogs[descriptor.id]?.canUpgradeSecurity == true {
                                Button("Upgrade Vault…") { upgrade = descriptor.id }.disabled(model.offline || model.busy)
                            } else { Text("Ask the vault owner to upgrade.").font(.caption) }
                        }
                    }
                    Text("Changing a saved password does not change it at the website. Register the replacement there, then save it here.").font(.caption)
                }
            }
        }
        .accessibilityIdentifier("security-health-list")
        .navigationTitle("Security")
        .sheet(isPresented: $registrations) { CredentialBackupsView(model: model) }
        .confirmationDialog("Upgrade this vault?", isPresented: Binding(get: { upgrade != nil }, set: { if !$0 { upgrade = nil } }), titleVisibility: .visible) {
            Button("Choose Backup Folder and Upgrade") { if let id = upgrade { model.beginSecurityUpgrade(id) }; upgrade = nil }
        } message: {
            Text("Older apps, CLI companions, and extensions will stop opening this vault. Update all clients first. An encrypted backup will be written and verified before the upgrade; history starts now. There is no in-place downgrade.")
        }
    }
    private func findingCount(_ kind: PasswordHealthKind? = nil) -> Int {
        Set(activeFindings.filter {
            (vault.isEmpty || $0.vaultID == vault) && (kind == nil || $0.kinds.contains(kind!))
        }.map { ItemRow.ID(vault: $0.vaultID, name: $0.item) }).count
    }
    private var backupCount: Int {
        model.catalogs.keys.filter { vault.isEmpty || $0 == vault }.flatMap { model.credentialAccounts(in: $0) }.filter { !$0.hasConfirmedAlternate }.count +
        model.localIdentities.filter { identity in !model.catalogs.values.contains { $0.security?.accounts.contains { $0.registrations.contains { $0.localIdentityID == identity.id } } == true } }.count
    }
}
