import AuthenticationServices
import SwiftUI
import MopAppSupport

struct AutoFillSettingsView: View {
    @Bindable var model: AppModel
    @State private var status = AutoFillPublicationStatus()
    @State private var enabling = false
    @State private var nextEnable = Date.distantPast
    @State private var settingsError: String?
    var body: some View {
        Section("AutoFill") {
            Label(title, systemImage: status.phase == .current ? "checkmark.circle" : "key")
            if let last = status.lastSuccess { Text("Suggestions last updated \(last, style: .relative) ago").font(.caption) }
            if let message = status.message { Text(message).font(.callout) }
            if let message = model.autoFillRefreshMessage { Text(message).font(.callout) }
            if status.phase == .disabled {
                Button("Enable AutoFill") {
                    enabling = true; nextEnable = Date().addingTimeInterval(10)
                    Task {
                        _ = await ASSettingsHelper.requestToTurnOnCredentialProviderExtension()
                        status = await AutoFillPublisher.shared.status(); enabling = false
                    }
                }.disabled(enabling || Date() < nextEnable)
            }
            Button("Open AutoFill Settings…") {
                Task {
                    do { try await ASSettingsHelper.openCredentialProviderAppSettings() }
                    catch { settingsError = "Open System Settings (Settings on iPhone or iPad), choose AutoFill & Passwords, and enable 2ndPass." }
                }
            }
            Button("Open Verification Code Settings…") {
                Task {
                    do { try await ASSettingsHelper.openVerificationCodeAppSettings() }
                    catch { settingsError = "Open AutoFill & Passwords in system settings to configure verification codes." }
                }
            }
            if let settingsError { Text(settingsError).font(.callout) }
            if model.authenticated {
                Button("Refresh Suggestions") { model.refreshAutoFillSuggestions() }.disabled(model.busy || model.refreshing)
            } else {
                Button("Unlock to Refresh Suggestions") { model.unlock() }.disabled(!model.canUnlock)
            }
            Text("Websites and usernames appear in system suggestions and the account picker without authentication. Item and vault names stay encrypted. Filling a credential requires authentication, even when 2ndPass is locked or closed.").font(.caption)
            Text("2ndPass fills passwords, verification codes, and passkeys from cloud vaults, plus device-local passkeys. Choose Create Login in the password picker to generate a password, then Save and Fill to store the login before filling it.").font(.caption).foregroundStyle(.secondary)
        }
        .task {
            while !Task.isCancelled {
                status = await AutoFillPublisher.shared.status()
                do { try await Task.sleep(for: .seconds(2)) } catch { return }
            }
        }
    }
    private var title: String {
        switch status.phase {
        case .disabled: "2ndPass AutoFill is disabled"
        case .updating: "Updating suggestions…"
        case .current: "Suggestions are up to date"
        case .failed: "Suggestions need attention"
        case .notUpdated: "Suggestions have not been updated"
        }
    }
}
