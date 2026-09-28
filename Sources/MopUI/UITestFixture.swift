// Explicit UI automation fixture, compiled only into debug Mac and simulator builds.
// It tests presentation only; cryptographic and hardware acceptance are separate.
#if DEBUG && (os(macOS) || targetEnvironment(simulator))
import Foundation
import Synchronization
import MopCore
import MopAppSupport

final class UITestVaultService: VaultService, Sendable {
    static let vaultID = "00000000-0000-0000-0000-000000000001"
    private struct State {
        var authenticatedAt: TimeInterval?
        var catalog = ItemCatalog(vault: "personal", revision: "1", items: [
            VaultItem(name: "Example Login", type: .login, fields: [
                ItemField(path: "username", type: .username, value: "sample@example.test"),
                ItemField(path: "password", type: .password),
                ItemField(path: "website", type: .website, value: "https://example.test"),
                ItemField(path: "notes", type: .notes, value: "UI automation fixture")
            ])
        ])
    }
    private let state = Mutex(State())
    var authenticatedAt: TimeInterval? { state.withLock { $0.authenticatedAt } }
    func lock() { state.withLock { $0.authenticatedAt = nil } }
    func execute(_ operation: VaultOperation, vault: String?, offline: Bool) async throws -> VaultResult {
        try state.withLock { state in
            var result = VaultResult()
            switch operation {
            case .discover:
                result.vaults = [.init(id: Self.vaultID, name: "personal", format: "mop-vault-v7", enrolled: ProcessInfo.processInfo.environment["MOP_UI_ENROLLMENT"] != "1")]
                result.defaultVault = Self.vaultID
                return result
            case .catalog:
                if ProcessInfo.processInfo.environment["MOP_UI_IDENTITY_PENDING"] == "1" { throw MopError.identityPending }
                if ProcessInfo.processInfo.environment["MOP_UI_VAULT_TRUST_FAILURE"] == "1" { throw MopError.vaultUntrusted }
                state.authenticatedAt = ProcessInfo.processInfo.systemUptime
                if ProcessInfo.processInfo.environment["MOP_UI_SEARCH_TEST"] == "1", state.catalog.items.count == 1 {
                    state.catalog.items.append(VaultItem(name: "SSH Server", fields: [
                        ItemField(path: "ssh%20username", type: .username, value: "sshd")
                    ]))
                }
                if ProcessInfo.processInfo.environment["MOP_UI_OTP_TEST"] == "1",
                   !state.catalog.items[0].fields.contains(where: { $0.type == .otp }) {
                    state.catalog.items[0].fields.insert(contentsOf: [ItemField(path: "otp", type: .otp), ItemField(path: "otp-url", type: .otp), ItemField(path: "otp-legacy", type: .concealed)], at: 0)
                }
            case .read(let reference):
                guard state.authenticatedAt != nil else { throw MopError.authentication }
                if reference.field == "otp" || reference.field == "otp-url" || reference.field == "otp-legacy" {
                    let input = reference.field == "otp" ? "JBSWY3DPEHPK3PXP" : "otpauth://totp/2ndPass:test@example.com?secret=JBSWY3DPEHPK3PXP&issuer=2ndPass"
                    let otp = try TimeBasedOTP(input), date = Date()
                    result.value = SecretBytes(utf8: try otp.code(at: date))
                    result.otpExpiresAt = otp.expires(at: date); result.otpPeriod = otp.period
                } else { result.value = "ui-fixture-password" }
                return result
            case .save(let edit):
                guard state.authenticatedAt != nil else { throw MopError.authentication }
                guard edit.revision == state.catalog.revision else { throw MopError.vaultConflict }
                state.catalog.items.removeAll { $0.name == (edit.originalName ?? edit.item.name) }
                var item = edit.item
                for index in item.fields.indices where item.fields[index].type.concealed { item.fields[index].value = nil }
                state.catalog.items.append(item)
                state.catalog.revision = UUID().uuidString
            case .passwordQuality: return result
            case .members: return result
            case .manage(.requestEnrollment), .manage(.restartEnrollment), .manage(.cancelEnrollment):
                state.authenticatedAt = ProcessInfo.processInfo.systemUptime
                return result
            case .manage(.devices), .manage(.automaticEnrollment): return result
            case .recentlyDeleted: break
            default: throw MopError.invalidProcess
            }
            result.catalog = state.catalog
            result.deletedCatalog = ItemCatalog(vault: "personal", revision: state.catalog.revision, items: [])
            return result
        }
    }
}
#endif
