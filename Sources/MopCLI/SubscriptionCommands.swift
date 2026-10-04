import ArgumentParser
import Foundation
import MopSubscriptions
import MopSubscriptionVerification

struct Subscription: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Inspect the shared Pro subscription (reporting only).", subcommands: [Status.self], defaultSubcommand: Status.self)
    struct Status: AsyncParsableCommand {
        @Flag var json = false
        @Flag var offline = false
        func run() async throws {
            let status = await CLISubscription.status(offline: offline)
            if json {
                let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; encoder.outputFormatting = [.sortedKeys]
                print(String(decoding: try encoder.encode(status), as: UTF8.self))
            } else { print(status.diagnostic + (status.source == .cache ? " (cached)" : "")) }
        }
    }
}

enum CLISubscription {
    static func status(offline: Bool) async -> SubscriptionStatus {
        do {
            let config = try SubscriptionRuntime.configuration()
            if config.environment == "Development" { return SubscriptionStatus(.developmentExempt) }
            guard config.publicationEnabled, let appID = config.appAppleID else { return SubscriptionStatus(.unavailable) }
            let verifier = try AppleSubscriptionVerifier(appAppleID: appID)
            let cloud = SubscriptionCloud(container: config.container)
            return await SubscriptionReader(configuration: config, verifier: verifier) {
                let account = try await cloud.account()
                return try await .init(account: account, evidence: cloud.fetch(account: account))
            }.status(offline: offline)
        } catch { return SubscriptionStatus(.unavailable) }
    }
    static func reportIfNeeded(_ command: any ParsableCommand, arguments: [String]) async {
        // ArgumentParser returns a synchronous internal HelpCommand for help requests.
        // Operational commands are async except the SSH-agent entry point.
        guard command is any AsyncParsableCommand || command is SSHAgent else { return }
        // Work on parsed command types, never inspect argument values for bypasses.
        if command is Completion || command is Subscription.Status || command is Device.Identity { return }
        if let restore = command as? Vault.RestoreBackup, restore.dryRun { return }
        // Options after -- belong to a child, not to sp.
        let ownArguments = arguments.prefix { $0 != "--" }
        let status = await status(offline: ownArguments.contains("--offline"))
        if status.status != .developmentExempt {
            IO.diagnostic("sp: " + status.diagnostic + (status.source == .cache ? " (cached)" : "") + "; reporting only.\n")
        }
    }
}
