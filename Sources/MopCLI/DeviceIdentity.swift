import ArgumentParser
import MopKeychain

/// Retained for packaging, installation and upgrades from earlier releases.
/// Account identities replaced device management, but signing validation remains
/// a local, noninteractive check and does not access vaults or create keys.
struct Device: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Application signing diagnostics.",
        shouldDisplay: false, subcommands: [Identity.self])

    struct Identity: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Verify application signing and the private Keychain group.")
        func run() throws { try IO.output(SigningIdentity.accessGroup() + "\n") }
    }
}
