import ArgumentParser
import MopKeychain
import MopAppSupport
import Foundation
import MopCore

struct Device: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Inspect the signed application identity.", subcommands: [Identity.self])

    struct Identity: ParsableCommand {
        func run() throws {
            // Installer checks through symlinks must also exercise the bundle
            // identity required by CloudKit's push registration.
            guard Bundle.main.bundleIdentifier != nil else { throw MopError.signing }
            try IO.output(SigningIdentity.accessGroup() + "\n")
        }
    }
}
