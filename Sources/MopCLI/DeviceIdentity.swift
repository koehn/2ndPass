import ArgumentParser
import MopKeychain
import MopAppSupport

struct Device: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Generate public enrollment requests for hardware device keys.", subcommands: [Request.self, Identity.self])
    struct Request: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        func run() async throws {
            let result = try await storage.execute(.manage(.deviceRequest))
            if let data = result.document { try IO.output(String(decoding: data, as: UTF8.self) + "\n") }
            IO.diagnostic(result.message + "\n")
        }
    }
    struct Identity: ParsableCommand {
        func run() throws { try IO.output(SigningIdentity.accessGroup() + "\n") }
    }
}
