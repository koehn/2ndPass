import ArgumentParser
import Foundation
import MopCore
import MopVault

@main
struct Mop: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mop",
        abstract: "Read and manage an encrypted vault using your Mac's Secure Enclave.",
        version: "0.4.0",
        subcommands: [Read.self, Write.self, List.self, Delete.self, Run.self, Inject.self, Vault.self, Device.self, Completion.self]
    )

    static func main() async {
        do {
            var command = try parseAsRoot()
            if var asyncCommand = command as? any AsyncParsableCommand { try await asyncCommand.run() }
            else { try command.run() }
        } catch let error as MopError {
            IO.diagnostic("mop: \(error.errorDescription ?? "Operation failed.")\n")
            exit(withError: ExitCode(error.exitCode))
        } catch {
            if exitCode(for: error) == .success { exit(withError: error) }
            // Parser diagnostics can echo unexpected arguments. Do not accidentally
            // reveal a secret supplied as an unsupported positional argument.
            IO.diagnostic("mop: Invalid command arguments. Use 'mop --help' or 'mop <command> --help'.\n")
            exit(withError: ExitCode(2))
        }
    }

}

struct Read: AsyncParsableCommand {
    @OptionGroup var storage: VaultOptions
    static let configuration = CommandConfiguration(abstract: "Read one secret field.")
    @Argument(help: "A mop://vault/item/[section/]field reference.") var reference: String
    @OptionGroup var output: OutputOptions
    @Flag(name: [.short, .long], help: "Do not append a newline.") var noNewline = false

    func run() async throws {
        let destination = try output.destination(storage: storage)
        let value = try await storage.service.read(SecretReference(reference))
        try output.emit(value + (noNewline ? "" : "\n"), to: destination)
    }
}

struct Write: AsyncParsableCommand {
    @OptionGroup var storage: VaultOptions
    static let configuration = CommandConfiguration(abstract: "Create a field from a hidden prompt or UTF-8 stdin.")
    @Argument var reference: String
    @Flag(help: "Replace an existing field; fails if it does not exist.") var replace = false

    func run() async throws {
        try storage.requireOnline()
        let reference = try SecretReference(reference)
        let value = try IO.secret()
        try await storage.service.write(reference, value: value, replace: replace)
    }
}

struct List: AsyncParsableCommand {
    @OptionGroup var storage: VaultOptions
    static let configuration = CommandConfiguration(abstract: "List references without secret values.")
    @Option(help: "Filter by a decoded, case-sensitive vault name.") var vault: String?
    @Flag(help: "Output a JSON array of reference strings.") var json = false

    func run() async throws {
        let references = try await storage.service.list(vault: vault).map(\.description)
        if json {
            let data = try JSONEncoder().encode(references)
            try IO.output(String(decoding: data, as: UTF8.self) + "\n")
        } else {
            try IO.output(references.isEmpty ? "" : references.joined(separator: "\n") + "\n")
        }
    }
}

struct Delete: AsyncParsableCommand {
    @OptionGroup var storage: VaultOptions
    static let configuration = CommandConfiguration(abstract: "Delete exactly one field after authentication.")
    @Argument var reference: String

    func run() async throws { try storage.requireOnline(); try await storage.service.delete(SecretReference(reference)) }
}

struct Run: AsyncParsableCommand {
    @OptionGroup var storage: VaultOptions
    static let configuration = CommandConfiguration(
        abstract: "Resolve environment references and execute a command. Resolved secrets are masked on stdout and stderr by default.",
        discussion: "Usage: mop run [--env-file FILE] -- COMMAND [ARGS...]. Later dotenv files override earlier files and inherited variables."
    )
    @Option(help: "Literal dotenv file. May be repeated.", completion: .file()) var envFile: [String] = []
    @Flag(help: "Disable output masking and preserve direct execution and terminal behavior.") var noMasking = false
    @Argument(parsing: .postTerminator, help: "Command and arguments after --; no implicit shell.") var command: [String] = []

    func run() async throws {
        try Execute.validate(command)
        let files = try envFile.map { try IO.input(file: $0) }
        let environment = try await storage.service.resolvedEnvironment(inherited: ProcessInfo.processInfo.environment, files: files)
        if noMasking { try Execute.run(command, environment: environment.variables) }
        try MaskedExecute.run(command, environment: environment.variables, secrets: environment.secrets)
    }
}

struct Inject: AsyncParsableCommand {
    @OptionGroup var storage: VaultOptions
    static let configuration = CommandConfiguration(abstract: "Resolve {{ mop://vault/item/[section/]field }} placeholders.")
    @OptionGroup var output: OutputOptions
    @Option(name: [.short, .long], help: "Read a UTF-8 template file instead of stdin.", completion: .file()) var inFile: String?

    func run() async throws {
        let destination = try output.destination(storage: storage)
        let result = try await storage.service.inject(IO.input(file: inFile), variables: ProcessInfo.processInfo.environment)
        try output.emit(result, to: destination)
    }
}
