import ArgumentParser

struct Completion: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Generate Bash, zsh, or Fish completions without accessing secrets.")

    enum Shell: String, CaseIterable, ExpressibleByArgument { case bash, zsh, fish }
    @Argument(help: "Shell to generate completions for.") var shell: Shell

    func run() throws {
        try IO.output(Mop.completionScript(for: CompletionShell(rawValue: shell.rawValue)!) + "\n")
    }
}
