import Darwin
import Foundation
import MopCore

enum Execute {
    static func validate(_ arguments: [String]) throws {
        guard let first = arguments.first, !first.isEmpty, arguments.allSatisfy({ !$0.contains("\0") }) else {
            throw MopError.invalidProcess
        }
    }

    static func paths(_ command: String, environment: [String: String]) -> [String] {
        command.contains("/") ? [command] :
            (environment["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin")
                .split(separator: ":", omittingEmptySubsequences: false)
                .map { ($0.isEmpty ? "." : String($0)) + "/" + command }
    }

    /// Replace mop, preserving its terminal, process group, signals and exit status.
    /// Unlike execvp, never falls back to a shell for an executable text file.
    static func run(_ arguments: [String], environment: [String: String]) throws -> Never {
        try validate(arguments)
        let paths = paths(arguments[0], environment: environment)
        let argumentPointers = arguments.map { strdup($0) }
        let environmentPointers = environment.keys.sorted().map { strdup($0 + "=" + environment[$0]!) }
        defer {
            argumentPointers.forEach { free($0) }
            environmentPointers.forEach { free($0) }
        }
        guard argumentPointers.allSatisfy({ $0 != nil }), environmentPointers.allSatisfy({ $0 != nil }) else {
            throw MopError.launch
        }
        let argv = argumentPointers + [nil]
        let envp = environmentPointers + [nil]
        var denied = false
        for path in paths {
            argv.withUnsafeBufferPointer { args in
                envp.withUnsafeBufferPointer { env in
                    _ = execve(path, args.baseAddress!, env.baseAddress!)
                }
            }
            switch errno {
            case ENOENT, ENOTDIR: continue
            case EACCES: denied = true
            default: throw MopError.launch
            }
        }
        throw denied ? MopError.launch : MopError.executableNotFound
    }
}
