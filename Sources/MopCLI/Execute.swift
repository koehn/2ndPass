import Darwin
import Foundation
import MopCore

enum Execute {
    static func validate(_ arguments: [String]) throws {
        guard let first = arguments.first, !first.isEmpty, arguments.allSatisfy({ !$0.contains("\0") }) else {
            throw MopError.invalidProcess
        }
    }

    static func paths(_ command: String, environment: [String: SecretBytes]) -> [SecretBytes] {
        let commandBytes = SecretBytes(utf8: command)
        if command.contains("/") { return [commandBytes + "\0"] }
        let path = environment["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin"
        return path.split(separator: 58, omittingEmptySubsequences: false).map { directory in
            let entry = SecretBuilder()
            if directory.isEmpty { entry.append(46) } else { entry.append(directory) }
            entry.append(47); entry.append(commandBytes); entry.append(0)
            return entry.finish()
        }
    }

    /// Replace mop, preserving its terminal, process group, signals and exit status.
    /// Unlike execvp, never falls back to a shell for an executable text file.
    static func run(_ arguments: [String], environment: [String: SecretBytes]) throws -> Never {
        try validate(arguments)
        let paths = paths(arguments[0], environment: environment)
        let argumentPointers = arguments.map { strdup($0) }
        defer { argumentPointers.forEach { free($0) } }
        let environmentBlock = try EnvironmentBlock(environment)
        guard argumentPointers.allSatisfy({ $0 != nil }) else {
            throw MopError.launch
        }
        let argv = argumentPointers + [nil]
        var denied = false
        for path in paths {
            argv.withUnsafeBufferPointer { args in
                environmentBlock.withPointers { env in
                    path.withUnsafeBytes { bytes in
                        _ = execve(bytes.baseAddress!.assumingMemoryBound(to: CChar.self), args.baseAddress!, env)
                    }
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
