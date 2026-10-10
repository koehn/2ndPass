import Darwin
import MopCore

enum BundleLaunch {
    /// Keep stdin, terminal, environment and exit status intact. Use the real
    /// bundle path as argv[0] too, so Foundation identifies the app after exec.
    static func replaceProcess(executable: String, arguments: [String]) throws -> Never {
        let pointers = ([executable] + arguments).map { strdup($0) }
        defer { pointers.forEach { free($0) } }
        guard pointers.allSatisfy({ $0 != nil }) else { throw MopError.launch }
        (pointers + [nil]).withUnsafeBufferPointer { argv in
            _ = execv(executable, argv.baseAddress!)
        }
        throw MopError.launch
    }
}
