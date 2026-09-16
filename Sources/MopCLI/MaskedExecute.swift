import Darwin
import Dispatch
import Foundation
import MopCore
import Synchronization

// Signal handlers perform only async-signal-safe operations. CLI commands execute
// once per process; handlers are installed before spawning and removed on error.
private nonisolated(unsafe) var maskedChild: pid_t = 0
private nonisolated(unsafe) var pendingTermination: Int32 = 0
private func relayTermination(_ number: Int32) {
    pendingTermination = number
    if maskedChild > 0 { _ = kill(maskedChild, number) }
}

enum MaskedExecute {
    static func run(_ arguments: [String], environment: [String: String], secrets: [String]) throws -> Never {
        let status = try execute(arguments, environment: environment, secrets: secrets)
        let terminatingSignal = status & 0x7f
        if terminatingSignal != 0 {
            signal(terminatingSignal, SIG_DFL)
            _ = raise(terminatingSignal)
            exit(128 + terminatingSignal)
        }
        exit((status >> 8) & 0xff)
    }

    // Descriptor injection permits pipeline tests without changing the test
    // process's standard streams or introducing a CLI authentication bypass.
    static func execute(_ arguments: [String], environment: [String: String], secrets: [String],
                        input: Int32 = STDIN_FILENO, output: Int32 = STDOUT_FILENO,
                        errorOutput: Int32 = STDERR_FILENO) throws -> Int32 {
        try Execute.validate(arguments)
        pendingTermination = 0
        let patterns = MaskPatterns(secrets: secrets)
        var out = [Int32](repeating: -1, count: 2)
        var err = [Int32](repeating: -1, count: 2)
        guard pipe(&out) == 0 else { throw MopError.launch }
        guard pipe(&err) == 0 else { out.forEach { _ = close($0) }; throw MopError.launch }
        defer { (out + err).filter { $0 >= 0 }.forEach { _ = close($0) } }
        // Pipe descriptors must not overlap the child's standard descriptors.
        for index in out.indices where out[index] < 3 {
            let moved = fcntl(out[index], F_DUPFD_CLOEXEC, 3)
            guard moved >= 0 else { throw MopError.launch }
            _ = close(out[index]); out[index] = moved
        }
        for index in err.indices where err[index] < 3 {
            let moved = fcntl(err[index], F_DUPFD_CLOEXEC, 3)
            guard moved >= 0 else { throw MopError.launch }
            _ = close(err[index]); err[index] = moved
        }
        for fd in out + err {
            guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw MopError.launch }
        }
        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw MopError.launch }
        defer { posix_spawn_file_actions_destroy(&actions) }
        if input != STDIN_FILENO {
            guard posix_spawn_file_actions_adddup2(&actions, input, STDIN_FILENO) == 0 else { throw MopError.launch }
        }
        guard posix_spawn_file_actions_adddup2(&actions, out[1], STDOUT_FILENO) == 0,
              posix_spawn_file_actions_adddup2(&actions, err[1], STDERR_FILENO) == 0 else { throw MopError.launch }
        for fd in out + err {
            guard posix_spawn_file_actions_addclose(&actions, fd) == 0 else { throw MopError.launch }
        }
        let signals: [Int32] = [SIGINT, SIGTERM, SIGHUP, SIGQUIT]
        let oldHandlers = signals.map { signal($0, relayTermination) }
        let oldPipe = signal(SIGPIPE, SIG_IGN)
        defer {
            maskedChild = 0
            for (number, handler) in zip(signals, oldHandlers) { signal(number, handler) }
            signal(SIGPIPE, oldPipe)
        }
        var attributes: posix_spawnattr_t?
        guard posix_spawnattr_init(&attributes) == 0 else { throw MopError.launch }
        defer { posix_spawnattr_destroy(&attributes) }
        var defaults = sigset_t(0)
        for number in signals + [SIGPIPE] { sigaddset(&defaults, number) }
        var mask = sigset_t(0)
        guard posix_spawnattr_setsigdefault(&attributes, &defaults) == 0,
              posix_spawnattr_setsigmask(&attributes, &mask) == 0,
              posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK)) == 0 else { throw MopError.launch }
        let argv = arguments.map { strdup($0) }
        let envp = environment.keys.sorted().map { strdup($0 + "=" + environment[$0]!) }
        defer { (argv + envp).forEach { free($0) } }
        guard (argv + envp).allSatisfy({ $0 != nil }) else { throw MopError.launch }
        var child: pid_t = 0
        var denied = false
        var spawned = false
        for path in Execute.paths(arguments[0], environment: environment) {
            let code = (argv + [nil]).withUnsafeBufferPointer { args in
                (envp + [nil]).withUnsafeBufferPointer { env in
                    posix_spawn(&child, path, &actions, &attributes, args.baseAddress!, env.baseAddress!)
                }
            }
            if code == 0 { spawned = true; break }
            if code == EACCES { denied = true; continue }
            if code == ENOENT || code == ENOTDIR { continue }
            throw MopError.launch
        }
        guard spawned else { throw denied ? MopError.launch : MopError.executableNotFound }
        maskedChild = child
        if pendingTermination != 0 { _ = kill(child, pendingTermination) }
        _ = close(out[1]); out[1] = -1
        _ = close(err[1]); err[1] = -1
        let childPID = child
        let failure = Mutex(false)
        let group = DispatchGroup()
        for (source, destination) in [(out[0], output), (err[0], errorOutput)] {
            group.enter()
            DispatchQueue.global().async {
                defer { group.leave() }
                do { try pump(source: source, destination: destination, patterns: patterns) }
                catch {
                    failure.withLock { $0 = true }
                    // A child ignoring TERM must not prevent cleanup after output failure.
                    _ = kill(childPID, SIGKILL)
                }
            }
        }
        // Keep the PID reserved until the filters finish: a pump failure must
        // never signal a reused PID after the child has been reaped.
        var information = siginfo_t()
        var observed: Int32
        repeat { observed = waitid(P_PID, id_t(child), &information, WEXITED | WNOWAIT) } while observed < 0 && errno == EINTR
        group.wait()
        var status: Int32 = 0
        var waited: pid_t
        repeat { waited = waitpid(child, &status, 0) } while waited < 0 && errno == EINTR
        maskedChild = 0
        guard waited == child, !failure.withLock({ $0 }) else { throw MopError.inputOutput }
        return status
    }

    private static func pump(source: Int32, destination: Int32, patterns: MaskPatterns) throws {
        var masker = SecretMasker(patterns: patterns)
        var buffer = [UInt8](repeating: 0, count: 16_384)
        while true {
            let count = Darwin.read(source, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw MopError.inputOutput }
            let result = masker.consume(Data(buffer.prefix(count)), final: count == 0)
            try result.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let written = Darwin.write(destination, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                    if written < 0 && errno == EINTR { continue }
                    guard written > 0 else { throw MopError.inputOutput }
                    offset += written
                }
            }
            if count == 0 { return }
        }
    }
}
