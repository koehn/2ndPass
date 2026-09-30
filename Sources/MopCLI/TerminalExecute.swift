import Darwin
import MopCore

private nonisolated(unsafe) var terminalChild: pid_t = 0
private nonisolated(unsafe) var terminalPendingSignal: Int32 = 0
private func relayTerminalSignal(_ number: Int32) {
    terminalPendingSignal = number
    if terminalChild > 0 { _ = kill(terminalChild, number) }
}

/// Run a child while the parent continues serving the SSH agent. Both processes
/// stay in the shell's foreground process group so the child can use the terminal.
/// Like MaskedExecute, this is called once by the CLI and owns signal handlers.
enum TerminalExecute {
    static func run(_ arguments: [String], environment: [String: SecretBytes]) throws -> Int32 {
        try Execute.validate(arguments)
        let environmentBlock = try EnvironmentBlock(environment)
        let pointers = arguments.map { strdup($0) }
        defer { pointers.forEach { free($0) } }
        guard pointers.allSatisfy({ $0 != nil }) else { throw MopError.launch }

        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw MopError.launch }
        defer { posix_spawn_file_actions_destroy(&actions) }
        // Inherit standard streams, but not the agent sockets or other open files.
        for fd in [STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO] {
            if fcntl(fd, F_GETFD) >= 0 {
                guard posix_spawn_file_actions_addinherit_np(&actions, fd) == 0 else { throw MopError.launch }
            } else if errno != EBADF { throw MopError.launch }
        }
        var attributes: posix_spawnattr_t?
        guard posix_spawnattr_init(&attributes) == 0 else { throw MopError.launch }
        defer { posix_spawnattr_destroy(&attributes) }
        let signals: [Int32] = [SIGINT, SIGTERM, SIGHUP, SIGQUIT]
        var defaults = sigset_t(0)
        for number in signals + [SIGPIPE, SIGTSTP, SIGTTIN, SIGTTOU] { sigaddset(&defaults, number) }
        var mask = sigset_t(0)
        // Deliberately omit SETPGROUP: creating a background group stops terminal I/O.
        guard posix_spawnattr_setsigdefault(&attributes, &defaults) == 0,
              posix_spawnattr_setsigmask(&attributes, &mask) == 0,
              posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else {
            throw MopError.launch
        }
        terminalPendingSignal = 0
        let oldHandlers = signals.map { signal($0, relayTerminalSignal) }
        defer {
            terminalChild = 0
            for (number, handler) in zip(signals, oldHandlers) { signal(number, handler) }
        }
        var child: pid_t = 0
        var denied = false
        var spawned = false
        for path in Execute.paths(arguments[0], environment: environment) {
            let code = (pointers + [nil]).withUnsafeBufferPointer { argv in
                environmentBlock.withPointers { env in
                    path.withUnsafeBytes { bytes in
                        posix_spawn(&child, bytes.baseAddress!.assumingMemoryBound(to: CChar.self), &actions, &attributes, argv.baseAddress!, env)
                    }
                }
            }
            if code == 0 { spawned = true; break }
            if code == EACCES { denied = true; continue }
            if code == ENOENT || code == ENOTDIR { continue }
            throw MopError.launch
        }
        guard spawned else { throw denied ? MopError.launch : MopError.executableNotFound }
        terminalChild = child
        if terminalPendingSignal != 0 { _ = kill(child, terminalPendingSignal) }
        var status: Int32 = 0
        var waited: pid_t
        repeat { waited = waitpid(child, &status, 0) } while waited < 0 && errno == EINTR
        terminalChild = 0
        guard waited == child else { throw MopError.inputOutput }
        let terminatingSignal = status & 0x7f
        return terminatingSignal == 0 ? (status >> 8) & 0xff : 128 + terminatingSignal
    }
}
