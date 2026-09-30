#if os(macOS)
import Darwin
import Foundation
import MopCore

/// A process instance, not just a reusable PID. Start time survives exec.
public struct SSHAgentProcess: Equatable, Sendable {
    public let pid: pid_t
    let parent: pid_t
    let seconds: UInt64
    let microseconds: UInt64

    public static func read(_ pid: pid_t) throws -> Self {
        var info = proc_bsdinfo()
        let size = MemoryLayout<proc_bsdinfo>.size
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(size)) == size,
              info.pbi_uid == getuid(), info.pbi_ruid == getuid(), info.pbi_status != SZOMB else {
            throw MopError.authentication
        }
        return Self(pid: pid, parent: pid_t(info.pbi_ppid), seconds: info.pbi_start_tvsec, microseconds: info.pbi_start_tvusec)
    }

    func sameInstance(as other: Self) -> Bool {
        pid == other.pid && seconds == other.seconds && microseconds == other.microseconds
    }
}

/// Token comes from the kernel socket API, never from agent request data.
struct SSHAgentPeer {
    let token: audit_token_t
    let process: SSHAgentProcess
    let path: String
    var cacheKey: String { withUnsafeBytes(of: token) { Data($0).base64EncodedString() } }

    init(socket: Int32) throws {
        var token = audit_token_t()
        var size = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(socket, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) == 0,
              size == MemoryLayout<audit_token_t>.size,
              token.val.1 == getuid(), token.val.3 == getuid() else { throw MopError.authentication }
        self.token = token
        process = try SSHAgentProcess.read(pid_t(token.val.5))
        path = try Self.path(token)
        try validate(root: nil)
    }

    private static func path(_ value: audit_token_t) throws -> String {
        var token = value
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        // Checks the audit token's PID version, including exec/PID reuse.
        guard proc_pidpath_audittoken(&token, &buffer, UInt32(buffer.count)) > 0 else { throw MopError.authentication }
        return String(cString: buffer)
    }

    func validate(root: SSHAgentProcess?) throws {
        guard try Self.path(token) == path, process.sameInstance(as: try SSHAgentProcess.read(process.pid)) else {
            throw MopError.authentication
        }
        if let root {
            // Fail closed on reparenting, missing ancestry, or an exited/reused root.
            guard root.sameInstance(as: try SSHAgentProcess.read(root.pid)) else { throw MopError.authentication }
            var chain: [SSHAgentProcess] = []
            var current = try SSHAgentProcess.read(process.pid)
            var seen = Set<pid_t>()
            while !current.sameInstance(as: root) {
                guard chain.count < 128, current.parent > 1, seen.insert(current.pid).inserted else { throw MopError.authentication }
                chain.append(current)
                current = try SSHAgentProcess.read(current.parent)
            }
            chain.append(current)
            // Confirm the observed chain has not changed while traversing it.
            for entry in chain {
                guard try SSHAgentProcess.read(entry.pid) == entry else { throw MopError.authentication }
            }
        }
        guard try Self.path(token) == path else { throw MopError.authentication }
    }
}
#endif
