import Foundation
import Darwin
import MopCore
import Synchronization

public struct CLIResult: Sendable {
    public let output: Data
    public let diagnostic: String
    public var text: String { String(decoding: output, as: UTF8.self) }
    public func decode<T: Decodable>(_ type: T.Type) throws -> T {
        do { return try JSONDecoder().decode(type, from: output) }
        catch { throw CLIError.malformedResponse }
    }
    public var offlineDate: String? {
        let prefix = "mop: offline cache from "
        guard let line = diagnostic.split(separator: "\n").first(where: { $0.hasPrefix(prefix) }) else { return nil }
        let date = String(line.dropFirst(prefix.count).prefix(20))
        return ISO8601DateFormatter().date(from: date) == nil ? nil : date
    }
}

public enum CLIError: LocalizedError, Sendable {
    case missingExecutable, malformedResponse, failed(Int32), launch
    public var errorDescription: String? {
        switch self {
        case .missingExecutable: return "Open the packaged Mop.app. Its bundled command-line executable is missing."
        case .malformedResponse: return "The command returned an unreadable response."
        case .launch: return "The bundled command could not be started."
        case .failed(let code):
            // Never display arbitrary subprocess diagnostics or secret output.
            let errors: [Int32: MopError] = [2: .invalidProcess, 3: .authentication, 4: .notFound,
                5: .duplicate, 6: .keychain(0), 7: .inputOutput, 8: .signing, 9: .vaultMissing,
                10: .invalidVault, 11: .vaultConflict, 12: .deviceUnavailable, 13: .deviceNotEnrolled,
                14: .invalidDevice, 15: .filePermissions, 16: .vaultUntrusted, 17: .cloudUnavailable,
                18: .cloudAccount, 19: .cloudQuota, 20: .cloudThrottled, 21: .cloudPermission,
                22: .cloudUncertain]
            return errors[code]?.errorDescription ?? "The command did not complete successfully."
        }
    }
}

public struct CLIClient: Sendable {
    public let executable: URL
    public init(executable: URL) { self.executable = executable }

    public static func arguments(_ command: [String], vault: String?, offline: Bool) -> [String] {
        command + (vault.map { ["--cloud-vault", $0] } ?? []) + (offline ? ["--offline"] : [])
    }

    public static func environment(_ inherited: [String: String]) -> [String: String] {
        var result = inherited
        result.removeValue(forKey: "MOP_CLOUD_VAULT")
        result.removeValue(forKey: "MOP_VAULT_FILE")
        return result
    }

    public func run(_ command: [String], vault: String? = nil, offline: Bool = false,
                    input: String? = nil) async throws -> CLIResult {
        let args = Self.arguments(command, vault: vault, offline: offline)
        // LocalAuthentication in the CLI blocks its own process, never the UI thread.
        return try await Task.detached { try execute(args, input: input) }.value
    }

    private func execute(_ args: [String], input: String?) throws -> CLIResult {
            guard FileManager.default.isExecutableFile(atPath: executable.path) else { throw CLIError.missingExecutable }
            let process = Process()
            process.executableURL = executable
            process.arguments = args
            // GUI selection must never inherit an invisible shell vault override.
            process.environment = Self.environment(ProcessInfo.processInfo.environment)
            let stdout = Pipe(), stderr = Pipe(), stdin = Pipe()
            process.standardOutput = stdout; process.standardError = stderr; process.standardInput = stdin
            do { try process.run() } catch { throw CLIError.launch }
            let buffers = Mutex((out: Data(), err: Data()))
            let readers = DispatchGroup()
            readers.enter()
            DispatchQueue.global().async {
                let bytes = stdout.fileHandleForReading.readDataToEndOfFile()
                buffers.withLock { $0.out = bytes }; readers.leave()
            }
            readers.enter()
            DispatchQueue.global().async {
                let bytes = stderr.fileHandleForReading.readDataToEndOfFile()
                buffers.withLock { $0.err = bytes }; readers.leave()
            }
            // A child can reject arguments before reading stdin. Do not let that
            // broken pipe terminate the GUI process with SIGPIPE.
            _ = fcntl(stdin.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1)
            // Secrets travel only through stdin, never arguments, files, or logging.
            do {
                if let input { try stdin.fileHandleForWriting.write(contentsOf: Data(input.utf8)) }
            } catch { /* The child exit status determines the authoritative outcome. */ }
            try? stdin.fileHandleForWriting.close()
            process.waitUntilExit(); readers.wait()
            guard process.terminationReason == .exit, process.terminationStatus == 0 else {
                throw CLIError.failed(process.terminationReason == .exit ? process.terminationStatus : 22)
            }
            return buffers.withLock { CLIResult(output: $0.out, diagnostic: String(decoding: $0.err, as: UTF8.self)) }
    }
}
