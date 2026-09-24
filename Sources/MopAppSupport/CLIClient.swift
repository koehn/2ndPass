#if os(macOS)
import Foundation
import Darwin
import MopCore
import Synchronization

public struct CLIResult: Sendable {
    public let output: SecretBytes
    public let diagnostic: SecretBytes
    public var text: String { String(decoding: output, as: UTF8.self) }
    public func decode<T: Decodable>(_ type: T.Type) throws -> T {
        do { return try output.withFoundationData { try JSONDecoder().decode(type, from: $0) } }
        catch { throw CLIError.malformedResponse }
    }
    public var offlineDate: String? {
        let prefix = "mop: offline cache from "
        guard let line = diagnostic.split(separator: 10).first(where: { $0.starts(with: prefix.utf8) }) else { return nil }
        let date = String(decoding: line.dropFirst(prefix.utf8.count).prefix(20), as: UTF8.self)
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
            if code == 17 { return "CloudKit could not complete the operation. Check your connection and retry. Refreshing account membership requires online access." }
            // Never display arbitrary subprocess diagnostics or secret output.
            let errors: [Int32: MopError] = [2: .invalidProcess, 3: .authentication, 4: .notFound,
                5: .duplicate, 6: .keychain(0), 7: .inputOutput, 8: .signing, 9: .vaultMissing,
                10: .invalidVault, 11: .vaultConflict, 13: .notVaultMember,
                14: .invalidIdentity, 15: .filePermissions, 16: .vaultUntrusted, 17: .cloudUnavailable,
                18: .cloudAccount, 19: .cloudQuota, 20: .cloudThrottled, 21: .cloudPermission,
                22: .cloudUncertain, 23: .invalidVaultName, 24: .ambiguousVault,
                25: .vaultSelectionMismatch, 26: .legacyVault, 27: .vaultDeleteUncertain, 28: .vaultDeleteCleanup,
                29: .cloudInvalidRequest]
            return errors[code]?.errorDescription ?? "The command did not complete successfully."
        }
    }
}

public struct CLIClient: Sendable {
    public let executable: URL
    public init(executable: URL) { self.executable = executable }

    public static func arguments(_ command: [String], vault: String?, offline: Bool) -> [String] {
        command + (vault.map { ["--vault", $0] } ?? []) + (offline ? ["--offline"] : [])
    }

    public static func environment(_ inherited: [String: String]) -> [String: String] {
        var result = inherited
        result.removeValue(forKey: "MOP_CLOUD_VAULT")
        return result
    }

    public func run(_ command: [String], vault: String? = nil, offline: Bool = false,
                    input: SecretBytes? = nil) async throws -> CLIResult {
        let args = Self.arguments(command, vault: vault, offline: offline)
        // LocalAuthentication in the CLI blocks its own process, never the UI thread.
        return try await Task.detached { try execute(args, input: input) }.value
    }

    private func execute(_ args: [String], input: SecretBytes?) throws -> CLIResult {
            guard FileManager.default.isExecutableFile(atPath: executable.path) else { throw CLIError.missingExecutable }
            let process = Process()
            process.executableURL = executable
            process.arguments = args
            // GUI selection must never inherit an invisible shell vault override.
            process.environment = Self.environment(ProcessInfo.processInfo.environment)
            let stdout = Pipe(), stderr = Pipe(), stdin = Pipe()
            process.standardOutput = stdout; process.standardError = stderr; process.standardInput = stdin
            do { try process.run() } catch { throw CLIError.launch }
            let buffers = Mutex((out: Result<SecretBytes, Error>.success(""), err: Result<SecretBytes, Error>.success("")))
            let readers = DispatchGroup()
            readers.enter()
            DispatchQueue.global().async {
                let bytes = Result { try SecretBytes.read(descriptor: stdout.fileHandleForReading.fileDescriptor) }
                buffers.withLock { $0.out = bytes }; readers.leave()
            }
            readers.enter()
            DispatchQueue.global().async {
                let bytes = Result { try SecretBytes.read(descriptor: stderr.fileHandleForReading.fileDescriptor) }
                buffers.withLock { $0.err = bytes }; readers.leave()
            }
            // A child can reject arguments before reading stdin. Do not let that
            // broken pipe terminate the GUI process with SIGPIPE.
            _ = fcntl(stdin.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1)
            // Secrets travel only through stdin, never arguments, files, or logging.
            do {
                if let input { try input.write(descriptor: stdin.fileHandleForWriting.fileDescriptor) }
            } catch { /* The child exit status determines the authoritative outcome. */ }
            try? stdin.fileHandleForWriting.close()
            process.waitUntilExit(); readers.wait()
            guard process.terminationReason == .exit, process.terminationStatus == 0 else {
                throw CLIError.failed(process.terminationReason == .exit ? process.terminationStatus : 22)
            }
            return try buffers.withLock { CLIResult(output: try $0.out.get(), diagnostic: try $0.err.get()) }
    }
}

#endif
