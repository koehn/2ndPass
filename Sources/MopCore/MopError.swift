import Foundation

/// Deliberately contains no secret values, OS error descriptions, or user input.
public enum MopError: Error, LocalizedError, Equatable {
    case invalidOutput
    case outputExists
    case invalidReference
    case invalidEnvironment(line: Int)
    case invalidTemplate
    case authentication
    case notFound
    case duplicate
    case keychain(Int32)
    case inputOutput
    case invalidUTF8
    case signing
    case invalidProcess
    case executableNotFound
    case launch
    case vaultMissing
    case invalidVault
    case vaultConflict
    case vaultUntrusted
    case deviceUnavailable
    case deviceNotEnrolled
    case invalidDevice
    case invalidRecovery
    case filePermissions

    public var exitCode: Int32 {
        switch self {
        case .invalidOutput, .invalidReference, .invalidEnvironment, .invalidTemplate, .invalidProcess: 2
        case .authentication: 3
        case .notFound: 4
        case .duplicate, .outputExists: 5
        case .keychain: 6
        case .inputOutput, .invalidUTF8: 7
        case .signing: 8
        case .launch: 126
        case .executableNotFound: 127
        case .vaultMissing: 9
        case .invalidVault: 10
        case .vaultConflict: 11
        case .vaultUntrusted: 16
        case .deviceUnavailable: 12
        case .deviceNotEnrolled: 13
        case .invalidDevice, .invalidRecovery: 14
        case .filePermissions: 15
        }
    }

    public var errorDescription: String? {
        switch self {
        case .invalidOutput: "Invalid output options; use --out-file with --force or an octal --file-mode through 0777."
        case .outputExists: "Output file already exists; use --force to replace it."
        case .invalidReference: "Invalid secret reference; use mop://vault/item/[section/]field with percent-encoded components."
        case .invalidEnvironment(let line): "Invalid literal dotenv assignment on line \(line)."
        case .invalidTemplate: "Invalid or unterminated mop template placeholder."
        case .authentication: "Authentication failed, was cancelled, or is unavailable. No further access was performed."
        case .notFound: "Secret not found."
        case .duplicate: "The requested secret, enrollment, or file already exists."
        case .keychain(let status): "Keychain operation failed (OSStatus \(status))."
        case .inputOutput: "Unable to read or write input/output."
        case .invalidUTF8: "Secret or input is not valid UTF-8."
        case .signing: "A provisioned, signed mop application bundle is required; see README.md for installation."
        case .invalidProcess: "Invalid command arguments or environment."
        case .executableNotFound: "Executable not found."
        case .launch: "Unable to execute the requested program."
        case .vaultMissing: "Vault file not found. Use 'mop vault init' or select an existing file with --vault-file."
        case .invalidVault: "Vault is invalid, unsupported, or failed integrity verification."
        case .vaultConflict: "Vault changed or has unresolved file versions. No changes were overwritten; use 'mop vault conflicts' and 'mop vault resolve'."
        case .vaultUntrusted: "Vault key is not trusted at this path. Use 'mop vault trust' with a fingerprint from a trusted Mac or a revision hash of a known-good backup. Never trust a hash obtained only from the suspect file."
        case .deviceUnavailable: "Secure Enclave is unavailable in this user session. No software-key fallback is enabled."
        case .deviceNotEnrolled: "This device is not enrolled. Export a device request and approve it on an authorized Mac, or use recovery."
        case .invalidDevice: "Device record or enrollment request is invalid, unavailable, or does not match the expected fingerprint."
        case .invalidRecovery: "Recovery key is invalid or does not belong to this vault."
        case .filePermissions: "Unsafe file type, permissions, or protected output path."
        }
    }
}
