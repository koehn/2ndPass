import Foundation

/// Deliberately contains no secret values, OS error descriptions, or user input.
public enum MopError: Error, LocalizedError, Equatable {
    case conversionRequired
    case identityPending
    case cloudInvalidRequest
    case cloudUnavailable, cloudAccount, cloudQuota, cloudThrottled, cloudPermission, cloudUncertain, offlineWrite
    case invalidVaultName, ambiguousVault, vaultSelectionMismatch, legacyVault
    case vaultDeleteUncertain, vaultDeleteCleanup, confirmationRequired, operationCancelled
    case invalidOutput
    case outputExists
    case invalidReference
    case invalidEnvironment(line: Int)
    case invalidOTP
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
        case .conversionRequired: 31
        case .identityPending: 30
        case .vaultDeleteUncertain: 27
        case .vaultDeleteCleanup: 28
        case .confirmationRequired, .operationCancelled: 2
        case .invalidVaultName: 23
        case .ambiguousVault: 24
        case .vaultSelectionMismatch: 25
        case .legacyVault: 26
        case .cloudInvalidRequest: 29
        case .cloudUnavailable: 17
        case .cloudAccount: 18
        case .cloudQuota: 19
        case .cloudThrottled: 20
        case .cloudPermission: 21
        case .cloudUncertain: 22
        case .offlineWrite: 2
        case .invalidOTP, .invalidOutput, .invalidReference, .invalidEnvironment, .invalidTemplate, .invalidProcess: 2
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
        case .invalidOTP: "Enter a valid Base32 secret or otpauth://totp URL (SHA1, SHA256, or SHA512; 6 or 8 digits)."
        case .conversionRequired: "This device-based vault requires one-time online conversion on a previously connected device. Converted vaults use account membership and iCloud Keychain."
        case .identityPending: "Waiting for your Mop identity in iCloud Keychain. Enable iCloud Passwords & Keychain on this device using the same Apple Account, then refresh. No replacement identity was created."
        case .vaultDeleteUncertain: "Vault deletion could not be confirmed. Local data was retained. Retry mop vault delete with the same UUID to reconcile."
        case .vaultDeleteCleanup: "The cloud vault was deleted, but local cleanup failed. Retry mop vault delete with the same UUID to finish cleanup."
        case .confirmationRequired: "Vault deletion requires interactive confirmation or --yes. Authentication is still required with --yes."
        case .operationCancelled: "Operation cancelled; no vault was deleted."
        case .invalidVaultName: "Invalid vault name; use 1–63 lowercase letters or digits separated by single hyphens."
        case .ambiguousVault: "Multiple vaults have this name. Select a UUID and rename the conflicting vault."
        case .vaultSelectionMismatch: "The reference does not match the selected vault or its authenticated name."
        case .legacyVault: "Legacy vault format is unsupported. Use an older Mop client to access it; no migration is provided."
        case .cloudInvalidRequest: "CloudKit rejected the request configuration. Verify the deployed record types and query indexes in the signed CloudKit environment; enrollment queries require MopRequest with a queryable recordName index."
        case .cloudUnavailable: "CloudKit is unavailable. Retry online or explicitly select --offline for cached reads."
        case .cloudAccount: "An available iCloud account matching this local binding is required."
        case .cloudQuota: "The iCloud storage quota is exceeded."
        case .cloudThrottled: "CloudKit is throttling requests. Retry later."
        case .cloudPermission: "CloudKit access was denied; verify provisioning and account permissions."
        case .cloudUncertain: "The commit outcome is uncertain. Run mop vault sync online to reconcile before writing again."
        case .offlineWrite: "This command requires online CloudKit access; offline writes are not supported."
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
        case .vaultMissing: "Vault not found. Use mop vault init or select --vault NAME-OR-UUID."
        case .invalidVault: "Vault is invalid, unsupported, or failed integrity verification."
        case .vaultConflict: "Vault changed concurrently. No committed changes were overwritten; retry the command."
        case .vaultUntrusted: "Vault key is not trusted in this local binding. Use 'mop vault trust' with a fingerprint from a trusted Mac or a revision hash of a known-good backup. Never trust a hash obtained only from the suspect file."
        case .deviceUnavailable: "Secure Enclave is unavailable in this user session. No software-key fallback is enabled."
        case .deviceNotEnrolled: "This device is not enrolled. Publish a device request and approve it on an authorized Mac, or use recovery."
        case .invalidDevice: "Device record or enrollment request is invalid, unavailable, or does not match the expected fingerprint."
        case .invalidRecovery: "Recovery key is invalid or does not belong to this vault."
        case .filePermissions: "Unsafe file type, permissions, or protected output path."
        }
    }
}
