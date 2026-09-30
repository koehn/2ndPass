import Foundation

/// Deliberately contains no secret values, OS error descriptions, or user input.
public enum MopError: Error, LocalizedError, Equatable {
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
    case deviceRemovalPending
    case lastOwnerDevice
    case deviceRemoved
    case notVaultMember
    case invalidIdentity
    case invalidRecovery
    case filePermissions
    case unsupportedLocalIdentity
    case enclaveUnavailable
    case localOperationForbidden
    case localIdentityCapability
    case invalidLocalIdentity

    public var exitCode: Int32 {
        switch self {
        case .identityPending: 30
        case .vaultDeleteUncertain: 27
        case .vaultDeleteCleanup: 28
        case .confirmationRequired, .operationCancelled, .lastOwnerDevice: 2
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
        case .notVaultMember, .deviceRemoved, .deviceRemovalPending: 13
        case .invalidIdentity, .invalidRecovery: 14
        case .filePermissions: 15
        case .unsupportedLocalIdentity: 35
        case .enclaveUnavailable: 31
        case .localOperationForbidden: 32
        case .localIdentityCapability: 33
        case .invalidLocalIdentity: 34
        }
    }

    public var errorDescription: String? {
        switch self {
        case .invalidOTP: "Enter a valid Base32 secret or otpauth://totp URL (SHA1, SHA256, or SHA512; 6 or 8 digits)."
        case .deviceRemovalPending: "This device was removed, but local cleanup could not finish. Reconnect to retry cleanup before adding it again."
        case .lastOwnerDevice: "Add another owner device before removing this one. Every personal vault must retain an owner device."
        case .deviceRemoved: "This device was removed. Its local account access has been cleared. Choose Reconnect to add it again."
        case .identityPending: "This device has no usable enrolled hardware identity. Enroll it through an authorized owner device or use the separate recovery device."
        case .vaultDeleteUncertain: "Vault deletion could not be confirmed. Local data was retained. Retry sp vault delete with the same UUID to reconcile."
        case .vaultDeleteCleanup: "The cloud vault was deleted, but local cleanup failed. Retry sp vault delete with the same UUID to finish cleanup."
        case .confirmationRequired: "Vault deletion requires the exact vault UUID and --confirm. Authentication is still required."
        case .operationCancelled: "Operation cancelled; no vault was deleted."
        case .invalidVaultName: "Invalid vault name; use 1–63 lowercase letters or digits separated by single hyphens."
        case .ambiguousVault: "Multiple vaults have this name. Select a UUID and rename the conflicting vault."
        case .vaultSelectionMismatch: "The reference does not match the selected vault or its authenticated name."
        case .legacyVault: "Legacy vault format is unsupported. Use an older 2ndPass client to access it; no migration is provided."
        case .cloudInvalidRequest: "CloudKit rejected the request configuration. Verify the MopV7Revision, MopV7Attachment, MopV7Head and MopV7Enrollment record types in the signed CloudKit environment."
        case .cloudUnavailable: "CloudKit is unavailable. Retry online or explicitly select --offline for cached reads."
        case .cloudAccount: "An available iCloud account matching this local binding is required."
        case .cloudQuota: "The iCloud storage quota is exceeded."
        case .cloudThrottled: "CloudKit is throttling requests. Retry later."
        case .cloudPermission: "CloudKit access was denied; verify provisioning and account permissions."
        case .cloudUncertain: "The commit outcome is uncertain. Run sp vault sync online to reconcile before writing again."
        case .offlineWrite: "This command requires online CloudKit access; offline writes are not supported."
        case .invalidOutput: "Invalid output options; use --out-file with --force or an octal --file-mode through 0777."
        case .outputExists: "Output file already exists; use --force to replace it."
        case .invalidReference: "Invalid secret reference; use sp://vault/item/[section/]field with percent-encoded components."
        case .invalidEnvironment(let line): "Invalid literal dotenv assignment on line \(line)."
        case .invalidTemplate: "Invalid or unterminated sp template placeholder."
        case .authentication: "Authentication failed, was cancelled, or is unavailable. No further access was performed."
        case .notFound: "Secret not found."
        case .duplicate: "The requested secret, enrollment, or file already exists."
        case .keychain(let status): "Keychain operation failed (OSStatus \(status))."
        case .inputOutput: "Unable to read or write input/output."
        case .invalidUTF8: "Secret or input is not valid UTF-8."
        case .signing: "A provisioned, signed 2ndPass application bundle is required; see README.md for installation."
        case .invalidProcess: "Invalid command arguments or environment."
        case .executableNotFound: "Executable not found."
        case .launch: "Unable to execute the requested program."
        case .vaultMissing: "Vault not found. Use sp vault init or select --vault NAME-OR-UUID."
        case .invalidVault: "Vault is invalid, unsupported, or failed integrity verification."
        case .vaultConflict: "Vault changed concurrently. Refresh and review the current values before submitting the change again."
        case .vaultUntrusted: "Vault checkpoint is not trusted in this local binding. Import an encrypted checkpoint with an independently verified digest. Never trust a digest obtained only from the suspect file."
        case .notVaultMember: "This device is not an authorized vault member. Request enrollment from the owner or use the separate hardware recovery device."
        case .invalidIdentity: "Device identity or recipient key is invalid, unavailable, or does not match the expected fingerprint."
        case .invalidRecovery: "Hardware recovery identity or recovery request is invalid or does not belong to this vault."
        case .filePermissions: "Unsafe file type, permissions, or protected output path."
        case .unsupportedLocalIdentity: "This development identity uses an unsupported record format. No key was changed. Use the previous development build to delete it explicitly after registering a replacement."
        case .enclaveUnavailable: "Secure Enclave hardware is not available to this process. No software fallback is provided."
        case .localOperationForbidden: "That operation is not allowed on the device-local vault. Only newly generated hardware-bound asymmetric identities are supported, not ordinary secrets or imported private keys. No rename, share, private export, backup, or recovery."
        case .localIdentityCapability: "That operation is not supported by this identity’s key type or capability."
        case .invalidLocalIdentity: "Invalid device-local identity: the name is empty, too long, or the algorithm and protocol do not match."
        }
    }
}
