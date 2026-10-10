@preconcurrency import CloudKit
import Foundation
import Synchronization
import MopCore
import MopAuth
import MopSync
import MopVaultNext

public enum ItemRecoveryFailure: Error, LocalizedError {
    public static func message(for error: any Error) -> String {
        if Authentication.requiresRenewal(error) {
            return "Your device needs to authenticate again. Your recovery progress is saved. Choose Resume Recovery Setup and unlock when prompted."
        }
        switch error as? CloudSyncAdapterError {
        case .engineAlreadyOwned: return "Another app or extension is synchronizing your vaults. Recovery continues automatically when it releases synchronization."
        case .operationInterrupted: return "Synchronization was interrupted while preparing recovery. Your saved work will continue automatically."
        case .leaseUnavailable: return "Recovery could not access the local synchronization lock. Your saved work will retry automatically."
        default: return (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }
    case codeRequired, pending, configurationBusy, recoveryInProgress
    public var errorDescription: String? {
        switch self {
        case .codeRequired: "Enter your saved recovery code again to continue."
        case .pending: "Recovery is waiting for encrypted records or keys. It continues automatically when records and keys arrive; an existing device may need to unlock."
        case .configurationBusy: "A recovery-key change is incomplete. Resume it before creating a vault or starting another change."
        case .recoveryInProgress: "Complete recovery before opening your vaults."
        }
    }
}

