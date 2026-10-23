import Foundation

extension EncryptedItemRepository {
    /// Caller reverified request authority. One retry per verified observation
    /// prevents a persistent processing error from becoming a hot retry loop.
    public func resumeVerifiedGrantRequest(_ expected: SyncOperation, observation: String,
        outcome: SyncOperationOutcome, permit: any RepositoryWritePermit) throws -> Bool {
        try permit.withWritePermission {
            try transaction {
                guard expected.kind == .enrollment, expected.state == .needsAttention,
                      expected.failure == .invalidAuthority else { return false }
                let key = journalKey(expected.account, expected.database, expected.id.uuidString)
                guard let current: SyncOperation = try journalValue("SyncOperation", key: key), current == expected else {
                    throw SyncJournalError.staleOperation
                }
                let marker = blobKey(expected.account, "enrollment-recovery:" + expected.database + ":" + expected.id.uuidString)
                let previous: String? = try journalValue("StateBlob", key: marker)
                guard previous != observation else { return false }
                var resumed = current
                switch outcome {
                case .completed: resumed.state = .ready; resumed.dependencies = []; resumed.failure = nil
                case .waiting(let dependencies): resumed.state = .waitingForDependency; resumed.dependencies = dependencies; resumed.failure = .dependency
                default: return false
                }
                resumed.nextAttempt = nil; resumed.retryNotBefore = nil; resumed.revision = UUID()
                try writeJournal(observation, entity: "StateBlob", key: marker)
                try writeJournal(resumed, entity: "SyncOperation", key: key, account: expected.account, database: expected.database)
                return true
            }
        }
    }
}
