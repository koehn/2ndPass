import Foundation

/// A bounded, notification-driven wait. Timeout returns the durable receipt's
/// actual status; it does not roll back a local save or imply delivery failed.
public enum MutationDeliveryWaiter {
    public static func wait(repository: EncryptedItemRepository, mutationID: UUID,
                            account: String, timeout: Duration) async throws -> MutationDeliveryReceipt {
        guard timeout > .zero else {
            guard let receipt = try await repository.mutationReceipt(id: mutationID, account: account) else {
                throw ItemRepositoryError.missingMutation
            }
            return receipt
        }
        return try await withThrowingTaskGroup(of: MutationDeliveryReceipt.self) { group in
            group.addTask {
                // Subscribe before reading, so an acknowledgement between those
                // operations cannot leave a caller waiting for a missed wakeup.
                let changes = await repository.changes()
                for await _ in changes {
                    try Task.checkCancellation()
                    guard let receipt = try await repository.mutationReceipt(id: mutationID, account: account) else {
                        throw ItemRepositoryError.missingMutation
                    }
                    if receipt.status != .queued { return receipt }
                }
                throw CancellationError()
            }
            group.addTask {
                try await Task.sleep(for: timeout)
                guard let receipt = try await repository.mutationReceipt(id: mutationID, account: account) else {
                    throw ItemRepositoryError.missingMutation
                }
                return receipt
            }
            defer { group.cancelAll() }
            guard let result = try await group.next() else { throw CancellationError() }
            try Task.checkCancellation()
            return result
        }
    }
}
