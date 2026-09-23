import Foundation
import MopCore

/// One command owns all opened sessions, including on partial resolution failure.
public final class RoutedSecretStore: AsyncSecretStore {
    private let repository: CloudRepository
    private let rows: [VaultDescriptor]
    private let selection: String?
    private let open: (VaultDescriptor) async throws -> CloudSecretStore
    private let diagnostic: (String) -> Void
    private var onClose: (() -> Void)?
    private var closed = false
    private var stores: [String: CloudSecretStore] = [:]

    public init(repository: CloudRepository, rows: [VaultDescriptor], selection: String?,
                diagnostic: @escaping (String) -> Void = { _ in },
                onClose: @escaping () -> Void = {},
                open: @escaping (VaultDescriptor) async throws -> CloudSecretStore) {
        self.repository = repository; self.rows = rows; self.selection = selection
        self.open = open; self.diagnostic = diagnostic; self.onClose = onClose
    }

    private func store(_ row: VaultDescriptor) async throws -> CloudSecretStore {
        guard !closed else { throw MopError.authentication }
        if let store = stores[row.id] { return store }
        let store = try await open(row)
        guard store.name == row.name else { store.close(); throw MopError.vaultSelectionMismatch }
        stores[row.id] = store
        return store
    }

    private func resolve(_ reference: SecretReference) throws -> VaultDescriptor {
        if let selection {
            let row = try repository.resolve(selection, in: rows)
            guard row.name == reference.vault else { throw MopError.vaultSelectionMismatch }
            return row
        }
        return try repository.resolve(reference.vault, in: rows, nameOnly: true)
    }

    public func read(_ reference: SecretReference) async throws -> SecretBytes {
        try await store(resolve(reference)).read(reference)
    }
    public func write(_ reference: SecretReference, value: SecretBytes, replace: Bool) async throws {
        try await store(resolve(reference)).write(reference, value: value, replace: replace)
    }
    public func delete(_ reference: SecretReference) async throws {
        try await store(resolve(reference)).delete(reference)
    }
    public func list(vault: String?) async throws -> [SecretReference] {
        let included: [VaultDescriptor]
        if let selector = vault ?? selection {
            let row = try repository.resolve(selector, in: rows)
            if let selection, try repository.resolve(selection, in: rows).id != row.id { throw MopError.vaultSelectionMismatch }
            included = [row]
        } else {
            included = rows.filter { $0.supported && $0.enrolled }
            for row in rows where !row.supported || !row.enrolled {
                diagnostic("Skipping vault \(row.id): \(row.supported ? "not enrolled" : "unsupported legacy format; use an older client").")
            }
            for row in included { _ = try repository.resolve(row.name!, in: rows, nameOnly: true) }
        }
        var result: [SecretReference] = []
        for row in included { result += try await store(row).list(vault: nil) }
        return result.sorted()
    }
    public func close() {
        guard !closed else { return }
        closed = true
        for store in stores.values { store.close() }
        stores.removeAll()
        onClose?(); onClose = nil
    }
    deinit { close() }
}
