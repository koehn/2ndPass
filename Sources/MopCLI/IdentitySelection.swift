import ArgumentParser
import Foundation
import MopCore
import MopLocalIdentity

/// Shared selection syntax for identity consumers, independent of storage type.
struct IdentitySelection {
    let reference: ItemReference

    init(_ selector: String, vault: String?) throws {
        if selector.contains("://") {
            let reference = try ItemReference(selector)
            if let vault, (UUID(uuidString: vault)?.uuidString.lowercased() ?? vault) != reference.vault,
               !(LocalVault.isLocal(vault) && LocalVault.isLocal(reference.vault)) {
                throw ValidationError("--vault conflicts with the identity reference's vault.")
            }
            self.reference = reference
        } else {
            guard let vault else { throw ValidationError("Specify --vault with an identity name, or use sp://VAULT/NAME.") }
            reference = try ItemReference(vault: vault, name: selector)
        }
    }

    // Backend dispatch is centralized here. Future cloud identity support belongs
    // here rather than changing the command syntax or interpreting keys as local.
    func openStore() throws -> LocalIdentityStore {
        try Self.requireSupportedBackend(reference.vault)
        return try LocalIdentityStore.open()
    }

    static func requireSupportedBackend(_ vault: String) throws {
        guard LocalVault.isLocal(vault) else {
            throw ValidationError("Identity operations in vault '\(vault)' are not implemented yet.")
        }
    }
}
