import CryptoKit
import Foundation
import Synchronization
import MopCore
import MopVaultNext

/// One cache per authenticated app session. Leases can be replaced when membership
/// changes without another enclave unwrap. invalidate() closes every root, including
/// roots retained by old leases, and permanently forbids new entries.
final class UnlockedDeviceCache: @unchecked Sendable {
    private struct State {
        var valid = true
        var roots: [String: Root] = [:]
    }
    private let state = Mutex(State())
    func open(_ key: String, create: () throws -> any DeviceOperations) throws -> any DeviceOperations {
        try state.withLock { value in
            guard value.valid else { throw MopError.authentication }
            let root: Root
            if let existing = value.roots[key] { root = existing }
            else { root = Root(try create()); value.roots[key] = root }
            return Lease(root)
        }
    }
    func invalidate() {
        state.withLock { value in
            value.valid = false
            value.roots.values.forEach { $0.close() }
            value.roots.removeAll()
        }
    }
    deinit { invalidate() }

    private final class Root: @unchecked Sendable {
        private struct State: @unchecked Sendable { var provider: (any DeviceOperations)? }
        let identity: DevicePublicKey
        private let state: Mutex<State>
        init(_ provider: any DeviceOperations) {
            identity = provider.identity; state = Mutex(State(provider: provider))
        }
        func withDevice<T: Sendable>(_ body: (any DeviceOperations) throws -> T) throws -> T {
            try state.withLock { value in
                guard let provider = value.provider else { throw MopError.authentication }
                try provider.checkAuthorization()
                return try body(provider)
            }
        }
        func close() {
            state.withLock { value in
                // The backend owns the shared LAContext, not a legacy key root.
                if let enclave = value.provider as? EnclaveDevice { enclave.releaseHandles() }
                else { value.provider?.close() }
                value.provider = nil
            }
        }
        deinit { close() }
    }
    private final class Lease: DeviceOperations {
        private let root: Root
        private let active = Mutex(true)
        var identity: DevicePublicKey { root.identity }
        init(_ root: Root) { self.root = root }
        private func use<T: Sendable>(_ body: (any DeviceOperations) throws -> T) throws -> T {
            try active.withLock { valid in
                guard valid else { throw MopError.authentication }
                return try root.withDevice(body)
            }
        }
        func checkAuthorization() throws { try use { try $0.checkAuthorization() } }
        func sign(_ bytes: Data) throws -> Data { try use { try $0.sign(bytes) } }
        func unwrap(_ envelope: KeyEnvelope, context: Data) throws -> SymmetricKey { try use { try $0.unwrap(envelope, context: context) } }
        func close() { active.withLock { $0 = false } }
        deinit { close() }
    }
}
