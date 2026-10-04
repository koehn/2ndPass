import Foundation

public struct VaultProvisioningBinding: Codable, Equatable, Sendable {
    public let scope: VaultScope
    public let address: VaultCloudAddress
    public let setupID: String
    public let controlDigest: String
    public init(scope: VaultScope, address: VaultCloudAddress, setupID: String, controlDigest: String) {
        self.scope = scope; self.address = address; self.setupID = setupID; self.controlDigest = controlDigest
    }
}
public enum VaultProvisioningPhase: String, Codable, Sendable { case prepared, commissioningStarted, controlConfirmed, blocked }
public struct VaultProvisioningState: Codable, Equatable, Sendable {
    public let binding: VaultProvisioningBinding
    public let controlBytes: Data
    public let phase: VaultProvisioningPhase
    public let headSystemFields: Data?
}
public enum VaultControlRecordKind: Sendable { case genesis, head }
public struct ProvisioningCloudRecord: Sendable {
    public let bytes: Data
    public let systemFields: Data
    public init(bytes: Data, systemFields: Data) { self.bytes = bytes; self.systemFields = systemFields }
}
public typealias CloudControlValidator = @Sendable (VaultProvisioningBinding, Data) async throws -> Void
public protocol VaultProvisioningTransport: Sendable {
    func zoneExists(binding: VaultProvisioningBinding) async throws -> Bool
    func createZone(binding: VaultProvisioningBinding) async throws
    func readControl(_ kind: VaultControlRecordKind, binding: VaultProvisioningBinding) async throws -> ProvisioningCloudRecord?
    func createControl(_ kind: VaultControlRecordKind, binding: VaultProvisioningBinding, bytes: Data) async throws -> ProvisioningCloudRecord
}
public enum VaultProvisioningError: Error, Equatable, Sendable {
    case invalidBinding, missingInitialization, staleState, blocked, controlMismatch, zoneMissing, operationInterrupted
}

/// One explicit commissioning operation; CKSyncEngine never queues zone creation.
/// The lease is retained across every network await, including interrupted work.
public actor VaultProvisioningCoordinator {
    private let repository: EncryptedItemRepository
    private let transport: any VaultProvisioningTransport
    private let leaseURL: URL
    private let accountValidator: CloudAccountValidator
    private let accountAuthorization: any RepositoryWritePermit
    private var activePermit: ConflictPublicationPermit?
    private var generation = 0
    private var running = false
    public init(repository: EncryptedItemRepository, transport: any VaultProvisioningTransport,
                leaseURL: URL, accountValidator: @escaping CloudAccountValidator,
                accountAuthorization: any RepositoryWritePermit) {
        self.repository = repository; self.transport = transport; self.leaseURL = leaseURL; self.accountValidator = accountValidator
        self.accountAuthorization = accountAuthorization
    }
    public func stop() { generation += 1; activePermit?.invalidate() }
    public func provision(binding: VaultProvisioningBinding, controlBytes: Data,
                          authorization: any RepositoryWritePermit,
                          validator: @escaping CloudControlValidator) async throws -> VaultProvisioningState {
        guard !running else { throw VaultProvisioningError.operationInterrupted }
        running = true; defer { running = false }
        let operation = generation
        let lease = try SynchronizationLease(url: leaseURL)
        let operationPermit = ConflictPublicationPermit(lease: lease,
            authorization: ProvisioningAccountPermit(account: accountAuthorization, session: authorization))
        activePermit = operationPermit
        defer { operationPermit.invalidate(); activePermit = nil; withExtendedLifetime(lease) {} }
        try await check(operation, operationPermit)
        try await validator(binding, controlBytes)
        try await check(operation, operationPermit)
        var state = try await repository.prepareProvisioning(binding: binding, controlBytes: controlBytes, authorization: operationPermit)
        try await check(operation, operationPermit)
        guard state.phase != .blocked else { throw VaultProvisioningError.blocked }
        var exists = try await transport.zoneExists(binding: binding)
        try await check(operation, operationPermit)
        if !exists {
            guard state.phase == .prepared else {
                _ = try await repository.advanceProvisioning(state, to: .blocked, authorization: operationPermit)
                throw VaultProvisioningError.zoneMissing
            }
            try await transport.createZone(binding: binding)
            try await check(operation, operationPermit)
            exists = try await transport.zoneExists(binding: binding)
            try await check(operation, operationPermit)
            guard exists else { throw VaultProvisioningError.zoneMissing }
        }
        if state.phase == .prepared {
            state = try await repository.advanceProvisioning(state, to: .commissioningStarted, authorization: operationPermit)
            try await check(operation, operationPermit)
        }
        var head: ProvisioningCloudRecord?
        do {
        for kind in [VaultControlRecordKind.genesis, .head] {
            var record = try await transport.readControl(kind, binding: binding)
            try await check(operation, operationPermit)
            if record == nil {
                guard state.phase != .controlConfirmed else {
                    _ = try await repository.advanceProvisioning(state, to: .blocked, authorization: operationPermit)
                    throw VaultProvisioningError.controlMismatch
                }
                _ = try await transport.createControl(kind, binding: binding, bytes: controlBytes)
                try await check(operation, operationPermit)
                record = try await transport.readControl(kind, binding: binding)
                try await check(operation, operationPermit)
            }
            guard let record, record.bytes == controlBytes else {
                _ = try await repository.advanceProvisioning(state, to: .blocked, authorization: operationPermit)
                throw VaultProvisioningError.controlMismatch
            }
            try await validator(binding, record.bytes)
            try await check(operation, operationPermit)
            if case .head = kind { head = record }
        }
        } catch VaultProvisioningError.zoneMissing {
            try await repository.blockProvisioning(binding.scope)
            throw VaultProvisioningError.zoneMissing
        } catch VaultProvisioningError.controlMismatch {
            // Malformed typed records are also a durable publication failure,
            // including a previously confirmed control changed on the server.
            try await repository.blockProvisioning(binding.scope)
            throw VaultProvisioningError.controlMismatch
        }
        guard let head else { throw VaultProvisioningError.controlMismatch }
        if state.phase == .controlConfirmed { return state }
        return try await repository.advanceProvisioning(state, to: .controlConfirmed,
            headSystemFields: head.systemFields, authorization: operationPermit)
    }
    private func check(_ expected: Int, _ authorization: any RepositoryWritePermit) async throws {
        try Task.checkCancellation()
        try authorization.withWritePermission {}
        guard generation == expected, try await accountValidator() else { throw VaultProvisioningError.operationInterrupted }
        guard generation == expected else { throw VaultProvisioningError.operationInterrupted }
        try authorization.withWritePermission {}
        try Task.checkCancellation()
    }
}

private struct ProvisioningAccountPermit: RepositoryWritePermit {
    let account: any RepositoryWritePermit
    let session: any RepositoryWritePermit
    func withWritePermission<T>(_ body: () throws -> T) throws -> T {
        try account.withWritePermission { try session.withWritePermission(body) }
    }
}

/// Shared predicate used by the engine and deterministic tests without creating
/// a CloudKit container or starting native networking.
public enum VaultPublicationGate {
    public static func isReady(_ scope: VaultScope, repository: EncryptedItemRepository,
                               account: String, database: String, addresses: [VaultCloudAddress],
                               validator: CloudControlValidator?) async throws -> Bool {
        guard scope.account == account, scope.database == database, let validator,
              let state = try await repository.provisioning(scope), state.phase == .controlConfirmed,
              addresses.contains(state.binding.address),
              try await repository.admission(scope: scope)?.phase != .prepared else { return false }
        try await validator(state.binding, state.controlBytes)
        return try await repository.provisioning(scope) == state
    }
}
