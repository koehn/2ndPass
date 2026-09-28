import ArgumentParser
import Foundation
import MopCore
import MopVaultNext
import MopAppSupport

struct VaultOptions: ParsableArguments {
    @Option(help: "Vault name or UUID.") var vault: String?
    @Option(help: "Device-local state directory; never synchronize it.", completion: .directory) var stateDirectory: String?
    @Flag(help: "Read a previously verified encrypted checkpoint. Remote revocation cannot be checked.") var offline = false
    var stateURL: URL { stateDirectory.map { URL(fileURLWithPath: $0) } ?? AppStorageLocation.defaultState }
    var selection: String? { vault }
    func validate() throws { if let vault, UUID(uuidString: vault) == nil { try VaultName.validate(vault) } }
    func requireOnline() throws { guard !offline else { throw MopError.offlineWrite } }
    func native() -> NativeVaultService { NativeVaultService(state: stateURL) }
    func execute(_ operation: VaultOperation, selection: String? = nil) async throws -> VaultResult {
        let service = native(); defer { service.lock() }
        return try await service.execute(operation, vault: selection ?? vault, offline: offline)
    }
    func open() async throws -> CommandStore { CommandStore(options: self) }
    var service: AsyncSecretService { AsyncSecretService { CommandStore(options: self) } }
}

final class CommandStore: AsyncSecretStore {
    let options: VaultOptions
    let service: any VaultService
    private let usageStore: any ItemUsageStoring
    private var used: Set<ItemUsageIdentity> = []
    init(options: VaultOptions, service: (any VaultService)? = nil, usageStore: (any ItemUsageStoring)? = nil) {
        self.options = options; self.service = service ?? options.native()
        self.usageStore = usageStore ?? ItemUsageStore(state: options.stateURL)
    }
    func close() { service.lock() }
    func perform(_ operation: VaultOperation, reference: SecretReference? = nil) async throws -> VaultResult {
        try await service.execute(operation, vault: options.vault ?? reference?.vault, offline: options.offline)
    }
    func read(_ reference: SecretReference) async throws -> SecretBytes {
        let result = try await perform(.read(reference), reference: reference)
        guard let value = result.value else { throw MopError.notFound }
        if let identity = result.usageIdentity, used.insert(identity).inserted {
            await ItemUsageLogging.record([identity], store: usageStore)
        }
        return value
    }
    func write(_ reference: SecretReference, value: SecretBytes, replace: Bool) async throws { _ = try await perform(.write(reference, value, replace: replace), reference: reference) }
    func delete(_ reference: SecretReference) async throws { _ = try await perform(.delete(reference), reference: reference) }
    func catalog() async throws -> ItemCatalog { try await perform(.catalog).requireCatalog() }
    func saveItem(_ edit: ItemEdit) async throws { _ = try await perform(.save(edit)) }
    func list(vault: String?) async throws -> [SecretReference] {
        let result = try await service.execute(.discover, vault: nil, offline: options.offline)
        var references: [SecretReference] = []
        for row in result.vaults where vault == nil || row.name == vault || row.id == vault {
            let catalog = try await service.execute(.catalog, vault: row.id, offline: options.offline).requireCatalog()
            for item in catalog.items { for field in item.fields {
                references.append(try SecretReference(vault: catalog.vault, relativePath: SecretReference.encode(item.name) + "/" + field.path))
            } }
        }
        return references
    }
}
private func emit(_ result: VaultResult) throws {
    if let bytes = result.document { try IO.output(String(decoding: bytes, as: UTF8.self) + "\n"); IO.diagnostic(result.message + "\n") }
    else { try IO.output(result.message + "\n") }
}
private func readFile(_ path: String) throws -> Data { try LocalFile.read(URL(fileURLWithPath: path), limit: 24 * 1024 * 1024) }

struct Vault: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Manage hardware-protected personal and shared vaults.", subcommands: [Devices.self, Enrollment.self, Initialize.self, ListVaults.self, Sync.self, Rename.self, Export.self, Fingerprint.self, Members.self, Invite.self, Accept.self, Approve.self, RemoveMember.self, RemoveDevice.self, Role.self, Recovery.self, ReplaceRecovery.self, ReconcileShare.self, Import.self, DeleteVault.self])
    struct Devices: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List or remove devices across enrolled personal vaults.")
        @OptionGroup var storage: VaultOptions
        @Option(help: "Remove this device UUID. Omit to list devices.") var remove: String?
        func validate() throws {
            if let remove, UUID(uuidString: remove) == nil { throw MopError.invalidProcess }
        }
        func run() async throws {
            let operation: VaultManagement = remove.map { .removeAccountDevice(UUID(uuidString: $0)!) } ?? .devices
            let result = try await storage.execute(.manage(operation))
            struct Row: Encodable { let id: UUID; let name: String; let isCurrent: Bool }
            let rows = result.devices.map { Row(id: $0.id, name: $0.name, isCurrent: $0.isCurrent) }
            try IO.output(String(decoding: JSONEncoder().encode(rows), as: UTF8.self) + "\n")
            IO.diagnostic(result.message + "\n")
        }
    }
    struct Enrollment: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Manage own-device iCloud enrollment and explicit reconnection.")
        @OptionGroup var storage: VaultOptions
        @Argument(help: "request, restart, reconnect, cancel, status, confirm, inbox, approve, or decline") var action: String
        @Option var name = "New device"
        @Option var requestID: String?
        @Option var code: String?
        func validate() throws {
            guard ["request", "restart", "reconnect", "cancel", "status", "confirm", "inbox", "approve", "decline"].contains(action),
                  !["approve", "decline"].contains(action) || requestID.flatMap(UUID.init(uuidString:)) != nil,
                  !["approve", "confirm"].contains(action) || code != nil else { throw MopError.invalidProcess }
        }
        func run() async throws {
            let operation: VaultManagement
            switch action {
            case "request": operation = .requestEnrollment(name: name)
            case "reconnect": operation = .reconnect
            case "restart": operation = .restartEnrollment(name: name)
            case "cancel": operation = .cancelEnrollment
            case "status": operation = .checkEnrollment
            case "confirm": operation = .confirmEnrollment(code: code!)
            case "inbox": operation = .enrollmentInbox
            case "approve": operation = .approveEnrollment(id: UUID(uuidString: requestID!)!, code: code!)
            case "decline": operation = .rejectEnrollment(id: UUID(uuidString: requestID!)!)
            default: throw MopError.invalidProcess
            }
            let result = try await storage.execute(.manage(operation))
            struct Row: Encodable { let id: UUID; let name: String; let code: String?; let readyForApproval: Bool }
            let rows = result.enrollments.map { Row(id: $0.id, name: $0.request.name, code: $0.verificationCode, readyForApproval: $0.acceptance != nil) }
            try IO.output(String(decoding: JSONEncoder().encode(rows), as: UTF8.self) + "\n")
            IO.diagnostic(result.message + "\n")
        }
    }
    struct Initialize: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "init", abstract: "Create a vault on this device. Hardware recovery is optional.")
        @OptionGroup var storage: VaultOptions
        @Argument var name: String
        @Option(completion: .file()) var recoveryRequest: String?
        @Option(help: "Independently verified fingerprint of the recovery device request.") var fingerprint: String?
        func validate() throws {
            try VaultName.validate(name)
            guard (recoveryRequest == nil) == (fingerprint == nil) else { throw MopError.invalidRecovery }
        }
        func run() async throws {
            try storage.requireOnline()
            if let recoveryRequest {
                let request = try ExchangeFile.decode(DeviceRequest.self, from: readFile(recoveryRequest)); try request.validate()
                guard request.recovery, request.fingerprint == fingerprint else { throw MopError.invalidRecovery }
            }
            let id = storage.vault ?? UUID().uuidString
            IO.diagnostic("2ndpass: creation UUID \(id); retain it to reconcile an interrupted submission.\n")
            try emit(await storage.execute(.create(name: name, recovery: recoveryRequest.map { URL(fileURLWithPath: $0) }, fingerprint: fingerprint), selection: id))
        }
    }
    struct ListVaults: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "list", abstract: "List trusted vaults and iCloud vaults needing device enrollment.")
        @OptionGroup var storage: VaultOptions
        @Flag var json = false
        func run() async throws {
            let result = try await storage.execute(.discover)
            if result.deviceRemoved { IO.diagnostic("This device was removed. Run 2ndpass vault enrollment reconnect to opt in before requesting enrollment again.\n") }
            let rows = result.vaults
            if json { try IO.output(String(decoding: JSONEncoder().encode(rows), as: UTF8.self) + "\n") }
            else { for row in rows { try IO.output("\(row.name ?? "")\t\(row.id)\t\(row.format)\n") } }
        }
    }
    struct Sync: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Verify new revisions and reconcile uncertain writes; never replay a secret mutation.")
        @OptionGroup var storage: VaultOptions
        func run() async throws { try emit(await storage.execute(.sync)) }
    }
    struct Rename: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        @Argument var name: String
        func validate() throws { try VaultName.validate(name) }
        func run() async throws { try emit(await storage.execute(.rename(name))) }
    }
    struct Export: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        @Argument(completion: .file()) var file: String
        func run() async throws { try emit(await storage.execute(.export(URL(fileURLWithPath: file)))) }
    }
    struct Fingerprint: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        func run() async throws { try emit(await storage.execute(.manage(.fingerprint))) }
    }
    struct Members: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        func run() async throws {
            for member in try await storage.execute(.members).members { try IO.output("\(member.id)\t\(member.role)\n") }
        }
    }
    struct Invite: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Verify a public device request and issue a one-day invitation. JSON on stdout; share URL/checkpoint on stderr.")
        @OptionGroup var storage: VaultOptions
        @Argument(completion: .file()) var request: String
        @Option var fingerprint: String
        @Option var role: String = "editor"
        func run() async throws {
            guard let role = MemberRole(rawValue: role) else { throw MopError.invalidProcess }
            try emit(await storage.execute(.manage(.invite(request: readFile(request), fingerprint: fingerprint, role: role))))
        }
    }
    struct Accept: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Accept an independently verified invitation; return acceptance JSON to the owner.")
        @OptionGroup var storage: VaultOptions
        @Argument(completion: .file()) var invitation: String
        @Option var checkpoint: String
        @Option var shareURL: String?
        func run() async throws { try emit(await storage.execute(.manage(.accept(packet: readFile(invitation), checkpoint: checkpoint, shareURL: shareURL.flatMap(URL.init(string:)))))) }
    }
    struct Approve: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Approve the exact accepted device and grant current secrets. Stale invitations must be reissued.")
        @OptionGroup var storage: VaultOptions
        @Argument(completion: .file()) var acceptance: String
        @Option var fingerprint: String
        func run() async throws { try emit(await storage.execute(.manage(.approve(packet: readFile(acceptance), fingerprint: fingerprint)))) }
    }
    struct RemoveMember: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        @Argument var member: String
        func run() async throws {
            guard let id = UUID(uuidString: member) else { throw MopError.invalidProcess }
            try emit(await storage.execute(.manage(.removeMember(id))))
        }
    }
    struct RemoveDevice: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        @Argument var device: String
        func run() async throws {
            guard let id = UUID(uuidString: device) else { throw MopError.invalidProcess }
            try emit(await storage.execute(.manage(.removeDevice(id))))
        }
    }
    struct Role: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        @Argument var member: String
        @Argument var role: String
        func run() async throws {
            guard let id = UUID(uuidString: member), let role = MemberRole(rawValue: role) else { throw MopError.invalidProcess }
            try emit(await storage.execute(.manage(.role(id, role))))
        }
    }
    struct ReplaceRecovery: AsyncParsableCommand {
        @OptionGroup var storage: VaultOptions
        @Argument(completion: .file()) var request: String
        @Option var fingerprint: String
        func run() async throws { try emit(await storage.execute(.manage(.replaceRecovery(request: readFile(request), fingerprint: fingerprint)))) }
    }
    struct Recovery: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "recover", abstract: "Run on the enrolled recovery device. Verify backup and replacement request fingerprints independently.")
        @OptionGroup var storage: VaultOptions
        @Argument(completion: .file()) var backup: String
        @Option var checkpoint: String
        @Option(completion: .file()) var ownerRequest: String
        @Option var ownerFingerprint: String
        @Option(completion: .file()) var recoveryRequest: String
        @Option var recoveryFingerprint: String
        @Flag(help: "Create a new vault under the current account, retaining the source. Owner request must belong to this device.") var copy = false
        func run() async throws {
            let owner = try readFile(ownerRequest), recovery = try readFile(recoveryRequest)
            guard try ExchangeFile.decode(DeviceRequest.self, from: owner).fingerprint == ownerFingerprint,
                  try ExchangeFile.decode(DeviceRequest.self, from: recovery).fingerprint == recoveryFingerprint else { throw MopError.invalidIdentity }
            try emit(await storage.execute(.manage(.recoverHardware(backup: LocalFile.read(URL(fileURLWithPath: backup), limit: VerifiedVault.maximumBackupSize), checkpoint: checkpoint, owner: owner, recovery: recovery, copy: copy))))
        }
    }
    struct ReconcileShare: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Retry cloud participant permissions after a committed roster change.")
        @OptionGroup var storage: VaultOptions
        func run() async throws { try emit(await storage.execute(.manage(.reconcileShare))) }
    }
    struct Import: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Trust an independently verified v7 checkpoint for an already enrolled device; never converts old formats.")
        @OptionGroup var storage: VaultOptions
        @Argument(completion: .file()) var file: String
        @Option var checkpoint: String
        @Option(help: "Actual zone owner record name for a shared database vault; omit for your own private vault.") var sharedOwner: String?
        func run() async throws { try emit(await storage.execute(.manage(.importCheckpoint(document: LocalFile.read(URL(fileURLWithPath: file), limit: VerifiedVault.maximumBackupSize), fingerprint: checkpoint, sharedOwner: sharedOwner)))) }
    }
    struct DeleteVault: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "delete", abstract: "Delete the selected cloud vault. Backups and local ciphertext remain.")
        @OptionGroup var storage: VaultOptions
        @Option(help: "Repeat the exact vault UUID to confirm deletion.") var confirm: String
        func run() async throws {
            guard let selected = storage.vault, UUID(uuidString: selected) != nil, confirm == selected else { throw MopError.confirmationRequired }
            try emit(await storage.execute(.deleteVault))
        }
    }
}
