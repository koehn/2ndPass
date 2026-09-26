import Foundation
import MopAuth
import MopAppSupport
import MopCore
import MopVaultNext
import CloudKit

@main struct Check {
    static func run() async throws {
        let args = Array(CommandLine.arguments.dropFirst())
        guard let mode = args.first else { throw MopError.invalidProcess }
        if mode == "service-engine" {
            // This public-service probe uses ordinary vault zones. Never run it
            // in the application container: isolated local files do not isolate iCloud.
            let configuration = try DefaultVaultPlatformConfiguration().cloudConfiguration()
            guard configuration.environment == "Development", configuration.container != "iCloud.com.koehn.mop" else {
                print("service-engine requires a separately provisioned test container; refusing the application container")
                throw MopError.cloudInvalidRequest
            }
            let state = FileManager.default.temporaryDirectory.appendingPathComponent("mop-v6-native-probe-" + UUID().uuidString)
            try LocalFile.privateDirectory(state)
            let service = NativeVaultService(state: state)
            defer { service.lock() }
            let recoveryResult = try await service.execute(.manage(.deviceRequest(recovery: true)), vault: nil)
            guard let requestBytes = recoveryResult.document else { throw MopError.invalidRecovery }
            let request = try ExchangeFile.decode(DeviceRequest.self, from: requestBytes)
            let requestFile = state.appendingPathComponent("public-recovery-request.json")
            try LocalFile.write(requestBytes, to: requestFile)
            let id = UUID().uuidString
            let created = try await service.execute(.create(name: "disposable-native-probe", recovery: requestFile, fingerprint: request.fingerprint), vault: id)
            let catalog = try created.requireCatalog()
            let item = VaultItem(name: "login", type: .login, fields: [ItemField(path: "username", type: .username, value: "probe-user"), ItemField(path: "website", type: .website, value: "https://example.test"), ItemField(path: "password", type: .password, value: "disposable-public-test-password")])
            let saved = try await service.execute(.save(ItemEdit(revision: catalog.revision, item: item, create: true)), vault: id)
            guard try saved.requireCatalog().items.first?.fields.first(where: { $0.type == .password })?.value == nil else { throw MopError.invalidVault }
            let reference = try SecretReference("mop://disposable-native-probe/login/password")
            guard try await service.execute(.read(reference), vault: id).value == SecretBytes(utf8: "disposable-public-test-password") else { throw MopError.invalidVault }
            service.lock()
            guard try await service.execute(.read(reference), vault: id, offline: true).value == SecretBytes(utf8: "disposable-public-test-password") else { throw MopError.invalidVault }
            print("PASS: public NativeVaultService hardware requests, creation, typed item save, concealed catalog, read, lock, reauthentication and offline read")
            print("Retained Development zone mop-v6-\(id); state \(state.path). Only the fixed public test password was stored.")
            print("Device-only v6 Keychain identities retained; no existing vault or old-format identity accessed.")
            print("NOT TESTED: separate physical recovery device, second Apple Account, or extension process")
            return
        }
        let context = try Authentication.authorize(reason: "test disposable Mop v6 hardware credentials")
        defer { context.invalidate() }
        if mode == "cloud-engine" {
            let transport = try CloudRevisionTransport(container: "iCloud.com.koehn.mop", environment: "Development")
            let owner = try EnclaveDevice(member: UUID(), context: context)
            let recovery = try EnclaveDevice(member: owner.identity.member, context: context)
            defer { owner.close(); recovery.close() }
            let root = try VaultEngine.create(name: "disposable-v6-cloud-probe", owner: owner, recovery: recovery.identity)
            let address = try await VaultAddress(container: "iCloud.com.koehn.mop", environment: "Development", account: transport.account(),
                                                 database: .private, owner: CKCurrentUserDefaultName, vault: root.id, namespace: .probe)
            let folder = FileManager.default.temporaryDirectory.appendingPathComponent("mop-v6-cloud-probe-" + root.id.uuidString)
            let storage = try FileVerifiedStateStore(directory: folder, address: address)
            // Retain the exact root before submitting the first remote mutation.
            try root.bytes.write(to: folder.appendingPathComponent("genesis.json"), options: .atomic)
            try await transport.initialize(root, at: address)
            let coordinator = try PublicationCoordinator(address: address, checkpoint: root, transport: transport, storage: storage)
            let proposal = try VaultEngine.write("probe/password", value: SecretBytes(utf8: "disposable-test-password"), in: root, device: owner)
            try await coordinator.publish(proposal)
            _ = try await coordinator.refresh()
            guard await coordinator.offlineSnapshot().0.digest == proposal.digest else { throw MopError.invalidVault }
            let head = try await transport.head(at: address)
            try await transport.publish(proposal.digest, expectedVersion: head.version, at: address)
            do {
                try await transport.publish(root.digest, expectedVersion: head.version, at: address)
                throw MopError.invalidVault
            } catch MopError.vaultConflict { print("PASS: actual v6 transport fences a stale server version") }
            guard try await transport.revision(proposal.digest, at: address) == proposal.bytes else { throw MopError.invalidVault }
            print("PASS: actual v6 Enclave engine, immutable CloudKit asset, conditional head, durable journal and refresh")
            print("Retained disposable Development zone: mop-v6-probe-\(root.id.uuidString); local ciphertext: \(folder.path)")
            print("NOT TESTED: shared database, multiple accounts, multiple physical devices")
            return
        }
        if mode == "keychain-create" || mode == "keychain-open" {
            guard args.count == (mode == "keychain-create" ? 3 : 4),
                  args[1].hasPrefix("mop-v6-probe-"), UUID(uuidString: String(args[1].dropFirst(13))) != nil,
                  let member = UUID(uuidString: args[2]) else { throw MopError.invalidProcess }
            let device = try DeviceKeychain.open(scope: args[1], member: member, context: context, create: mode == "keychain-create")
            defer { device.close() }
            if mode == "keychain-open" { guard device.identity.fingerprint == args[3] else { throw MopError.invalidIdentity } }
            _ = try device.sign(Data("mop-v6-disposable-keychain-probe".utf8))
            print("PASS: provisioned device Keychain \(mode), hardware signature; fingerprint \(device.identity.fingerprint)")
            print("Retained disposable item: scope \(args[1]), member \(args[2]); no existing identity accessed/deleted")
            return
        }
        guard mode == "engine" else { throw MopError.invalidProcess }
        let owner = try EnclaveDevice(member: UUID(), context: context)
        let member = try EnclaveDevice(member: UUID(), context: context)
        defer { owner.close(); member.close() }
        let recovery = try EnclaveDevice(member: owner.identity.member, context: context)
        defer { recovery.close() }
        var vault = try VaultEngine.create(name: "hardware-probe", owner: owner, recovery: recovery.identity)
        vault = try VaultEngine.write("probe/password", value: SecretBytes(utf8: "disposable-test-password"), in: vault, device: owner)
        let invite = try VaultEngine.invite(member: member.identity.member, role: .editor, to: vault, owner: owner, expires: Date().addingTimeInterval(300))
        let acceptance = try Acceptance(invitation: invite, expectedCheckpoint: vault.digest, device: member)
        vault = try VaultEngine.approve(acceptance, expectedDeviceFingerprint: member.identity.fingerprint, in: vault, owner: owner)
        guard try VaultEngine.read("probe/password", in: vault, device: member) == SecretBytes(utf8: "disposable-test-password") else { throw MopError.invalidVault }
        print("PASS: v6 create/write/invite/approve/read with separate hardware key pairs on this Mac")
        vault = try VaultEngine.remove(member: member.identity.member, from: vault, owner: owner)
        do {
            _ = try VaultEngine.read("probe/password", in: vault, device: member)
            throw MopError.invalidVault
        } catch MopError.notVaultMember { print("PASS: removed recipient denied current revision") }
        let replacement = try EnclaveDevice(member: owner.identity.member, context: context)
        defer { replacement.close() }
        let nextRecovery = try EnclaveDevice(member: owner.identity.member, context: context)
        defer { nextRecovery.close() }
        vault = try VaultEngine.recover(vault, using: recovery, owner: replacement.identity, replacementRecovery: nextRecovery.identity)
        guard try VaultEngine.read("probe/password", in: vault, device: replacement) == SecretBytes(utf8: "disposable-test-password") else { throw MopError.invalidVault }
        print("PASS: hardware recovery rotates to replacement hardware owner and recovery keys")
        replacement.close()
        do {
            _ = try VaultEngine.read("probe/password", in: vault, device: replacement)
            throw MopError.invalidVault
        } catch MopError.authentication { print("PASS: closed production provider rejects further key use") }
        print("NOT TESTED: multiple physical devices, multiple Apple Accounts, or CloudKit sharing")
    }
    static func main() async {
        do { try await run() }
        catch {
            print("BLOCKED/FAIL: \((error as NSError).domain) code \((error as NSError).code)")
            exit(1)
        }
    }
}
