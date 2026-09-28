import CryptoKit
import Foundation
import LocalAuthentication
import Testing
import MopCore
@testable import MopVaultNext

// Opt-in profiling with synthetic data only. Never opens device keys or vaults
// belonging to the application. Use a release build for meaningful timings.
private final class ProfileDevice: DeviceOperations {
    let base: any DeviceOperations
    var unwrapSeconds = 0.0, signSeconds = 0.0
    var unwraps = 0
    init(_ base: any DeviceOperations) { self.base = base }
    var identity: DevicePublicKey { base.identity }
    func sign(_ bytes: Data) throws -> Data {
        let start = ProcessInfo.processInfo.systemUptime
        defer { signSeconds += ProcessInfo.processInfo.systemUptime - start }
        return try base.sign(bytes)
    }
    func unwrap(_ envelope: KeyEnvelope, context: Data) throws -> SymmetricKey {
        let start = ProcessInfo.processInfo.systemUptime
        defer { unwrapSeconds += ProcessInfo.processInfo.systemUptime - start; unwraps += 1 }
        return try base.unwrap(envelope, context: context)
    }
    func close() { base.close() }
    func reset() { unwrapSeconds = 0; signSeconds = 0; unwraps = 0 }
}

private struct RemovalScenario {
    let name: String
    let fields: Int
    let attachments: Int
    let attachmentBytes: Int
    let recipients: Int
}

private func fixture(_ scenario: RemovalScenario, owner: ProfileDevice) throws -> (VerifiedVault, UUID) {
    var root = try VaultEngine.create(name: "synthetic-profile", owner: owner)
    var removed: UUID!
    for _ in 1..<scenario.recipients {
        let peer = try TestDevice(member: owner.identity.member)
        let invitation = try VaultEngine.invite(member: peer.identity.member, role: .owner, to: root, owner: owner, expires: Date().addingTimeInterval(86400))
        let acceptance = try Acceptance(invitation: invitation, expectedCheckpoint: root.digest, device: peer)
        root = try VaultEngine.approve(acceptance, expectedDeviceFingerprint: peer.identity.fingerprint, in: root, owner: owner)
        removed = peer.identity.device
    }
    let header = try VaultEngine.header(root, operation: .content)
    var records: [String: SealedObject] = [:], references: [String: String] = [:]
    var items: [VaultItem] = []
    var keys: [String: ItemKey] = [:]
    var material = SymmetricKey(size: .bits256), itemID = ""
    var itemIndex = -1
    var fieldIndex = 0
    for index in 0..<scenario.fields {
        let attachment = index < scenario.attachments
        let full = scenario.fields == 6287
        let groupCount = full && itemIndex >= 839 ? 6 : 7
        if index == 0 || fieldIndex == groupCount {
            itemIndex += 1; fieldIndex = 0; itemID = UUID().uuidString
            material = SymmetricKey(size: .bits256)
            keys[itemID] = try ItemKey.wrap(material, vault: root.id, item: itemID, generation: 1, recipients: root.membership.recipients)
            items.append(VaultItem(name: "item-\(itemIndex)", fields: []))
        }
        let name = "item-\(itemIndex)", field = "field-\(fieldIndex)", id = UUID().uuidString
        fieldIndex += 1
        let count = attachment ? scenario.attachmentBytes / scenario.attachments : 48
        let bytes = Data(repeating: UInt8(index % 251), count: count)
        records[id] = try SealedObject.field(bytes, key: material, vault: root.id, item: itemID, generation: 1, id: id)
        references[name + "/" + field] = id
        items[items.count - 1].fields.append(ItemField(path: field, type: attachment ? .attachment : .password))
    }
    let revision = try Revision.seal(header: header, references: references, records: records, itemKeys: keys, items: items, signer: owner)
    return (try root.applying(revision), removed)
}

@Test func profileDeviceRemovalScenarios() async throws {
    let environment = ProcessInfo.processInfo.environment
    guard environment["MOP_PROFILE_REMOVAL"] == "1" else { return }
    let hardware = environment["MOP_PROFILE_HARDWARE"] == "1"
    let context = LAContext()
    let base: any DeviceOperations
    if hardware {
        _ = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "profile disposable 2ndPass encryption keys")
        base = try EnclaveDevice(member: UUID(), context: context)
    } else { base = try TestDevice() }
    let owner = ProfileDevice(base)
    defer { owner.close(); context.invalidate() }
    let scenarios = [
        RemovalScenario(name: "100-fields", fields: 100, attachments: 0, attachmentBytes: 0, recipients: 3),
        RemovalScenario(name: "908-fields", fields: 908, attachments: 0, attachmentBytes: 0, recipients: 3),
        RemovalScenario(name: "6287-fields", fields: 6287, attachments: 0, attachmentBytes: 0, recipients: 3),
        RemovalScenario(name: "17-attachments-38MB", fields: 17, attachments: 17, attachmentBytes: 38_083_750, recipients: 3),
        RemovalScenario(name: "6287-fields-17-attachments", fields: 6287, attachments: 17, attachmentBytes: 38_083_750, recipients: 3),
        RemovalScenario(name: "6287-fields-5-devices", fields: 6287, attachments: 0, attachmentBytes: 0, recipients: 5),
    ]
    let repeats = Int(environment["MOP_PROFILE_REPEATS"] ?? "3") ?? 3
    for scenario in scenarios {
        if let selected = environment["MOP_PROFILE_SCENARIO"], !selected.split(separator: ",").contains(Substring(scenario.name)) { continue }
        print("PROFILE_START \(hardware ? "enclave" : "software") \(scenario.name)")
        let (root, target) = try fixture(scenario, owner: owner)
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("mop-removal-profile-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: folder) }
        for (digest, bytes) in root.loadedAttachments { try bytes.write(to: folder.appendingPathComponent(digest)) }
        for iteration in 0..<repeats {
            let clock = { ProcessInfo.processInfo.systemUptime }
            let verifyStart = clock()
            var fromDisk = try VerifiedVault(checkpoint: root.bytes, independentlyVerifiedDigest: root.digest)
            let verifySeconds = clock() - verifyStart
            let diskStart = clock()
            for digest in fromDisk.attachmentDigests {
                fromDisk = try fromDisk.loadingAttachment(Data(contentsOf: folder.appendingPathComponent(digest)), digest: digest)
            }
            let diskSeconds = clock() - diskStart
            owner.reset()
            let start = clock()
            var fieldsStart = start, fieldsEnd = start
            let changed = try VaultEngine.remove(device: target, from: fromDisk, owner: owner) { completed, total in
                if completed == 0 { fieldsStart = clock() }
                if completed == total { fieldsEnd = clock() }
            }
            let removalSeconds = clock() - start
            #expect(owner.unwraps == root.revision.itemKeys.count + 1)
            if scenario.fields == 6287 { #expect(root.revision.itemKeys.count == 908) }
            let unwrapSeconds = owner.unwrapSeconds, signSeconds = owner.signSeconds, unwraps = owner.unwraps
            let validationStart = clock()
            _ = try root.applying(changed.bytes)
            let validationSeconds = clock() - validationStart
            let catalogStart = clock()
            _ = try VaultEngine.catalog(in: changed, device: owner)
            _ = try VaultEngine.catalog(in: changed, device: owner, deleted: true)
            let catalogSeconds = clock() - catalogStart
            #if DEBUG
            let configuration = "debug"
            #else
            let configuration = "release"
            #endif
            let row: [String: Any] = ["operation": "remove", "scenario": scenario.name, "hardware": hardware, "iteration": iteration, "configuration": configuration,
                "fields": scenario.fields, "items": root.revision.itemKeys.count, "attachments": scenario.attachments, "recipients_before": scenario.recipients,
                "checkpoint_bytes": root.bytes.count, "attachment_bytes": root.loadedAttachments.values.reduce(0) { $0 + $1.count },
                "verify_s": verifySeconds, "local_attachment_load_s": diskSeconds, "remove_s": removalSeconds,
                "field_loop_s": fieldsEnd - fieldsStart, "unwrap_s": unwrapSeconds, "unwrap_count": unwraps,
                "sign_s": signSeconds, "publication_validation_s": validationSeconds, "catalogs_s": catalogSeconds]
            print("PROFILE_JSON " + String(decoding: try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]), as: UTF8.self))
            let newDevice = try TestDevice(member: owner.identity.member)
            let invitation = try VaultEngine.invite(member: newDevice.identity.member, role: .owner, to: fromDisk, owner: owner, expires: Date().addingTimeInterval(300))
            let acceptance = try Acceptance(invitation: invitation, expectedCheckpoint: fromDisk.digest, device: newDevice)
            owner.reset()
            let addStart = clock()
            let enrolled = try VaultEngine.approve(acceptance, expectedDeviceFingerprint: newDevice.identity.fingerprint, in: fromDisk, owner: owner)
            let addSeconds = clock() - addStart
            #expect(owner.unwraps == root.revision.itemKeys.count + 1)
            #expect(enrolled.attachmentDigests == root.attachmentDigests)
            let addition: [String: Any] = ["operation": "add", "scenario": scenario.name, "hardware": hardware, "iteration": iteration,
                "configuration": configuration, "fields": scenario.fields, "items": root.revision.itemKeys.count,
                "total_s": addSeconds, "unwrap_s": owner.unwrapSeconds, "unwrap_count": owner.unwraps]
            print("PROFILE_JSON " + String(decoding: try JSONSerialization.data(withJSONObject: addition, options: [.sortedKeys]), as: UTF8.self))
            #expect(changed.membership.role(of: owner.identity) == .owner)
            #expect(!changed.membership.devices.contains { $0.device == target })
        }
    }
}
