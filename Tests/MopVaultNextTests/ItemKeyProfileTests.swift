import CryptoKit
import Foundation
import LocalAuthentication
import Testing
@testable import MopVaultNext

// Disposable primitive-level comparison, deliberately not a production format.
private struct BenchField {
    let index: Int
    let aad: Data
    var ciphertext: Data
}
private struct BenchGroup {
    let id: String
    var generation: UInt64
    var envelopes: [String: KeyEnvelope]
    var fields: [BenchField]
}
private func keyContext(_ group: BenchGroup, _ recipient: DevicePublicKey, _ vault: UUID) throws -> Data {
    try Codec.encode(EnvelopeContext(vault: vault, epoch: group.generation, recipient: recipient.fingerprint, object: group.id))
}
private func wrap(_ key: SymmetricKey, group: BenchGroup, recipients: [DevicePublicKey], vault: UUID) throws -> [String: KeyEnvelope] {
    try Dictionary(uniqueKeysWithValues: recipients.map {
        ($0.fingerprint, try KeyEnvelope.seal(key, to: $0.encryption, context: keyContext(group, $0, vault)))
    })
}
private func payload(_ index: Int, attachments: Bool) -> Data {
    Data(repeating: UInt8(index % 251), count: attachments && index < 17 ? 38_083_740 / 17 : 48)
}

@Test func profileItemKeyLayout() async throws {
    let env = ProcessInfo.processInfo.environment
    guard env["MOP_PROFILE_ITEM_KEYS"] == "1" else { return }
    let hardware = env["MOP_PROFILE_HARDWARE"] == "1"
    let context = LAContext()
    let owner: any DeviceOperations
    if hardware {
        _ = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "benchmark disposable 2ndPass item keys")
        owner = try EnclaveDevice(member: UUID(), context: context)
    } else { owner = try TestDevice() }
    defer { owner.close(); context.invalidate() }
    let survivor = try TestDevice(), removed = try TestDevice(), added = try TestDevice()
    defer { survivor.close(); removed.close(); added.close() }
    let recipients = [owner.identity, survivor.identity, removed.identity]
    let clock = { ProcessInfo.processInfo.systemUptime }
    for attachments in [false, true] {
        for itemKeys in [false, true] {
            let vault = UUID()
            var fixture: [BenchGroup] = []
            var index = 0
            for item in 0..<908 {
                let count = item < 839 ? 7 : 6 // Exactly 908 items and 6,287 fields.
                var fields: [BenchField] = []
                for field in 0..<count {
                    let aad = Data("prototype/\(vault)/item/\(item)/field/\(field)".utf8)
                    fields.append(BenchField(index: index, aad: aad, ciphertext: Data()))
                    index += 1
                }
                for batch in itemKeys ? [fields] : fields.map({ [$0] }) {
                    let key = SymmetricKey(size: .bits256)
                    var group = BenchGroup(id: "key-\(fixture.count)", generation: 1, envelopes: [:], fields: batch)
                    group.envelopes = try wrap(key, group: group, recipients: recipients, vault: vault)
                    for i in group.fields.indices {
                        group.fields[i].ciphertext = try AES.GCM.seal(payload(group.fields[i].index, attachments: attachments), using: key, authenticating: group.fields[i].aad).combined!
                    }
                    fixture.append(group)
                }
            }
            #expect(index == 6287)
            for operation in ["remove", "add-rewrap-all", "add-append-only"] {
                for iteration in 0..<(Int(env["MOP_PROFILE_REPEATS"] ?? "1") ?? 1) {
                    var output: [BenchGroup] = []
                    var unwrapSeconds = 0.0
                    let start = clock()
                    for old in fixture {
                        let unwrapStart = clock()
                        let key = try owner.unwrap(old.envelopes[owner.identity.fingerprint]!, context: keyContext(old, owner.identity, vault))
                        unwrapSeconds += clock() - unwrapStart
                        var next = old
                        if operation == "remove" {
                            next.generation += 1
                            let replacement = SymmetricKey(size: .bits256)
                            for i in next.fields.indices {
                                let field = old.fields[i]
                                let plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: field.ciphertext), using: key, authenticating: field.aad)
                                next.fields[i].ciphertext = try AES.GCM.seal(plaintext, using: replacement, authenticating: field.aad).combined!
                            }
                            next.envelopes = try wrap(replacement, group: next, recipients: [owner.identity, survivor.identity], vault: vault)
                        } else if operation == "add-rewrap-all" {
                            next.generation += 1
                            next.envelopes = try wrap(key, group: next, recipients: recipients + [added.identity], vault: vault)
                        } else {
                            next.envelopes.merge(try wrap(key, group: next, recipients: [added.identity], vault: vault)) { _, new in new }
                        }
                        output.append(next)
                    }
                    let elapsed = clock() - start
                    // Full plaintext and recipient checks outside the timed interval.
                    let reader = operation == "remove" ? survivor : added
                    for (old, next) in zip(fixture, output) {
                        let key = try reader.unwrap(next.envelopes[reader.identity.fingerprint]!, context: keyContext(next, reader.identity, vault))
                        for field in next.fields {
                            let plain = try AES.GCM.open(AES.GCM.SealedBox(combined: field.ciphertext), using: key, authenticating: field.aad)
                            #expect(plain == payload(field.index, attachments: attachments))
                        }
                        if operation == "remove" { #expect(next.envelopes[removed.identity.fingerprint] == nil) }
                        else { #expect(next.fields.map(\.ciphertext) == old.fields.map(\.ciphertext)) }
                        if operation == "add-append-only" {
                            for (recipient, envelope) in old.envelopes { #expect(next.envelopes[recipient] == envelope) }
                        }
                    }
                    let row: [String: Any] = ["layout": itemKeys ? "item" : "field", "operation": operation,
                        "hardware": hardware, "attachments": attachments ? 17 : 0, "attachment_bytes": attachments ? 38_083_740 : 0,
                        "items": 908, "fields": 6287, "iteration": iteration, "total_s": elapsed,
                        "unwrap_s": unwrapSeconds, "unwrap_count": fixture.count,
                        "envelopes_after": output.reduce(0) { $0 + $1.envelopes.count }]
                    print("ITEM_PROFILE_JSON " + String(decoding: try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]), as: UTF8.self))
                }
            }
        }
    }
}
