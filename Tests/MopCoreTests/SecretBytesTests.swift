import Darwin
import Foundation
import Synchronization
import Testing
@testable import MopCore

@Test func ownedStorageWipesGrowthAndLastOwnerOnSuccessAndThrow() throws {
    let releases = Mutex<[Int]>([])
    let observer: @Sendable (UnsafeRawBufferPointer) -> Void = { bytes in
        #expect(bytes.allSatisfy { $0 == 0 })
        releases.withLock { $0.append(bytes.count) }
    }
    weak var released: SecretBytes?
    do {
        let builder = SecretBuilder(onWipe: observer)
        builder.append([UInt8](repeating: 0xAB, count: 32))
        builder.append([UInt8](repeating: 0xCD, count: 33))
        let value = builder.finish()
        released = value
        #expect(value.count == 65)
        #expect(value.prefix(32).allSatisfy { $0 == 0xAB })
        #expect(value.suffix(33).allSatisfy { $0 == 0xCD })
        let alias = value
        #expect(alias === value)
        #expect(!releases.withLock { $0.contains(65) })
        withExtendedLifetime(alias) {}
    }
    #expect(released == nil)
    #expect(releases.withLock { $0.contains(32) && $0.contains(65) })
    do {
        let builder = SecretBuilder(onWipe: observer)
        builder.append([UInt8](repeating: 0xAB, count: 40))
        builder.append(0xCD) // capacity grows to 80; the unused tail must be wiped too.
        _ = builder.finish()
    }
    #expect(releases.withLock { $0.contains(80) })
    func fail() throws {
        let builder = SecretBuilder(onWipe: observer)
        builder.append([UInt8](repeating: 0xEF, count: 73))
        throw MopError.inputOutput
    }
    #expect(throws: MopError.inputOutput) { try fail() }
    #expect(releases.withLock { $0.contains(73) })
    func readFailure() throws {
        let builder = SecretBuilder(onWipe: observer)
        builder.append("secret prefix".utf8)
        _ = try builder.readChunk(descriptor: -1)
    }
    #expect(throws: MopError.inputOutput) { try readFailure() }
    #expect(releases.withLock { $0.contains(16_384 + 13) })
}

@Test func ownedUTF8ValidationPreservesBytesAndRejectsInvalidScalars() throws {
    for text in ["", "a\0b\n", "é", "e\u{301}", "🔒秘密", "\u{10FFFF}"] {
        let value = SecretBytes(utf8: text)
        #expect(try value.validatedUTF8() === value)
        #expect(value.elementsEqual(text.utf8))
        #expect(String(describing: value) == "<concealed>")
    }
    for bytes: [UInt8] in [[0x80], [0xC0, 0x80], [0xC2], [0xE0, 0x80, 0x80],
                           [0xED, 0xA0, 0x80], [0xF0, 0x80, 0x80, 0x80],
                           [0xF4, 0x90, 0x80, 0x80], [0xF5, 0x80, 0x80, 0x80], [0xC2, 0x41]] {
        #expect(throws: MopError.invalidUTF8) { try SecretBytes(copying: bytes).validatedUTF8() }
    }
}

@Test func ownedMaskTrieGrowsAndPreservesIndependentCopies() {
    let secrets = (0..<256).map { SecretBytes(copying: [UInt8($0), 0x42, 0x43]) }
    let patterns = MaskPatterns(secrets: secrets)
    var masker = SecretMasker(patterns: patterns)
    #expect(masker.consume(SecretBytes(copying: [0xFF])).isEmpty)
    var other = masker
    #expect(masker.consume(SecretBytes(copying: [0x42, 0x43]), final: true) == "[concealed by sp]")
    #expect(other.consume("", final: true) == SecretBytes(copying: [0xFF]))
    for secret in secrets {
        var filter = SecretMasker(patterns: patterns)
        #expect(filter.consume(secret, final: true) == "[concealed by sp]")
    }
}

private final class EphemeralStore: SecretStore, AsyncSecretStore {
    weak var value: SecretBytes?
    var closes = 0
    var reads = 0
    var cancel = false
    func read(_ reference: SecretReference) throws -> SecretBytes {
        if reference.field == "missing" {
            if cancel { throw CancellationError() }
            throw MopError.notFound
        }
        reads += 1
        let result = SecretBytes(utf8: "owned\n秘密")
        value = result
        return result
    }
    func write(_ reference: SecretReference, value: SecretBytes, replace: Bool) throws {}
    func list(vault: String?) throws -> [SecretReference] { [] }
    func delete(_ reference: SecretReference) throws {}
    func close() { closes += 1 }
}

@Test func resolutionReleasesFetchedValuesOnErrorAndAfterRendering() throws {
    let store = EphemeralStore()
    let service = SecretService { store }
    #expect(throws: MopError.notFound) { try service.inject("{{sp://v/i/token}}{{sp://v/i/missing}}") }
    #expect(store.value == nil)
    #expect(store.closes == 1)
    let result = try service.inject("prefix {{sp://v/i/token}} {{sp://v/i/token}} suffix")
    #expect(result == "prefix owned\n秘密 owned\n秘密 suffix")
    #expect(store.reads == 2)
    #expect(store.value == nil)
    #expect(store.closes == 2)
}

@Test func asyncResolutionReleasesValuesOnCancellationAndPreservesOutput() async throws {
    let store = EphemeralStore()
    let service = AsyncSecretService { store }
    store.cancel = true
    do {
        _ = try await service.inject("{{sp://v/i/token}}{{sp://v/i/missing}}")
        Issue.record("Expected cancellation")
    } catch is CancellationError {} catch { Issue.record("Unexpected error type") }
    #expect(store.value == nil)
    #expect(store.closes == 1)
    #expect(try await service.inject("{{sp://v/i/token}}") == "owned\n秘密")
    #expect(store.value == nil)
    #expect(store.closes == 2)
}
