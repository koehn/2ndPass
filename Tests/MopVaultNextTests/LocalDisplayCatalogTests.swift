import Foundation
import Testing
import MopCore
@testable import MopVaultNext

@Test func localDisplayCatalogAuthenticatesRowsDeviceAndScope() throws {
    let device = try TestDevice(), other = try TestDevice()
    let context = Data("account/private/vault/device/root".utf8)
    let created = try LocalDisplayCatalogKey.create(context: context, device: device)
    let item = UUID(), version = UUID(), plaintext = Data("private title and visible username".utf8)
    let row = try created.key.seal(plaintext, item: item, version: version)
    #expect(!String(decoding: row, as: UTF8.self).contains("private title"))
    let reopened = try LocalDisplayCatalogKey.open(created.envelope, context: context, device: device)
    #expect(try reopened.open(row, item: item, version: version) == plaintext)
    #expect(throws: (any Error).self) { try reopened.open(row, item: UUID(), version: version) }
    #expect(throws: (any Error).self) { try reopened.open(row, item: item, version: UUID()) }
    var damaged = row; damaged[damaged.startIndex] ^= 1
    #expect(throws: (any Error).self) { try reopened.open(damaged, item: item, version: version) }
    #expect(throws: MopError.vaultUntrusted) { try LocalDisplayCatalogKey.open(created.envelope, context: Data("other vault".utf8), device: device) }
    #expect(throws: MopError.vaultUntrusted) { try LocalDisplayCatalogKey.open(created.envelope, context: context, device: other) }
    let before = device.unwrappedContexts.count
    for _ in 0..<100 { _ = try reopened.open(row, item: item, version: version) }
    #expect(device.unwrappedContexts.count == before)
    #expect(other.unwrappedContexts.isEmpty)
}
