import Foundation
import CloudKit
import Testing
import MopCore
import MopSync
@testable import MopAppSupport

@Test func nativeItemAccountNamespacesBindContainerEnvironmentAndRealUserIdentity() throws {
    let first = try NativeItemCloudAccount.namespace(container: "iCloud.one", environment: "Development", userRecordName: "user-one")
    let production = try NativeItemCloudAccount.namespace(container: "iCloud.one", environment: "Production", userRecordName: "user-one")
    let container = try NativeItemCloudAccount.namespace(container: "iCloud.two", environment: "Development", userRecordName: "user-one")
    let account = try NativeItemCloudAccount.namespace(container: "iCloud.one", environment: "Development", userRecordName: "user-two")
    #expect(Set([first, production, container, account]).count == 4)
    #expect(try NativeItemCloudAccount.namespace(container: "iCloud.one", environment: "Development", userRecordName: "user-one") == first)
    #expect(!first.contains("user-one") && !first.contains("iCloud.one"))
    #expect(throws: MopError.cloudAccount) { try NativeItemCloudAccount.namespace(container: "iCloud.one", environment: "Development", userRecordName: CKCurrentUserDefaultName) }
    #expect(throws: MopError.cloudAccount) { try NativeItemCloudAccount.namespace(container: "iCloud.one", environment: "Development", userRecordName: "") }
}

@Test func itemAccountChangedNotificationImmediatelyAndPermanentlyInvalidatesLifetime() {
    let center = NotificationCenter()
    let lifetime = ItemCloudAccountLifetime(center: center)
    #expect(lifetime.isValid)
    center.post(name: .CKAccountChanged, object: nil)
    #expect(!lifetime.isValid)
    center.post(name: .CKAccountChanged, object: nil)
    #expect(!lifetime.isValid)
    let newLifetime = ItemCloudAccountLifetime(center: center)
    #expect(newLifetime.isValid)
    lifetime.invalidate()
    #expect(!lifetime.isValid && newLifetime.isValid)
    newLifetime.invalidate()
    #expect(!newLifetime.isValid)
}

@Test func itemStoreNamespaceSeparatesCloudContainersAndEnvironments() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-namespace-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let development = try AppStorageLocation.itemSyncDirectory(root: root, container: "iCloud.example.first", environment: "Development")
    let production = try AppStorageLocation.itemSyncDirectory(root: root, container: "iCloud.example.first", environment: "Production")
    let otherContainer = try AppStorageLocation.itemSyncDirectory(root: root, container: "iCloud.example.second", environment: "Production")
    #expect(Set([development, production, otherContainer]).count == 3)
    #expect(try AppStorageLocation.itemSyncDirectory(root: root, container: "iCloud.example.first", environment: "Development") == development)
    let scope = ItemScope(account: "same-account", vaultID: UUID(), itemID: UUID())
    for (index, directory) in [development, production, otherContainer].enumerated() {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
        #expect(try await repository.item(scope) == nil)
        _ = try await repository.commitLocalMutation(EncryptedItemVersion(scope: scope, baseVersionID: nil, ciphertext: Data([UInt8(index)])))
    }
    for (index, directory) in [development, production, otherContainer].enumerated() {
        let repository = try EncryptedItemRepository(storeURL: directory.appendingPathComponent("items.sqlite"))
        #expect(try await repository.item(scope)?.ciphertext == Data([UInt8(index)]))
    }
    #expect(throws: MopError.signing) { try AppStorageLocation.itemSyncDirectory(root: root, container: "", environment: "Production") }
    #expect(throws: MopError.signing) { try AppStorageLocation.itemSyncDirectory(root: root, container: "iCloud.example", environment: "unknown") }
}
