@preconcurrency import CoreData
import Foundation

enum RepositoryModel {
    static func make() -> NSManagedObjectModel {
        let model = NSManagedObjectModel()
        model.versionIdentifiers = ["MopEncryptedItems1"]
        model.entities = [
            entity("Item", versionAttributes() + [
                attribute("serverSystemFields", .binaryDataAttributeType, optional: true),
                attribute("acceptedVersion", .binaryDataAttributeType, optional: true),
                attribute("publicationBaseVersion", .binaryDataAttributeType, optional: true)
            ]),
            entity("AdmissionItem", versionAttributes()),
            entity("PendingMutation", versionAttributes() + [
                attribute("mutationID", .UUIDAttributeType),
                attribute("createdAt", .dateAttributeType),
                attribute("sequence", .integer64AttributeType)
            ], unique: "mutationID"),
            entity("Conflict", [
                attribute("key", .stringAttributeType), attribute("account", .stringAttributeType),
                attribute("vaultID", .UUIDAttributeType), attribute("itemID", .UUIDAttributeType),
                attribute("database", .stringAttributeType), attribute("zoneOwner", .stringAttributeType),
                attribute("conflictID", .UUIDAttributeType), attribute("local", .binaryDataAttributeType),
                attribute("remote", .binaryDataAttributeType), attribute("serverSystemFields", .binaryDataAttributeType)
            ]),
            entity("VaultBoundary", [attribute("key", .stringAttributeType),
                attribute("nonce", .UUIDAttributeType), attribute("initialization", .binaryDataAttributeType, optional: true)]),
            entity("StateBlob", [attribute("key", .stringAttributeType), attribute("value", .binaryDataAttributeType)]),
            entity("MutationReceipt", [
                attribute("key", .stringAttributeType), attribute("account", .stringAttributeType),
                attribute("scopeKey", .stringAttributeType), attribute("scope", .binaryDataAttributeType),
                attribute("mutationID", .UUIDAttributeType), attribute("versionID", .UUIDAttributeType),
                attribute("status", .stringAttributeType)
            ]),
            entity("SyncRequest", [
                attribute("key", .stringAttributeType), attribute("account", .stringAttributeType),
                attribute("database", .stringAttributeType), attribute("generation", .integer64AttributeType),
                attribute("handledGeneration", .integer64AttributeType), attribute("reason", .stringAttributeType)
            ]),
            entity("HistoryCheckpoint", [attribute("key", .stringAttributeType), attribute("value", .binaryDataAttributeType)])
        ]
        return model
    }

    private static func versionAttributes() -> [NSAttributeDescription] {
        [attribute("key", .stringAttributeType), attribute("account", .stringAttributeType),
         attribute("vaultID", .UUIDAttributeType), attribute("itemID", .UUIDAttributeType),
         attribute("database", .stringAttributeType), attribute("zoneOwner", .stringAttributeType),
         attribute("versionID", .UUIDAttributeType), attribute("baseVersionID", .UUIDAttributeType, optional: true),
         attribute("generation", .stringAttributeType),
         attribute("ciphertextSize", .integer64AttributeType),
         attribute("ciphertext", .binaryDataAttributeType), attribute("healthItemID", .UUIDAttributeType, optional: true), attribute("isTombstone", .booleanAttributeType)]
    }

    private static func attribute(_ name: String, _ type: NSAttributeType, optional: Bool = false) -> NSAttributeDescription {
        let value = NSAttributeDescription()
        value.name = name
        value.attributeType = type
        value.isOptional = optional
        return value
    }

    private static func entity(_ name: String, _ properties: [NSAttributeDescription], unique: String = "key") -> NSEntityDescription {
        let result = NSEntityDescription()
        result.name = name
        result.managedObjectClassName = "NSManagedObject"
        result.properties = properties
        result.uniquenessConstraints = [[unique]]
        return result
    }
}
