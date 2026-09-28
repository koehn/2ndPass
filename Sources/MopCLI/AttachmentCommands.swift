import ArgumentParser
import Foundation
import MopCore
import MopAppSupport

extension Item {
    struct Attachments: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "attachment", abstract: "Add or export an encrypted attachment field.", subcommands: [Add.self, Export.self])
        struct Add: AsyncParsableCommand {
            @OptionGroup var storage: VaultOptions
            @Argument(completion: .file()) var file: String
            @Option(help: "Existing item name.") var item: String
            @Option(help: "New field name.") var field: String
            func run() async throws {
                try storage.requireOnline()
                let attachment = try AttachmentFiles.read(URL(fileURLWithPath: file))
                let store = try await storage.open(); defer { store.close() }
                let catalog = try await store.catalog()
                guard var target = catalog.items.first(where: { $0.name == item }) else { throw MopError.notFound }
                let path = SecretReference.encode(field.precomposedStringWithCanonicalMapping)
                guard !field.isEmpty else { throw MopError.invalidReference }
                guard !target.fields.contains(where: { $0.path == path }) else { throw MopError.duplicate }
                var added = ItemField(path: path, type: .attachment, value: try attachment.encodedValue())
                added.label = attachment.fileName; target.fields.append(added)
                try await store.saveItem(ItemEdit(revision: catalog.revision, item: target, create: false))
                try IO.output("Attachment saved.\n")
            }
        }
        struct Export: AsyncParsableCommand {
            @OptionGroup var storage: VaultOptions
            @Argument(help: "secondpass://vault/item/field reference.") var reference: String
            @Option(help: "Destination file; must not already exist.", completion: .file()) var output: String
            func run() async throws {
                let ref = try SecretReference(reference)
                let service = storage.native(); defer { service.lock() }
                let result = try await service.execute(.read(ref), vault: storage.vault ?? ref.vault, offline: storage.offline)
                guard let value = result.value else { throw MopError.notFound }
                var attachment = try Attachment.decode(String(decoding: value, as: UTF8.self))
                defer { SecretBytes.wipe(&attachment.data) }
                try LocalFile.write(attachment.data, to: URL(fileURLWithPath: output), replace: false)
                try IO.output("Attachment exported. The destination file is unencrypted.\n")
            }
        }
    }
}
