import Foundation

/// An authenticated command-scoped store. close() invalidates its authorization.
public protocol SecretStore: AnyObject {
    func read(_ reference: SecretReference) throws -> SecretBytes
    func write(_ reference: SecretReference, value: SecretBytes, replace: Bool) throws
    func list(vault: String?) throws -> [SecretReference]
    func delete(_ reference: SecretReference) throws
    func close()
}

public struct ResolvedEnvironment {
    public let variables: [String: SecretBytes]
    public let secrets: [SecretBytes]
}

public struct SecretService {
    private let openStore: () throws -> any SecretStore

    public init(openStore: @escaping () throws -> any SecretStore) { self.openStore = openStore }

    private func withStore<T>(_ body: (any SecretStore) throws -> T) throws -> T {
        let store = try openStore()
        defer { store.close() }
        return try body(store)
    }

    public func read(_ reference: SecretReference) throws -> SecretBytes {
        try withStore { try $0.read(reference) }
    }

    public func write(_ reference: SecretReference, value: SecretBytes, replace: Bool) throws {
        try withStore { try $0.write(reference, value: value, replace: replace) }
    }

    public func list(vault: String?) throws -> [SecretReference] {
        try withStore { try $0.list(vault: vault).sorted() }
    }

    public func delete(_ reference: SecretReference) throws {
        try withStore { try $0.delete(reference) }
    }

    private func resolve(_ references: [SecretReference]) throws -> [SecretReference: SecretBytes] {
        if references.isEmpty { return [:] }
        return try withStore { store in
            var values: [SecretReference: SecretBytes] = [:]
            for reference in references where values[reference] == nil {
                values[reference] = try store.read(reference)
            }
            return values
        }
    }

    public func environment(inherited: [String: String], files: [SecretBytes]) throws -> [String: SecretBytes] {
        try resolvedEnvironment(inherited: inherited, files: files).variables
    }

    public func resolvedEnvironment(inherited: [String: String], files: [SecretBytes]) throws -> ResolvedEnvironment {
        var environment = inherited.mapValues { SecretBytes(utf8: $0) }
        for file in files { environment.merge(try DotEnv.parse(file)) { _, new in new } }
        let references = try SecretParsing.references(in: environment)
        let values = try resolve(references.keys.sorted().compactMap { references[$0] })
        for (key, reference) in references {
            guard let value = values[reference], !value.contains(0) else { throw MopError.invalidProcess }
            environment[key] = value
        }
        return ResolvedEnvironment(variables: environment, secrets: Array(values.values))
    }

    public func inject(_ template: SecretBytes, variables: [String: String] = [:]) throws -> SecretBytes {
        _ = try template.validatedUTF8()
        let placeholders = try SecretParsing.placeholders(template, variables: variables)
        let values = try resolve(placeholders.map(\.1))
        return SecretParsing.render(template, placeholders: placeholders, values: values)
    }
}
