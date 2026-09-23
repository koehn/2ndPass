import Foundation

/// An authenticated command-scoped store. close() invalidates its authorization.
public protocol AsyncSecretStore: AnyObject {
    func read(_ reference: SecretReference) async throws -> SecretBytes
    func write(_ reference: SecretReference, value: SecretBytes, replace: Bool) async throws
    func list(vault: String?) async throws -> [SecretReference]
    func delete(_ reference: SecretReference) async throws
    func close()
}

public struct AsyncSecretService {
    private let openStore: () async throws -> any AsyncSecretStore

    public init(openStore: @escaping () async throws -> any AsyncSecretStore) { self.openStore = openStore }

    private func withStore<T>(_ body: (any AsyncSecretStore) async throws -> T) async throws -> T {
        let store = try await openStore()
        defer { store.close() }
        return try await body(store)
    }

    public func read(_ reference: SecretReference) async throws -> SecretBytes {
        try await withStore { try await $0.read(reference) }
    }

    public func write(_ reference: SecretReference, value: SecretBytes, replace: Bool) async throws {
        try await withStore { try await $0.write(reference, value: value, replace: replace) }
    }

    public func list(vault: String?) async throws -> [SecretReference] {
        try await withStore { try await $0.list(vault: vault).sorted() }
    }

    public func delete(_ reference: SecretReference) async throws {
        try await withStore { try await $0.delete(reference) }
    }

    private func resolve(_ references: [SecretReference]) async throws -> [SecretReference: SecretBytes] {
        if references.isEmpty { return [:] }
        return try await withStore { store in
            var values: [SecretReference: SecretBytes] = [:]
            for reference in references where values[reference] == nil {
                values[reference] = try await store.read(reference)
            }
            return values
        }
    }

    public func environment(inherited: [String: String], files: [SecretBytes]) async throws -> [String: SecretBytes] {
        try await resolvedEnvironment(inherited: inherited, files: files).variables
    }

    public func resolvedEnvironment(inherited: [String: String], files: [SecretBytes]) async throws -> ResolvedEnvironment {
        var environment = inherited.mapValues { SecretBytes(utf8: $0) }
        for file in files { environment.merge(try DotEnv.parse(file)) { _, new in new } }
        let references = try SecretParsing.references(in: environment)
        let values = try await resolve(references.keys.sorted().compactMap { references[$0] })
        for (key, reference) in references {
            guard let value = values[reference], !value.contains(0) else { throw MopError.invalidProcess }
            environment[key] = value
        }
        return ResolvedEnvironment(variables: environment, secrets: Array(values.values))
    }

    public func inject(_ template: SecretBytes, variables: [String: String] = [:]) async throws -> SecretBytes {
        _ = try template.validatedUTF8()
        let placeholders = try SecretParsing.placeholders(template, variables: variables)
        let values = try await resolve(placeholders.map(\.1))
        return SecretParsing.render(template, placeholders: placeholders, values: values)
    }
}
