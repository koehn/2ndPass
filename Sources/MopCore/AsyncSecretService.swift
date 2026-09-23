import Foundation

/// An authenticated command-scoped store. close() invalidates its authorization.
public protocol AsyncSecretStore: AnyObject {
    func read(_ reference: SecretReference) async throws -> String
    func write(_ reference: SecretReference, value: String, replace: Bool) async throws
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

    public func read(_ reference: SecretReference) async throws -> String {
        try await withStore { try await $0.read(reference) }
    }

    public func write(_ reference: SecretReference, value: String, replace: Bool) async throws {
        try await withStore { try await $0.write(reference, value: value, replace: replace) }
    }

    public func list(vault: String?) async throws -> [SecretReference] {
        try await withStore { try await $0.list(vault: vault).sorted() }
    }

    public func delete(_ reference: SecretReference) async throws {
        try await withStore { try await $0.delete(reference) }
    }

    private func resolve(_ references: [SecretReference]) async throws -> [SecretReference: String] {
        if references.isEmpty { return [:] }
        return try await withStore { store in
            var values: [SecretReference: String] = [:]
            for reference in references where values[reference] == nil {
                values[reference] = try await store.read(reference)
            }
            return values
        }
    }

    public func environment(inherited: [String: String], files: [String]) async throws -> [String: String] {
        try await resolvedEnvironment(inherited: inherited, files: files).variables
    }

    public func resolvedEnvironment(inherited: [String: String], files: [String]) async throws -> ResolvedEnvironment {
        var environment = inherited
        for file in files { environment.merge(try DotEnv.parse(file)) { _, new in new } }
        guard environment.allSatisfy({ !$0.key.isEmpty && !$0.key.contains("=") && !$0.key.contains("\0") && !$0.value.contains("\0") }) else {
            throw MopError.invalidProcess
        }
        var references: [String: SecretReference] = [:]
        for key in environment.keys.sorted() {
            if let value = environment[key], value.hasPrefix("mop://") {
                references[key] = try ReferenceExpansion.resolve(value, variables: environment)
            }
        }
        let values = try await resolve(references.keys.sorted().compactMap { references[$0] })
        for (key, reference) in references {
            guard let value = values[reference], !value.contains("\0") else { throw MopError.invalidProcess }
            environment[key] = value
        }
        return ResolvedEnvironment(variables: environment, secrets: Array(values.values))
    }

    public func inject(_ template: String, variables: [String: String] = [:]) async throws -> String {
        var cursor = template.startIndex
        var placeholders: [(Range<String.Index>, SecretReference)] = []
        while let opening = template.range(of: "{{", range: cursor..<template.endIndex) {
            guard let closing = Self.placeholderEnd(in: template, from: opening.upperBound) else {
                if template[opening.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("mop://") {
                    throw MopError.invalidTemplate
                }
                break
            }
            let token = template[opening.upperBound..<closing.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines)
            if token.hasPrefix("mop://") {
                placeholders.append((opening.lowerBound..<closing.upperBound, try ReferenceExpansion.resolve(token, variables: variables)))
            }
            cursor = closing.upperBound
        }
        let values = try await resolve(placeholders.map(\.1))
        var output = template
        for (range, reference) in placeholders.reversed() {
            output.replaceSubrange(range, with: values[reference]!)
        }
        return output
    }

    // A variable's closing brace is not the first brace of the template delimiter.
    private static func placeholderEnd(in text: String, from start: String.Index) -> Range<String.Index>? {
        var cursor = start
        while cursor < text.endIndex {
            if text[cursor...].hasPrefix("${") {
                guard let end = text[text.index(cursor, offsetBy: 2)...].firstIndex(of: "}") else { return nil }
                cursor = text.index(after: end)
            } else if text[cursor...].hasPrefix("}}") {
                return cursor..<text.index(cursor, offsetBy: 2)
            } else { cursor = text.index(after: cursor) }
        }
        return nil
    }

}
