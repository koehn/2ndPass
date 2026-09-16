import Foundation

/// Immutable trie shared by independent stdout/stderr filters.
public struct MaskPatterns: Sendable {
    struct Node: Sendable {
        var edges: [UInt8: Int] = [:]
        var terminal = false
    }
    let nodes: [Node]
    public init(secrets: [String]) {
        var nodes = [Node()]
        for secret in Set(secrets.map { Data($0.utf8) }) where !secret.isEmpty {
            var index = 0
            for byte in secret {
                if let next = nodes[index].edges[byte] { index = next }
                else {
                    let next = nodes.count
                    nodes.append(Node())
                    nodes[index].edges[byte] = next
                    index = next
                }
            }
            nodes[index].terminal = true
        }
        self.nodes = nodes
    }
}

/// Leftmost-longest byte matching, retaining only an unresolved pattern prefix
/// between calls. Replacement bytes never enter the matcher.
public struct SecretMasker: Sendable {
    private let patterns: MaskPatterns
    private var pending: [UInt8] = []
    public init(patterns: MaskPatterns) { self.patterns = patterns }

    public mutating func consume(_ data: Data, final: Bool = false) -> Data {
        pending.append(contentsOf: data)
        var output = Data()
        var start = 0
        while start < pending.count {
            var node = 0
            var cursor = start
            var matchEnd: Int?
            while cursor < pending.count, let next = patterns.nodes[node].edges[pending[cursor]] {
                node = next
                cursor += 1
                if patterns.nodes[node].terminal { matchEnd = cursor }
            }
            if cursor == pending.count && !final && !patterns.nodes[node].edges.isEmpty { break }
            if let end = matchEnd {
                output.append(contentsOf: "[concealed by mop]".utf8)
                start = end
            } else {
                output.append(pending[start])
                start += 1
            }
        }
        pending.removeFirst(start)
        return output
    }
}
