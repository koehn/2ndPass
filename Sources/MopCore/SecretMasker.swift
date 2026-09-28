import Darwin
import Foundation

/// Immutable compact trie. Edge bytes reconstruct secrets, so the entire node
/// allocation is owned and wiped as well. Construction finishes before sharing.
public final class MaskPatterns: @unchecked Sendable {
    private struct Node {
        var byte: UInt8 = 0
        var child: Int = -1
        var sibling: Int = -1
        var terminal = false
    }
    private var nodes: UnsafeMutablePointer<Node>
    private var capacity = 16
    private var count = 1
    public init(secrets: [SecretBytes]) {
        nodes = .allocate(capacity: capacity)
        nodes.initialize(repeating: Node(), count: capacity)
        for secret in secrets where !secret.isEmpty {
            var parent = 0
            for byte in secret {
                if let next = next(parent, byte: byte) { parent = next; continue }
                if count == capacity {
                    let replacement = UnsafeMutablePointer<Node>.allocate(capacity: capacity * 2)
                    replacement.initialize(repeating: Node(), count: capacity * 2)
                    replacement.update(from: nodes, count: count)
                    destroy(); nodes = replacement; capacity *= 2
                }
                let index = count; count += 1
                nodes[index] = Node(byte: byte, sibling: nodes[parent].child)
                nodes[parent].child = index
                parent = index
            }
            nodes[parent].terminal = true
        }
    }
    fileprivate func next(_ parent: Int, byte: UInt8) -> Int? {
        var child = nodes[parent].child
        while child >= 0 {
            if nodes[child].byte == byte { return child }
            child = nodes[child].sibling
        }
        return nil
    }
    fileprivate func terminal(_ node: Int) -> Bool { nodes[node].terminal }
    fileprivate func hasChildren(_ node: Int) -> Bool { nodes[node].child >= 0 }
    private func destroy() {
        let bytes = capacity * MemoryLayout<Node>.stride
        let result = memset_s(nodes, bytes, 0, bytes)
        precondition(result == 0)
        nodes.deinitialize(count: capacity); nodes.deallocate()
    }
    deinit { destroy() }
}

/// Leftmost-longest byte matching. Pending prefixes and assembled output are
/// owned buffers; replacement bytes never enter the matcher.
public struct SecretMasker: Sendable {
    private let patterns: MaskPatterns
    private var pending: SecretBytes = ""
    public init(patterns: MaskPatterns) { self.patterns = patterns }

    public mutating func consume(_ data: SecretBytes, final: Bool = false) -> SecretBytes {
        let input = pending + data
        let output = SecretBuilder()
        var start = 0
        while start < input.count {
            var node = 0
            var cursor = start
            var matchEnd: Int?
            while cursor < input.count, let next = patterns.next(node, byte: input[cursor]) {
                node = next; cursor += 1
                if patterns.terminal(node) { matchEnd = cursor }
            }
            if cursor == input.count && !final && patterns.hasChildren(node) { break }
            if let end = matchEnd {
                output.append("[concealed by 2ndpass]".utf8); start = end
            } else { output.append(input[start]); start += 1 }
        }
        pending = SecretBytes(copying: input[start...])
        return output.finish()
    }
}
