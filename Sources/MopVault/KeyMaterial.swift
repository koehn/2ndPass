import Darwin
import Foundation

enum KeyMaterial {
    /// Best effort for framework-returned Data: CoW/framework aliases cannot be erased here.
    /// Keep the value unshared and defer this immediately after obtaining it.
    static func wipe(_ data: inout Data) {
        data.withUnsafeMutableBytes { bytes in
            guard let address = bytes.baseAddress, !bytes.isEmpty else { return }
            let result = memset_s(address, bytes.count, 0, bytes.count)
            precondition(result == 0)
        }
    }
}

/// Fixed, uniquely owned storage: no reallocations or copy-on-write backing storage.
/// Borrowed pointers must not escape the synchronous callbacks that receive them.
final class KeyBuffer: ContiguousBytes {
    private let storage: UnsafeMutableRawBufferPointer
    var count: Int = 0
    let capacity: Int

    init(capacity: Int) {
        precondition(capacity > 0)
        self.capacity = capacity
        storage = .allocate(byteCount: capacity, alignment: 1)
        storage.initializeMemory(as: UInt8.self, repeating: 0)
    }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(rebasing: storage[..<count]))
    }

    func withStorage<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try body(storage)
    }

    func wipe() {
        let result = memset_s(storage.baseAddress!, capacity, 0, capacity)
        precondition(result == 0)
    }

    deinit {
        wipe()
        storage.deallocate()
    }
}
